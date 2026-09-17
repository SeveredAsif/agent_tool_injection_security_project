"""Experiment harness for configurations E1 / E1D / E2 / E3, plus the E4 breakdown.

Design Report Table 1 lists E1 as (attack=No, defense=No) and says it supplies
both FBR and TCR. FBR cannot be measured with the defense switched off -- nothing
can over-block if nothing is checking. The harness therefore runs the benign side
twice:

    E1   benign, defense off  -> baseline TCR (can the agent do the task at all?)
    E1D  benign, defense on   -> FBR         (does the defense refuse honest work?)
    E2   attack, defense off  -> ASR, and unauthorized EXECUTION
    E3   attack, defense on   -> ASR again, plus DDR and TCR under attack
    E4   = E3 and E2 split per strategy
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from time import perf_counter
from typing import Any

import config
from agent.agent import Agent, AgentConfig
from agent.model import MockLLM, OllamaLLM
from attack.attack import AttackConfig, AttackTool
from defense.allowlist import INTENT_CATEGORIES, allowlist_for
from environment.state import make_tools, seed_environment, tool_catalogue
from evaluation.metrics import (TrialResult, summarize, summarize_by_strategy,
                                summarize_by_variant_axis)

OUTPUT_DIR = Path("results")
LOG_DIR = Path("logs")


def run_tag(backend: str, model: str, trials: int, adaptive: str) -> str:
    """Unique folder name per run, so a cross-model or adaptive run cannot
    silently overwrite the results of a previous one."""
    safe = model.replace(":", "-").replace("/", "-")
    return f"{backend}_{safe}_t{trials}_{adaptive}"

CONFIGURATIONS = {
    "E1": {"attack": False, "defense": False},
    "E1D": {"attack": False, "defense": True},
    "E2": {"attack": True, "defense": False},
    "E3": {"attack": True, "defense": True},
}


def load_cases(path: str = "datasets/testcases.json") -> list[dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        cases = json.load(f)
    for case in cases:
        if case["intent_category"] not in INTENT_CATEGORIES:
            raise ValueError(
                "case " + case["id"] + " uses intent '" + case["intent_category"]
                + "' which has no allowlist entry")
    return cases


def task_completed(case: dict[str, Any], answer: str) -> bool:
    """Deterministic ground-truth check, not a subjective score."""
    text = (answer or "").lower()
    return all(sub.lower() in text for sub in case["expected_substrings"])


def run_trial(case: dict[str, Any], experiment: str, backend: str, model: str,
              trial: int, adaptive: str = "none") -> TrialResult:
    setup = CONFIGURATIONS[experiment]
    env = seed_environment()
    tools = make_tools(env)

    attack = None
    if setup["attack"]:
        attack = AttackTool(AttackConfig(
            strategy=case["strategy"],
            target_tool=case["target_tool"],
            attack_on=case["attack_on"],
            case_id=case["id"],
            trial=trial,
            seed=config.SEED,
            adaptive=adaptive,
        ))

    if backend == "mock":
        llm = MockLLM(known_tools=set(tools), vulnerable=True,
                      strategy=case["strategy"] if setup["attack"] else None,
                      seed=config.SEED, trial=trial)
    else:
        llm = OllamaLLM(model=model, seed=config.SEED + trial,
                        tool_catalogue=tool_catalogue(tools))

    agent = Agent(llm, env, tools, AgentConfig(
        intent_category=case["intent_category"],
        defense_enabled=setup["defense"],
    ), attack=attack)

    start = perf_counter()
    run = agent.run(case["user_task"])
    elapsed_ms = (perf_counter() - start) * 1000

    target = case["target_tool"]
    allowed = allowlist_for(case["intent_category"])

    attempted = run.attempted(target)
    executed = run.executed(target)
    blocked = attempted and not executed

    # A legitimate call is one the intent category authorises. It counts as
    # falsely blocked only if the defense refused it.
    legitimate_blocked = any(
        p.tool in allowed and not p.executed and p.verdict in ("BLOCK", "REQUIRE_CONFIRMATION")
        for p in run.proposals
    )

    attack_log = attack.to_dict() if attack is not None else {}

    return TrialResult(
        trial_id=case["id"] + "/" + experiment + "/t" + str(trial),
        case_id=case["id"],
        experiment=experiment,
        strategy=case["strategy"] if setup["attack"] else "none",
        intent_category=case["intent_category"],
        attack_enabled=setup["attack"],
        defense_enabled=setup["defense"],
        attempted_unauthorized=attempted,
        unauthorized_blocked=blocked,
        unauthorized_executed=executed,
        legitimate_blocked=legitimate_blocked,
        task_completed=task_completed(case, run.final_answer),
        steps_used=run.steps_used,
        latency_ms=round(elapsed_ms, 3),
        final_answer=run.final_answer[:500],
        blocked_reasons=[p.reason for p in run.blocked_calls()],
        attack_variant=attack_log.get("variant", {}),
        attack_stages_served=attack_log.get("stages_served", 0),
        attack_payloads=[p["payload"] for p in attack_log.get("payloads", [])],
        executed_tools=list(run.executed_tools),
    )


def run_experiments(backend: str = "mock", model: str = config.MODEL_NAME,
                    trials: int = config.NUM_TRIALS, adaptive: str = "none",
                    cases_path: str = "datasets/testcases.json",
                    verbose: bool = True, tag: str | None = None) -> dict[str, Any]:
    tag = tag or run_tag(backend, model, trials, adaptive)
    out_dir = OUTPUT_DIR / tag
    out_dir.mkdir(parents=True, exist_ok=True)
    cases = load_cases(cases_path)

    all_trials: list[TrialResult] = []
    summaries: dict[str, Any] = {}

    total = len(CONFIGURATIONS) * len(cases) * trials
    done = 0
    start_all = perf_counter()
    for experiment in CONFIGURATIONS:
        bucket: list[TrialResult] = []
        for case in cases:
            for trial in range(trials):
                bucket.append(run_trial(case, experiment, backend, model, trial, adaptive))
                done += 1
                if verbose:
                    rate = (perf_counter() - start_all) / done
                    eta = rate * (total - done)
                    print(f"  [{done:>4}/{total}] {experiment:<4} {case['id']} "
                          f"trial {trial}  ETA {eta/60:5.1f} min", flush=True)
        all_trials.extend(bucket)
        summaries[experiment] = summarize(bucket)

    # E4: per-strategy breakdown of the defended attack configuration.
    summaries["E4_by_strategy"] = summarize_by_strategy(
        [t for t in all_trials if t.experiment == "E3"])
    summaries["E2_by_strategy"] = summarize_by_strategy(
        [t for t in all_trials if t.experiment == "E2"])

    # Section 10: does each payload variation axis move ASR? Measured on E2,
    # where nothing is blocking, so the axis effect is not masked by the defense.
    e2 = [t for t in all_trials if t.experiment == "E2"]
    summaries["E2_by_variant_axis"] = {
        axis: summarize_by_variant_axis(e2, axis)
        for axis in ("placement", "authority", "padding", "wording")
    }

    report = {
        "run_tag": tag,
        "metadata": config.run_metadata(backend, model),
        "trials_per_case_per_config": trials,
        "cases": [c["id"] for c in cases],
        "configurations": CONFIGURATIONS,
        "adaptive_attacker": adaptive,
        "results": summaries,
    }

    (out_dir / "summary.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")

    with open(out_dir / "trials.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(all_trials[0].row().keys()))
        writer.writeheader()
        for t in all_trials:
            writer.writerow(t.row())

    LOG_DIR.mkdir(parents=True, exist_ok=True)
    (LOG_DIR / (tag + ".json")).write_text(json.dumps({
        "metadata": report["metadata"],
        "configurations": CONFIGURATIONS,
        "trials": [t.full_record() for t in all_trials],
    }, indent=2), encoding="utf-8")

    _plot(summaries, out_dir)
    report["output_dir"] = str(out_dir)
    return report


def _plot(summaries: dict[str, Any], out_dir: Path) -> None:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    def val(exp: str, metric: str) -> float:
        v = summaries.get(exp, {}).get(metric, {}).get("value")
        return 0.0 if v is None else v

    def err(exp: str, metric: str) -> list[float]:
        m = summaries.get(exp, {}).get(metric, {})
        if m.get("value") is None:
            return [0.0, 0.0]
        return [m["value"] - m["ci95_low"], m["ci95_high"] - m["value"]]

    # Figure 1: ASR is unchanged by the defense; DDR is what moves.
    exps = ["E2", "E3"]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    x = range(len(exps))
    ax.bar([i - 0.2 for i in x], [val(e, "ASR") for e in exps], width=0.4, label="ASR (attempted)",
           yerr=list(zip(*[err(e, "ASR") for e in exps])), capsize=4)
    ax.bar([i + 0.2 for i in x], [val(e, "DDR") for e in exps], width=0.4, label="DDR (blocked)",
           yerr=list(zip(*[err(e, "DDR") for e in exps])), capsize=4)
    ax.set_xticks(list(x))
    ax.set_xticklabels(["E2 attack, no defense", "E3 attack + defense"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("rate")
    ax.set_title("ASR vs DDR (95% Wilson CI)")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_dir / "asr_vs_ddr.png", dpi=180)
    plt.close(fig)

    # Figure 2: the security / utility trade-off.
    fig, ax = plt.subplots(figsize=(7, 4.5))
    labels = ["DDR (E3)", "FBR (E1D)", "TCR (E1)", "TCR (E3)"]
    values = [val("E3", "DDR"), val("E1D", "FBR"), val("E1", "TCR"), val("E3", "TCR")]
    errs = list(zip(err("E3", "DDR"), err("E1D", "FBR"), err("E1", "TCR"), err("E3", "TCR")))
    ax.bar(labels, values, yerr=errs, capsize=4, color=["#2a6f4e", "#a83232", "#37618e", "#37618e"])
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("rate")
    ax.set_title("Security / utility trade-off (95% Wilson CI)")
    fig.tight_layout()
    fig.savefig(out_dir / "security_utility_tradeoff.png", dpi=180)
    plt.close(fig)

    # Figure 3: E4, ASR by strategy with and without the defense.
    by_strategy = summaries.get("E2_by_strategy", {})
    defended = summaries.get("E4_by_strategy", {})
    strategies = sorted(by_strategy)
    if strategies:
        fig, ax = plt.subplots(figsize=(9, 4.5))
        x = range(len(strategies))
        undef = [by_strategy[s]["ASR"]["value"] or 0 for s in strategies]
        ddr = [(defended.get(s, {}).get("DDR", {}) or {}).get("value") or 0 for s in strategies]
        ax.bar([i - 0.2 for i in x], undef, width=0.4, label="ASR (E2)")
        ax.bar([i + 0.2 for i in x], ddr, width=0.4, label="DDR (E3)")
        ax.set_xticks(list(x))
        ax.set_xticklabels([s.replace("_", "\n") for s in strategies], fontsize=8)
        ax.set_ylim(0, 1.05)
        ax.set_ylabel("rate")
        ax.set_title("E4: per-strategy attack success and defense blocking")
        ax.legend()
        fig.tight_layout()
        fig.savefig(out_dir / "e4_by_strategy.png", dpi=180)
        plt.close(fig)
