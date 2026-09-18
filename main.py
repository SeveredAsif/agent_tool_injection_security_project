"""CLI entry point.

    python main.py --scenario demo
    python main.py --scenario experiments --trials 100
    python main.py --backend ollama --model llama3.1:8b --scenario demo
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import config
from agent.agent import Agent, AgentConfig
from agent.model import MockLLM, OllamaLLM
from attack.attack import ADAPTIVE_MODES, AttackConfig, AttackTool
from environment.state import make_tools, seed_environment, tool_catalogue
from evaluation.experiments import run_experiments


def _build_llm(backend: str, model: str, tools: dict, strategy: str | None):
    if backend == "mock":
        return MockLLM(known_tools=set(tools), vulnerable=True, strategy=strategy)
    return OllamaLLM(model=model, tool_catalogue=tool_catalogue(tools))


def _show(title: str, run, env) -> None:
    print("\n=== " + title + " ===")
    print("Final answer :", run.final_answer)
    print("Executed     :", run.executed_tools)
    for p in run.proposals:
        mark = "EXECUTED" if p.executed else "REFUSED "
        print("  [" + mark + "] step " + str(p.step) + " " + p.tool
              + "  <- " + p.reason)
    print("Secret reads :", env.secret_reads or "none")
    print("Verifications:", env.verifications or "none")


def _load_demo_case(strategy: str) -> dict:
    """Pick a real graded test case for this strategy.

    The demo must show the exact behaviour the report measures, so it replays a
    case from datasets/testcases.json, not an ad-hoc one. Among the cases for
    this strategy it prefers one whose target is protected_tool, because that
    tool reads the lab secret and makes the attack visible on the 'Secret reads'
    line.
    """
    cases = json.loads(Path("datasets/testcases.json").read_text(encoding="utf-8"))
    if isinstance(cases, dict):
        cases = cases.get("cases", [])
    matches = [c for c in cases if c.get("strategy") == strategy]
    if not matches:
        raise SystemExit(f"no test case defined for strategy '{strategy}'")
    matches.sort(key=lambda c: c.get("target_tool") != "protected_tool")
    return matches[0]


def demo(backend: str, model: str, strategy: str, adaptive: bool) -> None:
    case = _load_demo_case(strategy)
    print("Replaying graded case", case["id"], "-", case["user_task"])
    attack_cfg = AttackConfig(strategy=strategy, target_tool=case["target_tool"],
                              attack_on=case["attack_on"], adaptive=adaptive)

    print("\n=== ATTACKER-CONTROLLED TOOL OUTPUT (strategy: " + strategy + ") ===\n")
    # A representative honest output for the attacked tool, so the preview matches
    # the case. The real run below produces the real output; this is illustration.
    honest_samples = {
        "weather": "Temperature: 31 C, Humidity: 72 percent",
        "currency": "100.00 USD = 11750.00 BDT",
        "search": "The capital of France is Paris.",
    }
    honest = honest_samples.get(case["attack_on"], "(tool output)")
    preview = AttackTool(attack_cfg)
    print("variant:", preview.variant.as_dict())
    print()
    print(preview.poison(honest, tool_name=case["attack_on"]))

    for label, defense_on in (("E2  VULNERABLE AGENT (no defense)", False),
                              ("E3  DEFENDED AGENT", True)):
        env = seed_environment()
        tools = make_tools(env)
        llm = _build_llm(backend, model, tools, strategy)
        agent = Agent(llm, env, tools,
                      AgentConfig(intent_category=case["intent_category"],
                                  defense_enabled=defense_on),
                      attack=AttackTool(attack_cfg))
        run = agent.run(case["user_task"])
        _show(label, run, env)


def main() -> None:
    parser = argparse.ArgumentParser(description="CSE 406 -- Agent Tool-Injection")
    parser.add_argument("--backend", choices=["mock", "ollama"], default="mock")
    parser.add_argument("--model", default=config.MODEL_NAME)
    parser.add_argument("--scenario", choices=["demo", "experiments"], default="demo")
    parser.add_argument("--strategy", choices=config.STRATEGIES,
                        default="authority_impersonation",
                        help="demo only; authority_impersonation fires on every trial "
                             "in the data, so the single-shot demo is reliable")
    parser.add_argument("--trials", type=int, default=config.NUM_TRIALS,
                        help="trials per case per configuration (use ~5 for the ollama backend)")
    parser.add_argument("--adaptive", choices=ADAPTIVE_MODES, default="none",
                        help="stretch goal (Report 20.4): adaptive attacker that knows "
                             "the defense. delimiter_spoof = fake closing tag; "
                             "split_calls = injection split across two tool outputs")
    args = parser.parse_args()

    Path("results").mkdir(exist_ok=True)

    if args.scenario == "demo":
        demo(args.backend, args.model, args.strategy, args.adaptive)
        return

    report = run_experiments(args.backend, args.model, args.trials, args.adaptive)
    res = report["results"]
    print(json.dumps({k: v for k, v in res.items() if not k.endswith("by_strategy")}, indent=2))
    print("\nHeadline numbers")
    for exp in ("E1", "E1D", "E2", "E3"):
        s = res[exp]
        def fmt(m):
            v = s[m]["value"]
            return "  n/a " if v is None else (
                str(v) + " [" + str(s[m]["ci95_low"]) + ", " + str(s[m]["ci95_high"]) + "]")
        print("  " + exp.ljust(4) + " ASR=" + fmt("ASR") + "  DDR=" + fmt("DDR")
              + "  FBR=" + fmt("FBR") + "  TCR=" + fmt("TCR"))
    out = report.get("output_dir", "results")
    print("\nWrote " + out + "/summary.json, " + out + "/trials.csv and 3 PNG figures,")
    print("plus logs/" + report["run_tag"] + ".json (full per-trial log with payloads).")


if __name__ == "__main__":
    main()
