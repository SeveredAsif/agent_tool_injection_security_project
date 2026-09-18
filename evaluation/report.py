"""Generate the final observations report from completed experiment runs.

Report structure follows the course instruction:
    the attack process, the expected outcome, the actual outcome, and if it
    differs then why, defense mechanism, does it work as expected or not,
    and are there any assumptions regarding the attack.

Every number is read from results/*/summary.json -- nothing is hand-written, so
the report cannot drift from the data.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

RESULTS = Path("results")
OUT = Path("REPORT.md")


# ---------------------------------------------------------------- helpers
def load_runs() -> dict[str, dict[str, Any]]:
    runs = {}
    for d in sorted(RESULTS.iterdir()):
        f = d / "summary.json" if d.is_dir() else None
        if f and f.exists():
            runs[d.name] = json.loads(f.read_text(encoding="utf-8"))
    return runs


def pick(runs: dict, backend="ollama", model=None, adaptive="none", prefer_max_trials=True):
    """Select the most authoritative run matching a filter."""
    cand = []
    for tag, r in runs.items():
        m = r.get("metadata", {})
        if m.get("model_backend") != backend:
            continue
        if model and m.get("model_name") != model:
            continue
        if r.get("adaptive_attacker", "none") != adaptive:
            continue
        cand.append((r.get("trials_per_case_per_config", 0), tag, r))
    if not cand:
        return None, None
    cand.sort(reverse=prefer_max_trials)
    return cand[0][1], cand[0][2]


def fmt(metric: dict | None, with_counts=True) -> str:
    if not metric or metric.get("value") is None:
        return "n/a"
    s = f"{metric['value']:.3f} [{metric['ci95_low']:.3f}, {metric['ci95_high']:.3f}]"
    if with_counts:
        s += f" ({metric['numerator']}/{metric['denominator']})"
    return s


def headline_table(res: dict) -> str:
    rows = [
        "| Configuration | ASR | DDR | FBR | TCR |",
        "| --- | --- | --- | --- | --- |",
    ]
    names = {
        "E1": "E1 — benign, no defense",
        "E1D": "E1D — benign, defense on",
        "E2": "E2 — attack, no defense",
        "E3": "E3 — attack, defense on",
    }
    for key, label in names.items():
        e = res.get(key)
        if not e:
            continue
        rows.append(f"| {label} | {fmt(e.get('ASR'))} | {fmt(e.get('DDR'))} | "
                    f"{fmt(e.get('FBR'))} | {fmt(e.get('TCR'))} |")
    return "\n".join(rows)


def strategy_table(res: dict) -> str:
    e2 = res.get("E2_by_strategy", {})
    e3 = res.get("E4_by_strategy", {})
    rows = ["| Strategy | ASR (E2, no defense) | ASR (E3, defense) | DDR (E3) | TCR (E3) |",
            "| --- | --- | --- | --- | --- |"]
    for s in sorted(e2):
        a, b = e2[s], e3.get(s, {})
        rows.append(f"| `{s}` | {fmt(a.get('ASR'), False)} | {fmt(b.get('ASR'), False)} | "
                    f"{fmt(b.get('DDR'), False)} | {fmt(b.get('TCR'), False)} |")
    return "\n".join(rows)


def axis_table(res: dict) -> str:
    axes = res.get("E2_by_variant_axis", {})
    if not axes:
        return "_not recorded in this run_"
    rows = ["| Axis | Level | ASR | n |", "| --- | --- | --- | --- |"]
    for axis, levels in axes.items():
        ordered = sorted(levels.items(), key=lambda kv: -(kv[1]["ASR"]["value"] or 0))
        for lvl, d in ordered:
            a = d["ASR"]
            label = lvl if len(lvl) < 46 else lvl[:44] + "…"
            rows.append(f"| {axis} | {label} | {a['value']:.2f} | {a['denominator']} |")
    return "\n".join(rows)


def delta(a: float | None, b: float | None) -> str:
    if a is None or b is None:
        return "n/a"
    return f"{b - a:+.3f}"


def overlap(m1: dict, m2: dict) -> bool:
    """Do two Wilson intervals overlap? Used instead of claiming significance."""
    if not m1 or not m2 or m1.get("value") is None or m2.get("value") is None:
        return False
    return not (m1["ci95_high"] < m2["ci95_low"] or m2["ci95_high"] < m1["ci95_low"])


def main() -> None:
    from evaluation.report_body import build
    runs = load_runs()
    if not runs:
        raise SystemExit("no runs found under results/")
    OUT.write_text(build(runs), encoding="utf-8")
    print(f"wrote {OUT} ({OUT.stat().st_size} bytes) from {len(runs)} run(s)")


if __name__ == "__main__":
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    main()
