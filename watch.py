"""Live dashboard for a run_all.py session.

    python watch.py            # one snapshot
    python watch.py --follow   # refresh every 20 s
"""
from __future__ import annotations

import argparse
import json
import time
from datetime import datetime, timedelta
from pathlib import Path

SEC_PER_TRIAL = 19.7

STATUS = Path("logs/run_all_status.json")
RUNLOG = Path("logs/run_all.log")

MARK = {"done": "[x]", "running": "[>]", "pending": "[ ]",
        "failed": "[!]", "skipped": "[-]"}


def bar(done: int, total: int, width: int = 28) -> str:
    if not total:
        return " " * width
    filled = int(width * done / total)
    return "#" * filled + "." * (width - filled)


def snapshot(tail: int = 8) -> None:
    if not STATUS.exists():
        print("no run in progress (logs/run_all_status.json not found)")
        return
    try:
        d = json.loads(STATUS.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        print("status file is mid-write, try again")
        return

    started = datetime.fromisoformat(d["started"])
    updated = datetime.fromisoformat(d["updated"])
    elapsed = (datetime.now() - started).total_seconds() / 60
    stale = (datetime.now() - updated).total_seconds()

    print("=" * 62)
    print(f" profile {d.get('profile', '?'):<10} estimate {d.get('estimate_hours', '?')} h"
          f"    elapsed {elapsed:.0f} min")
    print("=" * 62)

    # Calibrate from the phase actually running, rather than trusting a constant
    # measured on an earlier run at a different thermal/cache state.
    sec_per_trial = SEC_PER_TRIAL
    for p in d["phases"]:
        prog = p.get("progress") or {}
        if p.get("status") == "running" and p.get("eta_min") and prog.get("total"):
            left = prog["total"] - prog.get("done", 0)
            if left > 0:
                sec_per_trial = p["eta_min"] * 60 / left
        elif p.get("status") == "done" and p.get("elapsed_min") and p.get("trials"):
            sec_per_trial = p["elapsed_min"] * 60 / p["trials"]

    remaining = 0.0
    for p in d["phases"]:
        st = p.get("status", "pending")
        prog = p.get("progress") or {}
        done, total = prog.get("done", 0), prog.get("total", p.get("trials", 0))
        line = f" {MARK.get(st, '[?]')} {p['name']:<14}"
        if total:
            line += f" {bar(done, total)} {done:>5}/{total:<5}"
        else:
            line += " " * 42
        if st == "running":
            # Fall back to the per-trial estimate until the first progress line
            # lands, otherwise a just-started phase contributes nothing.
            eta = p.get("eta_min")
            if not eta:
                eta = max(0, total - done) * sec_per_trial / 60
            line += f" ETA {eta:.0f}m"
            remaining += eta
        elif st == "done" and p.get("elapsed_min"):
            line += f" took {p['elapsed_min']:.0f}m"
        elif st == "pending" and total:
            remaining += total * sec_per_trial / 60
        print(line)

    print("-" * 62)
    if d.get("finished"):
        print(f" FINISHED at {d['finished']}  ->  REPORT.md")
    else:
        eta_clock = datetime.now() + timedelta(minutes=remaining)
        print(f" estimated remaining: {remaining / 60:.1f} h"
              f"   -> finishes about {eta_clock:%H:%M} ({eta_clock:%a})")
        if stale > 600:
            print(f" WARNING: status not updated for {stale / 60:.0f} min -- run may have stopped.")

    if RUNLOG.exists() and tail:
        print("-" * 62)
        for line in RUNLOG.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]:
            print(" " + line)
    print("=" * 62)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--tail", type=int, default=8)
    args = ap.parse_args()
    while True:
        print()
        snapshot(args.tail)
        if not args.follow:
            return
        time.sleep(20)


if __name__ == "__main__":
    main()
