"""Live dashboard for the experiment runs.

    python watch.py            one snapshot
    python watch.py --follow   refresh every 20 s

The checkpoint files are the ground truth. Each finished trial appends one line
to logs/<tag>.jsonl. This tool reads those files directly, so it still works if
the orchestrator or its status file is missing.

Do NOT open any file in logs/ in an editor while a run is going. On Windows an
open file can block the orchestrator's status write.
"""
from __future__ import annotations

import argparse
import json
import re
import time
from datetime import datetime, timedelta
from pathlib import Path

LOG_DIR = Path("logs")
STATUS = LOG_DIR / "run_all_status.json"
RUNLOG = LOG_DIR / "run_all.log"

CASES = 8
CONFIGS = 4
SEC_PER_TRIAL = 14.0          # measured on llama3.1:8b, this machine

MARK = {"done": "[x]", "running": "[>]", "pending": "[ ]",
        "failed": "[!]", "skipped": "[-]"}

TAG = re.compile(r"^(?P<backend>\w+)_(?P<model>.+)_t(?P<n>\d+)_(?P<adaptive>\w+)$")


def bar(done: int, total: int, width: int = 24) -> str:
    if not total:
        return "." * width
    filled = min(width, int(width * done / total))
    return "#" * filled + "." * (width - filled)


def count_lines(path: Path) -> int:
    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def checkpoints() -> list[dict]:
    """Read every run checkpoint. This does not depend on the orchestrator."""
    out = []
    for p in sorted(LOG_DIR.glob("*.jsonl")):
        m = TAG.match(p.stem)
        if not m:
            continue
        n = int(m.group("n"))
        done = count_lines(p)
        total = n * CASES * CONFIGS
        try:
            age = (datetime.now() - datetime.fromtimestamp(p.stat().st_mtime)).total_seconds()
        except OSError:
            age = 1e9
        out.append({"tag": p.stem, "done": done, "total": total, "age_s": age,
                    "model": m.group("model"), "adaptive": m.group("adaptive")})
    return out


def show_checkpoints(rows: list[dict]) -> None:
    print(" RUN CHECKPOINTS  (ground truth: one line per finished trial)")
    print(" " + "-" * 60)
    active = None
    stale: list[dict] = []
    for r in rows:
        if r["done"] >= r["total"]:
            state = "complete"
        elif r["age_s"] < 300:
            state = "ACTIVE"
        elif r["done"] == 0:
            state = "not started"
        else:
            # Incomplete and not written recently. Either it is queued behind the
            # active run (its lines are reused seed trials), or it stopped.
            state = "queued"
            stale.append(r)
        if state == "ACTIVE":
            active = r
        print(f"  {bar(r['done'], r['total'])} {r['done']:>5}/{r['total']:<5} "
              f"{state:<11} {r['tag']}")
    if active:
        left = active["total"] - active["done"]
        eta = left * SEC_PER_TRIAL / 60
        finish = datetime.now() + timedelta(minutes=eta)
        print(" " + "-" * 60)
        print(f"  active : {active['tag']}")
        print(f"  left   : {left} trials  ~{eta:.0f} min  -> about {finish:%H:%M}")
    elif rows and all(r["done"] >= r["total"] for r in rows):
        print(" " + "-" * 60)
        print("  all checkpoints complete")
    else:
        # No run wrote a trial in the last 5 minutes, but work remains. Nothing
        # is being produced. This is always a fault. Say so clearly.
        print(" " + "-" * 60)
        print("  *** NOTHING IS RUNNING ***")
        print("  No trial was written in the last 5 minutes, but work remains.")
        for r in stale:
            print(f"    {r['tag']}  stopped at {r['done']}/{r['total']}"
                  f"  ({r['age_s'] / 60:.0f} min ago)")
        print("  Restart with:  python run_all.py --profile full")
        print("  It resumes from the checkpoints. No finished trial is repeated.")


def show_phases() -> bool:
    if not STATUS.exists():
        return False
    try:
        d = json.loads(STATUS.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return False
    started = datetime.fromisoformat(d["started"])
    elapsed = (datetime.now() - started).total_seconds() / 60
    print(f" ORCHESTRATOR    profile {d.get('profile', '?'):<9} elapsed {elapsed:.0f} min")
    print(" " + "-" * 60)
    for p in d.get("phases", []):
        st = p.get("status", "pending")
        prog = p.get("progress") or {}
        line = f"  {MARK.get(st, '[?]')} {p['name']:<14}"
        if prog.get("total"):
            line += f" {prog.get('done', 0)}/{prog['total']}"
        if st == "done" and p.get("elapsed_min"):
            line += f"  took {p['elapsed_min']:.0f}m"
        print(line)
    if d.get("finished"):
        print(f"  FINISHED {d['finished']}  ->  REPORT.md")
    return True


def snapshot(tail: int = 6) -> None:
    print("=" * 62)
    if not show_phases():
        print(" ORCHESTRATOR    status file absent (the run still works)")
    print("=" * 62)
    rows = checkpoints()
    if rows:
        show_checkpoints(rows)
    else:
        print(" no checkpoint files found under logs/")
    if RUNLOG.exists() and tail:
        print(" " + "-" * 60)
        try:
            age_min = (datetime.now()
                       - datetime.fromtimestamp(RUNLOG.stat().st_mtime)).total_seconds() / 60
            if age_min > 10:
                print(f"  run_all.log is STALE ({age_min:.0f} min old). The orchestrator is"
                      " not writing it.")
                print("  The checkpoint table above is the live view.")
            for line in RUNLOG.read_text(encoding="utf-8", errors="replace").splitlines()[-tail:]:
                print("  " + line)
        except OSError:
            pass
    print("=" * 62)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--follow", action="store_true")
    ap.add_argument("--tail", type=int, default=6)
    args = ap.parse_args()
    while True:
        print()
        snapshot(args.tail)
        if not args.follow:
            return
        time.sleep(20)


if __name__ == "__main__":
    main()
