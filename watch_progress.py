"""Live progress for a running Ollama experiment.

The experiment process only writes results/ when it finishes, so this reads the
Ollama server log instead and estimates how far along the run is.

    python watch_progress.py            # one snapshot
    python watch_progress.py --follow   # refresh every 30 s
"""
from __future__ import annotations

import argparse
import os
import re
import time
from datetime import datetime
from pathlib import Path

LOG = Path(os.environ.get("LOCALAPPDATA", "")) / "Ollama" / "server.log"
LINE = re.compile(r"\[GIN\] (\d{4}/\d{2}/\d{2} - \d{2}:\d{2}:\d{2}).*POST\s+\"/api/chat\"")

# 8 cases x 4 configurations x N trials; benign configs use ~2 model calls,
# attack configs ~4, so ~3 calls per trial on average.
CALLS_PER_TRIAL = 3.0


def snapshot(trials_per_case: int, cases: int = 8, configs: int = 4,
             since: str | None = None) -> None:
    if not LOG.exists():
        print("Ollama server log not found at", LOG)
        return
    stamps = []
    with LOG.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            m = LINE.search(line)
            if m:
                stamps.append(datetime.strptime(m.group(1), "%Y/%m/%d - %H:%M:%S"))
    if since:
        cutoff = datetime.strptime(since, "%Y-%m-%d %H:%M:%S")
        stamps = [s for s in stamps if s >= cutoff]
    if not stamps:
        print("no /api/chat calls recorded yet")
        return

    total_trials = cases * configs * trials_per_case
    expected_calls = total_trials * CALLS_PER_TRIAL
    done = len(stamps)
    elapsed = (stamps[-1] - stamps[0]).total_seconds()
    rate = done / elapsed if elapsed > 0 else 0.0
    remaining = max(0.0, expected_calls - done)
    eta_min = (remaining / rate / 60) if rate > 0 else float("nan")
    idle = (datetime.now() - stamps[-1]).total_seconds()

    print(f"model calls completed : {done} / ~{expected_calls:.0f}"
          f"  ({100 * done / expected_calls:.1f}%)")
    print(f"approx trials done    : {done / CALLS_PER_TRIAL:.0f} / {total_trials}")
    print(f"rate                  : {rate * 60:.1f} calls/min"
          f"  ({1 / rate:.1f} s per call)" if rate else "rate: n/a")
    print(f"estimated time left   : {eta_min:.0f} min")
    print(f"last call             : {stamps[-1]:%H:%M:%S}  ({idle:.0f}s ago)")
    if idle > 300:
        print("  WARNING: no model call in over 5 minutes -- the run may have stopped.")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--trials", type=int, default=5, help="the --trials value used for the run")
    ap.add_argument("--since", default=None, help='ignore calls before "YYYY-MM-DD HH:MM:SS"')
    ap.add_argument("--follow", action="store_true")
    args = ap.parse_args()
    while True:
        print("-" * 56)
        snapshot(args.trials, since=args.since)
        if not args.follow:
            return
        time.sleep(30)


if __name__ == "__main__":
    main()
