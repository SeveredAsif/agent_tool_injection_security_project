"""Wait for the current main.py child to finish, then restart the orchestrator.

The parent run_all.py process was killed at trial 1299 by a PermissionError in
its status writer. It is now blocked in proc.wait() and will exit without
starting the remaining phases. The child main.py is unaffected and keeps
writing trials.

This script waits for the child to finish all 1600 trials, then launches
run_all.py again. The restart is cheap: every finished trial is skipped from the
JSONL checkpoint.
"""
from __future__ import annotations

import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

CKPT = Path("logs/ollama_llama3.1-8b_t50_none.jsonl")
TARGET = 1600
LOG = Path("logs/resume_watcher.log")


def note(msg: str) -> None:
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


def lines() -> int:
    try:
        with CKPT.open("r", encoding="utf-8") as f:
            return sum(1 for ln in f if ln.strip())
    except OSError:
        return 0


def main() -> None:
    note(f"watching {CKPT} for {TARGET} trials")
    stalled = 0
    last = lines()
    while True:
        n = lines()
        if n >= TARGET:
            note(f"child finished: {n}/{TARGET}")
            break
        if n == last:
            stalled += 1
            if stalled % 20 == 0:
                note(f"no new trial for {stalled} minutes (at {n}/{TARGET})")
        else:
            stalled = 0
            last = n
        time.sleep(60)

    # Let the old processes unwind before starting a new one.
    note("waiting 60 s for the old processes to exit")
    time.sleep(60)

    note("starting run_all.py --profile full (resumes from checkpoints)")
    with open("logs/run_all_console_full2.log", "w", encoding="utf-8") as out:
        rc = subprocess.run([sys.executable, "-u", "run_all.py", "--profile", "full"],
                            stdout=out, stderr=subprocess.STDOUT).returncode
    note(f"run_all.py exited with code {rc}")


if __name__ == "__main__":
    main()
