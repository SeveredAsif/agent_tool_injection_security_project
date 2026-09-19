"""Run every remaining experiment, then write REPORT.md.

Resumable at trial level: each finished trial is checkpointed to
logs/<tag>.jsonl the moment it completes, so closing the laptop costs at most
one trial (~20 s). Re-running this script picks up exactly where it stopped.

    python run_all.py                  # deadline profile, ~6 h
    python run_all.py --profile full   # proposal-exact, ~18.5 h
    python run_all.py --report-only    # regenerate REPORT.md from existing data

Each phase streams per-trial progress to stdout and to logs/run_all.log.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

import config

# "mock" is only for smoke-testing this orchestrator; graded runs are "ollama".
BACKEND = os.environ.get("ATI_BACKEND", "ollama")

LOG_DIR = Path("logs")
STATUS = LOG_DIR / "run_all_status.json"
RUNLOG = LOG_DIR / "run_all.log"

PROGRESS = re.compile(r"\[\s*(\d+)/(\d+)\]")
RESUMED = re.compile(r"resuming: (\d+) trial")

# Measured on this machine: ~19.7 s per trial for an 8B model on CPU.
SEC_PER_TRIAL = 19.7

PROFILES = {
    # name              llama trials, mistral trials, adaptive trials
    "deadline": (20, 10, 5),
    "smoke": (1, 1, 1),
    "full": (50, 50, 5),
    "minimal": (10, 5, 5),
}


def log(msg: str) -> None:
    line = f"[{datetime.now():%H:%M:%S}] {msg}"
    print(line, flush=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with RUNLOG.open("a", encoding="utf-8") as f:
        f.write(line + "\n")


class Status:
    """Machine-readable progress, rewritten atomically after every update."""

    def __init__(self, phases: list[dict]):
        self.data = {
            "started": datetime.now().isoformat(timespec="seconds"),
            "updated": None,
            "current": None,
            "phases": phases,
        }
        self.save()

    def save(self) -> None:
        """Write the status file. NEVER raise.

        This is progress reporting only. A failure here must not stop an
        experiment that has already run for hours. On Windows a file viewer or
        editor holding the temp file open makes os.replace() raise
        PermissionError, so the temp name is unique per write and every error is
        swallowed.
        """
        self.data["updated"] = datetime.now().isoformat(timespec="seconds")
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            tmp = STATUS.with_name(f".{STATUS.name}.{os.getpid()}.tmp")
            tmp.write_text(json.dumps(self.data, indent=2), encoding="utf-8")
            os.replace(tmp, STATUS)
        except OSError:
            try:
                tmp.unlink(missing_ok=True)
            except (OSError, NameError, UnboundLocalError):
                pass

    def phase(self, name: str) -> dict:
        for p in self.data["phases"]:
            if p["name"] == name:
                return p
        raise KeyError(name)

    def update(self, name: str, **kw) -> None:
        self.phase(name).update(kw)
        self.data["current"] = name
        self.save()


def model_present(model: str) -> bool:
    try:
        tags = requests.get(config.OLLAMA_HOST + "/api/tags", timeout=10).json()
        return any(m.get("name") == model for m in tags.get("models", []))
    except requests.RequestException:
        return False


def pull_model(model: str, status: Status, name: str) -> bool:
    """Pull via the HTTP API so this does not depend on `ollama` being on PATH."""
    if model_present(model):
        log(f"{model} already present, skipping pull")
        return True
    log(f"pulling {model} (this is a ~4 GB download)")
    try:
        r = requests.post(config.OLLAMA_HOST + "/api/pull",
                          json={"model": model, "stream": True}, stream=True, timeout=7200)
        r.raise_for_status()
        last = 0.0
        for raw in r.iter_lines():
            if not raw:
                continue
            try:
                ev = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if "error" in ev:
                log(f"pull failed: {ev['error']}")
                return False
            total, completed = ev.get("total"), ev.get("completed")
            if total and completed:
                pct = 100.0 * completed / total
                if pct - last >= 5:
                    last = pct
                    log(f"  pull {ev.get('status', '')}: {pct:.0f}%")
                    status.update(name, progress={"done": int(pct), "total": 100})
        ok = model_present(model)
        log(f"pull {'succeeded' if ok else 'finished but model not listed'}")
        return ok
    except requests.RequestException as exc:
        log(f"pull failed: {exc}")
        return False


def run_experiment(name: str, argv: list[str], expected_trials: int, status: Status) -> bool:
    """Stream a main.py run, mirroring progress into the status file."""
    status.update(name, status="running", started=datetime.now().isoformat(timespec="seconds"),
                  progress={"done": 0, "total": expected_trials})
    log(f"START {name}: {' '.join(argv)}")
    t0 = time.time()
    proc = subprocess.Popen([sys.executable, "-u", *argv], stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                            errors="replace", bufsize=1)
    tail: list[str] = []
    fresh_start = None
    fresh_done = 0
    try:
        # This loop MUST keep reading until the pipe closes. The child writes to
        # this pipe. If the loop stops early, the pipe buffer fills and the child
        # blocks on its next print, which freezes the experiment with no error
        # message anywhere. Therefore every statement inside is guarded.
        for line in proc.stdout:
            try:
                line = line.rstrip()
                tail.append(line)
                del tail[:-40]
                m = RESUMED.search(line)
                if m:
                    log(f"  {name}: resuming, {m.group(1)} trial(s) already done")
                m = PROGRESS.search(line)
                if m:
                    done, total = int(m.group(1)), int(m.group(2))
                    if fresh_start is None:
                        fresh_start, fresh_done = time.time(), done
                    rate = ((time.time() - fresh_start) / max(1, done - fresh_done)) \
                        if done > fresh_done else SEC_PER_TRIAL
                    eta_s = rate * (total - done)
                    status.update(name, progress={"done": done, "total": total},
                                  eta_min=round(eta_s / 60, 1))
                    if done % 20 == 0 or done == total:
                        log(f"  {name}: {done}/{total}  ETA {eta_s / 60:.0f} min")
            except Exception:
                continue
    except Exception:
        # The pipe itself failed. Wait for the child, then report the exit code.
        pass
    finally:
        proc.wait()
    ok = proc.returncode == 0
    elapsed = (time.time() - t0) / 60
    status.update(name, status="done" if ok else "failed", eta_min=0,
                  elapsed_min=round(elapsed, 1),
                  finished=datetime.now().isoformat(timespec="seconds"))
    log(f"{'DONE ' if ok else 'FAIL '} {name} in {elapsed:.1f} min (exit {proc.returncode})")
    if not ok:
        for t in tail[-15:]:
            log(f"    | {t}")
    return ok


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--profile", choices=sorted(PROFILES), default="deadline")
    ap.add_argument("--model", default=config.MODEL_NAME)
    ap.add_argument("--cross-model", default=config.CROSS_MODEL_NAME)
    ap.add_argument("--report-only", action="store_true")
    ap.add_argument("--skip-cross", action="store_true")
    args = ap.parse_args()

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if args.report_only:
        subprocess.run([sys.executable, "-m", "evaluation.report"], check=False)
        return

    n_main, n_cross, n_adapt = PROFILES[args.profile]
    cases, configs = 8, 4
    t_main, t_cross, t_adapt = (n_main * cases * configs, n_cross * cases * configs,
                                n_adapt * cases * configs)
    est = (t_main + t_cross + t_adapt) * SEC_PER_TRIAL / 3600

    phases = [
        {"name": "selftest", "status": "pending", "trials": 0},
        {"name": "main_llama", "status": "pending", "trials": t_main},
        {"name": "pull_mistral", "status": "pending", "trials": 0},
        {"name": "cross_mistral", "status": "pending", "trials": t_cross},
        {"name": "adaptive", "status": "pending", "trials": t_adapt},
        {"name": "report", "status": "pending", "trials": 0},
    ]
    status = Status(phases)
    status.data["profile"] = args.profile
    status.data["estimate_hours"] = round(est, 1)
    status.save()

    log("=" * 60)
    log(f"run_all profile={args.profile}  estimate ~{est:.1f} h")
    log(f"  main   {args.model} x{n_main}  -> {t_main} trials")
    log(f"  cross  {args.cross_model} x{n_cross} -> {t_cross} trials")
    log(f"  adapt  {args.model} x{n_adapt} (both) -> {t_adapt} trials")
    log("resumable: rerun this script after a shutdown and it continues")
    log("=" * 60)

    # 1 -- self test
    status.update("selftest", status="running")
    ok = subprocess.run([sys.executable, "tests/test_project.py"],
                        capture_output=True, text=True).returncode == 0
    status.update("selftest", status="done" if ok else "failed")
    log(f"selftest {'passed' if ok else 'FAILED'}")
    if not ok:
        log("aborting: fix the test failures first")
        return

    # 2 -- main run
    run_experiment("main_llama",
                   ["main.py", "--backend", BACKEND, "--model", args.model,
                    "--scenario", "experiments", "--trials", str(n_main)],
                   t_main, status)

    # 3/4 -- cross-model
    if args.skip_cross:
        status.update("pull_mistral", status="skipped")
        status.update("cross_mistral", status="skipped")
    else:
        status.update("pull_mistral", status="running")
        got = pull_model(args.cross_model, status, "pull_mistral")
        status.update("pull_mistral", status="done" if got else "failed")
        if got:
            run_experiment("cross_mistral",
                           ["main.py", "--backend", BACKEND, "--model", args.cross_model,
                            "--scenario", "experiments", "--trials", str(n_cross)],
                           t_cross, status)
        else:
            log("cross-model run skipped (pull failed); the report will note its absence")
            status.update("cross_mistral", status="skipped")

    # 5 -- adaptive attacker
    run_experiment("adaptive",
                   ["main.py", "--backend", BACKEND, "--model", args.model,
                    "--scenario", "experiments", "--trials", str(n_adapt),
                    "--adaptive", "both"],
                   t_adapt, status)

    # 6 -- report
    status.update("report", status="running")
    rc = subprocess.run([sys.executable, "-m", "evaluation.report"],
                        capture_output=True, text=True)
    status.update("report", status="done" if rc.returncode == 0 else "failed")
    log(rc.stdout.strip() or rc.stderr.strip()[:500])

    status.data["current"] = None
    status.data["finished"] = datetime.now().isoformat(timespec="seconds")
    status.save()
    log("=" * 60)
    log("ALL DONE -- see REPORT.md")
    log("=" * 60)


if __name__ == "__main__":
    main()
