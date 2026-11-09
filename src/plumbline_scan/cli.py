"""plumbline-scan: mechanical pre-release checks for Harbor-format tasks."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, extras, guidance, report
from .checks import CHECKS, Options, Scan
from .docker import Docker
from .harbor import TaskError, find_tasks, load_task


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="plumbline-scan",
        description="Mechanical checks on Harbor-format tasks. PS-1 to PS-6 run the task in Docker: the reference "
                    "passes (k runs), a no-op fails, the answer is not recoverable from the image, the reference is "
                    "not a stub, the verifier does not trust files the agent can edit, network dependence. PS-7 to "
                    "PS-12 read the verifier's files only (no Docker): see --static-only. No API keys, no models.")
    p.add_argument("paths", nargs="*", help="task directories, or directories of task directories "
                                            "(or: plumbline-scan verify RECORD.json to check a signed audit record)")
    p.add_argument("-o", "--out", default="plumbline-scan-out", help="output directory (scan.json, scan.md, logs/)")
    p.add_argument("-k", type=int, default=3, help="reference runs per task (default 3)")
    p.add_argument("-j", "--jobs", type=int, default=1, help="tasks scanned in parallel (default 1)")
    p.add_argument("--network", choices=("auto", "sealed", "on"), default="auto",
                   help="auto (default): run sealed; when the reference fails and the task allows the network, "
                        "retry with it and mark the task network-dependent. sealed: never give the network. "
                        "on: always give it.")
    p.add_argument("--skip", default="", help=f"comma-separated checks to skip: {','.join(c for c in CHECKS if c != 'network')}")
    p.add_argument("--no-limits", action="store_true", help="ignore the task's cpus/memory limits")
    p.add_argument("--no-pull", action="store_true", help="never pull images; use local ones only")
    p.add_argument("--rm-images", action="store_true",
                   help="after each task, remove the images this scan pulled or built (never pre-existing ones)")
    p.add_argument("--timeout-mult", type=float, default=1.0, help="multiply the task's agent/verifier timeouts")
    p.add_argument("--no-grade-recovered", action="store_true", help="do not grade a fix recovered from git")
    p.add_argument("--sarif-root", default=".",
                   help="paths in scan.sarif are relative to this directory (your repository root; default: .)")
    p.add_argument("--static-only", action="store_true",
                   help="run only the static checks PS-7 to PS-12 (reads files; no Docker, no network); "
                        "never issues the badge")
    p.add_argument("--estimate", action="store_true",
                   help="print the task count, formats and the published price range for a deep audit, then exit "
                        "(no Docker, no network)")
    p.add_argument("--no-badge", action="store_true", help="do not write badge.svg/badge.md even when every check passes")
    p.add_argument("--subscribe", metavar="EMAIL",
                   help="opt in: send this email address (and nothing else) to plumblinegrader.com to hear about "
                        "new checks and Index releases")
    p.add_argument("--version", action="version", version=f"plumbline-scan {__version__}")
    return p.parse_args(argv)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    if argv[:1] == ["verify"]:
        from .verify import main as verify_main
        return verify_main(argv[1:])
    t_start = time.monotonic()
    a = parse_args(argv)
    if not a.paths and not a.subscribe:
        print("give one or more task directories (or --subscribe EMAIL)", file=sys.stderr)
        return 2
    if a.subscribe:
        ok, info, payload = extras.subscribe(a.subscribe, int((time.monotonic() - t_start) * 1000))
        print(f"subscribe: sent {json.dumps(payload)}: {'ok' if ok else 'not accepted (' + info + ')'}")
        if not a.paths:
            return 0 if ok else 1
    skip = tuple(s.strip() for s in a.skip.split(",") if s.strip())
    bad = [s for s in skip if s not in CHECKS]
    if bad:
        print(f"unknown check(s) in --skip: {', '.join(bad)}", file=sys.stderr)
        return 2
    try:
        dirs = find_tasks(a.paths)
    except TaskError as e:
        print(e, file=sys.stderr)
        return 2
    if not dirs:
        print("no Harbor tasks found (a task is a directory with task.toml)", file=sys.stderr)
        return 2
    if a.estimate:
        tasks, bad = [], []
        for d in dirs:
            try:
                tasks.append(load_task(d))
            except TaskError as e:
                bad.append(str(e))
        print(extras.estimate(tasks))
        for b in bad:
            print(f"not a loadable task: {b}")
        return 0
    out = Path(a.out)
    if a.static_only:
        return _static_only(a, dirs, out)
    docker = Docker(log_dir=out / "logs", limits=not a.no_limits, pull=not a.no_pull, timeout_mult=a.timeout_mult)
    err = docker.available()
    if err:
        print(err, file=sys.stderr)
        return 2
    opts = Options(k=a.k, network=a.network, skip=skip, grade_recovered=not a.no_grade_recovered)
    lock = threading.Lock()

    def log(msg: str) -> None:
        with lock:
            print(msg, flush=True)

    def one(d: Path) -> dict:
        try:
            task = load_task(d)
        except TaskError as e:
            return {"task": d.name, "path": str(d), "verdict": "ERROR", "error": str(e), "checks": {}, "seconds": 0}
        log(f"scanning {task.name} ({task.image})")
        try:
            rec = Scan(task, docker, opts, log).run()
        except Exception as e:  # one broken task must not end the scan
            rec = {"task": task.name, "path": str(d), "verdict": "ERROR", "error": f"{type(e).__name__}: {e}",
                   "checks": {}, "seconds": 0}
        finally:
            if a.rm_images:
                docker.remove_created(task)
        log(f"done {task.name}: {rec.get('verdict')} in {rec.get('seconds', 0):.0f}s")
        partial = out / "partial"
        partial.mkdir(parents=True, exist_ok=True)
        (partial / f"{task.name}.json").write_text(json.dumps(rec, indent=2))
        return rec

    with ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        records = list(ex.map(one, dirs))
    guidance.annotate(records, docker.log_dir)
    meta = {"date": dt.date.today().isoformat(), "k": a.k, "network": a.network, "paths": a.paths}
    j, m = report.write(out, records, meta)
    sf = report.write_sarif(out, records, Path(a.sarif_root))
    badge_note = "" if a.no_badge else extras.write_badge(out, records, meta["date"])[1]
    print()
    print(report.table(records))
    print(f"\nJSON: {j}\nSummary: {m}\nSARIF: {sf}")
    if badge_note:
        print(badge_note[:1].upper() + badge_note[1:])
    print()
    print(report.FOOTER)
    return 1 if any(r.get("verdict") == "FLAGGED" for r in records) else 0


def _static_only(a: argparse.Namespace, dirs: list, out: Path) -> int:
    """PS-7 to PS-12 only: no Docker, no network. Same outputs as a full scan, with the dynamic checks absent."""
    from dataclasses import asdict

    from .checks import detector_checks, verdict
    records = []
    for d in dirs:
        try:
            task = load_task(d)
        except TaskError as e:
            records.append({"task": d.name, "path": str(d), "verdict": "ERROR", "error": str(e), "checks": {}})
            continue
        checks = detector_checks(task)
        records.append({"task": task.name, "path": str(d),
                        "reference_kind": "repository patch" if task.is_patch_task else "script",
                        "checks": {k: asdict(c) for k, c in checks.items()},
                        # never "OK": PS-1 to PS-6 did not run
                        "verdict": "INCOMPLETE" if verdict(checks) == "OK" else verdict(checks)})
    guidance.annotate(records, out / "logs")
    meta = {"date": dt.date.today().isoformat(), "mode": "static only (PS-7 to PS-12; PS-1 to PS-6 not run)",
            "paths": a.paths}
    j, m = report.write(out, records, meta)
    sf = report.write_sarif(out, records, Path(a.sarif_root))
    print(report.table(records))
    print(f"\nStatic checks only (PS-7 to PS-12); PS-1 to PS-6 need Docker and were not run.")
    print(f"JSON: {j}\nSummary: {m}\nSARIF: {sf}\n")
    print(report.FOOTER)
    return 1 if any(r.get("verdict") == "FLAGGED" for r in records) else 0
