#!/usr/bin/env python3
"""Run Plumbline Scan on Harbor-format tasks and print a short summary for a coding agent to relay.

    python3 run_scan.py [PATH] [--full] [--out DIR] [--scanner auto|bundled|path|module] [--json]

PATH is one task directory (with task.toml) or a directory of them (default: the current directory).
By default only the static checks run (PS-7 to PS-12: no Docker, no network, seconds). --full also runs the
Docker checks (PS-1 to PS-6) when Docker answers; otherwise it says so and runs the static checks.

The scanner is found in this order (--scanner auto): a copy bundled with this skill or plugin (vendor/ next to
this script, or a src/plumbline_scan in a parent folder, as in the plumbline-scan repository), then the
`plumbline-scan` command on PATH, then an importable `plumbline_scan` module. Nothing is downloaded, no model is
called, and no result is sent anywhere.

Exit codes: 0 no task flagged, 1 at least one task flagged, 2 usage error, 3 scanner not found.
Standard library only; Python 3.11+.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
INSTALL_HINT = (
    "Plumbline Scan is not installed. Install it (Python 3.11+, no runtime dependencies):\n"
    "  pip install git+https://github.com/plumblinegrader/plumbline-scan@v0.4.1\n"
    "or install this skill from the plumbline-scan repository, which bundles the scanner."
)
CAVEATS = [
    "These are mechanical checks. A clean scan does not mean the tests are strong enough: a wrong solution "
    "may still pass them. Scan does not search for wrong solutions that the tests accept.",
    "The static checks (PS-7 to PS-12) report a grader shape, not a proven exploit. Treat each flag as a lead "
    "to confirm by running the task.",
    "Everything ran on this machine. No model was called and nothing was uploaded.",
]


def bundled_src() -> Path | None:
    """A scanner source folder shipped with the skill: vendor/ (standalone install) or a parent repo's src/."""
    candidates = [HERE / "vendor", HERE.parent / "vendor"]
    for parent in [HERE, *HERE.parents]:
        candidates += [parent / "src", parent / "plumbline-scan" / "src"]
    for c in candidates:
        if (c / "plumbline_scan" / "__init__.py").is_file():
            return c
    return None


def scanner_command(mode: str) -> tuple[list[str], dict[str, str]] | None:
    env = dict(os.environ)
    if mode in ("auto", "bundled"):
        src = bundled_src()
        if src is not None:
            env["PYTHONPATH"] = os.pathsep.join([str(src), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
            return [sys.executable, "-m", "plumbline_scan"], env
        if mode == "bundled":
            return None
    if mode in ("auto", "path"):
        exe = shutil.which("plumbline-scan")
        if exe:
            return [exe], env
        if mode == "path":
            return None
    if importlib.util.find_spec("plumbline_scan") is not None:
        return [sys.executable, "-m", "plumbline_scan"], env
    return None


def docker_ready() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=20).returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def summarize(scan: dict, static_only: bool, note: str = "") -> dict:
    tasks = scan.get("tasks", [])
    verdicts: dict[str, int] = {}
    items = []
    for t in tasks:
        verdicts[t.get("verdict", "?")] = verdicts.get(t.get("verdict", "?"), 0) + 1
        checks = t.get("checks", {}).items()
        for name, ch in sorted(checks, key=lambda kv: (len(kv[1].get("id", kv[0])), kv[1].get("id", kv[0]))):
            if ch.get("status") in ("FLAG", "WARN", "ERROR"):
                items.append({"task": t.get("task"), "check": ch.get("id", name), "status": ch["status"],
                              "summary": ch.get("summary", ""), "fix": ch.get("fix", "")})
    return {"tool": scan.get("tool", "plumbline-scan"), "version": scan.get("version"), "tasks": len(tasks),
            "verdicts": verdicts, "static_only": static_only, "note": note, "findings": items,
            "caveats": CAVEATS}


def render(s: dict, out: Path) -> str:
    mode = "static checks only (PS-7 to PS-12)" if s["static_only"] else "all checks (PS-1 to PS-12)"
    counts = ", ".join(f"{k} {v}" for k, v in sorted(s["verdicts"].items())) or "none"
    lines = [f"## Plumbline Scan {s['version'] or ''}: {s['tasks']} task(s), {mode}", "",
             f"Verdicts: {counts}."]
    if s["note"]:
        lines += ["", s["note"]]
    if s["findings"]:
        lines += ["", "| Task | Check | Status | What it found | How to fix |", "|---|---|---|---|---|"]
        for f in s["findings"]:
            cells = [f["task"], f["check"], f["status"], f["summary"], f["fix"] or "-"]
            lines.append("| " + " | ".join(str(c).replace("|", "/") for c in cells) + " |")
    else:
        lines += ["", "No check flagged or warned."]
    if s["static_only"]:
        lines += ["", "INCOMPLETE is expected with static checks only: PS-1 to PS-6 need Docker (run with --full)."]
    lines += ["", f"Full report: {out / 'scan.md'} (JSON: {out / 'scan.json'}, SARIF: {out / 'scan.sarif'})", ""]
    lines += [f"- {c}" for c in s["caveats"]]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("path", nargs="?", default=".")
    ap.add_argument("--full", action="store_true", help="also run the Docker checks PS-1 to PS-6")
    ap.add_argument("--out", default="plumbline-scan-out")
    ap.add_argument("--scanner", choices=["auto", "bundled", "path", "module"], default="auto")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON instead of Markdown")
    a = ap.parse_args(argv)

    target = Path(a.path)
    if not target.exists():
        print(f"error: {target} does not exist", file=sys.stderr)
        return 2
    found = scanner_command(a.scanner)
    if found is None:
        print(INSTALL_HINT, file=sys.stderr)
        return 3
    cmd, env = found
    out = Path(a.out).resolve()
    static_only, note = True, ""
    if a.full:
        if docker_ready():
            static_only = False
        else:
            note = "Docker is not available here, so only the static checks ran (PS-7 to PS-12)."
    args = cmd + [str(target), "-o", str(out)] + (["--static-only"] if static_only else [])
    proc = subprocess.run(args, env=env, capture_output=True, text=True)
    scan_json = out / "scan.json"
    if proc.returncode not in (0, 1) or not scan_json.is_file():
        sys.stderr.write(proc.stdout + proc.stderr)
        print(f"error: the scanner exited {proc.returncode} without a report", file=sys.stderr)
        return proc.returncode or 2
    s = summarize(json.loads(scan_json.read_text(encoding="utf-8")), static_only, note)
    print(json.dumps(s, indent=1) if a.json else render(s, out))
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())
