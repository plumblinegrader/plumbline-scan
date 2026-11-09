#!/usr/bin/env python3
"""Install the Plumbline Scan agent skill into a coding agent's skill or rule folder.

    python3 install_skill.py --agent claude            # this project: .claude/skills/plumbline-scan/
    python3 install_skill.py --agent claude-user       # every project: ~/.claude/skills/plumbline-scan/
    python3 install_skill.py --agent codex             # ~/.codex/skills/plumbline-scan/ (+ AGENTS.md snippet)
    python3 install_skill.py --agent cursor            # this project: .cursor/rules/plumbline-scan.mdc

Options: --project DIR (default: current directory), --home DIR (default: your home folder), --force to replace
an earlier install, --no-bundle to skip copying the scanner (then install it with pip).

By default the scanner itself (pure Python, Apache-2.0, no runtime dependencies) is copied next to the skill, so
the skill works with no pip install. Nothing is downloaded and nothing is sent anywhere. Standard library only.
"""

from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
SKILL = HERE / "skills" / "plumbline-scan"
RUNNER = SKILL / "scripts" / "run_scan.py"


def scanner_root() -> Path | None:
    """The scanner's project folder (contains src/plumbline_scan, LICENSE, NOTICE): this repo, or a sibling folder."""
    for c in (HERE, HERE.parent / "plumbline-scan"):
        if (c / "src" / "plumbline_scan" / "__init__.py").is_file():
            return c
    return None


def bundle(dest_dir: Path) -> Path | None:
    root = scanner_root()
    if root is None:
        return None
    vendor = dest_dir / "vendor"
    shutil.copytree(root / "src" / "plumbline_scan", vendor / "plumbline_scan",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("LICENSE", "NOTICE"):
        if (root / name).is_file():
            shutil.copy2(root / name, vendor / name)
    return vendor


def place(target: Path, force: bool) -> None:
    if target.exists():
        if not force:
            raise SystemExit(f"{target} already exists; re-run with --force to replace it")
        shutil.rmtree(target) if target.is_dir() else target.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)


def install(agent: str, project: Path, home: Path, force: bool = False, with_scanner: bool = True) -> list[Path]:
    written: list[Path] = []
    if agent in ("claude", "claude-user", "codex"):
        base = {"claude": project / ".claude", "claude-user": home / ".claude", "codex": home / ".codex"}[agent]
        target = base / "skills" / "plumbline-scan"
        place(target, force)
        shutil.copytree(SKILL, target, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "vendor"))
        written.append(target / "SKILL.md")
        if with_scanner and bundle(target):
            written.append(target / "vendor")
        if agent == "codex":
            snippet = target / "AGENTS-snippet.md"
            shutil.copy2(HERE / "integrations" / "codex" / "AGENTS-snippet.md", snippet)
            written.append(snippet)
    elif agent == "cursor":
        rule = project / ".cursor" / "rules" / "plumbline-scan.mdc"
        helper = project / ".cursor" / "plumbline-scan"
        place(rule, force)
        place(helper, force)
        shutil.copy2(HERE / "integrations" / "cursor" / "plumbline-scan.mdc", rule)
        helper.mkdir(parents=True)
        shutil.copy2(RUNNER, helper / "run_scan.py")
        written += [rule, helper / "run_scan.py"]
        if with_scanner and bundle(helper):
            written.append(helper / "vendor")
    else:
        raise SystemExit(f"unknown agent {agent!r}")
    return written


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--agent", required=True, choices=["claude", "claude-user", "codex", "cursor"])
    ap.add_argument("--project", default=".")
    ap.add_argument("--home", default=str(Path.home()))
    ap.add_argument("--force", action="store_true")
    ap.add_argument("--no-bundle", action="store_true")
    a = ap.parse_args(argv)
    written = install(a.agent, Path(a.project).resolve(), Path(a.home).resolve(), a.force, not a.no_bundle)
    for p in written:
        print("wrote", p)
    if not any(p.name == "vendor" for p in written):
        print("Scanner not bundled: install it with  pip install git+https://github.com/plumblinegrader/plumbline-scan@v0.4.1")
    if a.agent == "codex":
        print("If your Codex version does not load skills, paste AGENTS-snippet.md into your AGENTS.md.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
