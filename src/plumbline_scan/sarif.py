"""SARIF 2.1.0 output, so findings show in GitHub code scanning (and other SARIF viewers)."""

from __future__ import annotations

import os
from pathlib import Path

from . import __version__
from .guidance import ANCHOR, CHECK_IDS, FIX, HELP_URI, NAMES, WHY, anchor

LEVEL = {"FLAG": "error", "WARN": "warning", "ERROR": "warning", "NETWORK": "note"}


def _rules() -> list[dict]:
    rules = []
    for check, rid in CHECK_IDS.items():
        fixes = [v for (c, _), v in FIX.items() if c == check]
        rules.append({
            "id": rid,
            "name": NAMES[check].replace(" ", ""),
            "shortDescription": {"text": NAMES[check]},
            "fullDescription": {"text": WHY[check]},
            "help": {"text": " ".join(fixes), "markdown": "\n\n".join(fixes)},
            "helpUri": f"{HELP_URI}#{rid.lower()}",
            "defaultConfiguration": {"level": "note" if check == "network" else "error"},
            "properties": {"tags": ["harbor", "task-quality"]},
        })
    return rules


def _uri(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return Path(os.path.relpath(path.resolve(), root.resolve())).as_posix()


def build(records: list[dict], root: Path) -> dict:
    results = []
    for rec in records:
        for check, ch in rec.get("checks", {}).items():
            level = LEVEL.get(ch["status"])
            if not level:
                continue
            msg = f"{rec['task']}: {ch['summary']}"
            if ch.get("fix"):
                msg += f"\nFix: {ch['fix']}"
            results.append({
                "ruleId": CHECK_IDS[check],
                "level": level,
                "message": {"text": msg},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": _uri(Path(rec["path"]) / anchor(rec, check), root),
                                         "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1}}}],
                "partialFingerprints": {"plumblineScan/v1": f"{rec['task']}:{CHECK_IDS[check]}:{ch['status']}"},
                "properties": {"task": rec["task"], "status": ch["status"], "evidence": ch.get("evidence", {})},
            })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "plumbline-scan", "version": __version__, "informationUri": HELP_URI,
                                "rules": _rules()}},
            "originalUriBaseIds": {"%SRCROOT%": {"uri": root.resolve().as_uri() + "/"}},
            "results": results,
        }],
    }


assert set(ANCHOR) == set(CHECK_IDS)
