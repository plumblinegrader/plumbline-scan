"""End-to-end: scan the synthetic toy tasks with Docker (builds small images from python:3.12-slim)."""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from plumbline_scan.cli import main

TOY = Path(__file__).parent / "toy_tasks"


def _docker_ok() -> bool:
    if not shutil.which("docker"):
        return False
    return subprocess.run(["docker", "version"], capture_output=True).returncode == 0


pytestmark = [pytest.mark.docker, pytest.mark.skipif(not _docker_ok(), reason="Docker not available")]

EXPECTED = {
    # task: {check: status}
    "good": {"reference": "PASS", "empty": "PASS", "leaked_answer": "PASS", "stub": "PASS",
             "editable_input": "PASS", "network": "PASS"},
    "stub": {"reference": "FLAG", "stub": "FLAG"},
    "empty-passes": {"reference": "PASS", "empty": "FLAG"},
    "leaked": {"reference": "PASS", "empty": "PASS", "leaked_answer": "FLAG", "editable_input": "N/A"},
    "editable-input": {"reference": "PASS", "editable_input": "FLAG"},
    "needs-network": {"reference": "PASS", "network": "NETWORK", "empty": "PASS"},
}


def test_scan_toy_tasks(tmp_path, capsys):
    rc = main([str(TOY), "-o", str(tmp_path), "-k", "2", "-j", "3"])
    assert rc == 1  # some tasks are flagged
    data = json.loads((tmp_path / "scan.json").read_text())
    got = {t["task"]: {c: v["status"] for c, v in t["checks"].items()} for t in data["tasks"]}
    for task, want in EXPECTED.items():
        for check, status in want.items():
            assert got[task][check] == status, (task, check, got[task])
    leaked = next(t for t in data["tasks"] if t["task"] == "leaked")
    assert leaked["checks"]["leaked_answer"]["details"]["recovered"]["full"] is True
    out = capsys.readouterr().out
    assert out.rstrip().endswith("plumblinegrader.com/sample?src=scan")
    assert (tmp_path / "scan.md").read_text().count("sample?src=scan") == 1
