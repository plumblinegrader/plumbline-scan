"""Unit tests: no Docker needed."""

import json
from pathlib import Path

import pytest

from plumbline_scan import leak, report
from plumbline_scan.checks import network_markers, placeholder_reason, restored_by_test_sh, verifier_paths
from plumbline_scan.docker import parse_reward
from plumbline_scan.harbor import find_tasks, load_task, network_settings, reverse_patch

TOY = Path(__file__).parent / "toy_tasks"


def test_find_and_load_toy_tasks():
    dirs = find_tasks([str(TOY)])
    assert {d.name for d in dirs} == {"good", "stub", "empty-passes", "leaked", "editable-input", "needs-network"}
    t = load_task(TOY / "leaked")
    assert t.is_patch_task and "computed_area" in t.reference_patch
    assert t.image.startswith("plumbline-scan/leaked:") and t.build_context == TOY / "leaked" / "environment"
    assert t.memory == "512m" and t.cpus == 1.0
    assert not load_task(TOY / "good").is_patch_task


def test_embedded_patch_in_solve_sh(tmp_path):
    d = tmp_path / "t"
    (d / "solution").mkdir(parents=True)
    (d / "tests").mkdir()
    (d / "environment").mkdir()
    (d / "environment" / "Dockerfile").write_text("FROM scratch\n")
    (d / "task.toml").write_text('[environment]\nmemory = "2G"\n')
    (d / "tests" / "test.sh").write_text("true\n")
    (d / "solution" / "solve.sh").write_text(
        "#!/bin/bash\ncat > fix.diff << '__SOLUTION__'\ndiff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n"
        "@@ -1 +1 @@\n-a = 1\n+a = compute_the_answer()\n__SOLUTION__\ngit apply fix.diff\n")
    t = load_task(d)
    assert t.is_patch_task and "compute_the_answer" in t.reference_patch and t.memory == "2048m"


def test_reverse_patch_roundtrip():
    p = "diff --git a/f b/f\n--- a/f\n+++ b/f\n@@ -1,1 +1,1 @@\n-old\n+new\n"
    r = reverse_patch(p)
    assert "-new" in r and "+old" in r and reverse_patch(r) == p


@pytest.mark.parametrize("cfg,agent,verifier", [
    ({}, True, True),
    ({"environment": {"allow_internet": False}}, False, False),
    ({"agent": {"network_mode": "no-network"}, "verifier": {"network_mode": "public"}}, False, True),
    ({"environment": {"network_mode": "none"}, "verifier": {"network_mode": "public"}}, False, True),
])
def test_network_settings(cfg, agent, verifier):
    n = network_settings(cfg)
    assert (n["agent"], n["verifier"]) == (agent, verifier)


@pytest.mark.parametrize("txt,js,reward,full", [
    ("1", "", 1.0, True), ("1.0\n", "", 1.0, True), ("0", "", 0.0, False), ("0.5", "", 0.5, False),
    ("", '{"reward": 1}', 1.0, True), ("0", '{"reward": 0.25}', 0.25, False),
    ("", '{"a": 1, "b": 0.5}', 0.5, False), ("", "", None, False), ("garbage", "", None, False),
])
def test_parse_reward(txt, js, reward, full):
    r, _, f = parse_reward(txt, js)
    assert r == reward and f == full


def test_placeholder_reason():
    assert "no solution written" in placeholder_reason(load_task(TOY / "stub"))
    assert placeholder_reason(load_task(TOY / "good")) == ""
    assert placeholder_reason(load_task(TOY / "leaked")) == ""


def test_patch_keys_skip_tests_and_prose():
    patch = ("diff --git a/src/m.py b/src/m.py\n--- a/src/m.py\n+++ b/src/m.py\n@@ -1 +1,2 @@\n"
             "+value = distinctive_function(argument)\n+return\n"
             "diff --git a/tests/test_m.py b/tests/test_m.py\n--- a/tests/test_m.py\n+++ b/tests/test_m.py\n"
             "@@ -1 +1 @@\n+assert distinctive_function(1) == 2\n"
             "diff --git a/CHANGELOG.md b/CHANGELOG.md\n--- a/CHANGELOG.md\n+++ b/CHANGELOG.md\n"
             "@@ -1 +1 @@\n+Fixed the distinctive function bug\n")
    assert leak.patch_keys(patch) == ["value = distinctive_function(argument)"]
    assert leak.fix_paths(patch) == ["src/m.py"]
    # A line the instruction already gives the agent is not a leak.
    assert leak.patch_keys(patch, instruction="use value = distinctive_function(argument)") == []


PROBE_OUT = """REPO=/app
KEYS_TOTAL=4
KEYS_AT_HEAD=0
KEYS_EFFECTIVE=4
HEAD=abc
AHEAD_COMMITS=1
REFS_NOT_IN_HEAD=refs/heads/fix
STASHES=0
SRC git_refs_not_in_head 4
UNREACHABLE_OBJECTS=0
SRC git_unreachable 0
CANDIDATE_COMMITS=1
BEST_COMMIT=deadbeef 4
FILE 1 /usr/lib/python3/something.py
FILE 4 /root/backup/m.py
DONE=1
"""


def test_parse_and_decide_probe():
    r = leak.decide(leak.parse_probe(PROBE_OUT), fix_names=("m.py",))
    assert r.status == "LEAKED"
    assert set(r.flagged_sources) == {"git_refs_not_in_head", "file:/root/backup/m.py", "git_commit:deadbeef"}
    clean = leak.decide(leak.parse_probe(PROBE_OUT.replace("SRC git_refs_not_in_head 4", "SRC git_refs_not_in_head 1")
                                         .replace("BEST_COMMIT=deadbeef 4", "BEST_COMMIT= 0")
                                         .replace("FILE 4 /root/backup/m.py", "")))
    assert clean.status == "CLEAN"
    assert leak.parse_probe("KEYS_TOTAL=3\n").status == "ERROR"
    nt = leak.decide(leak.parse_probe("KEYS_TOTAL=3\nKEYS_AT_HEAD=3\nKEYS_EFFECTIVE=0\nDONE=1\n"))
    assert nt.status == "NOT_TESTABLE"


def test_static_input_and_network_readings():
    t = load_task(TOY / "editable-input")
    assert verifier_paths(t) == ["/app/answer.txt", "/app/data/words.txt"]
    assert not restored_by_test_sh(t, "/app/data/words.txt")
    assert "urllib.request.urlopen" in network_markers(load_task(TOY / "needs-network"))
    assert network_markers(load_task(TOY / "good")) == []


def test_report_renders():
    rec = {"task": "x", "verdict": "FLAGGED", "seconds": 75,
           "checks": {"reference": {"status": "WARN", "summary": "flaky: 2/3", "details": {"passes": 2, "graded": 3}},
                      "empty": {"status": "FLAG", "summary": "no-op earns 1", "details": {}}}}
    t = report.table([rec])
    assert "WARN 2/3" in t and "1m15s" in t and "no-op earns 1" in t
    md = report.markdown([rec], {"date": "2026-01-01", "k": 3, "network": "auto"})
    assert md.rstrip().endswith(report.FOOTER) and "| PS-2 Empty solution fails | 1 |" in md
    json.dumps(rec)
