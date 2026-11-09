"""Static detectors PS-7..PS-11: a vulnerable grader and a clean one for each (no Docker, no model)."""

from pathlib import Path

import pytest

from plumbline_scan import detectors
from plumbline_scan.detectors import agent_reach
from plumbline_scan.harbor import load_task


def mktask(tmp_path, test_py=None, test_sh=None, env=None, solve="echo done\n", name="t"):
    """Write a minimal Harbor task and load it. `env` maps a path under environment/ to its text."""
    d = tmp_path / name
    (d / "tests").mkdir(parents=True)
    (d / "solution").mkdir()
    (d / "environment").mkdir()
    (d / "environment" / "Dockerfile").write_text("FROM python:3.11-slim\nWORKDIR /app\nCOPY . /app\n")
    (d / "task.toml").write_text('[environment]\n')
    (d / "instruction.md").write_text("do the task\n")
    (d / "solution" / "solve.sh").write_text(solve)
    (d / "tests" / "test.sh").write_text(test_sh or "uv run pytest /tests/test_outputs.py\n")
    if test_py is not None:
        (d / "tests" / "test_outputs.py").write_text(test_py)
    for rel, text in (env or {}).items():
        p = d / "environment" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return load_task(d)


def _run(task):
    return {k: v.status for k, v in detectors.run(task).items()}


# -- the reach model ----------------------------------------------------------------------------

@pytest.mark.parametrize("path,reach", [
    ("/app/out.txt", True), ("/root/report.txt", True), ("/tmp/x", True), ("/etc/ssh/sshd_config", True),
    ("/var/lib/flatpak/x", True), ("relative/out.json", True), ("./build.sh", True),
    ("/tests/test_outputs.py", False), ("/logs/verifier/reward.txt", False), ("/solution/solve.sh", False),
    ("/usr/bin/python3", False), ("/bin/ls", False), ("/proc/1/status", False),
    ("$HOME/.local/bin/env", False), ("", False), ("/", False),
])
def test_agent_reach(path, reach):
    assert agent_reach(path) is reach


# -- PS-7 readable_answer -----------------------------------------------------------------------

def test_ps7_expected_output_baked_into_image():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), env={"test_data/expected_output.json": '{"answer": 42}'},
                      test_py="def test_x():\n    assert True\n")
        assert _run(task)["readable_answer"] == "FLAG"


def test_ps7_verifier_reads_expected_from_agent_area():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_match():\n"
            "    expected = Path('/app/expected_answer.txt').read_text()\n"
            "    got = Path('/app/out.txt').read_text()\n"
            "    assert got == expected\n"))
        assert _run(task)["readable_answer"] == "FLAG"


def test_ps7_clean_expected_in_tests_dir():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        # Expected values live as literals in the verifier (under /tests, not readable by the agent).
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_match():\n"
            "    assert Path('/app/out.txt').read_text().strip() == '42'\n"),
            env={"input.csv": "1,2,3\n"})
        assert _run(task)["readable_answer"] == "PASS"


# -- PS-8 mutable_program -----------------------------------------------------------------------

def test_ps8_runs_agent_script():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import subprocess\n"
            "def test_runs():\n"
            "    r = subprocess.run(['/app/run_checks.sh'], capture_output=True)\n"
            "    assert r.returncode == 0\n"))
        assert _run(task)["mutable_program"] == "FLAG"


def test_ps8_interpreter_on_agent_file():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import subprocess\n"
            "def test_runs():\n"
            "    r = subprocess.run(['python3', '/app/solution.py'], capture_output=True)\n"
            "    assert b'OK' in r.stdout\n"))
        assert _run(task)["mutable_program"] == "FLAG"


def test_ps8_clean_standard_tools_only():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import subprocess\n"
            "def test_procs():\n"
            "    out = subprocess.run(['ps', 'aux'], capture_output=True, text=True).stdout\n"
            "    assert 'hang.py' not in out\n"),
            test_sh="apt-get install -y curl\ncurl -LsSf https://astral.sh/uv/install.sh | sh\n"
                    "source $HOME/.local/bin/env\nuv venv .tbench-testing\nsource .tbench-testing/bin/activate\n"
                    "uv run pytest /tests/test_outputs.py\n")
        assert _run(task)["mutable_program"] == "PASS"


# -- PS-9 keyword_match -------------------------------------------------------------------------

def test_ps9_keyword_and_length():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_report():\n"
            "    content = Path('/app/report.txt').read_text().lower()\n"
            "    assert 'sigterm' in content\n"
            "    assert len(content) > 100\n"))
        res = detectors.run(task)
        assert res["keyword_match"].status == "FLAG"
        assert "membership" in res["keyword_match"].details["python"][0]["kinds"]
        assert "length" in res["keyword_match"].details["python"][0]["kinds"]


def test_ps9_regex_grep_in_shell():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py="def test_x():\n    assert True\n",
                      test_sh="grep -q 'FIXED' /app/out.log && echo 1 > /logs/verifier/reward.txt\n")
        assert _run(task)["keyword_match"] == "WARN"


def test_ps9_clean_behavioural():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import json\n"
            "from pathlib import Path\n"
            "def test_value():\n"
            "    data = json.loads(Path('/app/out.json').read_text())\n"
            "    assert data == {'ok': True}\n"))
        assert _run(task)["keyword_match"] == "PASS"


# -- PS-10 mutable_measurement ------------------------------------------------------------------

def test_ps10_trusts_score_file():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import json\n"
            "from pathlib import Path\n"
            "def test_score():\n"
            "    results = json.loads(Path('/app/results.json').read_text())\n"
            "    assert results['accuracy'] >= 0.9\n"))
        assert _run(task)["mutable_measurement"] == "FLAG"


def test_ps10_timing_number_from_agent_file():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_fast():\n"
            "    elapsed = float(Path('/app/timing.txt').read_text())\n"
            "    assert elapsed < 2.0\n"))
        assert _run(task)["mutable_measurement"] == "FLAG"


def test_ps10_clean_verifier_times_itself():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import time, subprocess\n"
            "def test_fast():\n"
            "    t0 = time.monotonic()\n"
            "    subprocess.run(['true'])\n"
            "    assert time.monotonic() - t0 < 2.0\n"))
        assert _run(task)["mutable_measurement"] == "PASS"


# -- PS-11 runtime_state ------------------------------------------------------------------------

def test_ps11_plain_import_is_not_flagged():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        # The normal contract: put the agent's dir on the path and import its solution to test it.
        task = mktask(Path(tmp), test_py=(
            "import sys\n"
            "sys.path.insert(0, '/app')\n"
            "from solution import answer\n"
            "def test_api():\n"
            "    assert answer(2) == 4\n"
            "    assert answer(3) == 9\n"))
        assert _run(task)["runtime_state"] == "PASS"


def test_ps11_loads_code_from_agent_path():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import importlib.util\n"
            "def test_api():\n"
            "    spec = importlib.util.spec_from_file_location('m', '/app/plugin.py')\n"
            "    m = importlib.util.module_from_spec(spec)\n"
            "    spec.loader.exec_module(m)\n"
            "    assert m.check() is True\n"))
        assert _run(task)["runtime_state"] == "WARN"


def test_ps11_exec_agent_content():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_api():\n"
            "    exec(Path('/app/hook.py').read_text())\n"))
        assert _run(task)["runtime_state"] == "WARN"


def test_ps11_sources_agent_file_in_shell():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py="def test_x():\n    assert True\n",
                      test_sh="source /app/config/env.sh\npython3 -c 'import os; assert os.environ.get(\"OK\")'\n")
        assert _run(task)["runtime_state"] == "WARN"


def test_ps11_reads_agent_config_state():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_cfg():\n"
            "    cfg = Path('/app/settings.conf').read_text()\n"
            "    assert 'debug=false' in cfg\n"))
        # also a keyword match, but PS-11 must flag the shared-state read
        assert detectors.run(task)["runtime_state"].status == "WARN"


def test_ps11_clean_no_injection():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "import subprocess\n"
            "def test_http():\n"
            "    out = subprocess.run(['curl', '-s', 'http://localhost:8000/health'],\n"
            "                         capture_output=True, text=True).stdout\n"
            "    assert out == 'ok'\n"),
            test_sh="uv venv .tbench-testing\nsource .tbench-testing/bin/activate\n"
                    "uv run pytest /tests/test_outputs.py\n")
        assert _run(task)["runtime_state"] == "PASS"


# -- integration: the detectors are wired into a Scan record ------------------------------------

def test_detectors_in_scan_record_without_docker():
    import tempfile
    from plumbline_scan.checks import ALL_CHECKS, detector_checks
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(Path(tmp), test_py=(
            "from pathlib import Path\n"
            "def test_report():\n"
            "    assert 'done' in Path('/app/report.txt').read_text()\n"))
        checks = detector_checks(task)
        assert set(checks) == set(detectors.DETECTORS)
        assert checks["keyword_match"].status == "FLAG"
        # PS-7..PS-11 are included in the reporting order
        assert all(d in ALL_CHECKS for d in detectors.DETECTORS)
