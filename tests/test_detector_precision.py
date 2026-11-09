"""False-positive guards for the static detectors, each from a pattern seen on public task sets
(2026-10-12 sweep over 3,800 Harbor tasks). Each test pairs the clean shape with the risky one, so a
guard cannot hide a real hit."""

from test_detectors import _run, mktask

PATCH = "diff --git a/m.py b/m.py\n--- a/m.py\n+++ b/m.py\n@@ -1 +1 @@\n-x = 1\n+x = 2\n"


def patch_task(tmp_path, test_sh, name="p"):
    t = mktask(tmp_path, test_sh=test_sh, name=name)
    (t.path / "solution" / "solution.patch").write_text(PATCH)
    from plumbline_scan.harbor import load_task
    return load_task(t.path)


# -- PS-8: programs the verifier writes itself ------------------------------------------------------

def test_ps8_verifier_written_helper_is_not_flagged(tmp_path):
    sh = "cd /tmp\ncat > parser.py <<'EOF'\nimport sys\n# /// script\nprint('ok')\nEOF\nchmod +x parser.py\npython parser.py\n"
    assert _run(mktask(tmp_path, test_sh=sh))["mutable_program"] == "PASS"


def test_ps8_agent_helper_still_flagged(tmp_path):
    assert _run(mktask(tmp_path, test_sh="cd /app\npython parser.py\n"))["mutable_program"] == "FLAG"


def test_ps8_copied_from_tests_is_verifier_owned(tmp_path):
    sh = "cp /tests/check.sh /app/check.sh\nbash /app/check.sh\n"
    assert _run(mktask(tmp_path, test_sh=sh))["mutable_program"] == "PASS"
    sh = "cp /app/out.sh /tmp/run.sh\nbash /tmp/run.sh\n"  # copying the agent's file does not make it the verifier's
    assert _run(mktask(tmp_path, test_sh=sh, name="t2"))["mutable_program"] == "FLAG"


def test_ps8_heredoc_data_is_not_shell(tmp_path):
    sh = "cat > /tmp/notes.txt <<EOF\n/app/run_me.sh\nEOF\necho done\n"
    assert _run(mktask(tmp_path, test_sh=sh))["mutable_program"] == "PASS"
    sh = "bash <<EOF\n/app/run_me.sh\nEOF\n"  # a heredoc fed to a shell is code
    assert _run(mktask(tmp_path, test_sh=sh, name="t2"))["mutable_program"] == "FLAG"


def test_ps8_continuation_lines_are_one_command(tmp_path):
    sh = "pytest -q \\\n    --deselect=tests/unit/a.py \\\n    tests/unit/ 2>&1\n"
    assert _run(mktask(tmp_path, test_sh=sh))["mutable_program"] == "PASS"


def test_ps8_multiline_quoted_patch_is_data(tmp_path):
    sh = "echo 'diff --git a/x b/x\n+./evil.sh\n+source ./x.sh\n' > /tmp/p.diff\ngit apply /tmp/p.diff\n"
    r = _run(mktask(tmp_path, test_sh=sh))
    assert r["mutable_program"] == "PASS" and r["runtime_state"] == "PASS"


def test_ps8_repository_runner_in_patch_task_not_flagged(tmp_path):
    t = patch_task(tmp_path, "cd /app\n./tests/runtests.py model_fields\n")
    assert _run(t)["mutable_program"] == "PASS"
    # the same runner in a script task is still a finding
    assert _run(mktask(tmp_path, test_sh="cd /app\n./tests/runtests.py\n", name="s"))["mutable_program"] == "FLAG"


def test_ps8_program_outside_repository_in_patch_task_still_flagged(tmp_path):
    t = patch_task(tmp_path, "cd /app\n/opt/grader/bin/check\n")
    assert _run(t)["mutable_program"] == "FLAG"


# -- PS-9 ---------------------------------------------------------------------------------------------

def test_ps9_go_package_pattern_is_not_a_file(tmp_path):
    sh = "cd /app\ngo test ./... 2>&1 | grep -v '^ok'\n"
    assert _run(mktask(tmp_path, test_sh=sh))["keyword_match"] == "PASS"


def test_ps9_verifier_patching_its_own_runner(tmp_path):
    py = ("from pathlib import Path\n"
          "def patch_runner():\n"
          "    p = Path('/home/test-run.sh')\n"
          "    content = p.read_text()\n"
          "    if '--retry' in content:\n"
          "        return\n"
          "    p.write_text(content.replace('vitest', 'vitest --retry 3'))\n")
    assert _run(mktask(tmp_path, test_py=py))["keyword_match"] == "PASS"


def test_ps9_keyword_in_other_function_still_flagged(tmp_path):
    py = ("from pathlib import Path\n"
          "def test_setup():\n"
          "    p = Path('/var/log/audit.log')\n"
          "    p.write_text('sample')\n"
          "def test_logged():\n"
          "    content = Path('/var/log/audit.log').read_text()\n"
          "    assert 'sudo' in content\n")
    assert _run(mktask(tmp_path, test_py=py))["keyword_match"] == "FLAG"


# -- PS-11 --------------------------------------------------------------------------------------------

def test_ps11_repository_ci_script_in_patch_task(tmp_path):
    assert _run(patch_task(tmp_path, "cd /app\nsource ./tools/ci.sh\nci_unix_run_tests\n"))["runtime_state"] == "PASS"
    assert _run(mktask(tmp_path, test_sh="cd /app\nsource ./tools/ci.sh\n", name="s"))["runtime_state"] == "WARN"


# -- PS-7: only files the final image actually holds ---------------------------------------------------

def _with_dockerfile(tmp_path, dockerfile, name="d"):
    t = mktask(tmp_path, env={"data/expected_output.json": '{"a": 1}'}, test_py="def test_x():\n    assert True\n",
               name=name)
    (t.path / "environment" / "Dockerfile").write_text(dockerfile)
    return t


def test_ps7_file_never_copied_is_not_in_image(tmp_path):
    t = _with_dockerfile(tmp_path, "FROM python:3.12-slim\nCOPY app.py /app/app.py\n")
    assert _run(t)["readable_answer"] == "PASS"


def test_ps7_file_only_in_builder_stage(tmp_path):
    df = "FROM python:3.12 AS builder\nCOPY data /build/data\nFROM python:3.12-slim\nCOPY --from=builder /build/x /x\n"
    assert _run(_with_dockerfile(tmp_path, df))["readable_answer"] == "PASS"


def test_ps7_copied_directory_still_flagged(tmp_path):
    assert _run(_with_dockerfile(tmp_path, "FROM python:3.12-slim\nCOPY data /app/data\n"))["readable_answer"] == "FLAG"
    assert _run(_with_dockerfile(tmp_path, "FROM python:3.12-slim\nCOPY . /app\n", name="e"))["readable_answer"] == "FLAG"


# -- PS-9: an upper size cap is not keyword grading --------------------------------------------------

def test_ps9_upper_cap_is_not_length_grading(tmp_path):
    cap = "def test_size():\n    data = open('/app/re.json').read()\n    assert len(data) < 10_000_000\n"
    assert _run(mktask(tmp_path, test_py=cap))["keyword_match"] == "PASS"
    floor = "def test_size():\n    data = open('/app/report.txt').read()\n    assert len(data) > 100\n"
    assert _run(mktask(tmp_path, test_py=floor, name="f"))["keyword_match"] == "FLAG"
