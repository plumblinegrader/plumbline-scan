"""PS-12 loose_match: short expected values checked by substring (static; no Docker, no model)."""

import tempfile
from pathlib import Path

import pytest

from plumbline_scan import loosematch as lm
from plumbline_scan.harbor import load_task


def mktask(tmp, test_py=None, test_sh=None, extra=None):
    d = Path(tmp) / "t"
    (d / "tests").mkdir(parents=True)
    (d / "solution").mkdir()
    (d / "environment").mkdir()
    (d / "environment" / "Dockerfile").write_text("FROM python:3.11-slim\nWORKDIR /app\n")
    (d / "task.toml").write_text("[environment]\n")
    (d / "instruction.md").write_text("do the task\n")
    (d / "solution" / "solve.sh").write_text("echo done\n")
    (d / "tests" / "test.sh").write_text(test_sh or "uv run pytest /tests/test_outputs.py\n")
    if test_py is not None:
        (d / "tests" / "test_outputs.py").write_text(test_py)
    for rel, text in (extra or {}).items():
        p = d / "tests" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return load_task(d)


def kinds(hits):
    return sorted((h.kind, h.value, h.strength) for h in hits)


# -- what counts as short -------------------------------------------------------------------------

@pytest.mark.parametrize("v,short", [
    ("4", True), ("1628", True), ("$1,628", True), ("481.50", True), ("-3", True), ("12%", True),
    ("746342064230", True), ("yes", True), ("IL", True), ("x1", True), (42, True),
    ("four", False), ("polyester", False), ("20 hours", False), ("", False), ("  ", False),
    (".py", False), ("->", False), ("def ", False), (" 504 ", False), ("\n", False), (True, False), (None, False),
])
def test_is_short(v, short):
    assert lm.is_short(v) is short


def test_short_values_from_task_data():
    assert lm.short_values(["327", "1000", "camera", "IL", "943 Maple Drive"]) == ["327", "1000", "IL"]


# -- Python: positives ----------------------------------------------------------------------------

def test_py_literal_in_stdout_is_flag():
    src = ("import subprocess\n"
           "def test_answer():\n"
           "    r = subprocess.run(['python', '/app/solve.py'], capture_output=True, text=True)\n"
           "    assert '42' in r.stdout\n")
    hits = lm.scan_python(src, "tests/test_outputs.py")
    assert kinds(hits) == [("in", "42", "text")]
    assert hits[0].context == "assert" and hits[0].line == 4
    assert lm.decide(hits).status == "FLAG"


def test_py_file_read_and_str_haystacks():
    src = ("from pathlib import Path\n"
           "def test_a():\n"
           "    out = Path('/app/answer.txt').read_text()\n"
           "    assert '7' in out\n"
           "def test_b(result):\n"
           "    assert 'yes' in str(result).lower()\n"
           "def test_c():\n"
           "    assert open('/app/o.txt').read().find('1628') != -1\n")
    got = kinds(lm.scan_python(src, "t.py"))
    assert ("in", "7", "text") in got and ("in", "yes", "text") in got and (".find", "1628", "text") in got


def test_py_resolved_constant_and_regex_and_assertin():
    src = ("import re, unittest\n"
           "EXPECTED = '5244'\n"
           "def test_a(output):\n"
           "    assert EXPECTED in output\n"
           "def test_b(output):\n"
           "    assert re.search(r'3\\.5', output)\n"
           "class T(unittest.TestCase):\n"
           "    def test_c(self):\n"
           "        text = self.run_it()\n"
           "        self.assertIn('ok', text.strip())\n")
    got = kinds(lm.scan_python(src, "t.py"))
    assert ("in", "5244", "text") in got
    assert ("re.search", "3.5", "text") in got
    assert ("assertIn", "ok", "text") in got


def test_py_data_driven_needle_is_warn():
    # a loop over expected values taken from the task data
    src = ("def evaluate(messages, communicate_info):\n"
           "    for info_str in communicate_info:\n"
           "        for m in messages:\n"
           "            if info_str.lower() in m.content.lower().replace(',', ''):\n"
           "                return True\n")
    hits = lm.scan_python(src, "evaluator.py")
    assert [(h.strength, h.needle, h.context) for h in hits] == [("data", "info_str", "if")]
    assert lm.decide(hits).status == "WARN"


# -- Python: negatives ----------------------------------------------------------------------------

def test_py_exact_and_whole_token_checks_are_clean():
    src = ("import re\n"
           "def test_a(out):\n"
           "    assert out.strip() == '42'\n"
           "def test_b(out):\n"
           "    assert '42' in out.split()\n"
           "def test_c(out):\n"
           "    assert re.search(r'\\b42\\b', out)\n"
           "def test_d(out):\n"
           "    assert re.fullmatch('42', out)\n"
           "def test_e(rows):\n"
           "    assert '42' in ['41', '42']\n"
           "    assert 'id' in {'id': 1}\n"
           "    assert '4' in set(rows)\n"
           "def test_f(out):\n"
           "    assert 'Total revenue: 1628' in out\n"
           "    assert '\\n' in out\n")
    assert lm.scan_python(src, "t.py") == []


def test_py_list_named_haystack_is_clean_unknown_is_warn():
    src = ("def test_a(item_ids):\n"
           "    assert '42' in item_ids\n"
           "def test_b(result):\n"
           "    assert '42' in result\n")
    hits = lm.scan_python(src, "t.py")
    assert kinds(hits) == [("in", "42", "unknown")]
    assert lm.decide(hits).status == "WARN"


def test_py_not_in_and_unparsable_python():
    assert lm.scan_python("def t(out):\n    assert '0' not in out\n", "t.py") == []
    # a diff fragment that ast cannot parse falls back to the line rule
    hits = lm.scan_file("    assert '4' in result.stdout\n  )", "frag.py")
    assert kinds(hits) == [("in", "4", "text")]


# -- other languages ------------------------------------------------------------------------------

@pytest.mark.parametrize("rel,line,kind,value", [
    ("a_test.go", 'if !strings.Contains(out, "42") {', "strings.Contains", "42"),
    ("a_test.go", 'assert.Contains(t, body, "ok")', "Contains", "ok"),
    ("a.test.js", "expect(res.text).toContain('200');", ".toContain", "200"),
    ("a.test.ts", "expect(stdout).toMatch('3');", ".toMatch", "3"),
    ("ATest.java", 'assertTrue(output.contains("7"));', ".contains", "7"),
    ("lib.rs", 'assert!(out.contains("1.5"));', ".contains", "1.5"),
    ("a_spec.rb", 'expect(out).to include("yes")', "include", "yes"),
    ("t.clj", '(is (str/includes? out "42"))', "clojure.string/includes?", "42"),
    ("t.clj", '(is (str/includes? (bb "run" "foo") "6")))', "clojure.string/includes?", "6"),
])
def test_line_rules_positive(rel, line, kind, value):
    hits = lm.scan_file(line + "\n", rel)
    assert [(h.kind, h.value) for h in hits] == [(kind, value)]


@pytest.mark.parametrize("rel,line", [
    ("a_test.go", 'if out != "42" {'),
    ("a_test.go", 'if !strings.Contains(out, "total revenue") {'),
    ("a.test.js", "expect(res.text).toBe('200');"),
    ("a.test.js", "expect(res.text).toContain('Internal Server Error');"),
    ("ATest.java", 'assertEquals("7", output.trim());'),
    ("lib.rs", "assert_eq!(out, \"1.5\");"),
    ("a_test.go", '// strings.Contains(out, "42") in a comment'),
    ("frag.py", "    assert \"Could not find 'idx' in the table\" in err_msg\n  )"),
])
def test_line_rules_negative(rel, line):
    assert lm.scan_file(line + "\n", rel) == []


def test_shell_grep_rules():
    pos = ["grep -q '42' /app/out.txt", "grep 4 /app/answer.txt && echo 1 > /logs/verifier/reward.txt",
           'if [[ "$OUT" == *"1628"* ]]; then echo ok; fi', "grep -F '3.5' out.txt"]
    neg = ["grep -qw '42' /app/out.txt", "grep -x 42 out.txt", "grep -q '^42$' out.txt",
           "grep -v 0 out.txt", "grep -A 3 error log.txt", "grep -q 'Build succeeded' log.txt",
           "grep -q '\\b42\\b' out.txt"]
    for line in pos:
        assert lm.scan_lines(line, "tests/test.sh", "shell"), line
    for line in neg:
        assert lm.scan_lines(line, "tests/test.sh", "shell") == [], line


def test_scan_diff_reads_added_lines_only():
    patch = ("diff --git a/tests/test_x.py b/tests/test_x.py\n"
             "--- a/tests/test_x.py\n+++ b/tests/test_x.py\n"
             "@@ -10,3 +10,5 @@ def test_old():\n"
             "     x = 1\n"
             "-    assert '9' in out.stdout\n"
             "+    assert '4' in out.stdout\n"
             "+    assert out.stdout == '4'\n"
             "diff --git a/src/x_test.go b/src/x_test.go\n"
             "--- a/src/x_test.go\n+++ b/src/x_test.go\n"
             "@@ -1,1 +1,2 @@\n"
             " package x\n"
             '+\tif !strings.Contains(got, "12") { t.Fail() }\n')
    hits = lm.scan_diff(patch)
    assert [(h.file, h.line, h.value) for h in hits] == [("tests/test_x.py", 11, "4"), ("src/x_test.go", 2, "12")]


# -- a whole Harbor task --------------------------------------------------------------------------

def test_task_flag_and_pass():
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(tmp, test_py=("def test_answer():\n"
                                    "    out = open('/app/answer.txt').read()\n"
                                    "    assert '17' in out\n"))
        r = lm.loose_match(task)
        assert r.status == "FLAG" and "'17'" in r.summary
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(tmp, test_py=("def test_answer():\n"
                                    "    out = open('/app/answer.txt').read()\n"
                                    "    assert out.strip() == '17'\n"))
        assert lm.loose_match(task).status == "PASS"


def test_task_shell_verifier_flag():
    with tempfile.TemporaryDirectory() as tmp:
        task = mktask(tmp, test_sh="if grep -q 42 /app/out.txt; then echo 1 > /logs/verifier/reward.txt; fi\n")
        assert lm.loose_match(task).status == "FLAG"  # in shell, the `if grep` decides the reward
        hits = lm.grader_hits(task)
        assert [(h.kind, h.value, h.strength) for h in hits] == [("grep", "42", "text")]
