"""PS-12 loose_match: a short expected value checked by substring instead of an exact or whole-token match.

A grader that asks "does the expected value appear anywhere in the output?" pays a wrong answer
that happens to contain the right one: "$11628" passes for "1628" and "14 suitcases" passes
for "4". The risk is large only when the expected value is short: a number (any length,
since "1628" sits inside "11628" and "16280") or a string of 3 characters or fewer ("4", "yes",
"IL"). A long distinctive string inside free text is not flagged.

What counts as a loose check, per language (static, no Docker, no model):
    Python   '<v>' in <text>, <text>.find/count/index('<v>'), assertIn('<v>', <text>),
             re.search/findall('<v>', <text>) with no ^, $ or \\b anchor          (ast; whole files)
    shell    grep '<v>' without -w/-x and with no anchor; [[ $x == *<v>* ]]
    JS/TS    .toContain('<v>'), .includes('<v>'), .indexOf('<v>'), .toMatch('<v>')
    Go       strings.Contains(x, "<v>"), assert/require.Contains(t, x, "<v>")
    Java/Kotlin/C#/Rust/Scala/Swift  .contains("<v>"), assertThat(x).contains("<v>")
    Ruby     .include?("<v>"), include("<v>")
Not loose: membership in a list, set, dict or a .split() result (that is whole-token), ==, and
any anchored regex.

Each hit has a strength:
    text     the haystack is plainly text (str(), stdout, a file read, strings.Contains, grep)
    unknown  the haystack's type is not visible; a list membership would be exact, so worth a look
    data     the needle is a variable named like an expected value (expected, answer, info, ...);
             the values live in the task data, so the per-task data decides (see short_values)

Status: FLAG when a text-strength hit is inside an assertion or a return (in shell, also an `if`);
WARN for the rest;
PASS when nothing matched. Hits are leads, not findings: each needs a wrong output that the
grader pays, replayed in a fresh container, before it counts.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field

PASS, FLAG, WARN, NA = "PASS", "FLAG", "WARN", "N/A"

_NUMERIC = re.compile(r"[$€£¥]?\s?[-+]?\d[\d,_]*(?:\.\d+)?\s?%?")


def is_short(value) -> bool:
    """A value a substring check cannot pin down: any number, or 3 or fewer letters/digits."""
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return True
    if not isinstance(value, str):
        return False
    s = value.strip()
    if not s or s != value:
        return False  # empty, or padded with spaces: " 504 " is already a whole-token check
    if _NUMERIC.fullmatch(s):
        return True
    return len(value) <= 3 and value.isalnum()  # "def " (a keyword probe with its space) is not short


def short_values(values) -> list:
    """The short values in a task's list of expected values (for data-driven graders)."""
    return [v for v in values or [] if is_short(v)]


@dataclass
class Hit:
    file: str
    line: int
    kind: str          # the construct, e.g. "in", ".find", "grep", "strings.Contains"
    value: str         # the short expected value ("" for a data-driven needle)
    strength: str      # text | unknown | data
    context: str       # assert | return | if | other
    snippet: str = ""
    needle: str = ""   # the variable name, for data-driven hits


@dataclass
class LooseResult:
    status: str
    summary: str
    details: dict = field(default_factory=dict)


# -- Python (ast) -------------------------------------------------------------------------------

_TEXT_ATTRS = {"stdout", "stderr", "output", "out", "err", "text", "content", "message", "msg",
               "body", "data_str", "html", "log", "logs", "response_text"}
_TEXT_METHODS = {"read", "read_text", "decode", "lower", "upper", "casefold", "strip", "lstrip",
                 "rstrip", "getvalue", "replace", "join", "format", "title", "capitalize",
                 "readouterr", "get_data", "as_string", "to_string", "render", "dumps"}
_LIST_METHODS = {"split", "rsplit", "splitlines", "keys", "values", "items", "readlines", "findall"}
_LIST_CALLS = {"list", "set", "tuple", "sorted", "dict", "frozenset", "json.load", "json.loads",
               "os.listdir", "listdir", "glob", "glob.glob", "range", "enumerate", "zip"}
_TEXT_CALLS = {"str", "repr", "format", "check_output", "subprocess.check_output"}
_TEXT_NAMES = re.compile(r"(?:^|_)(out|output|outputs|stdout|stderr|text|txt|content|contents|message|"
                         r"msg|response|resp|log|logs|html|body|printed|captured|result_str|res_str|"
                         r"line|report|transcript|reply|answer_text|s|string)$", re.I)
_LIST_NAMES = re.compile(r"(?:^|_)(list|lst|items|keys|names|lines|tokens|words|set|ids|rows|cols|"
                         r"columns|values|elements|entries|files|args|tags|labels)$|s_list$", re.I)
_EXPECTED_NAMES = re.compile(r"^(?:expected|expect|exp|answer|ans|gold|golden|target|truth|ref|reference|"
                             r"want|wanted|correct|info|info_str|needle|solution|key_value)(?:_\w+)?$|"
                             r"(?:^|_)(?:expected|answer|gold|truth)(?:_|$)", re.I)


def _call_name(node: ast.Call) -> str:
    f = node.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    elif parts:
        parts.append("?")
    return ".".join(reversed(parts))


def _haystack_kind(node, textvars: set, listvars: set) -> str:
    """'text', 'list' (exact membership: not loose) or 'unknown'."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set, ast.Dict, ast.ListComp, ast.SetComp,
                         ast.DictComp, ast.GeneratorExp)):
        return "list"
    if isinstance(node, ast.JoinedStr):
        return "text"
    if isinstance(node, ast.Constant):
        return "text" if isinstance(node.value, str) else "unknown"
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        left = _haystack_kind(node.left, textvars, listvars)
        right = _haystack_kind(node.right, textvars, listvars)
        return "text" if "text" in (left, right) and "list" not in (left, right) else "unknown"
    if isinstance(node, ast.Call):
        name = _call_name(node)
        last = name.rsplit(".", 1)[-1]
        if name in _LIST_CALLS or last in _LIST_METHODS:
            return "list"
        if name in _TEXT_CALLS or last in _TEXT_METHODS:
            return "text"
        return "unknown"
    if isinstance(node, ast.Attribute):
        if node.attr in _TEXT_ATTRS:
            return "text"
        return "list" if _LIST_NAMES.search(node.attr) else "unknown"
    if isinstance(node, ast.Name):
        if node.id in listvars:
            return "list"
        if node.id in textvars:
            return "text"
        if _LIST_NAMES.search(node.id):
            return "list"
        return "text" if _TEXT_NAMES.search(node.id) else "unknown"
    return "unknown"


def _needle(node, consts: dict):
    """(value, needle_name): a resolved short literal, or a data-driven variable name; else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return (node.value, "") if is_short(node.value) else None
    if isinstance(node, ast.Name):
        if node.id in consts:
            v = consts[node.id]
            return (v, node.id) if is_short(v) else None
        return ("", node.id) if _EXPECTED_NAMES.search(node.id) else None
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in ("str", "repr") and len(node.args) == 1:
            a = node.args[0]
            if isinstance(a, ast.Constant) and isinstance(a.value, (int, float)) and not isinstance(a.value, bool):
                return (str(a.value), "")
            return _needle(a, consts)
        if name.rsplit(".", 1)[-1] in ("lower", "upper", "strip", "casefold") and isinstance(node.func, ast.Attribute):
            return _needle(node.func.value, consts)
    if isinstance(node, ast.Attribute) and _EXPECTED_NAMES.search(node.attr):
        return ("", node.attr)
    if isinstance(node, ast.Subscript):
        key = node.slice
        if isinstance(key, ast.Constant) and isinstance(key.value, str) and _EXPECTED_NAMES.search(key.value):
            return ("", key.value)
    if isinstance(node, ast.JoinedStr) and len(node.values) == 1 and isinstance(node.values[0], ast.FormattedValue):
        return _needle(node.values[0].value, consts)
    return None


_ANCHORS = re.compile(r"\\b|\\B|\^|\$|\\A|\\Z|\(\?<[=!]|\(\?[=!]")
_REGEX_META = re.compile(r"\\([.\-+*?()\[\]{}|$^\\/])")


def _regex_literal(pattern: str):
    """The literal a regex matches when it is unanchored and simple; None otherwise."""
    if _ANCHORS.search(pattern):
        return None
    lit = _REGEX_META.sub(r"\1", pattern)
    if re.search(r"(?<!\\)[\[\]()*+?{}|]", pattern):
        return None
    return lit


def _scope_names(scope) -> tuple:
    """Names bound once to a short string constant, to text, or to a list, within a scope."""
    counts: dict = {}
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            counts[n.targets[0].id] = counts.get(n.targets[0].id, 0) + 1
    consts, textvars, listvars = {}, set(), set()
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            name, v = n.targets[0].id, n.value
            if counts.get(name) != 1:
                continue
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                consts[name] = v.value
            kind = _haystack_kind(v, set(), set())
            if kind == "text":
                textvars.add(name)
            elif kind == "list":
                listvars.add(name)
    return consts, textvars, listvars


class _Contexts(ast.NodeVisitor):
    """Map each node id to the innermost grading context it sits in."""

    def __init__(self):
        self.ctx: dict = {}
        self.stack: list = ["other"]

    def generic_visit(self, node):
        self.ctx[id(node)] = self.stack[-1]
        super().generic_visit(node)

    def _with(self, node, ctx):
        self.stack.append(ctx)
        self.generic_visit(node)
        self.stack.pop()

    def visit_Assert(self, node):
        self._with(node, "assert")

    def visit_Return(self, node):
        self._with(node, "return")

    def visit_If(self, node):
        self.ctx[id(node)] = self.stack[-1]
        self.stack.append("if")
        self.visit(node.test)
        self.stack.pop()
        for n in node.body + node.orelse:
            self.visit(n)

    def visit_Call(self, node):
        name = _call_name(node).rsplit(".", 1)[-1]
        if name.startswith(("assert", "fail")) or name in ("expect", "check", "verify", "ok"):
            self._with(node, "assert")
        else:
            self.generic_visit(node)


def scan_python(source: str, rel: str) -> list:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # the graders' own invalid escapes are not our concern
            tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return []
    cv = _Contexts()
    cv.visit(tree)
    lines = source.splitlines()
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    module_names = _scope_names(tree)
    hits, seen = [], set()

    def add(node, kind, needle, hay_kind):
        value, name = needle
        if hay_kind == "list":
            return
        strength = "data" if not value else hay_kind
        key = (node.lineno, kind, value, name)
        if key in seen:
            return
        seen.add(key)
        ln = getattr(node, "lineno", 0)
        snippet = lines[ln - 1].strip()[:160] if 0 < ln <= len(lines) else ""
        hits.append(Hit(rel, ln, kind, value, strength, cv.ctx.get(id(node), "other"), snippet, name))

    for scope in scopes:
        if scope is tree:
            consts, textvars, listvars = module_names
            nodes = [n for top in tree.body if not isinstance(top, (ast.FunctionDef, ast.AsyncFunctionDef,
                                                                     ast.ClassDef))
                     for n in ast.walk(top)]
        else:
            c, t, l = _scope_names(scope)
            consts = {**module_names[0], **c}
            textvars, listvars = module_names[1] | t, module_names[2] | l
            nodes = list(ast.walk(scope))
        for n in nodes:
            if isinstance(n, ast.Compare):
                left = n.left
                for op, comp in zip(n.ops, n.comparators):
                    if isinstance(op, ast.In):
                        nd = _needle(left, consts)
                        if nd:
                            add(n, "in", nd, _haystack_kind(comp, textvars, listvars))
                    left = comp
            elif isinstance(n, ast.Call):
                name = _call_name(n)
                last = name.rsplit(".", 1)[-1]
                if last in ("find", "rfind", "index", "rindex", "count", "__contains__") and n.args \
                        and isinstance(n.func, ast.Attribute):
                    nd = _needle(n.args[0], consts)
                    hay = _haystack_kind(n.func.value, textvars, listvars)
                    # .index()/.count() on a list are exact; only a plainly-text receiver counts
                    if nd and (hay == "text" or (last in ("find", "rfind", "__contains__") and hay == "unknown")):
                        add(n, "." + last, nd, hay)
                elif last in ("assertIn", "assertTrue_in") and len(n.args) >= 2:
                    nd = _needle(n.args[0], consts)
                    if nd:
                        add(n, "assertIn", nd, _haystack_kind(n.args[1], textvars, listvars))
                elif last in ("assertRegex", "assertRegexpMatches") and len(n.args) >= 2:
                    p = n.args[1]
                    if isinstance(p, ast.Constant) and isinstance(p.value, str):
                        lit = _regex_literal(p.value)
                        if lit is not None and is_short(lit):
                            add(n, "assertRegex", (lit, ""), _haystack_kind(n.args[0], textvars, listvars))
                elif name in ("re.search", "re.findall", "re.finditer", "search", "findall") and len(n.args) >= 2:
                    p = n.args[0]
                    pat = p.value if isinstance(p, ast.Constant) and isinstance(p.value, str) else consts.get(
                        p.id) if isinstance(p, ast.Name) else None
                    if isinstance(pat, str):
                        lit = _regex_literal(pat)
                        if lit is not None and is_short(lit):
                            add(n, name, (lit, ""), _haystack_kind(n.args[1], textvars, listvars))
    return hits


# -- other languages and shell (line rules) -------------------------------------------------------

_Q = r"""(?P<q>["'`])(?P<v>[^"'`\n]{1,24})(?P=q)"""
# (kind, regex, language set, strength). A regex's named group "hay" (if any) is classified.
_LINE_RULES = [
    ("strings.Contains", re.compile(r"\bstrings\.Contains\(\s*(?P<hay>[^,\n]+),\s*" + _Q + r"\s*\)"), {"go"}, "text"),
    ("Contains", re.compile(r"\b(?:assert|require|suite|s)\.(?:Contains|StringContains)\(\s*\w+,\s*(?P<hay>[^,\n]+),\s*"
                            + _Q), {"go"}, "unknown"),
    (".toContain", re.compile(r"expect\(\s*(?P<hay>[^\n]*?)\)\s*(?:\.not)?\.toContain\(\s*" + _Q + r"\s*\)"),
     {"js"}, "unknown"),
    (".toMatch", re.compile(r"expect\(\s*(?P<hay>[^\n]*?)\)\.toMatch\(\s*" + _Q + r"\s*\)"), {"js"}, "text"),
    (".includes", re.compile(r"(?P<hay>[\w.\])]+)\.includes\(\s*" + _Q + r"\s*\)"), {"js"}, "unknown"),
    (".indexOf", re.compile(r"(?P<hay>[\w.\])]+)\.indexOf\(\s*" + _Q + r"\s*\)"), {"js"}, "unknown"),
    (".contains", re.compile(r"(?P<hay>[\w.\])]+)\.contains\(\s*" + _Q + r"\s*\)"),
     {"java", "kotlin", "csharp", "rust", "scala", "swift", "cpp"}, "unknown"),
    ("assertThat.contains", re.compile(r"assertThat\(\s*(?P<hay>[^\n]*?)\)\s*\.contains\(\s*" + _Q + r"\s*\)"),
     {"java", "kotlin"}, "unknown"),
    ("Assert.Contains", re.compile(r"Assert\.Contains\(\s*" + _Q + r"\s*,\s*(?P<hay>[^)\n]+)\)"), {"csharp"}, "unknown"),
    (".include?", re.compile(r"(?P<hay>[\w.\])]+)\.include\?\(?\s*" + _Q), {"ruby"}, "unknown"),
    ("include", re.compile(r"\bto\s+include\(\s*" + _Q + r"\s*\)"), {"ruby"}, "unknown"),
    ("str_contains", re.compile(r"\b(?:str_contains|strpos)\(\s*(?P<hay>[^,\n]+),\s*" + _Q), {"php"}, "text"),
    ("assertStringContainsString", re.compile(r"assertStringContainsString\(\s*" + _Q), {"php"}, "text"),
    # greedy haystack: the needle is the last quoted argument before the closing paren
    ("clojure.string/includes?", re.compile(r"(?:str|string|clojure\.string)/includes\?\s+(?P<hay>.+)\s+"
                                            r"(?P<q>\")(?P<v>[^\"\n]{1,24})\"\)"), {"clojure"}, "text"),
    # Python, for diff fragments that ast cannot parse
    ("in", re.compile(_Q + r"\s+in\s+(?P<hay>[^\n:#]+)"), {"python"}, "classify"),
    ("assertIn", re.compile(r"assertIn\(\s*" + _Q + r"\s*,\s*(?P<hay>[^\n]+)\)"), {"python"}, "classify"),
    ("[[ == *v* ]]", re.compile(r"\[\[\s*(?P<hay>\S+)\s*==?\s*\*\"?(?P<v>[^*\"\s]{1,24})\"?\*\s*\]\]"),
     {"shell"}, "text"),
]
_GREP = re.compile(r"\b(?:grep|egrep|fgrep|rg)\b(?P<flags>(?:\s+-[A-Za-z]+|\s+--[\w-]+(?:=\S+)?)*)\s+"
                   r"(?:(?P<q>[\"'])(?P<qv>[^\"'\n]{1,24})(?P=q)|(?P<v>[^\s|;&<>\"'-][^\s|;&<>\"']{0,23}))")

_EXT = {".py": "python", ".sh": "shell", ".bash": "shell", ".js": "js", ".mjs": "js", ".cjs": "js",
        ".ts": "js", ".tsx": "js", ".jsx": "js", ".go": "go", ".java": "java", ".kt": "kotlin",
        ".kts": "kotlin", ".cs": "csharp", ".rs": "rust", ".scala": "scala", ".swift": "swift",
        ".rb": "ruby", ".php": "php", ".clj": "clojure", ".cljs": "clojure", ".cljc": "clojure",
        ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp", ".h": "cpp", ".c": "cpp"}


def language_of(path: str) -> str:
    p = path.lower()
    for ext, lang in _EXT.items():
        if p.endswith(ext):
            return lang
    return "shell" if p.rsplit("/", 1)[-1] in ("test.sh", "run-tests.sh", "run_tests") else ""


def _py_hay_kind(text: str) -> str:
    t = text.strip().rstrip(")").strip()
    if re.search(r"\.(split|rsplit|splitlines|keys|values|items|readlines)\(\s*[^)]*\)?$", t) or t.startswith(("[", "{", "(")):
        return "list"
    if re.match(r"(?:str|repr)\(", t) or re.search(r"\.(stdout|stderr|output|text|content|read\(\)|read_text\(\)|"
                                                   r"decode\(\)|lower\(\)|upper\(\)|strip\(\)|getvalue\(\))", t):
        return "text"
    last = re.split(r"[^\w]+", t)
    word = next((w for w in reversed(last) if w), "")
    if _LIST_NAMES.search(word):
        return "list"
    return "text" if _TEXT_NAMES.search(word) else "unknown"


def _line_context(line: str) -> str:
    s = line.strip()
    if re.match(r"(?:assert|expect|require|Assert|t\.|self\.assert|assertThat|is\(|ok\(|\(is\s|\(testing)", s) \
            or re.search(r"\bassert\w*[!(\s]|\bexpect\(|\bshould\b|\bRequire\.|\.Should\(", s):
        return "assert"
    if re.match(r"return\b", s):
        return "return"
    if re.match(r"(?:if|elif|while|\}?\s*else if|unless)\b|\[\[|\[ |test\s", s):
        return "if"
    return "other"


def _inside_string(line: str, pos: int) -> bool:
    """True when position pos sits inside an already-open string literal on this line."""
    before = line[:pos].replace("\\\"", "").replace("\\'", "")
    return before.count('"') % 2 == 1 or before.count("'") % 2 == 1


def scan_lines(text: str, rel: str, lang: str, line_offsets=None) -> list:
    """Line rules for one file's text (or the added lines of one file in a diff)."""
    hits = []
    for i, raw in enumerate(text.splitlines()):
        line = raw.split("//", 1)[0] if lang in ("go", "js", "java", "kotlin", "csharp", "rust", "scala", "swift",
                                                 "php", "cpp") and "://" not in raw else raw
        if lang in ("python", "shell", "ruby") and line.lstrip().startswith("#"):
            continue
        if lang == "clojure" and line.lstrip().startswith(";"):
            continue
        lineno = line_offsets[i] if line_offsets else i + 1
        for kind, rx, langs, strength in _LINE_RULES:
            if lang not in langs:
                continue
            for m in rx.finditer(line):
                v = m.group("v")
                if not is_short(v) or _inside_string(line, m.start("q") if "q" in rx.groupindex else m.start()):
                    continue
                st = strength
                if st == "classify":
                    st = _py_hay_kind(m.group("hay"))
                    if st == "list":
                        continue
                hits.append(Hit(rel, lineno, kind, v.strip(), st, _line_context(line), line.strip()[:160]))
        if lang == "shell":
            for m in _GREP.finditer(line):
                flags = (m.group("flags") or "").split()
                shorts = [f[1:] for f in flags if not f.startswith("--")]
                letters = "".join(shorts)
                if (set(letters) & set("wxvf") or "--word-regexp" in flags or "--line-regexp" in flags
                        or "--invert-match" in flags):
                    continue  # whole-word/line match, a negative check, or patterns from a file
                if shorts and shorts[-1][-1:] in ("A", "B", "C", "m", "d", "D"):
                    continue  # the next word is that option's argument, not the pattern
                v = m.group("qv") if m.group("qv") is not None else m.group("v")
                lit = v if "F" in letters else _regex_literal(v)
                if lit is None or not is_short(lit):
                    continue
                hits.append(Hit(rel, lineno, "grep", lit.strip(), "text", _line_context(line), line.strip()[:160]))
    return hits


def scan_file(text: str, rel: str) -> list:
    lang = language_of(rel)
    if lang == "python":
        hits = scan_python(text, rel)
        if hits or _parses(text):
            return hits
        return scan_lines(text, rel, "python")
    if lang:
        return scan_lines(text, rel, lang)
    return []


def _parses(text: str) -> bool:
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(text)
        return True
    except (SyntaxError, ValueError):
        return False


def scan_diff(patch: str) -> list:
    """Hits on the added lines of a unified diff (a code-patch task's test patch)."""
    hits, cur, added, nums, newline = [], "", [], [], 0

    def flush():
        if cur and added:
            lang = language_of(cur)
            if lang:
                hits.extend(scan_lines("\n".join(added), cur, lang, nums))

    for line in patch.splitlines():
        if line.startswith("+++ "):
            flush()
            cur, added, nums = line[4:].strip(), [], []
            if cur.startswith("b/"):
                cur = cur[2:]
            continue
        if line.startswith("@@"):
            m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)", line)
            newline = int(m.group(1)) if m else 0
            continue
        if line.startswith("+"):
            added.append(line[1:])
            nums.append(newline)
            newline += 1
        elif line.startswith(" "):
            newline += 1
    flush()
    return hits


# -- a Harbor task's grader ---------------------------------------------------------------------

_SKIP_SUFFIX = (".pyc", ".so", ".png", ".jpg", ".jpeg", ".gif", ".gz", ".zip", ".tar", ".bin", ".enc", ".pdf",
                ".parquet", ".npy", ".pt", ".onnx", ".whl")


def grader_hits(task) -> list:
    """Every hit in a Harbor task's verifier: tests/test.sh and the files under tests/."""
    hits = scan_lines(task.test_sh, "tests/test.sh", "shell")
    tests = task.path / "tests"
    for p in sorted(tests.rglob("*")) if tests.is_dir() else []:
        if not p.is_file() or p.name == "test.sh" or p.suffix.lower() in _SKIP_SUFFIX or p.stat().st_size > 2_000_000:
            continue
        hits.extend(scan_file(p.read_text(errors="replace"), p.relative_to(task.path).as_posix()))
    return hits


_SHELL_KINDS = ("grep", "[[ == *v* ]]")


def decide(hits: list) -> LooseResult:
    # In shell, the `if grep ...` that writes the reward is the assertion.
    flags = [h for h in hits if h.strength == "text" and (h.context in ("assert", "return")
                                                         or (h.context == "if" and h.kind in _SHELL_KINDS))]
    rows = [h.__dict__ for h in hits]
    det = {"hits": rows[:40], "n_hits": len(hits), "n_flag": len(flags)}
    if flags:
        h = flags[0]
        more = "" if len(flags) == 1 else " (+%d more)" % (len(flags) - 1)
        return LooseResult(FLAG, "short value %r checked by substring (%s) at %s:%d%s"
                           % (h.value, h.kind, h.file, h.line, more), det)
    if hits:
        h = hits[0]
        what = ("expected value %s checked by substring; its values come from data" % (h.needle or "?")
                if h.strength == "data" else "short value %r checked by %s on a value of unknown type"
                % (h.value, h.kind))
        more = "" if len(hits) == 1 else " (+%d more)" % (len(hits) - 1)
        return LooseResult(WARN, what + " at %s:%d%s" % (h.file, h.line, more), det)
    return LooseResult(PASS, "no short expected value is checked by substring", det)


def loose_match(task) -> LooseResult:
    return decide(grader_hits(task))
