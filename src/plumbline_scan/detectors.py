"""Six static grader-robustness detectors (PS-7..PS-12).

Each inspects a task's verifier (tests/test.sh and every file under tests/), its
reference (solution/) and its image build context (environment/) and flags a
structural weakness that lets an agent earn full reward without doing the task.
They are deterministic: no Docker, no network, no model calls. They read files
and parse the Python verifier with the ``ast`` module; they never run it.

    PS-7  readable_answer      the agent can read the verifier or its expected
                               outputs before grading            (structural-extraction)
    PS-8  mutable_program      grading depends on a program the agent could have
                               changed                           (binary-hijacking)
    PS-9  keyword_match        the verifier grades by text/keyword matching on a
                               file the agent wrote              (keyword-gaming)
    PS-10 mutable_measurement  a measurement the grader trusts (score, timing,
                               counter) is inside the agent's reach (metric-spoofing)
    PS-11 runtime_state        run-time shared state the agent can write that the
                               verifier later trusts, incl. code it imports or
                               sources (mutable-input-tampering, run-time)
    PS-12 loose_match          a short expected value (a number, or 3 characters
                               or fewer) is checked by substring, so a wrong value
                               that contains it passes ("11628" for "1628");
                               see loosematch.py

PS-11 extends the dynamic PS-5 editable-input check: PS-5 flags graded files that
exist *before* the agent acts; PS-11 flags state and code channels created *at run
time* that the verifier then trusts.

Statuses: PASS, FLAG (a defect), WARN (worth a look), N/A (nothing to inspect).
"""

from __future__ import annotations

import ast
import fnmatch
import re
from dataclasses import dataclass, field

from . import loosematch
from .harbor import Task

PASS, FLAG, WARN, NA = "PASS", "FLAG", "WARN", "N/A"
DETECTORS = ("readable_answer", "mutable_program", "keyword_match", "mutable_measurement", "runtime_state",
             "loose_match")


@dataclass
class DetResult:
    status: str
    summary: str
    details: dict = field(default_factory=dict)


# -- the agent's reach --------------------------------------------------------------------------
# Paths the verifier runs from (/tests, /logs) and read-only system trees are out of the agent's
# reach; a relative path or anything under the working area (/app, /root, /home, /tmp, ...) is in it.

# The agent runs as root, so almost everything is writable. Out of reach: the verifier's own
# mounts (/tests, /logs), the pseudo-filesystems, and the read-only binary/library trees (an agent
# that rewrites those is binary-hijacking, which PS-8 catches by program name, not by path).
# Config, data, state and output under /etc, /var, /opt, /srv, /tmp, /usr/local, /app, /root, /home
# stay in reach: the agent edits them while doing the task.
_VERIFIER_ONLY = ("/tests", "/logs", "/solution", "/installed-agent", "/agent-logs", "/var/lib/harbor")
_SYSTEM = ("/proc", "/sys", "/dev", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/libx32",
           "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/lib32", "/usr/lib64", "/usr/libexec")


def _under(path: str, bases: tuple) -> bool:
    return any(path == b or path.startswith(b + "/") for b in bases)


def agent_reach(path: str | None) -> bool:
    """True when the agent could create or rewrite this path during its run."""
    if not path:
        return False
    p = path.strip()
    if not p or p in (".", "/") or "$" in p:  # a $VAR path is unresolved: usually the verifier's own toolchain
        return False
    if not p.startswith("/"):
        return True  # relative to the agent's working directory
    p = p.rstrip("/")
    return not _under(p, _VERIFIER_ONLY) and not _under(p, _SYSTEM)


# -- names that signal what a file holds --------------------------------------------------------

# Strong "this is the grader's own notion of the right answer" words only. "answer", "solution" and
# "key" are deliberately excluded: those usually name the agent's own output file, not an oracle.
_ANSWER_WORDS = {"expected", "golden", "gold", "groundtruth", "oracle", "reference", "canonical",
                 "truth", "correct"}
# "result(s)" alone is left out: it usually names the agent's answer file (results.json), not a measurement;
# such a file counts only when the field read is itself a metric (results["accuracy"]).
_METRIC_WORDS = {"score", "scores", "metric", "metrics", "benchmark", "bench",
                 "timing", "timings", "elapsed", "duration", "coverage", "stats", "accuracy",
                 "throughput", "latency", "perf", "count", "counter", "counters"}
_STATE_WORDS = {"config", "conf", "cfg", "settings", "setting", "env", "dotenv", "state", "cache",
                "registry", "manifest", "lock", "lockfile", "database", "db", "session", "profile",
                "sitecustomize", "usercustomize", "conftest", "pth"}
# Standard tools live in system locations; the agent does not own them.
_STD_TOOLS = frozenset(
    "sh bash dash zsh env python python2 python3 pytest uv uvx pip pip2 pip3 cat ls find grep egrep "
    "fgrep rg awk sed cut sort uniq head tail wc tr echo printf test true false diff cmp ps kill pkill "
    "pgrep sleep tar unzip gzip gunzip zcat curl wget git make cmake gcc g++ cc clang node npm npx yarn "
    "pnpm go cargo rustc java javac ruby perl jq chmod chown mkdir rmdir rm cp mv ln touch readlink "
    "realpath dirname basename xargs tee stat date id whoami hostname uname mktemp seq expr bc nproc "
    "timeout nohup dpkg apt apt-get coverage mypy ruff flake8 black pylint tox nose2".split())


def _tokens(name: str) -> set:
    return {t for t in re.split(r"[^a-z0-9]+", name.lower()) if t}


def _name_hits(path: str, words: set) -> bool:
    base = path.rstrip("/").rsplit("/", 1)[-1]
    return bool(_tokens(base) & words)


# -- Python verifier analysis (ast) -------------------------------------------------------------

_READ_XFORM = {"lower", "upper", "casefold", "strip", "rstrip", "lstrip", "splitlines", "split",
               "rsplit", "decode", "readlines", "readline", "read", "getvalue", "join"}
_READ_METH = {"read_text", "read_bytes", "read"}
_KW_METH = {"count", "find", "index", "rfind", "startswith", "endswith"}


@dataclass
class _PyFacts:
    reads: list = field(default_factory=list)          # {"path","func","reach"}
    writes: set = field(default_factory=set)           # resolved paths written by the verifier
    execs: list = field(default_factory=list)          # {"prog","reach","direct"}
    keyword: list = field(default_factory=list)        # {"path","func","kinds","patterns"}
    metric: list = field(default_factory=list)         # {"path","func","use"}
    injection: list = field(default_factory=list)      # {"kind","target"}
    state: list = field(default_factory=list)          # {"path","func"}
    local_writes: set = field(default_factory=set)     # (func, path) a Path variable rewrites in that function
    dynamic_shell: list = field(default_factory=list)  # {"func","line","expr"} shell=True command taken from data
    bare_execs: list = field(default_factory=list)     # non-standard programs run by bare name (PATH lookup)
    runs: list = field(default_factory=list)           # base names of every program run from an argv list
    answer_reads: list = field(default_factory=list)   # {"path","var","func"} content bound to expected*/golden*...
    data_reads: list = field(default_factory=list)     # {"path","func","call"} pandas/numpy reads with a literal path
    scoring_funcs: set = field(default_factory=set)    # functions that score a model (.score, accuracy_score, ...)
    self_report: dict = field(default_factory=dict)    # asserts on the agent object's own getters (PS-10)
    datavars: dict = field(default_factory=dict, repr=False)  # func -> names bound to data parsed at grade time
    syntax_error: bool = False


def _const_str(node, consts: dict):
    """Best-effort resolution of an expression to a string; None if not a string."""
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.Name):
        return consts.get(node.id)
    if isinstance(node, ast.JoinedStr):
        out = []
        for part in node.values:
            if isinstance(part, ast.Constant) and isinstance(part.value, str):
                out.append(part.value)
            else:
                out.append("{?}")  # an unknown piece; keeps leading path context intact
        return "".join(out)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        a, b = _const_str(node.left, consts), _const_str(node.right, consts)
        return None if a is None or b is None else a + b
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):  # Path("/app") / "data.sql"
        a, b = _const_str(node.left, consts), _const_str(node.right, consts)
        return None if not a or b is None else a.rstrip("/") + "/" + b
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name in ("Path", "PurePath", "PosixPath"):
            parts = [_const_str(a, consts) for a in node.args]
            return "/".join(p for p in parts if p) if parts and parts[0] is not None else None
        if name in ("os.path.join", "join") and node.args:
            parts = [_const_str(a, consts) for a in node.args]
            return "/".join(p for p in parts if p is not None) if all(p is not None for p in parts) else None
    return None


def _call_name(node: ast.Call) -> str:
    f = node.func
    if isinstance(f, ast.Name):
        return f.id
    if isinstance(f, ast.Attribute):
        parts = [f.attr]
        cur = f.value
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.append(cur.id)
        return ".".join(reversed(parts))
    return ""


def _unwrap(node):
    """Strip read/transform method chains (``.read_text().lower().strip()``) to the inner node."""
    while isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in _READ_XFORM:
        node = node.func.value
    return node


_GETSOURCE = ("inspect.getsource", "getsource", "inspect.getsourcelines", "getsourcelines")


def _root_name(node):
    while isinstance(node, ast.Attribute):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _content_path(node, consts: dict, pathvars: dict, handles: dict | None = None, modules=frozenset()):
    """If ``node`` reads a file's content, return the file path (resolved) or '' if a read but path
    unknown; None when it is not a file read. ``handles`` maps ``with open(P) as f`` names to P;
    ``modules`` are imported modules of the agent's code (``inspect.getsource(mod)`` reads mod.py)."""
    node = _unwrap(node)
    if handles and isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in handles:
        for lo, hi, path in handles[node.id]:  # f.read(), f.readlines(), iterating f, inside its with-block
            if lo <= getattr(node, "lineno", 0) <= hi:
                return path
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "open" and node.args:
            return _const_str(node.args[0], consts) or ""
        if name in _GETSOURCE and node.args:
            root = _root_name(node.args[0])
            if root and root in modules:
                return root + ".py"  # the agent's own source code, read as text
        if name in ("json.load", "json.loads", "load", "loads") and node.args:
            # json.load(open(p)) / json.loads(p.read_text()) / json.load(f)
            return _content_path(node.args[0], consts, pathvars, handles, modules)
        if isinstance(node.func, ast.Attribute) and node.func.attr in _READ_METH:
            base = node.func.value
            if isinstance(base, ast.Call) and _call_name(base) in ("Path", "PurePath", "PosixPath", "open"):
                return (_const_str(base.args[0], consts) if base.args else "") or ""
            if isinstance(base, ast.Name) and base.id in pathvars:
                return pathvars[base.id]
    if isinstance(node, ast.Name) and node.id in pathvars:
        # bare content var that we already know came from a read
        return None
    return None


def _is_write(node, consts: dict) -> str:
    if isinstance(node, ast.Call):
        name = _call_name(node)
        if name == "open" and len(node.args) >= 2:
            mode = _const_str(node.args[1], consts) or ""
            if any(c in mode for c in "wax"):
                return _const_str(node.args[0], consts) or ""
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("write_text", "write_bytes"):
            base = node.func.value
            if isinstance(base, ast.Call) and _call_name(base) in ("Path", "PurePath", "PosixPath") and base.args:
                return _const_str(base.args[0], consts) or ""
    return ""


def _local_write(node, consts: dict) -> str:
    """``p = Path("/x"); ...; p.write_text(...)``: the path a Path variable writes, or ''."""
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("write_text", "write_bytes")
            and isinstance(node.func.value, ast.Name) and node.func.value.id in consts):
        return consts[node.func.value.id]
    return ""


def _str_list(node, lists: dict):
    """The strings of a literal list/tuple/set (or a name bound to one, or a literal dict's keys); None if not one."""
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in ("items", "keys"):
        node = node.func.value
    if isinstance(node, ast.Name):
        return lists.get(node.id)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        vals = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        return vals if vals and len(vals) == len(node.elts) else None
    if isinstance(node, ast.Dict):
        vals = [k.value for k in node.keys if isinstance(k, ast.Constant) and isinstance(k.value, str)]
        return vals if vals and len(vals) == len(node.keys) else None
    return None


def _loop_target(t):
    if isinstance(t, ast.Tuple) and t.elts:
        t = t.elts[0]  # for key, value in d.items(): the key
    return t.id if isinstance(t, ast.Name) else None


def _scope_consts(scope) -> tuple:
    """Within one scope collect var->string-literal and var->content-source-path maps, file handles
    (``with open(P) as f``) and loop variables over literal string lists (var -> all values)."""
    consts, pathvars, contentvars, handles, loopvals, lists = {}, {}, {}, {}, {}, {}
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            name = n.targets[0].id
            lit = _const_str(n.value, consts)
            if lit is not None:
                consts[name] = lit
                pathvars[name] = lit
            vals = _str_list(n.value, lists)
            if vals:
                lists[name] = vals
    for n in ast.walk(scope):
        gens = []
        if isinstance(n, (ast.For, ast.AsyncFor)):
            gens = [(n.target, n.iter)]
        elif isinstance(n, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            gens = [(g.target, g.iter) for g in n.generators]
        for tgt, it in gens:
            var, vals = _loop_target(tgt), _str_list(it, lists)
            if var and var in loopvals and vals:
                loopvals[var] = loopvals[var] + [v for v in vals if v not in loopvals[var]]
            elif var and vals and var not in consts:
                loopvals[var] = vals
                consts[var] = vals[0]  # resolves a path loop to its first file (enough to name the read)
                pathvars[var] = vals[0]
    for n in ast.walk(scope):
        if isinstance(n, (ast.With, ast.AsyncWith)):
            for item in n.items:
                ce, var = item.context_expr, item.optional_vars
                if not isinstance(var, ast.Name) or not isinstance(ce, ast.Call):
                    continue
                mode = ""
                if _call_name(ce) == "open" and ce.args:
                    path = _const_str(ce.args[0], consts)
                    mode = _const_str(ce.args[1], consts) or "" if len(ce.args) > 1 else ""
                elif isinstance(ce.func, ast.Attribute) and ce.func.attr == "open":
                    path = _const_str(ce.func.value, consts)
                    mode = _const_str(ce.args[0], consts) or "" if ce.args else ""
                else:
                    continue
                if not any(c in mode for c in "wax+"):
                    hi = getattr(n, "end_lineno", None) or max(getattr(x, "lineno", 0) for x in ast.walk(n))
                    handles.setdefault(var.id, []).append((n.lineno, hi, path or ""))
    return consts, pathvars, contentvars, handles, loopvals


def _is_parse(node) -> bool:
    """``json.load(f)`` / ``json.loads(text)`` / ``yaml.safe_load``: the content becomes a structure, so membership
    and length on it test keys and item counts, not text."""
    node = _unwrap(node)
    return isinstance(node, ast.Call) and _call_name(node).split(".")[-1] in ("load", "loads", "safe_load",
                                                                              "full_load", "parse")


def _is_sequence(node) -> bool:
    """``f.readlines()``, ``text.splitlines()``, ``text.split()``, a list comprehension: a list of lines or items,
    so its length is an item count, not a text length."""
    return (isinstance(node, (ast.ListComp, ast.List)) or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("readlines", "splitlines", "split", "rsplit"))


def _contentvars(scope, consts, pathvars, handles, modules) -> tuple:
    """(content var -> source path, names holding parsed structures, names holding lists of lines/items)."""
    contentvars, parsed = {}, set()
    seqs = set()
    for n in ast.walk(scope):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            if _is_sequence(n.value):
                seqs.add(n.targets[0].id)
            cp = _content_path(n.value, consts, pathvars, handles, modules)
            if cp is not None:
                contentvars[n.targets[0].id] = cp
                if _is_parse(n.value):
                    parsed.add(n.targets[0].id)
    for n in ast.walk(scope):  # data = json.load(f); items = data["x"]: still structure
        if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, (ast.Subscript, ast.Call)) and _root_subscript(
                    n.value.func.value if isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Attribute)
                    else n.value) in parsed):
            parsed.add(n.targets[0].id)
    return contentvars, parsed, seqs


def _structured(node, parsed: set, seqs: set = frozenset(), sequences: bool = False) -> bool:
    if _is_parse(node):
        return True
    if sequences and (_is_sequence(node) or isinstance(node, ast.Name) and node.id in seqs):
        return True
    root = _root_subscript(node.func.value if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                           else node)
    return root in parsed


_COMMON_LIBS = frozenset(
    "numpy np pandas pd pytest requests sklearn scipy torch tensorflow yaml toml tomllib pyarrow polars matplotlib "
    "PIL cv2 bs4 lxml flask fastapi django sqlalchemy psycopg2 pymongo redis boto3 docker paramiko pexpect "
    "jsonschema hypothesis numba sympy networkx statsmodels transformers datasets joblib tqdm click rich "
    "httpx aiohttp websockets grpc google openai anthropic".split())


def agent_modules(tree) -> frozenset:
    """Modules the verifier imports that are the agent's code: not the standard library, not a common
    third-party package, and not a conftest/helper shipped next to the tests."""
    import sys
    std = getattr(sys, "stdlib_module_names", frozenset())
    names = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Import):
            names |= {a.name.split(".")[0] for a in n.names}
        elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
            names.add(n.module.split(".")[0])
    return frozenset(m for m in names if m not in std and m not in _COMMON_LIBS
                     and not m.startswith(("test", "conftest", "_")))


def _func_name(scope) -> str:
    return getattr(scope, "name", "<module>")


_DATA_READS = {"read_csv", "read_parquet", "read_json", "read_table", "read_excel", "read_feather", "loadtxt",
               "genfromtxt", "load_svmlight_file"}
_SCORING = {"score", "accuracy_score", "f1_score", "roc_auc_score", "precision_score", "recall_score",
            "mean_squared_error", "mean_absolute_error", "r2_score", "log_loss", "balanced_accuracy_score"}


def _root_subscript(node):
    """The variable at the root of ``a["x"]["y"]`` / ``a.b`` / ``a``; None for literals and expressions."""
    while isinstance(node, (ast.Subscript, ast.Attribute)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None


def _data_vars(scope) -> set:
    """Names bound (directly or through subscripts) to the result of a call: data parsed at grade time, e.g.
    ``parsed = parse_desktop_file(p); cmd = parsed["Desktop Entry"]["Exec"]``. Literal tables and strings the
    verifier builds itself (f-strings, ``.format``, ``join``, ``Path``) are excluded."""
    built = {"Path", "str", "format", "join", "list", "dict", "tuple", "int", "float", "repr", "quote", "strip",
             "replace", "expanduser", "abspath", "realpath", "dirname", "basename"}
    out = set()
    for _ in range(3):
        for n in ast.walk(scope):
            if not (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)):
                continue
            v = n.value
            if isinstance(v, ast.Call) and _call_name(v).split(".")[-1] not in built:
                out.add(n.targets[0].id)
            elif isinstance(v, (ast.Subscript, ast.Attribute)) and _root_subscript(v) in out:
                out.add(n.targets[0].id)
    return out


_GETTER = re.compile(r"^(get_?\w*|score|results?|accuracy|loss|metrics?|iters?|iterations|n_iter\w*|converged|"
                     r"error|precision|recall|f1|evaluate|report)$")


def _self_reports(tree, modules: frozenset) -> dict:
    """PS-10 refinement: asserts that compare a constant with what the agent's own object reports about
    itself (``trainer.get_results() == 1.0``), with nothing recomputed by the verifier."""
    classes = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module and n.module.split(".")[0] in modules:
            classes |= {a.asname or a.name for a in n.names}
    objs = set()
    for n in ast.walk(tree):
        if (isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name)
                and isinstance(n.value, ast.Call)):
            c = _call_name(n.value)
            if c in classes or (c.split(".")[0] in modules and "." in c):
                objs.add(n.targets[0].id)
    if not objs:
        return {}

    def getter(node):
        for x in ast.walk(node):
            if (isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and not x.args
                    and isinstance(x.func.value, ast.Name) and x.func.value.id in objs and _GETTER.match(x.func.attr)):
                return x.func.value.id + "." + x.func.attr + "()"
        return None

    def const(node):
        return isinstance(node, ast.Constant) or (isinstance(node, ast.UnaryOp) and isinstance(node.operand, ast.Constant))

    hits, total = [], 0
    for n in ast.walk(tree):
        if not isinstance(n, ast.Assert):
            continue
        total += 1
        t = n.test
        if isinstance(t, ast.Compare) and len(t.comparators) == 1:
            sides = (t.left, t.comparators[0])
            for a, b in (sides, sides[::-1]):
                g = getter(a)
                if g and const(b):
                    hits.append({"line": n.lineno, "call": g})
                    break
    return {"asserts": total, "self_reported": hits} if hits else {}


def analyze_python(source: str, rel: str) -> _PyFacts:
    f = _PyFacts()
    try:
        tree = ast.parse(source)
    except SyntaxError:
        f.syntax_error = True
        return f
    scopes = [tree] + [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]
    seen_reads = set()
    modules = agent_modules(tree)
    f.datavars = {_func_name(sc): _data_vars(sc) for sc in scopes if sc is not tree}
    f.self_report = _self_reports(tree, modules)
    mod_consts = {}  # top-level constants only (ast.walk(tree) would also pull in every function's locals)
    for n in tree.body:
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            lit = _const_str(n.value, mod_consts)
            if lit is not None:
                mod_consts[n.targets[0].id] = lit
    for scope in scopes:
        fn = _func_name(scope)
        consts, pathvars, _, handles, loopvals = _scope_consts(scope)
        if scope is not tree:  # module-level constants (DATA_DIR = "/app/x") are visible in every function
            consts = {**mod_consts, **consts}
            pathvars = {**mod_consts, **pathvars}
        contentvars, parsed, seqs = _contentvars(scope, consts, pathvars, handles, modules)

        def src_path(node, consts=consts, pathvars=pathvars, handles=handles, contentvars=contentvars):
            node2 = _unwrap(node)
            cp = _content_path(node2, consts, pathvars, handles, modules)
            if cp is not None:
                return cp
            node2 = node2.func.value if isinstance(node2, ast.Call) and isinstance(node2.func, ast.Attribute) else node2
            if isinstance(node2, ast.Name) and node2.id in contentvars:
                return contentvars[node2.id]
            return None

        ctx = (consts, pathvars, handles, modules, loopvals, parsed, seqs)
        for n in ast.iter_child_nodes(scope) if scope is tree else ast.walk(scope):
            if scope is tree and isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue  # handled as its own scope
            for sub in ast.walk(n) if scope is tree else [n]:
                _collect(sub, fn, ctx, contentvars, src_path, f, seen_reads)
    return f


def _collect(sub, fn, ctx, contentvars, src_path, f, seen_reads):
    consts, pathvars, handles, modules, loopvals, parsed, seqs = ctx
    # writes (verifier scratch, so a later read of the same path is not an agent channel)
    w = _is_write(sub, consts)
    if w:
        f.writes.add(w)
    lw = _local_write(sub, consts)
    if lw:  # counts only in this function: a verifier that reads, edits and rewrites its own harness file
        f.local_writes.add((fn, lw))
    # content bound to a name that says it is the grader's answer: expected_key = f.read()
    if isinstance(sub, ast.Assign) and len(sub.targets) == 1 and isinstance(sub.targets[0], ast.Name):
        var = sub.targets[0].id
        if _tokens(var) & _ANSWER_WORDS:
            tgt = src_path(sub.value)
            if tgt and agent_reach(tgt):
                f.answer_reads.append({"path": tgt, "var": var, "func": fn})
    # reads
    cp = _content_path(sub, consts, pathvars, handles, modules)
    if cp is not None:
        key = (fn, cp)
        if key not in seen_reads:
            seen_reads.add(key)
            f.reads.append({"path": cp, "func": fn, "reach": agent_reach(cp)})
    # executes a program
    if isinstance(sub, ast.Call):
        name = _call_name(sub)
        if name in ("subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output",
                    "subprocess.Popen", "run", "call", "check_call", "check_output", "Popen") and sub.args:
            _exec_from_argv(sub.args[0], consts, f)
            shell = any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True
                        for k in sub.keywords)
            if shell and _const_str(sub.args[0], consts) is None:
                root = _root_subscript(sub.args[0])
                if root and root in f.datavars.get(fn, ()):
                    f.dynamic_shell.append({"func": fn, "line": sub.lineno, "expr": ast.unparse(sub.args[0])[:80]})
        elif name.rsplit(".", 1)[-1] in _DATA_READS and sub.args:
            p = _const_str(sub.args[0], consts)
            if p:
                f.data_reads.append({"path": p, "func": fn, "call": name})
        if name.rsplit(".", 1)[-1] in _SCORING:
            f.scoring_funcs.add(fn)
        elif name in ("os.system", "system") and sub.args:
            _exec_from_shell(_const_str(sub.args[0], consts), f)
        elif name in ("exec", "eval") and sub.args:
            tgt = src_path(sub.args[0])
            if tgt is not None and agent_reach(tgt or "."):
                f.injection.append({"kind": "exec/eval of agent-reachable content", "target": tgt or "<dynamic>"})
        elif name in ("importlib.import_module", "import_module", "__import__",
                      "importlib.util.spec_from_file_location", "spec_from_file_location"):
            for a in sub.args:
                p = _const_str(a, consts)
                if p and agent_reach(p) and ("/" in p or p.endswith(".py")):
                    f.injection.append({"kind": "loads code from an agent-reachable path", "target": p})
        # A plain `sys.path.insert(0, "/app"); import solution` is the normal contract for testing
        # the agent's code, not an injection, so it is not flagged here.
        # keyword methods on content
        if isinstance(sub.func, ast.Attribute) and sub.func.attr in _KW_METH:
            tgt = src_path(sub.func.value)
            if tgt is not None and agent_reach(tgt or "."):
                pats = [p for p in (_const_str(a, consts) for a in sub.args) if p]
                _add_keyword(f, tgt, fn, "." + sub.func.attr, pats)
        # re.search/match/... over content
        if name in ("re.search", "re.match", "re.fullmatch", "re.findall", "re.finditer") and len(sub.args) >= 2:
            tgt = src_path(sub.args[1])
            if tgt is not None and agent_reach(tgt or "."):
                pat = _const_str(sub.args[0], consts)
                _add_keyword(f, tgt, fn, "re." + name.split(".")[1], [pat] if pat else [])
        # len(content) used in a comparison is handled at the Compare node
        # json parse of a metric-named file
        if name in ("json.load", "json.loads", "load", "loads") and sub.args:
            tgt = src_path(sub.args[0]) if name in ("json.load", "load") else None
            if tgt and agent_reach(tgt) and _name_hits(tgt, _METRIC_WORDS):
                _add_metric(f, tgt, fn, "parsed as JSON")
    # membership: 'kw' in content
    if isinstance(sub, ast.Compare):
        for op, comp in zip(sub.ops, sub.comparators):
            if isinstance(op, (ast.In, ast.NotIn)):
                if _structured(comp, parsed):
                    continue  # 'key' in json.load(f): a key check, not text matching
                tgt = src_path(comp)
                if tgt is not None and agent_reach(tgt or "."):
                    if isinstance(sub.left, ast.Name) and sub.left.id in loopvals:
                        pats = loopvals[sub.left.id]  # `for term in [...]: assert term in content`
                    else:
                        elt = _const_str(sub.left, consts)
                        pats = [elt] if elt else []
                    _add_keyword(f, tgt, fn, "membership", pats)
            elif isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Eq, ast.NotEq)):
                _numeric_compare(sub.left, comp, consts, src_path, fn, f, op, parsed, seqs)
    # numeric int()/float() conversion of a metric file's content
    if isinstance(sub, ast.Call) and _call_name(sub) in ("int", "float") and sub.args:
        tgt = src_path(sub.args[0])
        if tgt and agent_reach(tgt) and _name_hits(tgt, _METRIC_WORDS):
            _add_metric(f, tgt, fn, "read as a number")
    # subscripted metric field: data["score"] where data came from a metric file
    if isinstance(sub, ast.Subscript):
        tgt = src_path(sub.value)
        key = _const_str(sub.slice, consts)
        if tgt and agent_reach(tgt) and (_name_hits(tgt, _METRIC_WORDS) or (
                _name_hits(tgt, {"result", "results"}) and key and _tokens(key) & _METRIC_WORDS)):
            _add_metric(f, tgt, fn, "field " + (key or "?"))
    # state file read
    if cp is not None and agent_reach(cp) and _name_hits(cp, _STATE_WORDS):
        if not any(s["path"] == cp for s in f.state):
            f.state.append({"path": cp, "func": fn})


def _numeric_compare(left, comp, consts, src_path, fn, f, op=None, parsed=frozenset(), seqs=frozenset()):
    num = isinstance(comp, ast.Constant) and isinstance(comp.value, (int, float))
    target, len_left = left, True
    if not num and isinstance(left, ast.Constant) and isinstance(left.value, (int, float)):
        num, target, len_left = True, comp, False
    if not num:
        return
    # an upper cap (len(x) < N, N > len(x)) keeps output small; it cannot pay padded text, so it is not keyword grading
    upper = isinstance(op, (ast.Lt, ast.LtE)) if len_left else isinstance(op, (ast.Gt, ast.GtE))
    if isinstance(target, ast.Call) and _call_name(target) == "len" and target.args and not upper:
        if _structured(target.args[0], parsed, seqs, sequences=True):
            return  # len(json.load(f)["items"]) / len(f.readlines()) counts items, it is not a text length
        tgt = src_path(target.args[0])
        if tgt is not None and agent_reach(tgt or "."):
            _add_keyword(f, tgt, fn, "length", [])
        return
    tgt = src_path(target)
    if tgt and agent_reach(tgt) and _name_hits(tgt, _METRIC_WORDS):
        _add_metric(f, tgt, fn, "compared to a threshold")


def _add_keyword(f, path, fn, kind, pats):
    for h in f.keyword:
        if h["path"] == path and h["func"] == fn:
            if kind not in h["kinds"]:
                h["kinds"].append(kind)
            h["patterns"] = (h["patterns"] + [p for p in pats if p])[:12]
            return
    f.keyword.append({"path": path, "func": fn, "kinds": [kind], "patterns": [p for p in pats if p][:12]})


def _add_metric(f, path, fn, use):
    for h in f.metric:
        if h["path"] == path and h["func"] == fn:
            if use not in h["use"]:
                h["use"].append(use)
            return
    f.metric.append({"path": path, "func": fn, "use": [use]})


_PATH_OK = re.compile(r"^[\w./~@+-]+$")
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_INTERPRETERS = {"sh", "bash", "dash", "zsh", "python", "python2", "python3", "ruby", "perl", "node"}
# A verifier that builds its own virtualenv and sources its activate script is toolchain setup,
# not agent-controlled state; exclude those targets.
_VENV_CREATE = re.compile(r"(?:uv\s+venv|virtualenv|python[23]?\s+-m\s+venv)\s+([^\s;|&]+)")


def _base_name(p: str) -> str:
    return p.rstrip("/").rsplit("/", 1)[-1]


def _is_toolchain(path: str, venv_dirs: tuple) -> bool:
    if _base_name(path) in ("activate", "activate.sh", "activate.csh", "activate.fish", "env"):
        return True
    clean = path.lstrip("./")
    return any(clean == d or clean.startswith(d.rstrip("/") + "/") for d in venv_dirs)


def _exec_target(toks: list, venv_dirs: tuple):
    """The agent-reachable program a command runs, or None. Skips assignments, shebangs,
    inline code (-c/-m), standard tools and the verifier's own virtualenv. Bails when the
    program word is empty (an unresolved variable): we must not promote an argument to it."""
    toks = list(toks)
    while toks and toks[0] and _ASSIGN.match(toks[0]):
        toks.pop(0)
    if not toks or not toks[0] or toks[0].startswith("#"):
        return None
    prog = toks[0]
    base = _base_name(prog)
    if base in _INTERPRETERS:
        i = 1
        while i < len(toks):
            t = toks[i]
            if t in ("-c", "-m"):  # inline code or a module name, not an agent file
                return None
            if t.startswith("-"):
                i += 1
                continue
            if (_PATH_OK.match(t) and agent_reach(t) and _base_name(t) not in _STD_TOOLS
                    and not _is_toolchain(t, venv_dirs)):
                return t
            return None
        return None
    if base in _STD_TOOLS:
        return None
    if "/" in prog and _PATH_OK.match(prog) and agent_reach(prog) and not _is_toolchain(prog, venv_dirs):
        return prog
    return None


def _exec_from_argv(arg, consts, f):
    if isinstance(arg, (ast.List, ast.Tuple)):
        toks = [(_const_str(e, consts) or "") for e in arg.elts]
        if toks and toks[0] and not any("\n" in t or t.startswith("#!") for t in toks):
            base = _base_name(toks[0])
            f.runs.append(base)
            if ("/" not in toks[0] and _PATH_OK.match(toks[0]) and base not in _STD_TOOLS
                    and base not in _INTERPRETERS and not _ASSIGN.match(toks[0])):
                f.bare_execs.append(base)
        if not any("\n" in t or t.startswith("#!") for t in toks):
            tgt = _exec_target(toks, (".tbench-testing",))
            if tgt:
                f.execs.append({"prog": tgt, "reach": True, "direct": _base_name(toks[0]) not in _INTERPRETERS})
        for t in toks:  # an element that is itself a shell script
            if "\n" in t or t.startswith("#!") or re.search(r"(^|\s)(source|\.)\s", t):
                _shell_into_facts(t, f)
        return
    s = _const_str(arg, consts)
    if s:
        _shell_into_facts(s, f)


def _exec_from_shell(cmd, f):
    if cmd:
        _shell_into_facts(cmd, f)


def _shell_into_facts(text: str, f) -> None:
    sh = analyze_shell(text)
    for p in sh["execs"]:
        f.execs.append({"prog": p, "reach": True, "direct": True})
    for p in sh["source"]:
        f.injection.append({"kind": "shell sources an agent-reachable file", "target": p})


# -- shell verifier analysis --------------------------------------------------------------------

_SH_REACH = re.compile(r"(?<![\w/])((?:\./|/(?:app|root|home|tmp|workspace|data|srv|mnt|output|outputs)\b)[\w./-]*)")
_SH_READ_CMD = re.compile(r"\b(grep|egrep|fgrep|rg|diff|cmp|cat|head|tail|awk|sed|jq)\b")


_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
_SHELLS = {"sh", "bash", "dash", "zsh"}


def _shell_lines(text: str) -> list[str]:
    """Logical command lines: backslash continuations joined, and heredoc bodies dropped when they are
    data (``cat > helper.py <<EOF``), kept when a shell reads them (``bash <<EOF``, ``cat > x.sh <<EOF``)."""
    lines, buf, end, keep, quoted = [], "", None, True, False
    for raw in text.splitlines():
        if quoted:  # inside a multi-line '...' string (e.g. a patch passed to echo): data, not commands
            if raw.count("'") % 2:
                quoted = False
                lines.append(raw.split("'", 1)[1])
            continue
        if end is not None:
            if raw.strip() == end:
                end = None
            elif keep:
                lines.append(raw)
            continue
        if raw.rstrip().endswith("\\") and not raw.lstrip().startswith("#"):
            buf += raw.rstrip()[:-1] + " "
            continue
        line, buf = buf + raw, ""
        code = line.split("#", 1)[0] if not line.lstrip().startswith("#") else ""
        if code.count("'") % 2 and '"' not in code:  # opens a '...' string that ends on a later line
            quoted = True
            line = line.split("'", 1)[0]
        lines.append(line)
        m = _HEREDOC.search(line.split("#", 1)[0])
        if m:
            end = m.group(2)
            head = line[:m.start()].split()
            first = _base_name(head[0]) if head else ""
            target = re.search(r">\s*(\S+)", line[:m.start()])
            keep = first in _SHELLS or bool(target and target.group(1).endswith((".sh", ".bash")))
    if buf:
        lines.append(buf)
    return lines


def _norm(path: str) -> str:
    return path[2:] if path.startswith("./") else path


def analyze_shell(text: str) -> dict:
    out = {"reads": [], "execs": [], "source": [], "pythonpath": [], "writes": set()}
    venv_dirs = tuple(m.group(1).lstrip("./") for m in _VENV_CREATE.finditer(text)) + (".tbench-testing",)
    for m in re.finditer(r">>?\s*(\S+)", text):
        out["writes"].add(m.group(1))
    for raw in _shell_lines(text):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("#!"):
            continue
        toks = line.split()
        while toks and _ASSIGN.match(toks[0]):
            toks.pop(0)
        if not toks:
            continue
        head = toks[0]
        # a file the verifier itself copies into place is its own, not the agent's
        for cmd in re.split(r"&&|\|\||;", line):
            words = [w for w in cmd.split() if not w.startswith("-")]
            if (len(words) >= 3 and words[0] in ("cp", "install")
                    and all(_under(w, _VERIFIER_ONLY) for w in words[1:-1])):
                out["writes"].add(words[-1])
        if (head in (".", "source") and len(toks) > 1 and agent_reach(toks[1])
                and not _is_toolchain(toks[1], venv_dirs)):
            out["source"].append(toks[1])
        if "PYTHONPATH=" in line:
            for m in re.finditer(r"PYTHONPATH=([^\s;]+)", line):
                for part in m.group(1).split(":"):
                    if agent_reach(part) and not _is_toolchain(part, venv_dirs):
                        out["pythonpath"].append(part)
        tgt = _exec_target(toks, venv_dirs)
        if tgt:
            out["execs"].append(tgt)
        reach = [p for p in _SH_REACH.findall(line) if agent_reach(p) and "..." not in p]  # not `go test ./...`
        if _SH_READ_CMD.search(line) and reach:
            out["reads"].extend(reach)
    return out


# -- gather the grader's files ------------------------------------------------------------------

@dataclass
class Grader:
    task: Task
    py: list = field(default_factory=list)        # (rel, _PyFacts)
    shell: dict = field(default_factory=dict)     # merged shell facts
    env_files: list = field(default_factory=list)  # rel paths under environment/
    reads: list = field(default_factory=list)      # all python reads
    writes: set = field(default_factory=set)
    tests_text: str = ""                           # every verifier file, concatenated
    env_text: str = ""                             # environment/ text files (Dockerfile, setup scripts)


def _grader(task: Task) -> Grader:
    g = Grader(task=task)
    tests = task.path / "tests"
    shell_text = task.test_sh
    texts = []
    for p in sorted(tests.rglob("*")) if tests.is_dir() else []:
        if not p.is_file() or p.stat().st_size > 2_000_000:
            continue
        rel = p.relative_to(task.path).as_posix()
        if p.suffix in (".py", ".sh", ".bash", ".js", ".ts", ".rb", ".go", ".r", ".R", ".exp", "") or p.name == "test.sh":
            texts.append(p.read_text(errors="replace"))
        if p.suffix == ".py":
            g.py.append((rel, analyze_python(p.read_text(errors="replace"), rel)))
        elif p.suffix in (".sh", ".bash") and p.name != "test.sh":
            shell_text += "\n" + p.read_text(errors="replace")
    g.shell = analyze_shell(shell_text)
    for _, pf in g.py:
        g.reads.extend(pf.reads)
        g.writes |= pf.writes
    g.writes |= set(g.shell.get("writes", set()))
    env = task.path / "environment"
    g.env_files = [p.relative_to(env).as_posix() for p in sorted(env.rglob("*"))
                   if p.is_file()] if env.is_dir() else []
    g.tests_text = "\n".join(texts + [task.test_sh])
    env_texts = []
    for rel in g.env_files[:400]:
        p = env / rel
        if p.stat().st_size < 300_000 and (p.name == "Dockerfile" or p.suffix in (".sh", ".py", ".bash", ".yaml",
                                                                               ".yml", ".conf", ".txt", "")):
            env_texts.append(p.read_text(errors="replace"))
    g.env_text = "\n".join(env_texts)
    return g


def _read_not_scratch(path: str, writes: set) -> bool:
    """A read of a path the verifier does not itself write first (so the agent owns it)."""
    return path not in writes


# -- the detectors ------------------------------------------------------------------------------

def _in_image(task: Task, env_files: list) -> list:
    """The build-context files the final image stage copies in (COPY/ADD without --from). A file that sits in
    environment/ but is never copied, or is copied only into an earlier build stage, is not in the agent's image.
    Without a readable Dockerfile every file counts (we cannot tell)."""
    try:
        text = (task.path / "environment" / "Dockerfile").read_text(errors="replace")
    except OSError:
        return env_files
    text = re.sub(r"\\\n", " ", text)
    stage = re.split(r"(?im)^\s*FROM\s", text)[-1]
    srcs = []
    for m in re.finditer(r"(?im)^\s*(?:COPY|ADD)\s+(.+)$", stage):
        words = [w for w in m.group(1).split() if not w.startswith("--chown") and not w.startswith("--chmod")]
        if any(w.startswith("--from") for w in words) or len(words) < 2:
            continue
        if words[0].startswith("["):  # JSON form
            words = re.findall(r'"([^"]+)"', m.group(1))
        srcs += [w.lstrip("./").rstrip("/") for w in words[:-1] if not w.startswith("--")]
    out = []
    for f in env_files:
        for src in srcs:
            if src in ("", ".", "*") or f == src or f.startswith(src + "/") or fnmatch.fnmatch(f, src):
                out.append(f)
                break
    return out


def readable_answer(g: Grader) -> DetResult:  # PS-7
    image = _in_image(g.task, g.env_files)
    env_hits = [f for f in image if _name_hits(f, _ANSWER_WORDS)]
    # a verifier .py file also shipped into the image (same name) is grader logic in the image
    test_py = {p.rsplit("/", 1)[-1] for p, _ in g.py}
    logic_in_image = sorted({f for f in image if f.rsplit("/", 1)[-1] in test_py and f.endswith(".py")})
    read_hits = [r for r in g.reads if r["reach"] and _read_not_scratch(r["path"], g.writes)
                 and _name_hits(r["path"], _ANSWER_WORDS)]
    read_paths = sorted({r["path"] for r in read_hits})
    # found by how the content is used, not by the file name: expected_key = open("/tmp/key.txt").read()
    usage = sorted({r["path"] + " (as " + r["var"] + ")" for _, pf in g.py for r in pf.answer_reads
                    if _read_not_scratch(r["path"], g.writes) and r["path"] not in read_paths})
    heldout = _heldout_labels(g)
    det = {"env_answer_files": env_hits, "grader_logic_in_image": logic_in_image,
           "verifier_reads_expected": read_paths, "answer_by_usage": usage, "heldout_data": heldout}
    if usage:
        read_paths = read_paths + usage
    if not (env_hits or logic_in_image or read_paths) and heldout:
        return DetResult(WARN, "held-out evaluation data the verifier scores with is readable in the agent's image: "
                         + ", ".join(heldout[:3]), det)
    if env_hits or logic_in_image or read_paths:
        bits = []
        if env_hits:
            bits.append("expected-output file(s) baked into the image: " + ", ".join(env_hits[:4]))
        if logic_in_image:
            bits.append("verifier logic readable in the image: " + ", ".join(logic_in_image[:4]))
        if read_paths:
            bits.append("verifier reads expected outputs from the agent's area: " + ", ".join(read_paths[:4]))
        return DetResult(FLAG, "; ".join(bits), det)
    return DetResult(PASS, "no expected outputs or verifier logic are readable from the agent's area", det)


_HELDOUT_WORDS = {"test", "testing", "holdout", "heldout", "hidden", "eval", "evaluation", "validation", "val",
                  "private"}


def _heldout_labels(g: Grader) -> list:
    """Data the verifier scores a model on (``model.score(pd.read_csv(P))``) that sits in the agent's image under a
    held-out name: the agent can read the labels, or train on them."""
    out = set()
    for _, pf in g.py:
        for r in pf.data_reads:
            p = r["path"]
            if (r["func"] in pf.scoring_funcs and agent_reach(p) and _name_hits(p, _HELDOUT_WORDS)
                    and _read_not_scratch(p, g.writes) and p in g.env_text):
                out.add(p)
    return sorted(out)


def _workdir(task: Task) -> str:
    """The image's last WORKDIR (where a repository task keeps its repository), or ''."""
    df = task.path / "environment" / "Dockerfile"
    try:
        found = re.findall(r"^\s*WORKDIR\s+(\S+)", df.read_text(errors="replace"), re.M)
    except OSError:
        return ""
    return found[-1].rstrip("/") if found else ""


def mutable_program(g: Grader) -> DetResult:  # PS-8
    own = {_norm(w) for w in g.writes}
    # a program the verifier writes itself (``cat > parser.py <<EOF``) is the verifier's, not the agent's
    py = sorted({e["prog"] for _, pf in g.py for e in pf.execs if _norm(e["prog"]) not in own})
    sh = sorted({p for p in g.shell.get("execs", []) if _norm(p) not in own})
    progs = sorted(set(py) | set(sh))
    dyn = [d for _, pf in g.py for d in pf.dynamic_shell]
    det = {"programs": progs, "python": py, "shell": sh, "dynamic_shell": dyn}
    if dyn:
        d0 = dyn[0]
        return DetResult(FLAG, "verifier runs a shell command taken from data it read at grade time ("
                         + d0["expr"] + ", " + d0["func"] + " line " + str(d0["line"])
                         + "): whatever command the agent wrote there runs as the grader", det)
    if progs and g.task.is_patch_task:
        # In a repository-patch task the agent may edit the whole repository by design, and the
        # verifier runs the repository's own test suite. A runner inside the repository is that
        # suite, not a per-task finding: report it, do not flag it.
        repo = _in_repository(g, progs)
        det["repository_runners"] = repo
        progs = [p for p in progs if p not in repo]
        det["programs"] = progs
        if not progs:
            return DetResult(PASS, "grading runs only the repository's own test runner(s): " + ", ".join(repo[:3])
                             + " (repository-patch task: the whole repository is the agent's by design)", det)
    if progs:
        return DetResult(FLAG, "grading runs program(s) the agent could have changed: " + ", ".join(progs[:5]), det)
    bare = _custom_bare(g)
    subject = _subject_programs(g)
    det["custom_by_bare_name"], det["subject_programs"] = bare, subject
    if bare or subject:
        bits = []
        if bare:
            bits.append("runs custom program(s) by bare name, found through PATH in agent-writable directories: "
                        + ", ".join(bare[:4]))
        if subject:
            bits.append("trusts the program the task is about, run from the agent's own image with no identity "
                        "check: " + ", ".join(subject[:4]))
        return DetResult(WARN, "; ".join(bits), det)
    return DetResult(PASS, "grading does not execute any program from the agent's area", det)


def _custom_bare(g: Grader) -> list:
    """Programs the verifier runs by bare name that the image installs under an agent-writable directory
    (``RUN echo ... > /opt/devtools/formatter``): PATH resolves them to files the agent can rewrite."""
    out = set()
    for _, pf in g.py:
        for name in pf.bare_execs:
            # a file in a bin directory or under /opt (not a directory such as /etc/nginx/ or /run/sshd)
            for m in re.finditer(r"(/[\w.+-]+(?:/[\w.+-]+)*)/" + re.escape(name) + r"(?![\w./-])", g.env_text):
                d = m.group(1)
                if agent_reach(d + "/" + name) and (re.search(r"/(?:s?bin|libexec)$", d) or d.startswith("/opt/")):
                    out.add(name)
                    break
    return sorted(out)


# Programs that are the subject of a task (configured, fixed or installed by the agent) and that a verifier
# then runs from the agent's own image. Standard interpreters count only through the polyglot rule below.
# Build tools (gcc, make, git) are left out: the verifier uses them on the agent's code, they are not the subject.
_SUBJECT_TOOLS = ("bash", "zsh", "passwd", "chpasswd", "ssh", "scp", "sudo", "su", "gpg", "openssl", "nginx",
                  "apache2", "httpd", "crontab", "systemctl", "mysql", "psql", "redis-cli", "sqlite3", "node")
_RUNTIMES = ("node", "python3", "python", "ruby", "perl", "php", "bash", "sh", "deno", "bun", "lua", "Rscript")


def _subject_programs(g: Grader) -> list:
    if g.task.is_patch_task:  # the repository is the subject; its tooling is not
        return []
    instr = g.task.instruction or ""
    run = {r for _, pf in g.py for r in pf.runs}
    for raw in _shell_lines(g.task.test_sh):
        toks = raw.split("#", 1)[0].split()
        if toks:
            run.add(_base_name(toks[0]))
    out = []
    for t in _SUBJECT_TOOLS:
        if t not in run or _identity_checked(g, t):
            continue
        named = re.search(r"`" + re.escape(t) + r"(?:`|\s[^`]*`)", instr) or re.search(
            r"(?<![\w/])\." + re.escape(t) + r"(?:rc|_profile|_login|_logout|config)\b", instr)
        if named:
            out.append(t)
    # polyglot: one agent file run under two interpreters the instruction names (`node X` and `python3 X`)
    pairs = re.findall(r"`(" + "|".join(_RUNTIMES) + r")\s+(\S+)", instr)
    by_file = {}
    for interp, path in pairs:
        by_file.setdefault(path, set()).add(interp)
    for path, interps in by_file.items():
        quoted = [i for i in interps if re.search(r"['\"]" + re.escape(i) + r"['\"]", g.tests_text)]
        if len(quoted) >= 2 and not any(_identity_checked(g, i) for i in quoted):
            out.extend(sorted(i for i in quoted if i not in out))
    return out


def _identity_checked(g: Grader, tool: str) -> bool:
    t = re.escape(tool)
    return bool(re.search(r"\b" + t + r"['\"]?\s*,?\s*['\"]?--?(?:version|V)\b|(?:which|command -v|type)\s+['\"]?" + t
                          + r"\b|sha(?:1|256|512)sum|md5sum\s+\S*" + t + r"|dpkg\s+(?:-V|--verify)|rpm\s+-V|['\"](?:/usr)?/s?bin/"
                          + t + r"['\"]", g.tests_text))


def keyword_match(g: Grader) -> DetResult:  # PS-9
    hits = []
    for _, pf in g.py:
        for h in pf.keyword:
            if _read_not_scratch(h["path"], g.writes) and (h["func"], h["path"]) not in pf.local_writes:
                hits.append(h)
    sh_reads = [p for p in g.shell.get("reads", []) if _read_not_scratch(p, g.writes)]
    det = {"python": hits, "shell_text_reads": sorted(set(sh_reads))}
    if hits:
        f0 = hits[0]
        kinds = ", ".join(sorted({k for h in hits for k in h["kinds"]}))
        pats = sorted({p for h in hits for p in h["patterns"]})[:6]
        tail = (" for " + ", ".join(repr(p) for p in pats)) if pats else ""
        summary = ("verifier grades " + f0["path"] + " by " + kinds + tail
                   + (" (+%d more file)" % (len({h['path'] for h in hits}) - 1) if len({h['path'] for h in hits}) > 1 else ""))
        return DetResult(FLAG, summary, det)
    if sh_reads:
        return DetResult(WARN, "test.sh text-matches agent file(s): " + ", ".join(sorted(set(sh_reads))[:4]), det)
    return DetResult(PASS, "no text/keyword grading of agent-written files", det)


def mutable_measurement(g: Grader) -> DetResult:  # PS-10
    hits = []
    for _, pf in g.py:
        for h in pf.metric:
            if _read_not_scratch(h["path"], g.writes):
                hits.append(h)
    selfrep = [dict(r, file=rel) for rel, pf in g.py for r in [pf.self_report] if r]
    det = {"measurements": hits, "self_reported": selfrep}
    if not hits and selfrep:
        n = sum(len(r["self_reported"]) for r in selfrep)
        total = sum(r["asserts"] for r in selfrep)
        calls = sorted({c["call"] for r in selfrep for c in r["self_reported"]})
        status = FLAG if n == total and n >= 2 else WARN
        return DetResult(status, "verifier trusts metrics the agent's own object reports about itself ("
                         + ", ".join(calls[:4]) + "): %d of %d assertions, nothing recomputed" % (n, total), det)
    if hits:
        paths = sorted({h["path"] for h in hits})
        uses = sorted({u for h in hits for u in h["use"]})
        return DetResult(FLAG, "grader trusts measurement file(s) in the agent's reach: "
                         + ", ".join(paths[:4]) + " (" + "; ".join(uses[:4]) + ")", det)
    return DetResult(PASS, "no score/timing/counter file inside the agent's reach feeds the reward", det)


def _in_repository(g: Grader, paths: list) -> list:
    """For a repository-patch task, the paths inside the repository (relative, or under WORKDIR)."""
    if not g.task.is_patch_task:
        return []
    wd = _workdir(g.task)
    return [p for p in paths if not p.startswith("/") or (wd and _under(p, (wd,)))]


def runtime_state(g: Grader) -> DetResult:  # PS-11
    # Reported as WARN, never FLAG: in a hand check of public script tasks most hits were a config file that is
    # itself the deliverable, so a hit is a channel worth a look, not a defect on its own.
    sourced = g.shell.get("source", [])
    repo = _in_repository(g, sourced)  # the repository's own CI script: the repository is the agent's by design
    inj = [e for _, pf in g.py for e in pf.injection]
    inj += [{"kind": "test.sh sources an agent-reachable file", "target": p} for p in sourced if p not in repo]
    state = [s for _, pf in g.py for s in pf.state if _read_not_scratch(s["path"], g.writes)]
    det = {"code_injection": inj, "state_files": state}
    if repo:
        det["repository_scripts"] = repo
    if inj:
        kinds = sorted({e["kind"] for e in inj})
        tgts = sorted({e["target"] for e in inj})
        return DetResult(WARN, "verifier trusts agent-controlled code/state: " + "; ".join(kinds[:3])
                         + " (" + ", ".join(tgts[:4]) + ")", det)
    if state:
        paths = sorted({s["path"] for s in state})
        return DetResult(WARN, "verifier reads run-time shared state the agent can write: "
                         + ", ".join(paths[:4]), det)
    return DetResult(PASS, "verifier imports no agent code and trusts no run-time shared state", det)


def loose_match(g: Grader) -> DetResult:  # PS-12
    r = loosematch.loose_match(g.task)
    return DetResult(r.status, r.summary, r.details)


_FUNCS = {"readable_answer": readable_answer, "mutable_program": mutable_program,
          "keyword_match": keyword_match, "mutable_measurement": mutable_measurement,
          "runtime_state": runtime_state, "loose_match": loose_match}


def run(task: Task) -> dict:
    """Run the six detectors over a task. Deterministic; reads files only."""
    g = _grader(task)
    syntax = [rel for rel, pf in g.py if pf.syntax_error]
    out = {}
    for key in DETECTORS:
        res = _FUNCS[key](g)
        if syntax:
            res.details = {**res.details, "unparsed_python": syntax}
        out[key] = res
    return out
