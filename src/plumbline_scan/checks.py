"""The six checks, run per task.

1. reference      the official solution earns full reward, k runs in fresh containers (flakiness reported)
2. empty          a no-op solution (the verifier alone) earns zero reward
3. leaked_answer  the reference can be recovered inside the image; if from a git commit, whether it earns full reward
4. stub           the reference is a placeholder, or scores 0 in every run
5. editable_input the verifier grades against files that exist before the agent acts and are not restored
6. network        the verifier or reference needs the network: marked as such, not failed

Statuses: PASS, FLAG (a defect), WARN (worth a look), NETWORK (needs the network;
not a defect), N/A, ERROR (the check could not run).
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import asdict, dataclass, field

from . import detectors, leak
from .docker import Docker, InfraError, RunResult
from .harbor import Task

PASS, FLAG, WARN, NETWORK, NA, ERROR = "PASS", "FLAG", "WARN", "NETWORK", "N/A", "ERROR"
CHECKS = ("reference", "empty", "leaked_answer", "stub", "editable_input", "network")
# PS-7..PS-12 are static (no Docker, no model calls); see detectors.py. They are reported
# alongside the dynamic checks above.
ALL_CHECKS = CHECKS + detectors.DETECTORS


def detector_checks(task: Task) -> dict:
    """The static detectors (PS-7..PS-12) as Check objects (deterministic; reads files only)."""
    return {k: Check(r.status, r.summary, r.details) for k, r in detectors.run(task).items()}


@dataclass
class Check:
    status: str
    summary: str
    details: dict = field(default_factory=dict)


@dataclass
class Options:
    k: int = 3
    network: str = "auto"  # auto | sealed | on
    skip: tuple = ()
    grade_recovered: bool = True
    probe_timeout: float = 3600


# -- static readings ---------------------------------------------------------------------------

_NET = re.compile(r"\b(curl|wget|pip3? install|uv pip install|uvx|uv run --with|uv sync|apt-get install|apt install|"
                  r"apk add|npm (?:install|ci)|yarn install|pnpm install|go mod download|cargo fetch|git clone|"
                  r"hf_hub_download|snapshot_download|requests\.get|urllib\.request\.urlopen)\b")


def network_markers(task: Task) -> list[str]:
    """Run-time downloads named by the verifier (and, for script references, the solution)."""
    dirs = ["tests"] if task.is_patch_task else ["tests", "solution"]
    found = set()
    for sub in dirs:
        d = task.path / sub
        for f in sorted(d.rglob("*")) if d.is_dir() else []:
            if f.is_file() and f.suffix in (".sh", ".py", "", ".bash") and f.stat().st_size < 1_000_000:
                found.update(_NET.findall(f.read_text(errors="replace")))
    return sorted(found)


_PLACEHOLDER = re.compile(r"no solution|not implemented|placeholder|todo|fixme|tbd|to be written|fill (?:this )?in", re.I)
_NOOP_LINE = re.compile(r"^(?:#.*|set\s+-[a-z]+.*|echo\b.*|printf\b.*|true|:|exit(?:\s+\d+)?|cd\s+\S+.*|"
                        r"source\s+.*|\.\s+.*|export\s+.*)$")


def placeholder_reason(task: Task) -> str:
    """Why the reference looks like a placeholder; "" when it does not."""
    if not (task.path / "solution" / "solve.sh").is_file():
        return "solution/solve.sh is missing"
    lines = [ln.strip() for ln in task.solve_sh.splitlines() if ln.strip()]
    if not lines:
        return "solve.sh is empty"
    if task.is_patch_task:
        return ""
    effective = [ln for ln in lines if not _NOOP_LINE.match(ln)]
    extra = [f for f in (task.path / "solution").rglob("*") if f.is_file() and f.name != "solve.sh"]
    if not effective and not extra:
        said = [ln for ln in lines if ln.startswith(("echo", "printf")) and _PLACEHOLDER.search(ln)]
        return ("solve.sh only prints: " + said[0][:80]) if said else "solve.sh runs no command that could change anything"
    return ""


_PATH_LIT = re.compile(r"""["'](/(?:[A-Za-z0-9_.@+-]+/)*[A-Za-z0-9_.@+-]+)["']""")
_SYSTEM = ("/tests", "/logs", "/proc", "/sys", "/dev", "/usr", "/bin", "/sbin", "/lib", "/etc", "/opt", "/var",
           "/run", "/tmp", "/solution", "/root/.", "/nix", "/installed-agent", "/agent-logs")


def verifier_paths(task: Task) -> list[str]:
    """Absolute paths named in the verifier's files, minus system locations."""
    tests = task.path / "tests"
    found = set()
    for f in sorted(tests.rglob("*")) if tests.is_dir() else []:
        if not f.is_file() or f.stat().st_size > 1_000_000 or f.suffix in (".pyc", ".so", ".png", ".jpg", ".gz", ".zip"):
            continue
        for m in _PATH_LIT.finditer(f.read_text(errors="replace")):
            p = m.group(1).rstrip("/")
            if p != "/" and not p.startswith(_SYSTEM) and "*" not in p:
                found.add(p)
    return sorted(found)


def restored_by_test_sh(task: Task, path: str) -> bool:
    name = re.escape(path.rsplit("/", 1)[-1])
    return bool(re.search(r"\b(?:cp|install|rsync|curl|wget|tar|unzip|git\s+checkout)\b[^\n]*" + name, task.test_sh))


# -- the scan ----------------------------------------------------------------------------------

class Scan:
    def __init__(self, task: Task, docker: Docker, opts: Options, log=print):
        self.task, self.docker, self.opts, self.log = task, docker, opts, log
        self.net_needed = False
        self.ref_runs: list[RunResult] = []
        self.confirm: RunResult | None = None
        self.timings: dict = {}

    def _t(self, key: str, t0: float) -> None:
        self.timings[key] = round(self.timings.get(key, 0) + time.monotonic() - t0, 1)

    def run(self) -> dict:
        t, t_start = self.task, time.monotonic()
        out = {"task": t.name, "path": str(t.path), "image": t.image,
               "reference_kind": "repository patch" if t.is_patch_task else "script",
               "network_declared": t.network.get("declared", ""), "checks": {}}
        if t.unresolved_env:
            out["unresolved_env"] = t.unresolved_env
        # The static detectors (PS-7..PS-12) need no image, so they run even if the image is
        # unavailable.
        det = detector_checks(t)
        t0 = time.monotonic()
        try:
            out["image_note"] = self.docker.prepare(t)
        except InfraError as e:
            checks = {c: Check(ERROR, f"image unavailable: {str(e)[:200]}") for c in CHECKS}
            checks.update(det)
            out["checks"] = {k: asdict(checks[k]) for k in ALL_CHECKS if k in checks}
            out["verdict"] = verdict(checks)
            out["seconds"] = round(time.monotonic() - t_start, 1)
            return out
        self._t("image", t0)
        checks: dict[str, Check] = {}
        markers = network_markers(t)
        if "reference" not in self.opts.skip:
            checks["reference"] = self.check_reference()
        if "empty" not in self.opts.skip:
            checks["empty"] = self.check_empty()
        if "stub" not in self.opts.skip:
            checks["stub"] = self.check_stub()
        if "leaked_answer" not in self.opts.skip:
            checks["leaked_answer"] = self.check_leak()
        if "editable_input" not in self.opts.skip:
            checks["editable_input"] = self.check_inputs()
        checks["network"] = self.check_network(markers)
        checks.update(det)
        out["checks"] = {k: asdict(checks[k]) for k in ALL_CHECKS if k in checks}
        out["verdict"] = verdict(checks)
        self.timings["total"] = round(time.monotonic() - t_start, 1)
        out["seconds"] = self.timings["total"]
        out["timings"] = self.timings
        return out

    # 1 + 6 ------------------------------------------------------------------------------------
    def _may_retry_online(self) -> bool:
        if self.opts.network != "auto":
            return False
        return bool(self.task.network.get("agent") or self.task.network.get("verifier"))

    def check_reference(self) -> Check:
        t0 = time.monotonic()
        k, runs, retried = self.opts.k, [], []
        online = self.opts.network == "on"
        may_retry = self._may_retry_online()
        for i in range(k):
            r = self.docker.run(self.task, f"reference-{i + 1}", network=online, log_name=f"reference-{i + 1}")
            self.log(f"  {self.task.name}: reference run {i + 1}/{k}: {_fmt(r)}")
            if not online and not r.full and not r.infra_error and may_retry:
                r2 = self.docker.run(self.task, f"reference-{i + 1}-network", network=True)
                self.log(f"  {self.task.name}: reference run {i + 1}/{k} with network: {_fmt(r2)}")
                retried.append({"sealed": r.to_dict(), "network": r2.to_dict()})
                if r2.full:
                    self.net_needed = online = True
                elif not r2.infra_error:
                    may_retry = False  # the network did not help once: later runs stay sealed
                r = r2
            runs.append(r)
        confirm = None
        if self.net_needed:
            # One more sealed run: a sealed failure that was only flakiness must not read as network dependence.
            confirm = self.docker.run(self.task, "reference-sealed-confirm", network=False)
            self.log(f"  {self.task.name}: sealed confirmation run: {_fmt(confirm)}")
            if confirm.full:
                self.net_needed = False
        self.ref_runs, self.confirm = runs, confirm
        self._t("reference", t0)
        graded = [r for r in runs if not r.infra_error]
        passes = sum(r.full for r in graded)
        det = {"k": k, "passes": passes, "graded": len(graded), "runs": [r.to_dict() for r in runs],
               "sealed_then_network": retried, "sealed_confirm": confirm.to_dict() if confirm else None,
               "seconds_per_run": [r.seconds for r in runs]}
        net = " (with network)" if self.net_needed else ""
        if not graded:
            return Check(ERROR, "every run was lost to infrastructure: " + runs[0].infra_error[:160], det)
        if confirm is not None and confirm.full:
            return Check(WARN, f"flaky: a sealed run failed, the network retry and a later sealed run passed "
                               f"({passes}/{len(graded)} counted runs passed)", det)
        if passes == len(graded):
            return Check(PASS, f"full reward in {passes}/{len(graded)} runs{net}", det)
        rewards = ", ".join(_reward_str(r) for r in graded)
        if passes == 0:
            return Check(FLAG, f"never earns full reward ({rewards}){net}", det)
        return Check(WARN, f"flaky: full reward in {passes}/{len(graded)} runs ({rewards}){net}", det)

    def check_network(self, markers: list[str]) -> Check:
        det = {"declared": self.task.network.get("declared", ""), "markers": markers, "mode": self.opts.network}
        if self.net_needed:
            return Check(NETWORK, "reference fails sealed and passes with network"
                         + (f"; downloads: {', '.join(markers)}" if markers else ""), det)
        if self.opts.network == "on":
            return Check(NA, "not tested (--network on)" + (f"; downloads: {', '.join(markers)}" if markers else ""), det)
        sealed_pass = any(r.full and not r.network for r in self.ref_runs) or bool(self.confirm and self.confirm.full)
        if sealed_pass:
            return Check(PASS, "reference passes with the network off", det)
        if not self.ref_runs:
            return Check(NA, "reference not run", det)
        if markers:
            if self.opts.network == "sealed":
                return Check(WARN, f"not confirmed (--network sealed); downloads: {', '.join(markers)}", det)
            return Check(WARN, f"unknown: the reference fails either way; downloads: {', '.join(markers)}", det)
        return Check(NA, "unknown: the reference never passes", det)

    # 2 ----------------------------------------------------------------------------------------
    def check_empty(self) -> Check:
        t0 = time.monotonic()
        r = self.docker.run(self.task, "empty", network=self.net_needed or self.opts.network == "on", solve=False)
        self.log(f"  {self.task.name}: empty solution: {_fmt(r)}")
        self._t("empty", t0)
        det = {"run": r.to_dict()}
        if r.infra_error:
            return Check(ERROR, r.infra_error[:200], det)
        if r.full:
            return Check(FLAG, f"a no-op solution earns full reward ({_reward_str(r)})", det)
        if r.reward:
            return Check(WARN, f"a no-op solution earns partial reward ({_reward_str(r)})", det)
        return Check(PASS, f"no-op earns {_reward_str(r)}", det)

    # 4 ----------------------------------------------------------------------------------------
    def check_stub(self) -> Check:
        why = placeholder_reason(self.task)
        graded = [r for r in self.ref_runs if not r.infra_error]
        det = {"placeholder": why}
        if why:
            return Check(FLAG, f"placeholder reference: {why}", det)
        if graded and all(not r.reward for r in graded):
            return Check(FLAG, "the reference scores 0 in every run", det)
        if not graded:
            return Check(NA, "reference not run", det)
        return Check(PASS, "reference is a real solution", det)

    # 3 ----------------------------------------------------------------------------------------
    def check_leak(self) -> Check:
        t0 = time.monotonic()
        results, recovered = [], None
        for basis, keys, paths in leak.key_sets(self.task):
            if not keys:
                results.append(leak.ProbeResult(basis=basis, status="NOT_TESTABLE",
                                                note=f"no distinctive line in the {basis}"))
                continue
            files = {leak.KEYS_PATH: "\n".join(keys) + "\n", leak.PATHS_PATH: "\n".join(paths) + "\n"}
            try:
                out = self.docker.probe(self.task, leak.probe_script(), files, self.opts.probe_timeout,
                                        f"leak-probe-{basis.split()[0].strip(chr(39))}")
            except InfraError as e:
                results.append(leak.ProbeResult(basis=basis, status="ERROR", note=str(e)[:200]))
                continue
            r = leak.parse_probe(out.output)
            r.basis = basis
            r = leak.decide(r, fix_names=leak.file_names(paths))
            results.append(r)
            if (self.opts.grade_recovered and self.task.is_patch_task and r.best_commit
                    and any(s.startswith("git_commit:") for s in r.flagged_sources)):
                recovered = self._grade_recovered(r, paths)
        self._t("leaked_answer", t0)
        det = {"probes": [r.to_dict() for r in results], "recovered": recovered}
        leaked = [r for r in results if r.status == "LEAKED"]
        if leaked:
            where = "; ".join(f"{r.basis}: " + ", ".join(_short_src(s) for s in r.flagged_sources[:3]) for r in leaked)
            if recovered and recovered.get("full"):
                return Check(FLAG, f"recoverable ({where}); the recovered fix earns full reward", det)
            if recovered:
                return Check(FLAG, f"recoverable ({where}); the recovered fix does not earn full reward "
                                   f"({recovered.get('reward_raw') or recovered.get('note') or recovered.get('infra_error', '')[:60]})",
                             det)
            return Check(FLAG, f"recoverable ({where})", det)
        if any(r.status == "ERROR" for r in results):
            return Check(ERROR, "; ".join(r.note for r in results if r.status == "ERROR")[:200], det)
        if all(r.status == "NOT_TESTABLE" for r in results):
            return Check(NA, "; ".join(r.note for r in results)[:200], det)
        n = sum(r.keys_effective for r in results)
        return Check(PASS, f"no copy of the {' or '.join(r.basis for r in results if r.status == 'CLEAN')} "
                           f"found ({n} key lines searched)", det)

    def _grade_recovered(self, r: leak.ProbeResult, paths: list[str]) -> dict:
        commit = r.best_commit
        try:
            out = self.docker.probe(self.task, leak.recovered_diff_script(r.repo, commit, paths), {}, 600,
                                    "leak-recovered-diff")
        except InfraError as e:
            return {"commit": commit, "infra_error": str(e)[:200], "full": False}
        diff = out.output
        if not diff.lstrip().startswith("diff --git"):
            return {"commit": commit, "note": "no diff recovered", "full": False}
        if self.docker.log_dir is not None:
            d = self.docker.log_dir / self.task.name
            d.mkdir(parents=True, exist_ok=True)
            (d / "recovered.diff").write_text(diff)
        res = self.docker.run(self.task, "recovered-fix", network=self.net_needed or self.opts.network == "on",
                              patch=diff)
        self.log(f"  {self.task.name}: recovered fix from {commit[:12]}: {_fmt(res)}")
        return {"commit": commit, "diff_lines": diff.count("\n"), **res.to_dict()}

    # 5 ----------------------------------------------------------------------------------------
    def check_inputs(self) -> Check:
        if self.task.is_patch_task:
            return Check(NA, "repository task: the verifier reads the repository by design")
        paths = verifier_paths(self.task)
        if not paths:
            return Check(PASS, "the verifier names no absolute input path outside system locations", {"paths": []})
        state = "; ".join(
            f"if [ -e {shlex.quote(p)} ]; then printf 'P %s %s %s %s\\n' {shlex.quote(p)} "
            f"\"$( [ -d {shlex.quote(p)} ] && echo dir || echo file)\" \"$( [ -w {shlex.quote(p)} ] && echo w || echo ro)\" "
            f"\"$( [ -f {shlex.quote(p)} ] && cksum < {shlex.quote(p)} | tr ' ' : || echo -)\"; fi"
            for p in paths) + "; echo DONE=1"
        # The state of each path before the agent acts, then after the reference solution ran: a file
        # the reference changes is an output the agent is meant to edit, not an input.
        try:
            with self.docker.container(self.task, network=self.net_needed or self.opts.network == "on") as c:
                before = c.exec(state, 300).output
                c.copy_dir(self.task.path / "solution", "/solution")
                c.exec("bash /solution/solve.sh >/dev/null 2>&1", self.task.agent_timeout * self.docker.timeout_mult,
                       env=self.task.env.get("solution", {}))
                after = c.exec(state, 300).output
        except InfraError as e:
            return Check(ERROR, str(e)[:200], {"paths": paths})
        if "DONE=1" not in before:
            return Check(ERROR, "probe did not finish", {"paths": paths})
        rx = re.compile(r"^P (\S+) (dir|file) (w|ro) (\S+)$")
        sums_after = {m.group(1): m.group(4) for m in map(rx.match, after.splitlines()) if m}
        pre = []
        for line in before.splitlines():
            m = rx.match(line)
            if m:
                p = m.group(1)
                pre.append({"path": p, "kind": m.group(2), "writable": m.group(3) == "w",
                            "restored": restored_by_test_sh(self.task, p),
                            "changed_by_reference": sums_after.get(p, "gone") != m.group(4)})
        # A directory is where the agent writes; a file the reference edits is an output.
        flagged = [x["path"] for x in pre if x["kind"] == "file" and x["writable"] and not x["restored"]
                   and not x["changed_by_reference"]]
        det = {"paths": paths, "preexisting": pre, "flagged": flagged}
        if flagged:
            return Check(FLAG, f"graded inputs the agent can edit: {', '.join(flagged[:4])}"
                               + (f" (+{len(flagged) - 4})" if len(flagged) > 4 else ""), det)
        return Check(PASS, f"{len(paths)} named paths; none is a pre-existing editable input left unrestored", det)


def verdict(checks: dict[str, Check]) -> str:
    st = [c.status for c in checks.values()]
    if FLAG in st:
        return "FLAGGED"
    if WARN in st:
        return "WARN"
    if ERROR in st:
        return "INCOMPLETE"
    return "OK"


def _reward_str(r: RunResult) -> str:
    if r.timed_out:
        return "timeout"
    if r.reward is None:
        return "no reward"
    return f"{r.reward:g}"


def _fmt(r: RunResult) -> str:
    if r.infra_error:
        return "infra error: " + r.infra_error[:120]
    return f"reward {_reward_str(r)} in {r.seconds:.0f}s" + (f" ({r.note})" if r.note else "")


def _short_src(s: str) -> str:
    if s.startswith("git_commit:"):
        return "commit " + s.split(":", 1)[1][:12]
    return s.replace("git_refs_not_in_head", "git refs outside HEAD").replace("git_unreachable", "dangling git objects")
