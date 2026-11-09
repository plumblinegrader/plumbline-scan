"""Run a Harbor task in Docker the way Harbor's local Docker environment does.

Each run is a fresh container from the task image, kept alive with `sleep
infinity`. The solution directory is copied to /solution and solve.sh runs as
the oracle agent; then tests/ is copied to /tests and test.sh runs as the
verifier. Both run in the image's own working directory. The reward is read
from /logs/verifier/reward.txt or reward.json.

"Sealed" runs use `--network none`. "Network" runs use Docker's default bridge.
The Docker CLI is called directly, so every command is plain to audit.
"""

from __future__ import annotations

import json
import subprocess
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .harbor import Task


class InfraError(RuntimeError):
    """Docker itself failed (pull, build, start), not the task's code."""


@dataclass
class Exec:
    code: int
    output: str
    seconds: float
    timed_out: bool = False


@dataclass
class RunResult:
    label: str
    network: bool
    reward: float | None = None  # None: no reward file
    reward_raw: str = ""
    full: bool = False
    infra_error: str = ""
    timed_out: bool = False
    seconds: float = 0.0
    note: str = ""

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("label", "network", "reward", "reward_raw", "full", "infra_error",
                                             "timed_out", "seconds", "note")}


def parse_reward(txt: str, js: str) -> tuple[float | None, str, bool]:
    """(reward, raw text, full reward). reward.json wins over reward.txt, as in Harbor.

    reward.json may hold several metrics; with a "reward" key that one counts,
    otherwise full reward means every numeric value is at least 1."""
    js, txt = js.strip(), txt.strip()
    if js:
        try:
            data = json.loads(js)
        except json.JSONDecodeError:
            data = None
        if isinstance(data, (int, float)):
            return float(data), js, float(data) >= 1.0
        if isinstance(data, dict):
            if isinstance(data.get("reward"), (int, float)):
                v = float(data["reward"])
                return v, js, v >= 1.0
            nums = [float(v) for v in data.values() if isinstance(v, (int, float)) and not isinstance(v, bool)]
            if nums:
                return min(nums), js, min(nums) >= 1.0
    if txt:
        try:
            v = float(txt.split()[0])
            return v, txt, v >= 1.0
        except (ValueError, IndexError):
            return None, txt, False
    return None, "", False


@dataclass
class Docker:
    docker: str = "docker"
    log_dir: Path | None = None
    limits: bool = True  # apply the task's cpus/memory
    pull: bool = True
    timeout_mult: float = 1.0
    # Images this scan pulled or built (absent before): the only ones --rm-images removes.
    created_images: set = field(default_factory=set)

    def _run(self, args: list[str], timeout: float = 120, input_bytes: bytes | None = None):
        return subprocess.run([self.docker, *args], input=input_bytes, capture_output=True, timeout=timeout)

    def available(self) -> str:
        try:
            r = self._run(["version", "--format", "{{.Server.Version}}"], timeout=30)
        except (OSError, subprocess.SubprocessError) as e:
            return f"docker not usable: {e}"
        return "" if r.returncode == 0 else "docker not usable: " + r.stderr.decode(errors="replace").strip()[-300:]

    def has_image(self, image: str) -> bool:
        return self._run(["image", "inspect", image], timeout=60).returncode == 0

    def prepare(self, task: Task, build_timeout: float = 7200) -> str:
        """Make the task image present: build environment/ or pull docker_image. Returns a note."""
        if self.has_image(task.image):
            return "image present"
        if task.build_context is not None:
            for base in _from_images(task.build_context / "Dockerfile"):
                if not self.has_image(base):
                    self.created_images.add(base)
            r = self._run(["build", "-q", "-t", task.image, str(task.build_context)], timeout=build_timeout)
            if r.returncode != 0:
                raise InfraError("build failed: " + r.stderr.decode(errors="replace").strip()[-800:])
            self.created_images.add(task.image)
            return "built from environment/"
        if not self.pull:
            raise InfraError(f"image not present and --no-pull: {task.image}")
        err = ""
        for attempt in range(4):
            r = self._run(["pull", task.image], timeout=3600)
            if r.returncode == 0:
                self.created_images.add(task.image)
                return "pulled"
            err = r.stderr.decode(errors="replace").strip()[-500:]
            time.sleep(5 * (attempt + 1))
        raise InfraError(f"pull failed for {task.image}: {err}")

    def remove_created(self, task: Task) -> None:
        """Remove the images this scan created for the task (never ones that were already there)."""
        for img in [task.image] + (_from_images(task.build_context / "Dockerfile") if task.build_context else []):
            if img in self.created_images:
                self._run(["rmi", "-f", img], timeout=600)
                self.created_images.discard(img)

    @contextmanager
    def container(self, task: Task, network: bool):
        name = f"plumbline-scan-{uuid.uuid4().hex[:12]}"
        base = ["run", "-d", "--name", name, "--network", "bridge" if network else "none",
                "--label", "plumbline-scan=1"]
        if self.limits and task.cpus:
            base += ["--cpus", str(task.cpus)]
        if self.limits and task.memory:
            base += ["--memory", task.memory]
        for k, v in sorted(task.env.get("environment", {}).items()):
            base += ["-e", f"{k}={v}"]
        r = self._run(base + [task.image, "sh", "-c", "sleep infinity"], timeout=300)
        if r.returncode == 0 and not self._running(name):
            # An image ENTRYPOINT that does not exec its arguments: start it the way it can stay up.
            self._run(["rm", "-f", name], timeout=120)
            r = self._run(base + ["--entrypoint", "sh", task.image, "-c", "sleep infinity"], timeout=300)
        if r.returncode != 0 or not self._running(name):
            err = r.stderr.decode(errors="replace").strip()[-500:]
            self._run(["rm", "-f", name], timeout=120)
            raise InfraError(f"container did not start: {err}")
        try:
            yield Container(self, name)
        finally:
            self._run(["rm", "-f", name], timeout=120)

    def _running(self, name: str) -> bool:
        time.sleep(0.5)
        r = self._run(["inspect", "-f", "{{.State.Running}}", name], timeout=60)
        return r.stdout.decode().strip() == "true"

    # -- the Harbor phases -------------------------------------------------------------

    def run(self, task: Task, label: str, network: bool, solve: bool = True, patch: str | None = None,
            log_name: str | None = None) -> RunResult:
        """One trial in a fresh container: the reference solution (solve=True), a repository
        patch (patch=...), or nothing at all (the empty solution); then the verifier."""
        res = RunResult(label=label, network=network)
        t0 = time.monotonic()
        logs: list[str] = []
        try:
            with self.container(task, network) as c:
                c.exec("mkdir -p /logs/agent /logs/verifier /logs/artifacts", 60)
                if patch is not None:
                    c.put("/tmp/plumbline_scan.diff", patch)
                    a = c.exec(APPLY_SH, 600)
                    logs.append("== apply\n" + a.output)
                    if a.code != 0:
                        res.note = "patch did not apply"
                elif solve:
                    c.copy_dir(task.path / "solution", "/solution")
                    s = c.exec("bash /solution/solve.sh > /logs/agent/oracle.txt 2>&1; echo EXIT=$?; "
                               "tail -c 20000 /logs/agent/oracle.txt",
                               task.agent_timeout * self.timeout_mult, env=task.env.get("solution", {}))
                    logs.append("== solve.sh\n" + s.output)
                    if s.timed_out:
                        res.timed_out, res.note = True, "solve.sh timed out"
                if not res.timed_out:
                    c.copy_dir(task.path / "tests", "/tests")
                    v = c.exec("bash /tests/test.sh 2>&1", task.verifier_timeout * self.timeout_mult,
                               env=task.env.get("verifier", {}))
                    logs.append("== test.sh\n" + v.output[-200_000:])
                    if v.timed_out:
                        res.timed_out, res.note = True, "test.sh timed out"
                if not res.timed_out:
                    txt = c.exec("cat /logs/verifier/reward.txt 2>/dev/null", 60).output
                    js = c.exec("cat /logs/verifier/reward.json 2>/dev/null", 60).output
                    res.reward, res.reward_raw, res.full = parse_reward(txt, js)
                    if res.reward is None and not res.note:
                        res.note = "verifier wrote no reward file"
        except InfraError as e:
            res.infra_error = str(e)
        except subprocess.TimeoutExpired as e:
            res.infra_error = f"docker command timed out: {e.cmd[:3]}"
        res.seconds = round(time.monotonic() - t0, 1)
        self._log(task, log_name or label, logs, res)
        return res

    def probe(self, task: Task, script: str, files: dict[str, str], timeout: float, label: str) -> Exec:
        """Run an inspection script in a fresh sealed container (files are written first)."""
        with self.container(task, network=False) as c:
            for p, content in files.items():
                c.put(p, content)
            c.put("/tmp/plumbline_scan_probe.sh", script)
            r = c.exec("bash /tmp/plumbline_scan_probe.sh 2>/dev/null", timeout)
        self._log(task, label, ["== probe\n" + r.output], None)
        return r

    def _log(self, task: Task, label: str, parts: list[str], res: RunResult | None) -> None:
        if self.log_dir is None:
            return
        d = self.log_dir / task.name
        d.mkdir(parents=True, exist_ok=True)
        text = "\n".join(parts)
        if res is not None:
            text += "\n== result\n" + json.dumps(res.to_dict(), indent=2)
        (d / f"{label}.log").write_text(text)


# Apply a patch in the repository: the working directory if it is a git repo, else /app or /testbed.
APPLY_SH = r"""
for d in "$PWD" /app /testbed /workspace /repo; do
  if [ -d "$d" ] && git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; then cd "$d"; break; fi
done
git apply --verbose --reject /tmp/plumbline_scan.diff 2>&1 && exit 0
git checkout -- . 2>/dev/null; git apply --verbose --recount --ignore-whitespace /tmp/plumbline_scan.diff 2>&1 && exit 0
git checkout -- . 2>/dev/null; patch --batch --fuzz=5 -p1 -i /tmp/plumbline_scan.diff 2>&1
"""


def _from_images(dockerfile: Path) -> list[str]:
    import re

    if not dockerfile.is_file():
        return []
    stages = set()
    out = []
    for m in re.finditer(r"^\s*FROM\s+(?:--\S+\s+)*(\S+)(?:\s+AS\s+(\S+))?", dockerfile.read_text(), re.M | re.I):
        img = m.group(1)
        if "$" not in img and img.lower() != "scratch" and img not in stages:
            out.append(img)
        if m.group(2):
            stages.add(m.group(2))
    return out


@dataclass
class Container:
    docker: Docker
    name: str

    def put(self, path: str, content: str | bytes) -> None:
        data = content.encode() if isinstance(content, str) else content
        r = self.docker._run(["exec", "-i", self.name, "sh", "-c", f"cat > '{path}'"], timeout=300,
                             input_bytes=data)
        if r.returncode != 0:
            raise InfraError(f"write {path} failed: {r.stderr.decode(errors='replace')[-300:]}")

    def copy_dir(self, src: Path, dest: str) -> None:
        self.exec(f"rm -rf '{dest}' && mkdir -p '{dest}'", 60)
        if src.is_dir():
            r = self.docker._run(["cp", f"{src}/.", f"{self.name}:{dest}"], timeout=600)
            if r.returncode != 0:
                raise InfraError(f"copy {src.name}/ failed: {r.stderr.decode(errors='replace')[-300:]}")

    def exec(self, cmd: str, timeout: float, env: dict | None = None) -> Exec:
        args = ["exec"]
        for k, v in sorted((env or {}).items()):
            args += ["-e", f"{k}={v}"]
        args += [self.name, "bash", "-c", cmd]
        t0 = time.monotonic()
        try:
            r = self.docker._run(args, timeout=timeout)
        except subprocess.TimeoutExpired as e:
            self.docker._run(["kill", self.name], timeout=60)
            out = (e.stdout or b"") + (e.stderr or b"")
            return Exec(-1, out.decode(errors="replace"), time.monotonic() - t0, timed_out=True)
        out = r.stdout.decode(errors="replace") + r.stderr.decode(errors="replace")
        if r.returncode in (126, 127) and 'exec: "bash"' in out:
            raise InfraError("the image has no bash")
        return Exec(r.returncode, out, time.monotonic() - t0)
