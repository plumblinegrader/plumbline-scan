"""Read a Harbor task directory.

A Harbor task is a directory with:

    task.toml              timeouts, resources, network settings, optional docker_image
    instruction.md         what the agent is told
    environment/           the image's build context (Dockerfile), unless docker_image is set
    solution/solve.sh      the official (reference) solution, run as Harbor's oracle agent
    tests/test.sh          the verifier; writes /logs/verifier/reward.txt or reward.json

Nothing here runs Docker; it only parses files.
"""

from __future__ import annotations

import hashlib
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_TIMEOUT = 1800.0
PATCH_NAMES = ("gold_patch.diff", "solution.patch", "fix.patch", "solution.diff", "patch.diff")


@dataclass
class Task:
    name: str
    path: Path
    config: dict
    image: str  # a registry image (docker_image) or the local tag we build from environment/
    build_context: Path | None  # environment/ when the image is built here
    agent_timeout: float
    verifier_timeout: float
    cpus: float | None
    memory: str | None  # a docker --memory value ("4096m")
    reference_patch: str  # the reference as a repository patch, "" when the reference is only a script
    solve_sh: str
    test_sh: str
    instruction: str
    network: dict = field(default_factory=dict)  # {"agent": bool, "verifier": bool, "declared": str}
    env: dict = field(default_factory=dict)  # {"solution": {...}, "verifier": {...}, "environment": {...}}
    unresolved_env: list = field(default_factory=list)  # names a phase reads from the host (${VAR}): not supplied

    @property
    def is_patch_task(self) -> bool:
        return bool(self.reference_patch.strip())


class TaskError(ValueError):
    pass


def find_tasks(paths: list[str]) -> list[Path]:
    """Each path is a task directory or a directory of task directories."""
    out: list[Path] = []
    for p in map(Path, paths):
        if (p / "task.toml").is_file():
            out.append(p)
        elif p.is_dir():
            out.extend(sorted(d for d in p.iterdir() if (d / "task.toml").is_file()))
        else:
            raise TaskError(f"not a Harbor task or a directory of tasks: {p}")
    return out


_EMBEDDED_DIFF = re.compile(r"<<\s*'?(\w+)'?[^\n]*\n(diff --git .*?\n)\1\s*$", re.S | re.M)
_REVERSE_APPLY = re.compile(r"apply\s+(?:[^\n]*\s)?(?:-R|--reverse)\b|patch\s+(?:[^\n]*\s)?-R\b")


def reverse_patch(patch: str) -> str:
    """The inverse of a unified git diff (for references that apply a bug patch with -R)."""
    out, pending_old = [], ""
    for line in patch.splitlines(keepends=True):
        if line.startswith("--- "):
            pending_old = line[4:]
            continue
        if line.startswith("+++ "):
            new = line[4:]
            out.append("--- " + ("a/" + new[2:] if new.startswith("b/") else new))
            out.append("+++ " + ("b/" + pending_old[2:] if pending_old.startswith("a/") else pending_old))
            continue
        m = re.match(r"@@ -(\S+) \+(\S+) @@(.*)", line, re.S)
        if m:
            out.append(f"@@ -{m.group(2)} +{m.group(1)} @@{m.group(3)}")
        elif line.startswith("index "):
            m2 = re.match(r"index (\w+)\.\.(\w+)(.*)", line, re.S)
            out.append(f"index {m2.group(2)}..{m2.group(1)}{m2.group(3)}" if m2 else line)
        elif line.startswith("new file mode"):
            out.append(line.replace("new file mode", "deleted file mode", 1))
        elif line.startswith("deleted file mode"):
            out.append(line.replace("deleted file mode", "new file mode", 1))
        elif line.startswith("+"):
            out.append("-" + line[1:])
        elif line.startswith("-"):
            out.append("+" + line[1:])
        else:
            out.append(line)
    return "".join(out)


def reference_patch(task_dir: Path, solve_sh: str) -> str:
    """The reference as a forward repository patch: a patch file in solution/, or a diff
    written inline by solve.sh (cat > fix.diff << 'EOF' ... EOF). "" when there is none."""
    sol = task_dir / "solution"
    f = next((sol / n for n in PATCH_NAMES if (sol / n).is_file()), None)
    if f is None:
        m = _EMBEDDED_DIFF.search(solve_sh)
        return m.group(2) if m else ""
    text = f.read_text(errors="replace")
    return reverse_patch(text) if _REVERSE_APPLY.search(solve_sh) else text


def _memory(env: dict) -> str | None:
    if env.get("memory_mb"):
        return f"{int(env['memory_mb'])}m"
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([KMGT]?)i?B?\s*", str(env.get("memory", "")), re.I)
    if not m:
        return None
    n, unit = float(m.group(1)), (m.group(2) or "M").upper()
    mb = n * {"K": 1 / 1024, "M": 1, "G": 1024, "T": 1024 * 1024}[unit]
    return f"{int(mb)}m"


_OFF = ("none", "no-network", "off", "disabled", "false")


def network_settings(cfg: dict) -> dict:
    """Whether each phase gets the network under the task's own Harbor config.

    Harbor's default (no setting) is network on. `allow_internet = false` or a
    network_mode of none/no-network turns it off; [agent] and [verifier] may set
    their own network_mode over [environment]'s."""
    env = cfg.get("environment", {}) or {}
    base_on = env.get("allow_internet") is not False and str(env.get("network_mode", "")).lower() not in _OFF
    out, declared = {}, []
    for phase in ("agent", "verifier"):
        sect = cfg.get(phase, {}) or {}
        mode = str(sect.get("network_mode", "")).lower()
        out[phase] = (mode not in _OFF) if mode else base_on
        if mode:
            declared.append(f"{phase}={mode}")
    if "allow_internet" in env:
        declared.append(f"allow_internet={env['allow_internet']}")
    if env.get("network_mode"):
        declared.append(f"environment={env['network_mode']}")
    out["declared"] = ", ".join(declared) or "not set (Harbor default: network on)"
    return out


_TEMPLATE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}")


def _envs(cfg: dict) -> tuple[dict, list]:
    out, unresolved = {}, []
    for key, sect in (("environment", cfg.get("environment", {})), ("solution", cfg.get("solution", {})),
                      ("verifier", cfg.get("verifier", {}))):
        vals = {}
        for k, v in ((sect or {}).get("env", {}) or {}).items():
            v = str(v)
            names = _TEMPLATE.findall(v)
            if names:
                # A value taken from the host (an API key, typically). The scanner supplies none.
                unresolved += [f"{key}.{k} (${{{n}}})" for n in names]
                continue
            vals[k] = v
        out[key] = vals
    return out, unresolved


def _build_tag(task_dir: Path) -> str:
    h = hashlib.sha256()
    ctx = task_dir / "environment"
    for f in sorted(ctx.rglob("*")):
        if f.is_file() and "__pycache__" not in f.parts:
            h.update(f.relative_to(ctx).as_posix().encode() + b"\0" + f.read_bytes() + b"\0")
    name = re.sub(r"[^a-z0-9_.-]+", "-", task_dir.name.lower()).strip("-.")[:100] or "task"
    return f"plumbline-scan/{name}:{h.hexdigest()[:12]}"


def load_task(task_dir: str | Path) -> Task:
    d = Path(task_dir).resolve()
    try:
        cfg = tomllib.loads((d / "task.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise TaskError(f"{d.name}: cannot read task.toml: {e}") from e
    env = cfg.get("environment", {}) or {}
    image, ctx = env.get("docker_image") or "", None
    if not image:
        if not (d / "environment" / "Dockerfile").is_file():
            raise TaskError(f"{d.name}: no environment.docker_image and no environment/Dockerfile")
        ctx, image = d / "environment", _build_tag(d)
    test_sh = d / "tests" / "test.sh"
    if not test_sh.is_file():
        raise TaskError(f"{d.name}: no tests/test.sh")
    solve = d / "solution" / "solve.sh"
    solve_sh = solve.read_text(errors="replace") if solve.is_file() else ""
    envs, unresolved = _envs(cfg)
    cpus = env.get("cpus")
    return Task(
        name=d.name,
        path=d,
        config=cfg,
        image=image,
        build_context=ctx,
        agent_timeout=float((cfg.get("agent", {}) or {}).get("timeout_sec") or DEFAULT_TIMEOUT),
        verifier_timeout=float((cfg.get("verifier", {}) or {}).get("timeout_sec") or DEFAULT_TIMEOUT),
        cpus=float(cpus) if cpus else None,
        memory=_memory(env),
        reference_patch=reference_patch(d, solve_sh),
        solve_sh=solve_sh,
        test_sh=test_sh.read_text(errors="replace"),
        instruction=(d / "instruction.md").read_text(errors="replace") if (d / "instruction.md").is_file() else "",
        network=network_settings(cfg),
        env=envs,
        unresolved_env=unresolved,
    )
