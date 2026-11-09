"""Leaked answer: can the reference solution be recovered from inside the task image?

"Key lines" are distinctive lines of the reference: the lines a reference patch
adds to non-test, non-prose files, or (for tasks whose reference is a script)
the lines of the solution files and of the verifier's expected-output data.
Lines the agent is given anyway (in instruction.md, or already in the
repository at HEAD) are dropped.

A probe, written in bash so it runs on images without Python, then looks for
those lines in a fresh, sealed container of the image:

  * git objects HEAD does not reach: other branches, tags, the reflog, stashes;
  * unreachable (dangling) git objects;
  * the single commit outside HEAD whose diff holds the most key lines;
  * any other readable file (caches, site-packages, backups), and gzip/zip archives in package caches.

A git source is flagged when it holds at least half the key lines; a plain file
needs 80% (or 50% when it has the name of a file the fix touches), since short
code lines recur in unrelated code. When a commit is flagged, its diff against
HEAD on the fix's files is applied in a fresh container and graded: if it earns
full reward, the answer can be copied from the image.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from .harbor import Task

MIN_KEY_LEN = 12
MAX_KEYS = 200
FLAG_FRACTION = 0.5
FILE_FRACTION = 0.8
MIN_KEYS_FOUND = 2
MAX_COMMITS = 40
KEYS_PATH = "/tmp/plumbline_scan_keys.txt"
PATHS_PATH = "/tmp/plumbline_scan_paths.txt"

_BORING = re.compile(r"^(?:[#/*\s]*|[\W_]+|(?:return|pass|else|break|continue|end|fi|done|esac)\W*)$", re.I)
_TEST_DIR = re.compile(r"(^|/)(tests?|testing|__tests__|spec|specs|testdata|test_data|fixtures)(/|$)", re.I)
_TEST_FILE = re.compile(r"(^|/)(test_[^/]*|[^/]*_test\.[a-z]+|[^/]*\.(test|spec)\.[a-z]+|[^/]*Tests?\.[a-z]+|conftest\.py)$")
_PROSE_EXT = (".rst", ".md", ".txt", ".adoc")
_PROSE_NAMES = ("changelog", "changes", "news", "history", "authors", "release_notes", "release-notes")


def is_test_path(path: str) -> bool:
    return bool(_TEST_DIR.search(path) or _TEST_FILE.search(path))


def is_prose(path: str) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    parts = [p.lower() for p in path.split("/")[:-1]]
    return (name.endswith(_PROSE_EXT) or name.split(".", 1)[0] in _PROSE_NAMES
            or any(p.startswith(("changelog", "changes", "news", "release-note", "release_note")) for p in parts))


def added_by_file(patch: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    cur = None
    for line in patch.splitlines():
        if line.startswith("+++ "):
            p = line[4:].strip().split("\t")[0]
            cur = None if p == "/dev/null" else (p[2:] if p.startswith("b/") else p)
            if cur is not None:
                out.setdefault(cur, [])
        elif line.startswith(("--- ", "diff --git")):
            continue
        elif cur is not None and line.startswith("+"):
            out[cur].append(line[1:])
    return out


def touched_paths(patch: str) -> list[str]:
    paths = set()
    for m in re.finditer(r"^diff --git a/(\S+) b/(\S+)", patch, re.M):
        paths.update((m.group(1), m.group(2)))
    return sorted(paths)


def fix_paths(patch: str) -> list[str]:
    return [p for p in touched_paths(patch) if not is_test_path(p) and not is_prose(p)]


def _distinct(lines, given: str, seen: set, min_len: int = MIN_KEY_LEN) -> list[str]:
    out = []
    for raw in lines:
        s = raw.strip().rstrip(",")
        if len(s) < min_len or not re.search(r"[A-Za-z0-9]", s) or _BORING.match(s) or s in seen or s in given:
            continue
        seen.add(s)
        out.append(s)
    return out


def _cap(keys: list[str]) -> list[str]:
    keys.sort(key=lambda k: (-len(k), k))  # longest first: the most distinctive survive the cap
    return keys[:MAX_KEYS]


def patch_keys(patch: str, instruction: str = "") -> list[str]:
    seen: set = set()
    keys = []
    for path, lines in added_by_file(patch).items():
        if not is_test_path(path) and not is_prose(path):
            keys += _distinct(lines, instruction, seen)
    return _cap(keys)


# Shell plumbing that says nothing about the answer.
_SHELL_BOILER = re.compile(r"^(#!|#|set -|cd |echo |printf |exit|source |\. |export |mkdir |cat\s*>|cat <<|EOF|PY\b|"
                           r"python3? |pip3? |uv |apt-get |chmod |rm |cp |mv |ls |\}|\{|then|else|fi\b|done\b|do\b)")


def given_lines(task: Task) -> set[str]:
    """Stripped lines of the files in environment/: inputs the agent is given in plain sight."""
    env = task.path / "environment"
    out: set[str] = set()
    for f in env.rglob("*") if env.is_dir() else []:
        if f.is_file() and f.stat().st_size < 5_000_000 and "__pycache__" not in f.parts:
            out.update(ln.strip().rstrip(",") for ln in f.read_text(errors="replace").splitlines())
    return out


def solution_keys(task: Task) -> list[str]:
    """Distinctive lines of the solution files (scripts and the code or data they write)."""
    sol = task.path / "solution"
    seen: set = given_lines(task)
    keys = []
    for f in sorted(sol.rglob("*")) if sol.is_dir() else []:
        if not f.is_file() or f.stat().st_size > 2_000_000 or "__pycache__" in f.parts:
            continue
        lines = [ln for ln in f.read_text(errors="replace").splitlines() if not _SHELL_BOILER.match(ln.strip())]
        keys += _distinct(lines, task.instruction, seen, min_len=16)
    return _cap(keys)


_DATA_EXT = (".json", ".txt", ".csv", ".tsv", ".yaml", ".yml", ".out", ".expected", ".ans", ".answer")


def expected_output_keys(task: Task) -> list[str]:
    """Distinctive lines of the verifier's data files (expected outputs, answer keys) in tests/.

    Lines also present in environment/ are inputs the agent is given (a tests/ copy of an
    input, or an expected file that is the input with a few lines changed); only the
    lines that differ can be an answer."""
    tests = task.path / "tests"
    seen: set = given_lines(task)
    keys = []
    for f in sorted(tests.rglob("*")) if tests.is_dir() else []:
        if not f.is_file() or f.suffix.lower() not in _DATA_EXT or f.stat().st_size > 2_000_000:
            continue
        keys += _distinct(f.read_text(errors="replace").splitlines(), task.instruction, seen, min_len=8)
    return _cap(keys)


PROBE_SH = r"""
set -u
K=__KEYS__; P=__PATHS__
T=$(mktemp -d /tmp/plumbline_scan_t.XXXXXX)
REPO=""
for d in "$PWD" /app /testbed /workspace /repo /src; do
  if [ -d "$d" ] && git -C "$d" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    REPO=$(git -C "$d" rev-parse --show-toplevel 2>/dev/null); break
  fi
done
echo "REPO=$REPO"
if [ -n "$REPO" ]; then cd "$REPO"; fi
# 1. Drop key lines already present anywhere in the tree at HEAD.
if [ -n "$REPO" ] && git rev-parse --verify -q HEAD >/dev/null 2>&1; then
  timeout 300 git grep -h -o -F -f "$K" HEAD -- . 2>/dev/null | sort -u > "$T/athead" || true
else
  : > "$T/athead"
fi
if [ -s "$T/athead" ]; then grep -v -x -F -f "$T/athead" "$K" > "$T/keys" || true; else cp "$K" "$T/keys"; fi
echo "KEYS_TOTAL=$(wc -l < "$K")"
echo "KEYS_AT_HEAD=$(wc -l < "$T/athead")"
echo "KEYS_EFFECTIVE=$(wc -l < "$T/keys")"
count() { grep -a -o -F -f "$T/keys" 2>/dev/null | sort -u | wc -l; }
if [ ! -s "$T/keys" ]; then echo "DONE=1"; exit 0; fi
if [ -n "$REPO" ] && git rev-parse --verify -q HEAD >/dev/null 2>&1; then
  echo "HEAD=$(git rev-parse HEAD)"
  # 2. Objects reachable from any ref or reflog entry (branches, tags, stashes) but not from HEAD.
  timeout 600 git rev-list --objects --all --reflog --not HEAD 2>/dev/null | cut -d' ' -f1 > "$T/ahead_objs"
  echo "AHEAD_COMMITS=$(timeout 300 git rev-list --all --reflog --not HEAD 2>/dev/null | wc -l)"
  echo "REFS_NOT_IN_HEAD=$(git for-each-ref --format='%(refname)' 2>/dev/null | while read r; do
      git merge-base --is-ancestor "$r" HEAD 2>/dev/null || printf '%s ' "$r"; done)"
  echo "STASHES=$(git stash list 2>/dev/null | wc -l)"
  n=$(timeout 600 git cat-file --batch < "$T/ahead_objs" 2>/dev/null | count)
  echo "SRC git_refs_not_in_head $n"
  # 3. Unreachable objects: dangling commits and blobs, loose or packed.
  timeout 600 git fsck --unreachable --no-reflogs --no-progress 2>/dev/null > "$T/fsck"
  awk '{print $3}' "$T/fsck" > "$T/unreach"
  echo "UNREACHABLE_OBJECTS=$(wc -l < "$T/unreach")"
  n=$(timeout 600 git cat-file --batch < "$T/unreach" 2>/dev/null | count)
  echo "SRC git_unreachable $n"
  # 4. The commit outside HEAD whose diff on the fix's files holds the most key lines.
  longest=$(head -1 "$T/keys")
  { timeout 300 git log --all --reflog --format=%H -S"$longest" --not HEAD -- $(cat "$P") 2>/dev/null
    awk '$2=="commit"{print $3}' "$T/fsck"; } | awk '!s[$0]++' | head -__MAXC__ > "$T/cands"
  best=""; bestn=0
  while read c; do
    n=$(timeout 120 git diff HEAD "$c" -- $(cat "$P") 2>/dev/null | grep '^+' | count)
    if [ "$n" -gt "$bestn" ]; then best=$c; bestn=$n; fi
  done < "$T/cands"
  echo "CANDIDATE_COMMITS=$(wc -l < "$T/cands")"
  echo "BEST_COMMIT=$best $bestn"
fi
# 5. Any other readable file (outside .git, /proc, /sys, /dev and the probe's own files).
timeout 900 find / -xdev \( -path /proc -o -path /sys -o -path /dev -o -path '*/.git' -o -path "$T" \) -prune \
  -o -type f -size -20M ! -name 'plumbline_scan_*' -print0 2>/dev/null \
  | timeout 900 xargs -0 grep -I -l -F -f "$T/keys" 2>/dev/null > "$T/files" || true
while read f; do
  n=$(count < "$f")
  echo "FILE $n $f"
done < "$T/files" | sort -k2,2nr | head -40
# 6. Compressed files in package caches (pip wheels, npm tarballs, go module zips).
for d in /root/.cache /root/.npm /root/go/pkg/mod/cache /home/*/.cache /home/*/.npm /usr/local/share/.cache /var/cache /tmp; do
  [ -d "$d" ] || continue
  timeout 600 find "$d" -type f -size -50M 2>/dev/null | head -5000 | while read f; do
    if gzip -t "$f" 2>/dev/null; then n=$(gzip -dc "$f" 2>/dev/null | count)
    elif command -v unzip >/dev/null 2>&1 && unzip -tqq "$f" >/dev/null 2>&1; then n=$(unzip -p "$f" 2>/dev/null | count)
    else continue; fi
    [ "$n" -gt 0 ] && echo "ARCHIVE $n $f"
  done
done | sort -k2,2nr | head -20
rm -rf "$T"
echo "DONE=1"
"""


def probe_script() -> str:
    return PROBE_SH.replace("__KEYS__", KEYS_PATH).replace("__PATHS__", PATHS_PATH).replace("__MAXC__", str(MAX_COMMITS))


@dataclass
class ProbeResult:
    basis: str = ""
    status: str = "CLEAN"  # LEAKED | CLEAN | NOT_TESTABLE | ERROR
    keys_total: int = 0
    keys_at_head: int = 0
    keys_effective: int = 0
    repo: str = ""
    sources: list = field(default_factory=list)  # [{source, found, fraction}]
    flagged_sources: list = field(default_factory=list)
    best_commit: str = ""
    best_commit_keys: int = 0
    git: dict = field(default_factory=dict)
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def parse_probe(output: str) -> ProbeResult:
    r = ProbeResult()
    kv: dict[str, str] = {}
    for line in output.splitlines():
        m = re.match(r"^([A-Z_]+)=(.*)$", line)
        if m:
            kv[m.group(1)] = m.group(2).strip()
            continue
        m = re.match(r"^SRC (\S+) (\d+)\s*$", line)
        if m:
            r.sources.append({"source": m.group(1), "found": int(m.group(2))})
            continue
        m = re.match(r"^(FILE|ARCHIVE) (\d+) (.+)$", line)
        if m:
            r.sources.append({"source": ("file:" if m.group(1) == "FILE" else "archive:") + m.group(3),
                              "found": int(m.group(2))})

    def num(k):
        try:
            return int(kv.get(k, "0").split()[0])
        except (ValueError, IndexError):
            return 0

    r.keys_total, r.keys_at_head, r.keys_effective = num("KEYS_TOTAL"), num("KEYS_AT_HEAD"), num("KEYS_EFFECTIVE")
    r.repo = kv.get("REPO", "")
    best = kv.get("BEST_COMMIT", "").split()
    if len(best) == 2:
        r.best_commit, r.best_commit_keys = best[0], int(best[1])
    r.git = {k.lower(): kv[k] for k in ("HEAD", "AHEAD_COMMITS", "REFS_NOT_IN_HEAD", "STASHES",
                                        "UNREACHABLE_OBJECTS", "CANDIDATE_COMMITS") if k in kv}
    if "refs_not_in_head" in r.git:
        refs = r.git["refs_not_in_head"].split()
        r.git["refs_not_in_head"] = " ".join(refs[:20]) + (" ..." if len(refs) > 20 else "")
        r.git["refs_not_in_head_count"] = len(refs)
    if "DONE" not in kv:
        r.status, r.note = "ERROR", "probe did not finish (timeout or shell error)"
    return r


def decide(r: ProbeResult, fix_names: tuple = ()) -> ProbeResult:
    if r.status == "ERROR" and not r.sources:
        return r
    if r.keys_effective == 0:
        r.status = "NOT_TESTABLE"
        r.note = r.note or (f"every distinctive line of the {r.basis} is already in the repository at HEAD"
                            if r.keys_total else f"no distinctive line in the {r.basis}")
        return r
    need = max(min(MIN_KEYS_FOUND, r.keys_effective), 1)
    for s in r.sources:
        s["fraction"] = round(s["found"] / r.keys_effective, 3)

    def bar(src: str) -> float:
        if src.startswith("file:") and src.rsplit("/", 1)[-1] in fix_names:
            return FLAG_FRACTION
        return FILE_FRACTION if src.startswith(("file:", "archive:")) else FLAG_FRACTION

    r.flagged_sources = [s["source"] for s in r.sources if s["found"] >= need and s["fraction"] >= bar(s["source"])]
    if r.best_commit and r.best_commit_keys >= need and r.best_commit_keys / r.keys_effective >= FLAG_FRACTION:
        r.flagged_sources.append("git_commit:" + r.best_commit)
    if r.status != "ERROR":
        r.status = "LEAKED" if r.flagged_sources else "CLEAN"
    return r


def key_sets(task: Task) -> list[tuple[str, list[str], list[str]]]:
    """[(basis, keys, paths for the commit search)]: the reference patch, or for a script
    reference, the solution files and the verifier's expected outputs."""
    if task.is_patch_task:
        paths = fix_paths(task.reference_patch) or touched_paths(task.reference_patch) or ["."]
        return [("reference patch", patch_keys(task.reference_patch, task.instruction), paths)]
    return [("solution files", solution_keys(task), ["."]),
            ("verifier's expected outputs", expected_output_keys(task), ["."])]


def file_names(paths: list[str]) -> tuple:
    return tuple(sorted({p.rsplit("/", 1)[-1] for p in paths if p != "."}))


def recovered_diff_script(repo: str, commit: str, paths: list[str]) -> str:
    import shlex

    q = " ".join(shlex.quote(p) for p in paths)
    return f"cd {shlex.quote(repo or '.')} && git diff --binary HEAD {shlex.quote(commit)} -- {q}\n"
