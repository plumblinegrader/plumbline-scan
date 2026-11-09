"""Stable check IDs, and for every finding: why it matters, how to fix it, and the evidence."""

from __future__ import annotations

from pathlib import Path

CHECK_IDS = {"reference": "PS-1", "empty": "PS-2", "leaked_answer": "PS-3", "stub": "PS-4",
             "editable_input": "PS-5", "network": "PS-6",
             "readable_answer": "PS-7", "mutable_program": "PS-8", "keyword_match": "PS-9",
             "mutable_measurement": "PS-10", "runtime_state": "PS-11",
             "loose_match": "PS-12"}
NAMES = {"reference": "Reference passes", "empty": "Empty solution fails", "leaked_answer": "No leaked answer",
         "stub": "Reference is not a stub", "editable_input": "Verifier does not trust editable inputs",
         "network": "Network dependence",
         "readable_answer": "Answer and verifier logic not readable by the agent",
         "mutable_program": "Grading independent of agent-changed programs",
         "keyword_match": "No keyword grading of agent-written files",
         "mutable_measurement": "Measurements outside the agent's reach",
         "runtime_state": "Verifier trusts no agent-controlled run-time state",
         "loose_match": "Short expected values matched exactly, not by substring"}
HELP_URI = "https://plumblinegrader.com/scan"

WHY = {
    "reference": "If the official solution does not earn full reward every time, the task cannot be shown to be "
                 "solvable, and agents that solve it correctly may be scored as failures.",
    "empty": "If doing nothing earns reward, the task pays agents for no work and inflates every score.",
    "leaked_answer": "An agent with a shell can copy the answer from the image instead of solving the task.",
    "stub": "A placeholder reference means nobody has shown the task can be solved or that the verifier "
            "accepts a correct answer.",
    "editable_input": "The verifier grades against a file the agent can rewrite, so changing the input can change "
                      "the score of the same answer.",
    "network": "Not a defect. Results can change when a download fails, a package moves or a server is down, "
               "and the task cannot run in a sealed sandbox.",
    "readable_answer": "If the expected outputs or the verifier's own logic sit where the agent can read them, an "
                       "agent with a shell can copy or hard-code the answer instead of solving the task.",
    "mutable_program": "If grading runs a program the agent could rewrite, the agent can make that program report "
                       "success without doing the work.",
    "keyword_match": "Grading that looks for words or a minimum length in a file the agent writes pays for writing "
                     "the words, not for doing the task.",
    "mutable_measurement": "If the score, timing or counter the grader trusts comes from a file inside the agent's "
                           "reach, the agent can write favourable numbers.",
    "runtime_state": "If the verifier imports code, sources a file or reads run-time state the agent can write, the "
                     "agent controls what the verifier does or sees.",
    "loose_match": "A short expected value checked by substring passes a wrong answer that contains it: \"$11628\" "
                   "passes for \"1628\", and almost any text with a 4 passes for \"4\".",
}

FIX = {
    ("reference", "FLAG"): "Run the oracle yourself (`harbor run -p <task> -a oracle`) and read the test.sh output "
                           "in the failing run's log (listed in scan.md). Usual causes: the solution and the tests disagree, a dependency is "
                           "missing from the image, the timeout is too short, or the verifier needs the network "
                           "while task.toml turns it off.",
    ("reference", "WARN"): "Find the test that fails only sometimes in the failing run's log; remove the "
                           "dependence on timing, ordering, randomness or the clock (fix seeds, wait on conditions "
                           "instead of sleeps), raise tight timeouts, then re-scan with `-k 10`.",
    ("empty", "FLAG"): "Make the tests exercise the behaviour the task asks for, and make test.sh write reward 1 "
                       "only when they pass: take the exit status of the test command itself (not of a later "
                       "`echo` or `cd`), and fail when no test ran.",
    ("empty", "WARN"): "Partial credit for no work: check which tests pass on the untouched environment and drop "
                       "or rewrite them, or give them no weight.",
    ("leaked_answer", "FLAG"): "Rebuild the image without the answer. For git history, after checking out the base "
                               "commit: `git for-each-ref --format='%(refname)' | grep -v \"^refs/heads/$(git "
                               "branch --show-current)$\" | xargs -r -n1 git update-ref -d && git stash clear && "
                               "git reflog expire --expire=now --all && git gc --prune=now`, and make sure the "
                               "base commit has no descendants (or re-create the repository: `rm -rf .git && git "
                               "init && git add -A && git commit -m base`). For a file: do not COPY it into the "
                               "image, or delete it in the same RUN step that creates it.",
    ("stub", "FLAG"): "Write a real solution in solution/solve.sh (or a patch it applies) that earns full reward "
                      "under the task's own verifier.",
    ("editable_input", "FLAG"): "Have test.sh restore the inputs before grading (e.g. `cp /tests/data/words.txt "
                                "/app/data/words.txt`), or compute expected values from a copy under /tests that "
                                "the agent never sees.",
    ("network", "NETWORK"): "If the task should run offline, install the verifier's tools in the Dockerfile "
                            "instead of in test.sh (pytest, uv, apt packages) and vendor any data it downloads. "
                            "If it must use the network, keep that declared in task.toml.",
    ("network", "WARN"): "The verifier names downloads but the scan could not confirm whether they are needed; "
                         "see PS-1 first.",
    ("readable_answer", "FLAG"): "Keep expected outputs and verifier code under /tests (mounted only at grading "
                                 "time); do not COPY them into the image or write them to the agent's working area. "
                                 "Compare against values the agent never sees.",
    ("mutable_program", "FLAG"): "Do not grade by running a program from the agent's area. Run the task's own "
                                 "independent checks, copy the program under /tests and run that copy, or verify the "
                                 "resulting behaviour rather than a self-reported exit code.",
    ("keyword_match", "FLAG"): "Grade behaviour, not text: run what the agent produced and check its effect, instead "
                               "of searching an agent-written file for keywords or a minimum length.",
    ("keyword_match", "WARN"): "test.sh text-matches an agent-written file; confirm the reward does not hinge on the "
                               "keyword and move the check to behaviour.",
    ("mutable_measurement", "FLAG"): "Measure inside the verifier (time it yourself, count from the real artifacts) "
                                     "instead of trusting a score or metric file the agent can write.",
    ("runtime_state", "FLAG"): "Do not import or source agent code, and do not add the agent's directories to "
                               "sys.path or PYTHONPATH. Read only state the verifier created under /tests, and "
                               "verify behaviour rather than trusting run-time files.",
    ("loose_match", "FLAG"): "Compare the value exactly or as a whole token: parse the number and compare it "
                             "(`float(x) == 1628`), split into tokens, or use a word-bounded pattern "
                             "(`re.search(r'(?<![\\d.])1628(?![\\d.])', out)`, `grep -w`).",
    ("loose_match", "WARN"): "Check what the haystack is: if it is free text, match the value as a whole number "
                             "or token; if it is a list, the check is already exact. For data-driven checks, "
                             "look at the task data for numbers and values of 3 characters or fewer.",
}
ERROR_FIX = "The check could not run; see the log. Common causes: the image did not build or pull, or Docker ran out of disk or memory."

# The file a finding points at, for SARIF and editors.
ANCHOR = {"reference": "solution/solve.sh", "empty": "tests/test.sh", "leaked_answer": "environment/Dockerfile",
          "stub": "solution/solve.sh", "editable_input": "tests/test.sh", "network": "tests/test.sh",
          "readable_answer": "tests/test.sh", "mutable_program": "tests/test.sh", "keyword_match": "tests/test.sh",
          "mutable_measurement": "tests/test.sh", "runtime_state": "tests/test.sh",
          "loose_match": "tests/test.sh"}
DETECTOR_EVIDENCE = {
    "readable_answer": ("env_answer_files", "grader_logic_in_image", "verifier_reads_expected"),
    "mutable_program": ("programs",),
    "keyword_match": ("python", "shell_text_reads"),
    "mutable_measurement": ("measurements",),
    "runtime_state": ("code_injection", "state_files"),
    "loose_match": ("hits",),
}


def fix_for(check: str, status: str) -> str:
    if status == "ERROR":
        return ERROR_FIX
    return FIX.get((check, status), "")


def anchor(rec: dict, check: str) -> str:
    rel = ANCHOR[check]
    if check == "leaked_answer" and not (Path(rec["path"]) / rel).exists():
        rel = "task.toml"  # a prebuilt docker_image
    return rel


def _excerpt(log: Path, marker: str = "== test.sh", lines: int = 12) -> str:
    if not log.is_file():
        return ""
    text = log.read_text(errors="replace")
    part = text.split(marker, 1)[1] if marker in text else text
    part = part.split("\n== result", 1)[0]
    return "\n".join([ln for ln in part.splitlines() if ln.strip()][-lines:])


def evidence(rec: dict, check: str, log_root: Path | None) -> dict:
    """Commands to reproduce, the log to read and a short excerpt of it."""
    ch = rec["checks"][check]
    det = ch.get("details", {}) or {}
    logs = (log_root / rec["task"]) if log_root else None
    image = rec.get("image", "<image>")
    ev: dict = {}
    if check in ("reference", "stub"):
        runs = det.get("runs") or []
        bad = next((r for r in runs if not r.get("full")), None)
        if bad and logs:
            ev["log"] = str(logs / f"{bad['label']}.log")
            ev["excerpt"] = _excerpt(logs / f"{bad['label']}.log")
        ev["command"] = f"harbor run -p {rec['path']} -a oracle"
        if check == "stub" and det.get("placeholder"):
            ev["excerpt"] = det["placeholder"]
    elif check == "empty":
        if logs:
            ev["log"] = str(logs / "empty.log")
            ev["excerpt"] = _excerpt(logs / "empty.log")
        ev["command"] = f"harbor run -p {rec['path']} -a nop"
    elif check == "leaked_answer":
        srcs = [s for p in det.get("probes", []) for s in p.get("flagged_sources", [])]
        ev["sources"] = srcs[:10]
        rec_ = det.get("recovered") or {}
        repo = next((p.get("repo") for p in det.get("probes", []) if p.get("repo")), "") or "/app"
        cmds = []
        if any(s.startswith("git") for s in srcs):
            cmds.append(f"docker run --rm --entrypoint sh {image} -c 'cd {repo} && git log --all --reflog --oneline "
                        f"--not HEAD | head'")
        if rec_.get("commit"):
            cmds.append(f"docker run --rm --entrypoint sh {image} -c 'cd {repo} && git show --stat {rec_['commit']}'")
        for s in srcs:
            if s.startswith("file:"):
                cmds.append(f"docker run --rm --entrypoint sh {image} -c 'ls -l {s[5:]}'")
                break
        ev["command"] = "\n".join(cmds)
        if logs and (logs / "recovered.diff").is_file():
            ev["recovered_diff"] = str(logs / "recovered.diff")
            ev["log"] = str(logs / "recovered-fix.log")
    elif check == "editable_input":
        ev["paths"] = det.get("flagged", [])
        ev["command"] = (f"docker run --rm --entrypoint sh {image} -c 'ls -l "
                         + " ".join(det.get("flagged", [])[:5]) + "'") if det.get("flagged") else ""
    elif check == "network":
        ev["downloads"] = det.get("markers", [])
        ev["declared"] = det.get("declared", "")
        if logs:
            for name in ("reference-sealed-confirm.log", "reference-1.log"):
                if (logs / name).is_file():
                    ev["log"] = str(logs / name)
                    ev["excerpt"] = _excerpt(logs / name)
                    break
    elif check in DETECTOR_EVIDENCE:
        # Static detectors: no container log; the evidence is the structural finding itself.
        for key in DETECTOR_EVIDENCE[check]:
            if det.get(key):
                ev[key] = det[key]
    return {k: v for k, v in ev.items() if v}


def annotate(records: list[dict], log_root: Path | None) -> None:
    """Add id, why, fix and evidence to every non-passing check, in place."""
    for rec in records:
        for c, ch in rec.get("checks", {}).items():
            ch["id"] = CHECK_IDS[c]
            if ch["status"] in ("PASS", "N/A"):
                continue
            ch["why"] = WHY[c]
            ch["fix"] = fix_for(c, ch["status"])
            ch["evidence"] = evidence(rec, c, log_root)
