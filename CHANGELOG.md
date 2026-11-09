# Changelog

## 0.4.1 (first public release, November 10, 2026)

Recall fixes to the static checks, from the miss backlog (shapes a check should have caught and did not):

- PS-7 also finds an answer by how it is used (`expected_key = f.read()`); WARN for held-out scoring data in the
  agent's image.
- PS-8 flags a `shell=True` command taken from data parsed at grade time; WARN for custom programs found through
  PATH in agent-writable directories, and for the program a task is about run with no identity check.
- PS-9 follows `with open(p) as f`, loops over literal path lists and `inspect.getsource`; it no longer counts a
  key check on parsed JSON or a line count as text matching.
- PS-10 flags metrics the agent's own object reports about itself; a `results` file counts only for a metric field.

## 0.4.0 (private preview, October 2026)

Twelve checks: PS-1 to PS-6 run the task in Docker; PS-7 to PS-12 read the grader's files only.

- New `--static-only`: runs PS-7 to PS-12 with no Docker and no network. Tasks scanned this way are reported
  `INCOMPLETE` (never `OK`) and never get the badge.
- PS-11 (verifier trusts run-time agent state) reports `WARN`, never `FLAG`: most of its hits on public tasks
  were a config file that is itself the deliverable. A PS-11 hit alone no longer fails the scan or a CI job.
- Fewer false flags in the static checks:
  - a program the verifier writes or copies in itself is not "agent-changed" (PS-8);
  - heredoc bodies and multi-line quoted text are data, not shell commands; `\`-continued lines are one
    command (PS-8, PS-9, PS-11);
  - in a repository-patch task, the repository's own test runner or CI script is reported in the details, not
    flagged: the agent may edit the whole repository in every such task (PS-8, PS-11);
  - a verifier that reads, edits and rewrites its own harness file in one function is not keyword grading;
    `go test ./...` is not a file; an upper size cap is not a minimum length (PS-9);
  - only files the final image stage copies in count as baked into the image (PS-7).
- Removed `--share-stats`. No scan result is ever sent anywhere; `--subscribe` (email only, opt-in) remains.
- Help text covers all twelve checks; README documents offline install from a wheel.

## 0.3.0

PS-12 (short value matched by substring).

## 0.2.0

PS-7 to PS-11, static checks.

## 0.1.0

PS-1 to PS-6.
