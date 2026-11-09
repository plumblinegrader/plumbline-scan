# Plumbline Scan

A free command-line checker for [Harbor](https://github.com/laude-institute/harbor)-format tasks.
Run it on your tasks before you publish them. It needs **Docker and the task directory, nothing else** (the static checks need only the directory):
no API keys, no models, no account.

```bash
pip install .            # from this directory; Python 3.11+, no runtime dependencies
plumbline-scan path/to/tasks/ -o scan-out
plumbline-scan path/to/tasks/ -o scan-out --static-only   # no Docker: PS-7 to PS-12 only, in seconds
```

`path/to/tasks/` is one task directory (with `task.toml`) or a directory of them. `pip install .` fetches the
build tool (setuptools) once; on a machine with no network, build a wheel elsewhere (`pip wheel . -w dist`) and
`pip install --no-index dist/plumbline_scan-*.whl`.

Use it from Claude Code, Cursor or Codex: see AGENT-SKILL.md.

## What it checks

| ID | Check | Flags the task when |
|---|---|---|
| PS-1 | **Reference passes** | the official solution (`solution/solve.sh`, run as Harbor's oracle agent) does not earn full reward in every one of k fresh containers (default k=3). Some passing runs → **WARN, flaky**. |
| PS-2 | **Empty fails** | the verifier alone, with no solution at all, earns full reward. Partial reward → WARN. |
| PS-3 | **Leaked answer** | the reference can be recovered inside the image: from git objects HEAD does not reach (branches, tags, reflog, stashes), dangling git objects, or any readable file or package-cache archive. When a git commit holds the fix, its diff is applied in a fresh container and graded, so the report says whether the copied answer earns full reward. |
| PS-4 | **Stub solution** | `solve.sh` is a placeholder (only `echo`/comments, e.g. `echo "no solution written"`), or the reference scores 0 in every run. |
| PS-5 | **Verifier trusts editable inputs** | (script references only) an absolute path the verifier names is a file that already exists, writable, before the agent acts, and `test.sh` does not restore it. Files the reference solution itself changes are outputs, not inputs, and are not flagged. The verifier may then grade against an input the agent can rewrite. |
| PS-6 | **Network dependence** | not a defect: the reference is run with the network off first; if it fails and the task's `task.toml` lets it have the network, the run is repeated with the network on. Passing only then is reported as **NETWORK**, not as a failure. |

PS-7 to PS-12 are **static structural checks**: they read the verifier (`tests/test.sh` and every file under
`tests/`), the reference (`solution/`) and the image build context (`environment/`), parse the Python verifier with
the `ast` module, and never run it. They need no Docker, no network and no model, so they report even where the
image cannot be built. Each flags a grader design that lets an agent earn full reward without doing the task.

| ID | Check | Flags the task when |
|---|---|---|
| PS-7 | **Answer/logic readable by the agent** | an expected-output file (named `expected`/`golden`/`oracle`/…) is baked into the image, the verifier's own logic ships in the image, or the verifier reads its expected outputs from a path the agent can read, found by file name or by use (content read into a variable named `expected…`/`golden…`/`correct…`). The agent can copy or hard-code the answer. **WARN** when held-out data the verifier scores a model on (`test`/`holdout`/`eval` file passed to `.score`, `accuracy_score`, …) sits in the agent's image. |
| PS-8 | **Grading runs an agent-changed program** | grading executes a program from the agent's area (a script under `/app`, `./build`, an installed binary under `/opt`), so the agent can make that program report success. Standard tools (`ps`, `pytest`, `python`, …), the verifier's own virtualenv and programs the verifier writes or copies in itself are not flagged. In a repository-patch task the repository's own test runner is reported, not flagged (see Limits). Also FLAG: a `shell=True` command taken from data the verifier parsed at grade time (an `Exec=` line from an agent-written file). **WARN**: a custom program run by bare name that the image installs under `/opt` or a `bin` directory the agent can write; or the program the task is about (`passwd`, `ssh`, `bash`, `nginx`, …, named in the instruction) run from the agent's image with no identity check, including one file run under two interpreters the instruction names. |
| PS-9 | **Keyword grading of agent files** | the reward depends on a substring, regex, `.count`/`.find`, or a minimum length over the text of a file the agent wrote, rather than on behaviour. Reads through `with open(p) as f`, loops over literal path lists and `inspect.getsource(<agent module>)` count. A key check on parsed JSON (`'k' in json.load(f)`) and a line or item count are not text matching and are not flagged. |
| PS-10 | **Measurement inside the agent's reach** | the grader reads a score, timing or counter (a `score`/`metrics`/`timing`/… file, or a metric field such as `accuracy` in a `results` file) from the agent's area and uses its numbers for the reward, so the agent can write favourable numbers. Also: every assertion compares a constant with what the agent's own imported object reports about itself (`trainer.get_results() == 1.0`), with nothing recomputed (FLAG; WARN when only some assertions do). |
| PS-11 | **Verifier trusts run-time agent state** | the verifier `exec`s or `importlib`-loads agent code, sources an agent-written shell/config file, or reads run-time config/state the agent can write (a `config`/`.env`/`manifest`/…). A plain `sys.path.insert` + `import` to test the solution is not flagged. **Reported as WARN, never FLAG** (see Limits). |
| PS-12 | **Short value matched by substring** | a short expected value (any number, or 3 characters or fewer) is checked by substring instead of an exact or whole-token match: `'42' in out`, `.find`/`assertIn`/unanchored `re.search`, `grep 42` without `-w`/`-x`, `strings.Contains`, `.toContain`, `.contains`, `.include?`. A wrong value that contains the right one passes ("11628" for "1628"). FLAG when the haystack is plainly text and the check is an assertion; WARN when its type is not visible or the expected value comes from task data. Membership in a list or a `.split()` result is exact and not flagged. |

Statuses: `PASS`, `FLAG` (a defect), `WARN` (worth a look), `NETWORK`, `N/A`, `ERROR` (the check could not run,
e.g. the image would not build). A task's verdict is `FLAGGED`, `WARN`, `OK` or `INCOMPLETE` (a check could not
run; always the case with `--static-only` unless a static check flags or warns). The exit code is 1 when any task
is flagged, else 0 (2 for a usage error, e.g. no tasks found or Docker unavailable).

## Output

Every finding carries its check ID, why it matters, **how to fix it**, and the evidence (a command to
reproduce it, the log to read).

* a table in the terminal, with one line per finding and its fix;
* `scan-out/scan.json`: every check, every run, every reward, the probe's evidence, the fix guidance;
* `scan-out/scan.md`: a one-page Markdown summary to attach to a release;
* `scan-out/scan.sarif`: SARIF 2.1.0 for GitHub code scanning (paths relative to `--sarif-root`, default `.`);
* `scan-out/badge.svg` and `badge.md`: only when every task passes every check (see below);
* `scan-out/logs/<task>/`: the output of each run (`solve.sh`, `test.sh`, probes) and any recovered diff.

## In CI: GitHub Action and pre-commit

```yaml
permissions: { contents: read, security-events: write }
steps:
  - uses: actions/checkout@v4
  - uses: plumblinegrader/plumbline-scan@v0.4.1   # action.yml at the root of this repository
    with:
      path: tasks
```

The action installs the scanner, scans, adds `scan.md` to the job summary, uploads `scan.sarif` to code scanning
and the whole report as an artifact, and fails the job when a task is flagged (`fail-on-findings: false` to keep
it advisory). See `examples/github-workflow.yml`. `.pre-commit-hooks.yaml` offers a fast hook that only loads and
validates the tasks; the full scan belongs in CI.

## Badge

When every task passes every check, the scan writes `badge.svg` and a README snippet in `badge.md`:
"Plumbline Scan: basic checks passed (PS-1 to PS-12, version, date, task count)". It is never issued when a task is
flagged or incomplete, or when a check was skipped.

## Checking a signed Plumbline record

Plumbline audits come with a signed record (an in-toto statement in a DSSE envelope, Ed25519). The scanner
checks one, offline, against the key list you choose:

```bash
pip install '.[verify]'     # adds the cryptography package, used only for this
plumbline-scan verify record.attestation.json --tasks path/to/tasks --keys plumbline-keys.json
```

It prints who signed the record, whether it is unchanged and current, and, with `--tasks`, whether the
folder (the whole set or one task) holds exactly the audited files, naming any that differ. Exit 0: valid;
1: not; 2: an input could not be read. Without `--keys` it fetches
`https://plumblineverified.com/.well-known/plumbline-keys.json`. Format and keys: `docs/attestation/` in the
Plumbline repository.

## Deep-audit estimate

`plumbline-scan tasks/ --estimate` prints the task count, the formats, and the price range for a deep
wrong-solution audit at the prices published on plumblinegrader.com. It loads the tasks only: no Docker, no
network.

## Privacy: nothing leaves your machine unless you ask

A scan talks to Docker (and to registries for image pulls) and nothing else. No scan result is ever sent
anywhere. One opt-in flag sends data to plumblinegrader.com, and prints exactly what it sends:

* `--subscribe you@company.com`: your email address only, to hear about new checks and Index releases. It can be
  run on its own: `plumbline-scan --subscribe you@company.com`.

## How it runs a task

Like Harbor's local Docker environment: each run is a fresh container of the task image (`environment.docker_image`,
or built from `environment/`), kept up with `sleep infinity`; `solution/` is copied to `/solution` and
`bash /solution/solve.sh` runs in the image's working directory, then `tests/` is copied to `/tests` and
`bash /tests/test.sh` runs; the reward is read from `/logs/verifier/reward.txt` or `reward.json`.
The task's `cpus`/`memory` and timeouts are applied. Env values that `task.toml` takes from the host (`${VAR}`) are
**not** supplied: a verifier that needs an API key will fail here, and the report lists the missing names.

## Options

```
-k N               reference runs per task (default 3)
-j N               tasks in parallel (default 1)
--network MODE     auto (default) | sealed (never) | on (always)
--skip a,b         skip checks: reference, empty, leaked_answer, stub, editable_input
--rm-images        remove images this scan pulled or built, after each task (never pre-existing ones)
--no-pull          use local images only
--no-limits        ignore the task's cpus/memory
--timeout-mult X   scale the task's timeouts
--sarif-root DIR   make SARIF paths relative to DIR (your repository root)
--static-only      run PS-7 to PS-12 only; no Docker, no network; never issues the badge
--estimate         task count, formats and deep-audit price range; no Docker
--no-badge         never write the badge
--subscribe EMAIL  opt in to updates (sends the email address only)
```

## Limits

* The checks are mechanical. A clean scan does not mean the tests are strong enough: a wrong solution may still
  pass them.
* The leaked-answer check looks for the reference's distinctive lines (12+ characters, absent from the repository at
  HEAD and from `instruction.md`). A reference too short or too generic to have such lines is reported `N/A`.
  For script references it also looks for the verifier's expected-output data; tasks that are *about* recovering
  data from git history are flagged by design.
* The editable-input check reads paths from the verifier's source text; it does not prove an edit changes a score.
* The static checks (PS-7 to PS-12) report a grader *shape*, not a proven exploit. Treat a flag as a lead to
  confirm by running the task.
* PS-11 reports **WARN, never FLAG**. We read the code behind 8 sampled PS-11 hits on public script tasks (the
  reading was done by an AI model): most were a config file that is itself the deliverable (the verifier is meant
  to read it), and 1 of the 8 was a real way to earn the reward. Trade-off: a PS-11 hit alone no longer fails the
  scan (exit code 1) or a CI job, and does not block the badge, even when the channel is real. Read the WARN
  lines and check whether behaviour is also tested.
* PS-10 reads only score/metric-named files and misses measurements the verifier takes of agent code.
* In a repository-patch task (SWE-bench style) the agent may edit the whole repository, so the repository's own
  test runner or CI script could always be rewritten. That holds for every such task, so PS-8 and PS-11 report it
  in the details instead of flagging it, and look only for programs and scripts outside the repository.
* A task whose reference needs the network, when `task.toml` turns the network off, is reported as failing (that
  is what Harbor would do too).

## Tests

```bash
pip install '.[test]'
pytest                 # unit tests, plus an end-to-end scan of synthetic toy tasks when Docker is available
```

The toy tasks in `tests/toy_tasks/` are synthetic and small (they build on `python:3.12-slim`).

## License

Apache-2.0 (see `LICENSE` and `NOTICE`).

---

These are mechanical checks. They do not search for wrong solutions that the tests accept, the failure behind about 4 in 10 testable coding tasks in our audits of 11 public task sets. Free 20-task deep audit: plumblinegrader.com/sample?src=scan
