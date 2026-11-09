# Plumbline Scan for coding agents

Ask your coding agent "scan these tasks" and it runs Plumbline Scan's 12 mechanical checks (PS-1 to PS-12) on
your Harbor-format tasks, then reports each flag with its fix. The agent runs the real scanner on your machine:
no model calls inside the scan, no account, nothing uploaded.

The skill bundles the scanner (pure Python, no runtime dependencies), so it works without a separate install.

## Install

**Claude Code, as a plugin** (from inside Claude Code):

```text
/plugin marketplace add plumblinegrader/plumbline-scan
/plugin install plumbline-scan@plumblinegrader
```

**Claude Code, as a skill** (from a clone of this repository):

```bash
python3 install_skill.py --agent claude        # this project only: .claude/skills/plumbline-scan/
python3 install_skill.py --agent claude-user   # all your projects: ~/.claude/skills/plumbline-scan/
```

**Cursor** (project rule, from a clone):

```bash
python3 install_skill.py --agent cursor --project path/to/your/project   # .cursor/rules/plumbline-scan.mdc
```

**Codex** (from a clone):

```bash
python3 install_skill.py --agent codex   # ~/.codex/skills/plumbline-scan/
```

If your Codex version does not load skills, paste `integrations/codex/AGENTS-snippet.md` into your `AGENTS.md`.

Add `--force` to replace an earlier install and `--no-bundle` to use a scanner you installed with pip instead.

Tested: the Claude Code skill layout and all three installers, by this repository's test suite (install, then scan
a fixture task). The Cursor rule and the Codex files follow those tools' published formats and have not yet been
tried inside Cursor or Codex.

## Use

Ask in plain words: "check the tasks in `tasks/` for grader problems", "can this verifier be passed without doing
the task?", "lint this task before I publish it". The agent:

1. finds the task folders (each has a `task.toml`);
2. runs the static checks (PS-7 to PS-12, seconds, no Docker); the Docker checks (PS-1 to PS-6) run only when you
   ask for them;
3. reports each FLAG or WARN with the check ID, what it found and how to fix it;
4. offers to apply a fix to the verifier and re-scan, and changes nothing unless you say so.

Run it without an agent:

```bash
python3 skills/plumbline-scan/scripts/run_scan.py path/to/tasks --out scan-out          # static checks
python3 skills/plumbline-scan/scripts/run_scan.py path/to/tasks --out scan-out --full   # + Docker checks
```

Exit codes: 0 no task flagged, 1 a task was flagged, 2 usage error, 3 scanner not found.

## What it does not do

The checks are mechanical. A clean scan does not show that the tests are strong enough: Scan does not search for
wrong solutions that the tests accept. The static checks report a grader shape, not a proven exploit, so treat
each flag as a lead to confirm by running the task. The full list of checks and limits is in the scanner's
README.

License: Apache-2.0, like the scanner.
