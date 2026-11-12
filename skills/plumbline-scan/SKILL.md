---
name: plumbline-scan
description: Check Harbor-format AI training or evaluation tasks for grader defects before they ship, using Plumbline Scan's 12 mechanical checks (PS-1 to PS-12). Use when the user asks to scan, lint, check or review a task, a verifier, a tests/test.sh, or a folder of tasks with task.toml files, or asks whether a task's grader can be passed without doing the task. Runs locally with no model calls, and no scan results are uploaded; the static checks run fully offline, and the Docker checks (--full) pull images and run tasks as their own network settings allow.
allowed-tools: Bash, Read, Grep, Glob
---

# Plumbline Scan

Plumbline Scan checks Harbor-format tasks (a folder with `task.toml`, `instruction.md`, `tests/`, `solution/`,
`environment/`) for grader designs that let an agent earn the reward without doing the task: a reference that
fails, an empty answer that passes, a leaked answer in the image, keyword grading of agent-written files, short
values matched by substring, and more. Every finding comes with a fix.

## Steps

1. **Find the tasks.** Use the path the user gave. Otherwise look for folders that contain `task.toml`
   (Glob `**/task.toml`). If there are none, say this skill checks Harbor-format tasks and stop.
2. **Run the scan** with the script in this skill's `scripts/` folder (use its absolute path):

   ```bash
   python3 <this skill's folder>/scripts/run_scan.py <tasks path> --out plumbline-scan-out
   ```

   This runs the static checks (PS-7 to PS-12) in seconds, with no Docker and no network. Add `--full` only
   when the user wants the Docker checks (PS-1 to PS-6: the reference passes, an empty answer fails, no leaked
   answer, no stub reference, editable inputs, network); they build each task's image and take minutes per task.
   Exit code 1 means at least one task was flagged; that is a result, not an error. Exit code 3 means the scanner
   is missing: show the user the install line the script prints and stop.
3. **Report** what the script printed: the verdict counts, then one line per FLAG or WARN with the task, the check
   ID, what it found and how to fix it. Keep the three closing caveats. If the user wants detail, read
   `plumbline-scan-out/scan.md` or the task's entry in `scan.json`.
4. **Offer the fix, do not apply it unasked.** If the user wants, edit the task's verifier to follow the fix line
   (for example, compare a value exactly instead of by substring), then re-run step 2 on that task to show the
   flag is gone.

## Rules

- Never call a task "safe", "secure" or "certified". Say which checks passed. A clean scan does not show the tests
  are strong enough: Scan does not search for wrong solutions that the tests accept.
- A static flag (PS-7 to PS-12) is a lead, not proof. Say so when you report one.
- `INCOMPLETE` after a static-only run is expected: the Docker checks did not run.
- Do not upload, post or send scan results anywhere. The scan itself sends nothing.
