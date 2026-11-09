## Plumbline Scan (grader checks for Harbor-format tasks)

When asked to check, scan, lint or review a Harbor-format task (a folder with `task.toml`, `tests/`, `solution/`,
`environment/`), or whether a grader can be passed without doing the task:

1. Run `python3 ~/.codex/skills/plumbline-scan/scripts/run_scan.py <tasks path> --out plumbline-scan-out`
   (static checks PS-7 to PS-12: no Docker, no network). Add `--full` only if the user wants the Docker checks
   PS-1 to PS-6. Exit code 1 = a task was flagged (a result); exit code 3 = the scanner is missing (show the
   install line it prints).
2. Report the verdict counts and one line per FLAG or WARN with its fix, and keep the closing caveats.
3. Never call a task "safe" or "certified"; a static flag is a lead, not proof. Do not upload or send results.
