"""Terminal table, JSON and a one-page Markdown summary."""

from __future__ import annotations

import json
from pathlib import Path

from . import __version__
from .checks import ALL_CHECKS
from .guidance import CHECK_IDS

# The audit figure is from docs/scanner-plan.md; check it against the published audit before release.
AUDIT_FIGURE = "the failure behind about 4 in 10 testable coding tasks in our audits of 11 public task sets"
FOOTER = ("These are mechanical checks. They do not search for wrong solutions that the tests accept, "
          f"{AUDIT_FIGURE}. Free 20-task deep audit: plumblinegrader.com/sample?src=scan")

TITLES = {"reference": "Reference", "empty": "Empty", "leaked_answer": "Leak", "stub": "Stub",
          "editable_input": "Inputs", "network": "Network",
          "readable_answer": "Readable", "mutable_program": "Programs", "keyword_match": "Keyword",
          "mutable_measurement": "Metrics", "runtime_state": "RunState",
          "loose_match": "Loose"}
LONG = {"reference": "Reference passes", "empty": "Empty solution fails", "leaked_answer": "Leaked answer",
        "stub": "Stub solution", "editable_input": "Verifier trusts editable inputs", "network": "Network dependence",
        "readable_answer": "Answer/logic readable by the agent", "mutable_program": "Grading runs agent-changed programs",
        "keyword_match": "Keyword grading of agent files", "mutable_measurement": "Measurements inside the agent's reach",
        "runtime_state": "Verifier trusts run-time agent state",
        "loose_match": "Short value matched by substring"}


def _cell(rec: dict, c: str) -> str:
    ch = rec["checks"].get(c)
    if not ch:
        return "-"
    if c == "reference" and ch["status"] in ("PASS", "WARN", "FLAG") and ch.get("details", {}).get("graded"):
        d = ch["details"]
        return f"{ch['status']} {d['passes']}/{d['graded']}"
    return ch["status"]


def table(records: list[dict]) -> str:
    head = ["Task", *[TITLES[c] for c in ALL_CHECKS], "Verdict", "Time"]
    rows = [[r["task"][:48], *[_cell(r, c) for c in ALL_CHECKS], r.get("verdict", ""), _dur(r.get("seconds", 0))]
            for r in records]
    w = [max(len(str(x)) for x in col) for col in zip(head, *rows)]
    line = lambda xs: "  ".join(str(x).ljust(n) for x, n in zip(xs, w)).rstrip()
    out = [line(head), line(["-" * n for n in w]), *map(line, rows)]
    notes = []
    for r in records:
        for c in ALL_CHECKS:
            ch = r["checks"].get(c)
            if ch and ch["status"] not in ("PASS", "N/A"):
                notes.append(f"  {r['task'][:48]}  {CHECK_IDS[c]} {TITLES[c]}: {ch['status']}: {ch['summary']}")
                if ch.get("fix"):
                    notes.append(f"      fix: {ch['fix']}")
    if notes:
        out += ["", "Findings:", *notes]
    return "\n".join(out)


def _dur(s: float) -> str:
    s = int(s or 0)
    return f"{s // 60}m{s % 60:02d}s" if s >= 60 else f"{s}s"


def markdown(records: list[dict], meta: dict) -> str:
    n = len(records)
    flagged = [r for r in records if r.get("verdict") == "FLAGGED"]
    lines = [
        "# Plumbline Scan report", "",
        f"{n} task{'s' if n != 1 else ''} scanned on {meta['date']} with plumbline-scan {__version__} "
        + (f"({meta['mode']})." if meta.get("mode") else
           f"(reference runs k={meta['k']}, network mode: {meta['network']})."), "",
        f"**{len(flagged)} flagged**, "
        f"{sum(r.get('verdict') == 'WARN' for r in records)} with warnings, "
        f"{sum(r.get('verdict') == 'OK' for r in records)} OK, "
        f"{sum(r.get('verdict') in ('INCOMPLETE', 'ERROR') for r in records)} incomplete.", "",
        "| Check | Flagged | Warn | Network | Pass | N/A | Error |", "|---|---|---|---|---|---|---|",
    ]
    for c in ALL_CHECKS:
        cnt = {s: sum(r["checks"].get(c, {}).get("status") == s for r in records)
               for s in ("FLAG", "WARN", "NETWORK", "PASS", "N/A", "ERROR")}
        lines.append(f"| {CHECK_IDS[c]} {LONG[c]} | {cnt['FLAG']} | {cnt['WARN']} | {cnt['NETWORK']} | {cnt['PASS']} | "
                     f"{cnt['N/A']} | {cnt['ERROR']} |")
    lines += ["", "## Tasks", "", "| Task | " + " | ".join(TITLES[c] for c in ALL_CHECKS) + " | Verdict | Time |",
              "|---|" + "---|" * (len(ALL_CHECKS) + 2)]
    for r in records:
        lines.append(f"| {r['task']} | " + " | ".join(_cell(r, c) for c in ALL_CHECKS)
                     + f" | {r.get('verdict', '')} | {_dur(r.get('seconds', 0))} |")
    found = [(r, c, r["checks"][c]) for r in records for c in ALL_CHECKS
             if c in r["checks"] and r["checks"][c]["status"] not in ("PASS", "N/A")]
    if found:
        lines += ["", "## Findings", ""]
        for r, c, ch in found:
            lines.append(f"- **{r['task']}** · {CHECK_IDS[c]} {LONG[c]} · {ch['status']}: {ch['summary']}")
            if ch.get("why"):
                lines.append(f"  - Why it matters: {ch['why']}")
            if ch.get("fix"):
                lines.append(f"  - How to fix: {ch['fix']}")
            ev = ch.get("evidence") or {}
            if ev.get("command"):
                lines.append("  - Reproduce: " + "; ".join(f"`{x}`" for x in ev["command"].splitlines()))
            if ev.get("log"):
                lines.append(f"  - Log: `{ev['log']}`")
    times = [r["seconds"] for r in records if r.get("seconds")]
    if times:
        lines += ["", f"Scan time per task: median {_dur(sorted(times)[len(times) // 2])}, "
                      f"max {_dur(max(times))} (image pull or build included)."]
    lines += ["", "Nothing from this scan was sent anywhere."]
    lines += ["", "Statuses: PASS; FLAG (a defect); WARN (worth a look); NETWORK (needs the network, marked, "
                  "not failed); N/A; ERROR (the check could not run).", "", FOOTER, ""]
    return "\n".join(lines)


def write(out_dir: Path, records: list[dict], meta: dict) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    j = out_dir / "scan.json"
    j.write_text(json.dumps({"tool": "plumbline-scan", "version": __version__, **meta, "tasks": records},
                            indent=2, sort_keys=False) + "\n")
    m = out_dir / "scan.md"
    m.write_text(markdown(records, meta))
    return j, m


def write_sarif(out_dir: Path, records: list[dict], root: Path) -> Path:
    from . import sarif

    p = out_dir / "scan.sarif"
    p.write_text(json.dumps(sarif.build(records, root), indent=2) + "\n")
    return p
