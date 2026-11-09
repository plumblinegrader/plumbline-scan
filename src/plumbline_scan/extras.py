"""The optional extras: the deep-audit estimate, the scan badge, and the one opt-in network call
(--subscribe). Nothing here sends anything unless the user passed the flag."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path

from . import __version__
from .guidance import CHECK_IDS

API = os.environ.get("PLUMBLINE_SCAN_API", "https://plumblinegrader.com").rstrip("/")

# As published on plumblinegrader.com/pricing (read 2026-10-08). Update with the site.
PRICE_PER_TASK = 40
PRICE_MINIMUM = 1500
VOLUME_ABOVE = 1000
FREE_SAMPLE_TASKS = 20
SAMPLE_URL = "https://plumblinegrader.com/sample?src=scan"
PRICING_URL = "https://plumblinegrader.com/pricing?src=scan"


# -- --estimate ------------------------------------------------------------------------------

def estimate(tasks: list) -> str:
    """Task count, formats and the published price range for a deep audit. No Docker, no network."""
    n = len(tasks)
    kinds: dict[str, int] = {}
    for t in tasks:
        k = "Harbor, repository patch reference" if t.is_patch_task else "Harbor, script reference"
        kinds[k] = kinds.get(k, 0) + 1
    lines = [f"Tasks: {n}", "Formats: " + ", ".join(f"{k} ({v})" for k, v in sorted(kinds.items()))]
    if n == 0:
        return "\n".join(lines)
    price = max(n * PRICE_PER_TASK, PRICE_MINIMUM)
    if n > VOLUME_ABOVE:
        lines.append(f"Grader Audit (deep wrong-solution search) for {n:,} tasks: volume pricing above "
                     f"{VOLUME_ABOVE:,} tasks, at most ${price:,} at the list price of ${PRICE_PER_TASK} per task; "
                     f"request a quote: {PRICING_URL}")
    else:
        lines.append(f"Grader Audit (deep wrong-solution search) for {n:,} tasks: from ${price:,} "
                     f"(${PRICE_PER_TASK} per task, ${PRICE_MINIMUM:,} minimum); request a quote: {PRICING_URL}")
    lines.append(f"Free deep audit of up to {FREE_SAMPLE_TASKS} tasks: {SAMPLE_URL}")
    lines.append("Prices as published on plumblinegrader.com; every quote is fixed before work starts.")
    return "\n".join(lines)


# -- the badge -------------------------------------------------------------------------------

BADGE_LINK = "https://plumblinegrader.com/scan?src=badge"


def badge_eligible(records: list[dict]) -> tuple[bool, str]:
    if not records:
        return False, "no tasks scanned"
    bad = [r["task"] for r in records if r.get("verdict") in ("FLAGGED", "ERROR", "INCOMPLETE")]
    if bad:
        return False, f"{len(bad)} task(s) flagged or incomplete"
    skipped = {c for r in records for c in CHECK_IDS if c not in r.get("checks", {})}
    if skipped:
        return False, "some checks were skipped: " + ", ".join(sorted(CHECK_IDS[c] for c in skipped))
    return True, ""


def _svg(left: str, right: str, color: str = "#2e7d32") -> str:
    # Width from a fixed per-character estimate (Verdana 11px ~ 6.5px/char), as static badges do.
    lw, rw = int(len(left) * 6.5) + 12, int(len(right) * 6.5) + 12
    w = lw + rw
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" '
            f'aria-label="{left}: {right}"><title>{left}: {right}</title>'
            f'<rect width="{lw}" height="20" fill="#555"/><rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2}" y="14">{left}</text><text x="{lw + rw / 2}" y="14">{right}</text></g></svg>\n')


def write_badge(out_dir: Path, records: list[dict], date: str) -> tuple[Path | None, str]:
    ok, why = badge_eligible(records)
    if not ok:
        return None, f"badge not issued: {why}"
    svg = out_dir / "badge.svg"
    svg.write_text(_svg("Plumbline Scan", "PS-1 to PS-12 passed"))
    alt = f"Plumbline Scan: basic checks passed (PS-1 to PS-12, v{__version__}, {date}, {len(records)} tasks)"
    md = out_dir / "badge.md"
    md.write_text(f"[![{alt}](badge.svg)]({BADGE_LINK})\n")
    return md, f"badge: {md} (copy badge.svg next to your README)"


# -- the opt-in network call ----------------------------------------------------------------------

def _post(path: str, payload: dict, timeout: float = 10) -> tuple[bool, str]:
    req = urllib.request.Request(API + path, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json",
                                          "User-Agent": f"plumbline-scan/{__version__}"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300, f"HTTP {r.status}"
    except urllib.error.HTTPError as e:
        return False, f"HTTP {e.code}"
    except (urllib.error.URLError, OSError) as e:
        return False, str(getattr(e, "reason", e))[:120]


def subscribe(email: str, elapsed_ms: int) -> tuple[bool, str, dict]:
    """Sign up for new checks and Index releases: the email address only."""
    payload = {"kind": "notify", "email": email, "page": "plumbline-scan", "source": f"plumbline-scan {__version__}",
               "elapsed_ms": int(elapsed_ms)}
    ok, info = _post("/api/lead", payload)
    return ok, info, payload
