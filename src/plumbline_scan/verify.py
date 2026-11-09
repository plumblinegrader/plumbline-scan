"""`plumbline-scan verify`: check a signed Plumbline audit record, and optionally the files it covers.

    plumbline-scan verify record.json [--tasks TASKS_DIR] [--keys keys.json | URL] [--json]

The checking code is attestcore.py, a byte-for-byte copy of the one in plumbline-grader. The
signature check needs the `cryptography` package (pip install 'plumbline-scan[verify]'); nothing
else is added to the scanner. Exit 0: authentic, current and matching; 1: not; 2: input unreadable.
"""

from __future__ import annotations

import argparse
import json
import sys

from .attestcore import KEYSET_URL, AttestError, load_json_source, parse_time, report, verify


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="plumbline-scan verify",
                                description="Check a signed Plumbline audit record (in-toto statement in a DSSE "
                                            "envelope, Ed25519): who signed it, whether it is unchanged and "
                                            "current, and whether a folder holds exactly the audited files.")
    p.add_argument("envelope", help="the signed record (JSON)")
    p.add_argument("--tasks", default=None, help="a task-set folder, or one task's folder, to compare")
    p.add_argument("--keys", default=KEYSET_URL, help=f"Plumbline key list: file or https URL (default {KEYSET_URL})")
    p.add_argument("--json", action="store_true", help="print the verdict as JSON")
    p.add_argument("--now", default=None, help=argparse.SUPPRESS)
    a = p.parse_args(argv)
    try:
        env = load_json_source(a.envelope, "record")
        keys = load_json_source(a.keys, "key list")
        v = verify(env, keys, a.tasks, now=parse_time(a.now) if a.now else None)
    except AttestError as e:
        print(f"verify: {e}", file=sys.stderr)
        return 2
    print(json.dumps(v.to_json(), indent=1) if a.json else report(v))
    return 0 if v.ok else 1
