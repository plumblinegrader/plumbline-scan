"""Plumbline audit attestations: the verifier core (spec: docs/attestation/SPEC.md).

Standard library only, plus the `cryptography` package for the Ed25519 check, imported
when a signature is checked. This file is copied byte for byte into the standalone scanner
(tools/plumbline-scan/src/plumbline_scan/attestcore.py); tests/test_attest.py fails if the
two copies differ. Edit this one and copy it.

    manifest(dir)                       -> Manifest (files, per-task digests, set digest)
    pae(type, body)                     -> DSSE pre-authentication encoding
    verify(envelope, keyset, tasks_dir) -> Verdict with one Check per question
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://plumblinegrader.com/attestation/audit/v1"
PAYLOAD_TYPE = "application/vnd.in-toto+json"
MANIFEST_FORMAT = "plumbline-manifest-v1"
KEYSET_TYPE = "https://plumblinegrader.com/attestation/keys/v1"
KEYSET_URL = "https://plumblineverified.com/.well-known/plumbline-keys.json"
AUDIT_KINDS = ("test-suite-audit", "repair", "ai-judge-audit", "scan", "certification")

# The date forms both verifiers accept (a bare date is 00:00 UTC; no offset means UTC).
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}(:\d{2}(\.\d{1,6})?)?(Z|[+-]\d{2}:\d{2})?)?$")

# Left out of every manifest: version-control and operating-system clutter, Python caches.
SKIP_DIRS = frozenset({".git", "__MACOSX", "__pycache__"})
SKIP_FILES = frozenset({".DS_Store", "Thumbs.db", "desktop.ini"})


class AttestError(Exception):
    """A malformed input: a folder that cannot be manifested, an unreadable envelope or key set."""


# -- manifest ----------------------------------------------------------------------------

@dataclass(frozen=True)
class FileEntry:
    path: str  # relative, "/"-separated, NFC
    size: int
    sha256: str

    def line(self) -> str:
        return f"{self.sha256} {self.size} {self.path}\n"


@dataclass
class Manifest:
    files: list[FileEntry]

    @property
    def digest(self) -> str:
        return digest_lines(self.files)

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)

    def canonical(self) -> str:
        return "".join(f.line() for f in self.files)

    def tasks(self) -> dict[str, str]:
        """Task name (top-level folder) -> digest of its files, paths relative to the task folder."""
        groups: dict[str, list[FileEntry]] = {}
        for f in self.files:
            if "/" in f.path:
                top, rest = f.path.split("/", 1)
                groups.setdefault(top, []).append(FileEntry(rest, f.size, f.sha256))
        return {name: digest_lines(sort_entries(fs)) for name, fs in sorted(groups.items(), key=lambda kv: kv[0].encode())}


def sort_entries(entries: list[FileEntry]) -> list[FileEntry]:
    return sorted(entries, key=lambda f: f.path.encode("utf-8"))


def digest_lines(entries: list[FileEntry]) -> str:
    return hashlib.sha256("".join(f.line() for f in entries).encode("utf-8")).hexdigest()


def check_name(name: str, where: str) -> str:
    """One path component, NFC-normalized; refuses names the text format or other systems can't carry."""
    n = unicodedata.normalize("NFC", name)
    if n in ("", ".", "..") or "/" in n or "\\" in n or any(ord(c) < 0x20 or ord(c) == 0x7F for c in n):
        raise AttestError(f"unsupported file name {name!r} in {where or '.'}")
    return n


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(root: str | Path) -> Manifest:
    """Every regular file under root, bytes as they are (no line-ending or encoding changes).
    Symbolic links are refused, so the manifest means the same thing on every machine."""
    root = Path(root)
    if not root.is_dir():
        raise AttestError(f"not a folder: {root}")
    out: list[FileEntry] = []
    seen: dict[str, str] = {}

    def walk(d: Path, rel: str) -> None:
        with os.scandir(d) as it:
            items = sorted(it, key=lambda e: e.name)
        for e in items:
            st = os.lstat(e.path)
            if stat.S_ISLNK(st.st_mode):
                raise AttestError(f"symbolic link not allowed: {rel + e.name}")
            if stat.S_ISDIR(st.st_mode):
                if e.name in SKIP_DIRS:
                    continue
                walk(Path(e.path), rel + check_name(e.name, rel) + "/")
            elif stat.S_ISREG(st.st_mode):
                if e.name in SKIP_FILES:
                    continue
                path = rel + check_name(e.name, rel)
                folded = path.lower()
                if folded in seen:
                    raise AttestError(f"two paths differ only in letter case: {seen[folded]} and {path}")
                seen[folded] = path
                out.append(FileEntry(path, st.st_size, _sha256_file(Path(e.path))))
            else:
                raise AttestError(f"not a regular file: {rel + e.name}")

    walk(root, "")
    return Manifest(sort_entries(out))


def diff_files(expected: list[dict], actual: Manifest) -> dict[str, list[str]]:
    """Compare a recorded file list with a folder's manifest: changed, missing, added paths."""
    exp = {f["path"]: (f["size"], f["sha256"]) for f in expected}
    act = {f.path: (f.size, f.sha256) for f in actual.files}
    return {"changed": sorted(p for p in exp if p in act and exp[p] != act[p]),
            "missing": sorted(p for p in exp if p not in act),
            "added": sorted(p for p in act if p not in exp)}


# -- DSSE --------------------------------------------------------------------------------

def pae(payload_type: str, body: bytes) -> bytes:
    """DSSE v1 pre-authentication encoding: the exact bytes that are signed."""
    t = payload_type.encode("utf-8")
    return b"DSSEv1 %d %s %d %s" % (len(t), t, len(body), body)


def b64decode(s: str) -> bytes:
    """Standard or URL-safe base64, padding optional (DSSE allows either)."""
    if not isinstance(s, str):
        raise AttestError("expected a base64 string")
    s = s.strip().replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)
    except ValueError as e:
        raise AttestError(f"bad base64: {e}") from None


def keyid_of(raw_public_key: bytes) -> str:
    """A key's id: lowercase hex SHA-256 of its 32 raw Ed25519 public-key bytes."""
    return hashlib.sha256(raw_public_key).hexdigest()


def ed25519_verify(public_key: bytes, signature: bytes, message: bytes) -> bool:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        raise AttestError("checking a signature needs the 'cryptography' package: pip install cryptography") from None
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# -- key set -----------------------------------------------------------------------------

def parse_time(s) -> dt.datetime | None:
    """RFC 3339 date-time (or a bare date, read as 00:00 UTC) -> aware UTC datetime."""
    if s in (None, ""):
        return None
    if not isinstance(s, str) or not DATE_RE.match(s):
        raise AttestError(f"not an RFC 3339 date: {s!r}")
    try:
        t = dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        raise AttestError(f"not an RFC 3339 date: {s!r}") from None
    if t.tzinfo is None:
        t = t.replace(tzinfo=dt.timezone.utc)
    return t.astimezone(dt.timezone.utc)


def load_json_source(src: str, what: str, timeout: float = 15.0) -> dict:
    """A JSON file path, or an https:// URL (fetched with the standard library)."""
    if src.startswith("https://") or src.startswith("http://"):
        if not src.startswith("https://"):
            raise AttestError(f"{what}: only https:// URLs are accepted")
        import urllib.request
        req = urllib.request.Request(src, headers={"Accept": "application/json", "User-Agent": "plumbline-attest"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                data = r.read(4 << 20)
        except OSError as e:
            raise AttestError(f"{what}: could not fetch {src}: {e}") from None
    else:
        try:
            data = Path(src).read_bytes()
        except OSError as e:
            raise AttestError(f"{what}: could not read {src}: {e.strerror}") from None
    try:
        return json.loads(data)
    except ValueError as e:
        raise AttestError(f"{what}: not JSON ({e})") from None


def keyset_index(keyset: dict) -> tuple[dict[str, dict], list[str]]:
    """keyid -> key entry, for well-formed entries; problems with the others."""
    if not isinstance(keyset, dict) or keyset.get("keysetVersion") != KEYSET_TYPE:
        raise AttestError(f"not a Plumbline key set (keysetVersion must be {KEYSET_TYPE})")
    keys, problems = {}, []
    for i, k in enumerate(keyset.get("keys") or []):
        try:
            if k.get("algorithm") != "ed25519":
                raise AttestError(f"algorithm {k.get('algorithm')!r} is not ed25519")
            raw = b64decode(k.get("publicKey", ""))
            if len(raw) != 32:
                raise AttestError("public key is not 32 bytes")
            if keyid_of(raw) != k.get("keyid"):
                raise AttestError("keyid is not the SHA-256 of the public key")
            parse_time(k.get("validFrom")), parse_time(k.get("validUntil"))
            keys[k["keyid"]] = {**k, "_raw": raw}
        except (AttestError, AttributeError) as e:
            problems.append(f"key entry {i} ignored: {e}")
    return keys, problems


# -- verdict -----------------------------------------------------------------------------

@dataclass
class Check:
    name: str
    ok: bool | None  # None: not checked
    detail: str


@dataclass
class Verdict:
    checks: list[Check] = field(default_factory=list)
    statement: dict | None = None
    key: dict | None = None
    demo: bool = False
    expired: bool = False

    def add(self, name: str, ok: bool | None, detail: str) -> bool | None:
        self.checks.append(Check(name, ok, detail))
        return ok

    @property
    def ok(self) -> bool:
        """Authentic, untampered, current, and the files match when they were checked."""
        return bool(self.checks) and all(c.ok is not False for c in self.checks)

    @property
    def code(self) -> str:
        """One word for the outcome; the browser verifier returns the same codes."""
        failed = [c.name for c in self.checks if c.ok is False]
        if not failed:
            return "VALID"
        order = ("envelope", "signature", "key", "statement", "files", "current")
        return {"envelope": "MALFORMED", "signature": "BAD_SIGNATURE", "key": "KEY_NOT_ACCEPTED",
                "statement": "MALFORMED", "files": "FILES_DIFFER", "current": "EXPIRED"}[
            min(failed, key=order.index)]

    def to_json(self) -> dict:
        p = _d(_d(self.statement).get("predicate"))
        return {"code": self.code, "ok": self.ok, "demo": self.demo, "expired": self.expired,
                "keyid": (self.key or {}).get("keyid"), "kind": _d(p.get("audit")).get("kind"),
                "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks]}


def _d(x) -> dict:
    """x if it is a JSON object, else {} (records are read defensively; both verifiers do the same)."""
    return x if isinstance(x, dict) else {}


def _s(x) -> str:
    return x if isinstance(x, str) else ""


def _subjects(statement: dict) -> tuple[dict | None, dict[str, str]]:
    """The task-set subject and task name -> digest for the per-task subjects."""
    subs = [s for s in statement.get("subject") or [] if isinstance(s, dict)] \
        if isinstance(statement.get("subject"), list) else []
    tset = next((s for s in subs if _d(s.get("annotations")).get("plumbline.kind") == "task-set"), None)
    tasks = {}
    if tset:
        prefix = _s(tset.get("name")) + "/"
        for s in subs:
            if _d(s.get("annotations")).get("plumbline.kind") == "task" and _s(s.get("name")).startswith(prefix):
                tasks[s["name"][len(prefix):]] = _s(_d(s.get("digest")).get("sha256"))
    return tset, tasks


def check_statement(st: dict) -> list[str]:
    """What is missing or wrong in a statement, in plain words (empty: well formed)."""
    errs = []
    if st.get("_type") != STATEMENT_TYPE:
        errs.append(f"_type is not {STATEMENT_TYPE}")
    if st.get("predicateType") != PREDICATE_TYPE:
        errs.append(f"predicateType is not {PREDICATE_TYPE}")
    tset, _ = _subjects(st)
    if not tset or len(_s(_d(tset.get("digest")).get("sha256"))) != 64:
        errs.append("no task-set subject with a sha256 digest")
    p = st.get("predicate")
    if not isinstance(p, dict):
        return errs + ["no predicate"]
    kind = _d(p.get("audit")).get("kind")
    if kind not in AUDIT_KINDS:
        errs.append(f"audit kind {kind!r} is not one of {', '.join(AUDIT_KINDS)}")
    if kind == "certification" and not _d(p.get("audit")).get("criteria"):
        errs.append("a certification must name its criteria")
    for k in ("issuer", "method", "tool", "dates", "sample", "results"):
        if k not in p:
            errs.append(f"predicate.{k} is missing")
    d = _d(p.get("dates"))
    for k in ("issued", "validUntil"):
        try:
            if parse_time(d.get(k)) is None:
                errs.append(f"predicate.dates.{k} is missing")
        except AttestError as e:
            errs.append(f"predicate.dates.{k}: {e}")
    if not isinstance(p.get("demo", False), bool):
        errs.append("predicate.demo must be true or false")
    return errs


def verify(envelope: dict, keyset: dict, tasks_dir: str | Path | None = None,
           now: dt.datetime | None = None) -> Verdict:
    """Answer, in order: is the envelope readable; did a key in the key set sign it; is that
    key acceptable for the record's date; is the statement a Plumbline audit record; do the
    files match (when a folder is given); is the record still current."""
    now = now or dt.datetime.now(dt.timezone.utc)
    v = Verdict()

    # 1. envelope
    try:
        if not isinstance(envelope, dict):
            raise AttestError("not a JSON object")
        if envelope.get("payloadType") != PAYLOAD_TYPE:
            raise AttestError(f"payloadType is not {PAYLOAD_TYPE}")
        body = b64decode(envelope.get("payload", ""))
        sigs = envelope.get("signatures")
        if not isinstance(sigs, list) or not sigs:
            raise AttestError("no signatures")
        statement = json.loads(body)
        if not isinstance(statement, dict):
            raise AttestError("payload is not a JSON object")
    except (AttestError, ValueError) as e:
        v.add("envelope", False, f"Not a readable DSSE envelope: {e}")
        return v
    v.add("envelope", True, "Readable DSSE envelope carrying an in-toto statement.")

    # 2. signature
    try:
        keys, problems = keyset_index(keyset)
    except AttestError as e:
        v.add("signature", False, f"The key list could not be used: {e}")
        return v
    message = pae(PAYLOAD_TYPE, body)
    signer, unknown = None, []
    for s in sigs:
        k = keys.get(_s(s.get("keyid"))) if isinstance(s, dict) else None
        if k is None:
            unknown.append(str((s or {}).get("keyid", "?") if isinstance(s, dict) else "?"))
            continue
        try:
            good = ed25519_verify(k["_raw"], b64decode(s.get("sig", "")), message)
        except AttestError as e:
            if "cryptography" in str(e):
                raise
            good = False
        if good:
            signer = k
            break
    if signer is None:
        if unknown and len(unknown) == len(sigs):
            detail = ("Signed by a key that is not in the Plumbline key list "
                      f"(key id {unknown[0][:16]}…). It was not issued with a Plumbline key.")
        else:
            detail = "The signature does not match the contents. The record was altered after signing, or forged."
        v.add("signature", False, detail + ("" if not problems else " " + "; ".join(problems)))
        return v
    v.key = {k: val for k, val in signer.items() if k != "_raw"}
    v.statement = statement
    label = signer.get("label") or signer.get("purpose", "")
    v.add("signature", True, f"Signature valid. Signed by Plumbline key {signer['keyid'][:16]}… ({label}).")

    # 3. key status for the record's issue date
    pred = statement.get("predicate") if isinstance(statement.get("predicate"), dict) else {}
    try:
        issued = parse_time(_d(pred.get("dates")).get("issued"))
    except AttestError:
        issued = None
    revoked = signer.get("revoked")
    vf, vu = parse_time(signer.get("validFrom")), parse_time(signer.get("validUntil"))
    if revoked:
        why, when = _s(_d(revoked).get("reason")), _s(_d(revoked).get("date"))
        v.add("key", False, f"This key was revoked{' on ' + when if when else ''}{': ' + why if why else ''}. "
                            "Nothing it signed is accepted.")
    elif issued is None:
        v.add("key", False, "The record has no readable issue date, so the key's validity cannot be checked.")
    elif (vf and issued < vf) or (vu and issued > vu):
        v.add("key", False, f"Issued {issued.date()}, outside the key's validity "
                            f"({signer.get('validFrom', '?')} to {signer.get('validUntil', 'open')}).")
    else:
        v.add("key", True, f"Key valid on the issue date ({issued.date()}); not revoked.")
    sig_demo = signer.get("purpose") == "demo"
    v.demo = sig_demo or pred.get("demo") is True
    if sig_demo and pred.get("demo") is not True:
        v.add("key", False, "A DEMO key signed a record that does not say it is a demo. Not accepted.")
    issuer_kid = _d(pred.get("issuer")).get("keyid")
    if issuer_kid and issuer_kid != signer["keyid"]:
        v.add("key", False, "The record names a different issuer key from the one that signed it.")

    # 4. statement
    errs = check_statement(statement)
    v.add("statement", not errs, "A Plumbline audit record (in-toto Statement v1, audit predicate v1)."
          if not errs else "Not a well-formed Plumbline audit record: " + "; ".join(errs) + ".")

    # 5. files
    tset, tasks = _subjects(statement)
    if tasks_dir is not None and tset:
        _check_files(v, Path(tasks_dir), tset, tasks, pred)
    elif tasks_dir is None:
        v.add("files", None, "Files not checked (no folder given).")

    # 6. current
    try:
        until = parse_time(_d(pred.get("dates")).get("validUntil"))
    except AttestError:
        until = None
    if until is not None:
        v.expired = now > until
        v.add("current", not v.expired,
              f"Expired on {until.date()}: the audit needs to be redone before this record counts."
              if v.expired else f"Current: valid until {until.date()}.")
    return v


def _check_files(v: Verdict, folder: Path, tset: dict, tasks: dict[str, str], pred: dict) -> None:
    try:
        m = manifest(folder)
    except AttestError as e:
        v.add("files", False, f"The folder could not be checked: {e}")
        return
    want = _d(tset.get("digest")).get("sha256")
    if m.digest == want:
        v.add("files", True, f"All {len(m.files)} files match the audited task set, byte for byte.")
        return
    for name, d in tasks.items():
        if m.digest == d:
            v.add("files", True, f"This folder matches audited task {name!r}, byte for byte.")
            return
    if folder.name in tasks:
        listed = [{"path": f["path"].split("/", 1)[1], "size": f["size"], "sha256": f["sha256"]}
                  for f in (_d(pred.get("manifest")).get("files") or [])
                  if f.get("path", "").startswith(folder.name + "/")]
        detail = _diff_words(diff_files(listed, m)) if listed else ""
        v.add("files", False, f"This folder does not match audited task {folder.name!r}." + detail)
        return
    listed = _d(pred.get("manifest")).get("files")
    if listed:
        detail = _diff_words(diff_files(listed, m))
    else:
        have = m.tasks()
        bad = sorted(n for n in tasks if have.get(n) != tasks[n])
        extra = sorted(n for n in have if n not in tasks)
        detail = (f" Tasks that differ or are missing: {', '.join(bad)}." if bad else "") + \
                 (f" Tasks not in the record: {', '.join(extra)}." if extra else "")
    v.add("files", False, "These files do not match the audited task set." + detail)


def _diff_words(d: dict[str, list[str]], limit: int = 20) -> str:
    parts = []
    for k, label in (("changed", "Changed"), ("missing", "Missing"), ("added", "Not in the record")):
        if d[k]:
            more = f" and {len(d[k]) - limit} more" if len(d[k]) > limit else ""
            parts.append(f" {label}: {', '.join(d[k][:limit])}{more}.")
    return "".join(parts)


def report(v: Verdict) -> str:
    """The plain-language verdict printed by `attest verify`."""
    p = _d(_d(v.statement).get("predicate"))
    a, d, s = _d(p.get("audit")), _d(p.get("dates")), _d(p.get("sample"))
    tset, tasks = _subjects(v.statement or {})
    head = {"VALID": "VALID: an authentic Plumbline audit record, unchanged since it was signed.",
            "EXPIRED": "EXPIRED: authentic and unchanged, but past its re-audit date.",
            "FILES_DIFFER": "DOES NOT MATCH: the record is authentic, but these files are not the ones audited.",
            "BAD_SIGNATURE": "NOT VALID: the signature check failed.",
            "KEY_NOT_ACCEPTED": "NOT VALID: the signing key is not accepted for this record.",
            "MALFORMED": "NOT VALID: this is not a well-formed Plumbline audit record."}[v.code]
    lines = []
    if v.demo:
        lines.append("DEMO: signed with a demonstration key. This is a sample, not a real audit record.")
    lines.append(head)
    if v.statement and tset:
        what = _d(a.get("taskSet")).get("name") or tset.get("name")
        ver = _d(a.get("taskSet")).get("version")
        lines.append(f"  Audited:  {what}{' ' + ver if ver else ''} ({len(tasks)} tasks), {a.get('kind', '?')}")
        lines.append(f"  Issued:   {d.get('issued', '?')}   Valid until: {d.get('validUntil', '?')}")
        if s:
            seed = f", seed {s['seed']}" if s.get("seed") is not None else ""
            lines.append(f"  Sample:   {s.get('size', '?')} of {s.get('population', '?')} tasks ({s.get('design', '?')}{seed})")
        for r in p.get("results") if isinstance(p.get("results"), list) else []:
            r = _d(r)
            iv = _d(r.get("interval"))
            ci = (f" (95% interval {iv['low']:.1%} to {iv['high']:.1%})"
                  if isinstance(iv.get("low"), (int, float)) and isinstance(iv.get("high"), (int, float)) else "")
            lines.append(f"  Result:   {r.get('measure', '?')}: {r.get('count', '?')} of {r.get('of', '?')}{ci}")
    for c in v.checks:
        mark = {True: "ok  ", False: "FAIL", None: "--  "}[c.ok]
        lines.append(f"  [{mark}] {c.name}: {c.detail}")
    lines.append("  This proves who issued the record and that it is unchanged; it does not prove the audit was right.")
    return "\n".join(lines)
