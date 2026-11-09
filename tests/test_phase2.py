"""Fix guidance, SARIF, footer, --estimate, badge, and the opt-in calls (against a local server only)."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from plumbline_scan import extras, guidance, report, sarif
from plumbline_scan.cli import main
from plumbline_scan.harbor import load_task

TOY = Path(__file__).parent / "toy_tasks"


def _rec(task="good", **statuses):
    checks = {c: {"status": "PASS", "summary": "ok", "details": {}} for c in guidance.CHECK_IDS}
    for c, st in statuses.items():
        checks[c] = {"status": st, "summary": f"{c} {st}", "details": {}}
    verdict = "FLAGGED" if "FLAG" in statuses.values() else "OK"
    return {"task": task, "path": str(TOY / task), "image": "img", "reference_kind": "script",
            "checks": checks, "verdict": verdict, "seconds": 10}


def test_ids_and_fix_guidance():
    recs = [_rec(empty="FLAG", network="NETWORK", reference="WARN")]
    guidance.annotate(recs, None)
    ch = recs[0]["checks"]
    assert [ch[c]["id"] for c in guidance.CHECK_IDS] == ["PS-1", "PS-2", "PS-3", "PS-4", "PS-5", "PS-6",
                                                         "PS-7", "PS-8", "PS-9", "PS-10", "PS-11",
                                                         "PS-12"]
    assert "exit status" in ch["empty"]["fix"] and ch["empty"]["why"]
    assert "-k 10" in ch["reference"]["fix"]
    assert "Dockerfile" in ch["network"]["fix"]
    assert "fix" not in ch["stub"]  # passing checks carry no guidance
    for (check, status), text in guidance.FIX.items():
        assert check in guidance.CHECK_IDS and status in ("FLAG", "WARN", "NETWORK") and text


def test_sarif_shape(tmp_path):
    recs = [_rec(empty="FLAG", network="NETWORK"), _rec("leaked", leaked_answer="FLAG")]
    guidance.annotate(recs, None)
    s = sarif.build(recs, TOY)
    run = s["runs"][0]
    assert s["version"] == "2.1.0" and len(run["tool"]["driver"]["rules"]) == 12
    res = {(r["ruleId"], r["level"]): r for r in run["results"]}
    assert set(res) == {("PS-2", "error"), ("PS-6", "note"), ("PS-3", "error")}
    assert res[("PS-2", "error")]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "good/tests/test.sh"
    assert res[("PS-3", "error")]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "leaked/environment/Dockerfile"
    assert "Fix:" in res[("PS-2", "error")]["message"]["text"]
    p = report.write_sarif(tmp_path, recs, TOY)
    assert json.loads(p.read_text())["runs"][0]["results"]


def test_footer():
    assert report.FOOTER.startswith("These are mechanical checks.")
    assert report.FOOTER.endswith("plumblinegrader.com/sample?src=scan")


@pytest.mark.parametrize("n,expect", [(5, "from $1,500"), (100, "from $4,000"), (1240, "volume pricing")])
def test_estimate(n, expect):
    tasks = [load_task(TOY / "good")] * n
    text = extras.estimate(tasks)
    assert f"Tasks: {n}" in text and expect in text and "sample?src=scan" in text


def test_estimate_cli_needs_no_docker(capsys, monkeypatch):
    monkeypatch.setattr("plumbline_scan.cli.Docker", None)  # would raise if the CLI touched Docker
    assert main([str(TOY), "--estimate"]) == 0
    out = capsys.readouterr().out
    assert "Tasks: 6" in out and "repository patch reference (1)" in out


def test_badge(tmp_path):
    md, note = extras.write_badge(tmp_path, [_rec(), _rec("stub")], "2026-10-08")
    assert md and (tmp_path / "badge.svg").read_text().startswith("<svg")
    assert "PS-1 to PS-12" in md.read_text() and "plumblinegrader.com/scan" in md.read_text()
    none, note = extras.write_badge(tmp_path / "x", [_rec(empty="FLAG")], "2026-10-08")
    assert none is None and "flagged" in note
    skipped = _rec()
    del skipped["checks"]["leaked_answer"]
    assert not extras.badge_eligible([skipped])[0]


class _Server:
    def __init__(self, status=200):
        self.got = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.got.append((self.path, json.loads(body)))
                self.send_response(status)
                self.end_headers()
                self.wfile.write(b'{"ok":true}')

            def log_message(self, *a):
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}"


@pytest.fixture
def server(monkeypatch):
    s = _Server()
    monkeypatch.setattr(extras, "API", s.url)
    yield s
    s.httpd.shutdown()


def test_subscribe_sends_only_the_email(server, capsys):
    assert main(["--subscribe", "dev@example.com"]) == 0
    (path, body), = server.got
    assert path == "/api/lead" and body["kind"] == "notify" and body["email"] == "dev@example.com"
    assert set(body) == {"kind", "email", "page", "source", "elapsed_ms"}


def test_share_stats_flag_removed():
    # --share-stats was removed (no server endpoint); the CLI must reject it rather than ignore it.
    with pytest.raises(SystemExit):
        main(["--share-stats", "x"])
    assert not hasattr(extras, "share_stats")


def test_nothing_sent_by_default(server, tmp_path, monkeypatch):
    # A full CLI run without the opt-in flags must not call the API (the scan itself is faked).
    monkeypatch.setattr("plumbline_scan.cli.Scan", lambda task, d, o, log: type("S", (), {"run": lambda self: _rec(task.name)})())
    monkeypatch.setattr("plumbline_scan.docker.Docker.available", lambda self: "")
    main([str(TOY / "good"), "-o", str(tmp_path)])
    assert server.got == []
    assert "Nothing from this scan was sent" in (tmp_path / "scan.md").read_text()
    assert (tmp_path / "badge.md").exists() and (tmp_path / "scan.sarif").exists()


def test_static_only_needs_no_docker_and_never_says_ok(tmp_path, monkeypatch):
    from plumbline_scan.cli import main
    monkeypatch.setattr("plumbline_scan.cli.Docker", None)  # would raise if the CLI touched Docker
    toys = Path(__file__).parent / "toy_tasks"
    assert main([str(toys), "--static-only", "-o", str(tmp_path)]) == 0
    recs = json.loads((tmp_path / "scan.json").read_text())
    recs = recs.get("tasks", recs)
    assert recs and all(r["verdict"] == "INCOMPLETE" for r in recs)
    assert all("reference" not in r["checks"] and "loose_match" in r["checks"] for r in recs)
    assert not (tmp_path / "badge.svg").exists()
