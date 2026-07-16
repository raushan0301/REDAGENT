"""SQLMap output parser tests — deterministic, offline (no sqlmap binary)."""

from __future__ import annotations

from agent.tools.sqlmap_tool import _parse, _run
from tests.conftest import read_fixture


def _findings():
    return _parse("http://10.0.0.5/vuln.php?id=1", read_fixture("sqlmap_dvwa.txt"))


def test_detects_injectable_parameter():
    findings = _findings()
    assert len(findings) == 1
    f = findings[0]
    assert "id" in f.title
    assert f.severity == "High" and f.mitre == "T1190"


def test_extracts_injection_types_and_dbms():
    f = _findings()[0]
    assert "boolean-based blind" in f.detail
    assert "UNION query" in f.detail
    assert f.service == "MySQL >= 5.0.12"       # back-end DBMS captured
    assert "boolean-based blind" in f.evidence   # from Title lines


def test_all_tagged_exploitation_with_raw():
    f = _findings()[0]
    assert f.tool == "sqlmap" and f.phase == "exploitation"
    assert f.raw is not None


def test_no_injection_output_returns_empty():
    assert _parse("http://10.0.0.5/", "[INFO] all tested parameters do not appear to be injectable") == []


def test_default_run_is_non_destructive(monkeypatch):
    # Guard the safety default: no --dump unless allow_dump=True.
    captured = {}

    def fake_run(args, capture_output, text, timeout):
        captured["args"] = args
        class P:
            stdout, stderr = "", ""
        return P()

    monkeypatch.setattr("agent.tools.sqlmap_tool.subprocess.run", fake_run)

    _run("http://10.0.0.5/?id=1", allow_dump=False)
    assert "--dump" not in captured["args"]
    assert "--batch" in captured["args"]

    _run("http://10.0.0.5/?id=1", allow_dump=True)
    assert "--dump" in captured["args"]
