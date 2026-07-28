"""Nikto CSV parser tests — deterministic, offline (no nikto binary needed)."""

from __future__ import annotations

import subprocess
from unittest.mock import patch

import pytest

from agent.tools.nikto_tool import _classify_severity, _parse, nikto_scan
from tests.conftest import read_fixture


def _findings():
    return _parse("10.0.0.5", read_fixture("nikto_output.csv"))


# ---------------------------------------------------------------------------
# Parser unit tests
# ---------------------------------------------------------------------------

def test_header_and_footer_rows_skipped():
    # 6 data rows in fixture (the "Nikto v2.1.6" header rows + end row are skipped).
    assert len(_findings()) == 6


def test_all_findings_tagged_scanning():
    findings = _findings()
    assert all(f.tool == "nikto" and f.phase == "scanning" for f in findings)
    assert all(f.target == "10.0.0.5" for f in findings)


def test_mitre_t1190_set_on_all():
    assert all(f.mitre == "T1190" for f in _findings())


def test_cve_extracted_from_description():
    # phpinfo row embeds CVE-2012-4388; traversal row embeds CVE-2021-41773
    cves = {f.cve for f in _findings() if f.cve}
    assert "CVE-2012-4388" in cves
    assert "CVE-2021-41773" in cves


def test_path_traversal_classified_critical():
    findings = _findings()
    traversal = next(f for f in findings if "Path Traversal" in f.title or "traversal" in f.detail)
    assert traversal.severity == "Critical"


def test_directory_listing_classified_low():
    findings = _findings()
    dirlisting = next(f for f in findings if "Directory listing" in f.detail)
    assert dirlisting.severity == "Low"


def test_outdated_server_classified_medium():
    findings = _findings()
    outdated = next(f for f in findings if "outdated" in f.detail)
    assert outdated.severity == "Medium"


def test_evidence_includes_method_and_path():
    findings = _findings()
    # The traversal row description contains "Path Traversal"; path /cgi-bin/...passwd is in evidence
    traversal = next(f for f in findings if "Path Traversal" in f.detail)
    assert "POST" in traversal.evidence
    assert "/cgi-bin" in traversal.evidence


def test_osvdb_nonzero_appended_to_evidence():
    findings = _findings()
    # OSVDB-3092 row: directory listing
    dirlisting = next(f for f in findings if "Directory listing" in f.detail)
    assert "OSVDB-3092" in dirlisting.evidence


def test_raw_retained_on_every_finding():
    raw = read_fixture("nikto_output.csv")
    findings = _parse("10.0.0.5", raw)
    assert all(f.raw == raw for f in findings)


def test_title_truncated_at_80_chars():
    long_desc = "A" * 100
    csv_row = f'"Nikto v2.1.6","10.0.0.5","10.0.0.5","80","0","GET","/","{long_desc}"\n'
    findings = _parse("10.0.0.5", csv_row)
    assert len(findings) == 1
    assert findings[0].title.endswith("…")
    # title = "Nikto: " (7 chars) + 80 chars + "…"
    assert len(findings[0].title) == 7 + 80 + 1


def test_malformed_input_returns_empty_not_raises():
    assert _parse("10.0.0.5", "garbage\nnot,enough,columns") == []


def test_empty_input_returns_empty():
    assert _parse("10.0.0.5", "") == []


# ---------------------------------------------------------------------------
# Severity classifier unit tests
# ---------------------------------------------------------------------------

def test_classify_severity_critical_keywords():
    assert _classify_severity("Remote code execution via upload") == "Critical"
    assert _classify_severity("RCE possible through shell upload") == "Critical"


def test_classify_severity_high_keywords():
    assert _classify_severity("SQL injection in login form") == "High"
    assert _classify_severity("Directory traversal found") == "High"
    assert _classify_severity("Cross-site scripting (XSS)") == "High"


def test_classify_severity_low_keywords():
    assert _classify_severity("Server banner discloses version") == "Low"
    assert _classify_severity("Index of /var/www/ — directory listing") == "Low"


def test_classify_severity_default_medium():
    assert _classify_severity("Some misconfigured header") == "Medium"


# ---------------------------------------------------------------------------
# Scope gate + error handling (integration-level, binary mocked)
# ---------------------------------------------------------------------------

def test_out_of_scope_returns_status_finding(scoped_env):
    result = nikto_scan.invoke({"target": "8.8.8.8", "port": 80})
    assert len(result) == 1
    assert result[0].title == "Out of scope"


def test_binary_not_found_returns_tool_unavailable_finding(scoped_env):
    with patch("agent.tools.nikto_tool._run", side_effect=FileNotFoundError("nikto")):
        result = nikto_scan.invoke({"target": "10.0.0.1", "port": 80})
    assert len(result) == 1
    assert result[0].title == "Tool unavailable"
    assert "not found" in result[0].detail


def test_timeout_returns_tool_unavailable_finding(scoped_env):
    with patch("agent.tools.nikto_tool._run",
               side_effect=subprocess.TimeoutExpired(cmd="nikto", timeout=600)):
        result = nikto_scan.invoke({"target": "10.0.0.1", "port": 80})
    assert result[0].title == "Tool unavailable"
    assert "timed out" in result[0].detail


def test_no_findings_returns_status_finding(scoped_env):
    with patch("agent.tools.nikto_tool._run", return_value=""):
        result = nikto_scan.invoke({"target": "10.0.0.1", "port": 80})
    assert len(result) == 1
    assert result[0].title == "No findings"
