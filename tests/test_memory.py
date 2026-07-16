"""Tests for the compact state summary (token-discipline core)."""

from __future__ import annotations

from agent.memory import summarize_state, _MAX_ITEMS_PER_SECTION
from agent.tools.schema import Finding


def _recon(port_label, target="10.0.0.5", **kw):
    return Finding(tool="nmap", phase="recon", target=target,
                   title=f"Open port {port_label}", detail="x", **kw)


def test_empty_findings_no_actions():
    assert summarize_state([], set()) == "No findings yet."


def test_empty_findings_but_actions_tried():
    out = summarize_state([], {"nmap_scan"})
    assert "No findings yet." not in out
    assert "Tried: nmap_scan" in out


def test_target_and_services_listed():
    findings = [_recon("21/tcp — vsftpd 2.3.4"), _recon("22/tcp — OpenSSH 4.7p1")]
    out = summarize_state(findings, {"nmap_scan"})
    assert "Target: 10.0.0.5" in out
    assert "Open services:" in out
    assert "vsftpd 2.3.4" in out and "OpenSSH 4.7p1" in out
    assert "Tried: nmap_scan" in out


def test_vulnerabilities_filtered_by_cve_or_severity():
    findings = [
        Finding(tool="nuclei", phase="scanning", target="10.0.0.5",
                title="Apache Path Traversal", detail="x",
                cve="CVE-2021-41773", cvss=9.8, severity="Critical"),
        Finding(tool="nuclei", phase="scanning", target="10.0.0.5",
                title="Info banner", detail="x", severity="Info"),  # not a vuln
    ]
    out = summarize_state(findings, set())
    assert "Vulnerabilities:" in out
    assert "CVE-2021-41773 (Critical, CVSS 9.8)" in out
    assert "Info banner" not in out


def test_status_findings_excluded_from_signal():
    findings = [
        Finding(tool="nmap", phase="recon", target="10.0.0.5",
                title="Out of scope", detail="denied"),
        Finding(tool="nuclei", phase="scanning", target="10.0.0.5",
                title="Not implemented", detail="stub"),
    ]
    # Only status findings -> nothing to summarize.
    assert summarize_state(findings, set()) == "No findings yet."


def test_multiple_targets_labelled():
    findings = [_recon("80/tcp — Apache", target="10.0.0.5"),
                _recon("80/tcp — nginx", target="10.0.0.6")]
    out = summarize_state(findings, set())
    assert out.startswith("Targets: ")
    assert "10.0.0.5" in out and "10.0.0.6" in out


def test_section_capped_with_overflow_marker():
    overflow = 6
    findings = [_recon(f"{p}/tcp — svc{p}")
                for p in range(_MAX_ITEMS_PER_SECTION + overflow)]
    out = summarize_state(findings, set())
    services_line = next(l for l in out.splitlines() if l.startswith("Open services:"))
    assert f"(+{overflow} more)" in services_line


def test_dedupes_repeated_services():
    findings = [_recon("21/tcp — vsftpd 2.3.4"), _recon("21/tcp — vsftpd 2.3.4")]
    out = summarize_state(findings, set())
    services_line = next(l for l in out.splitlines() if l.startswith("Open services:"))
    assert services_line.count("vsftpd 2.3.4") == 1
