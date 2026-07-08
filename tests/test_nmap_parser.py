"""Nmap XML parser tests — deterministic, offline (no nmap binary needed)."""

from __future__ import annotations

from agent.tools.nmap_tool import _parse


def test_parses_only_open_ports(nmap_xml):
    findings = _parse("10.0.0.5", nmap_xml)
    ports = {f.title.split()[2] for f in findings}  # "Open port 21/tcp ..."
    # 21, 22, 80 open; 139 closed -> excluded
    assert ports == {"21/tcp", "22/tcp", "80/tcp"}
    assert len(findings) == 3


def test_extracts_service_and_version(nmap_xml):
    findings = _parse("10.0.0.5", nmap_xml)
    by_port = {f.evidence.split()[1]: f for f in findings}  # "port 21 open; ..."
    assert by_port["21"].service == "ftp"
    assert by_port["21"].version == "2.3.4"
    assert "vsftpd" in by_port["21"].title


def test_all_findings_tagged_recon_with_raw(nmap_xml):
    findings = _parse("10.0.0.5", nmap_xml)
    assert all(f.tool == "nmap" and f.phase == "recon" for f in findings)
    assert all(f.target == "10.0.0.5" for f in findings)
    assert all(f.raw == nmap_xml for f in findings)   # raw retained for report appendix


def test_malformed_xml_returns_empty_not_raises():
    assert _parse("10.0.0.5", "not xml at all") == []
