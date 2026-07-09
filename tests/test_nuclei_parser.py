"""Nuclei JSONL parser tests — deterministic, offline (no nuclei binary needed)."""

from __future__ import annotations

from agent.tools.nuclei_tool import _parse
from tests.conftest import read_fixture


def _findings():
    return _parse("http://10.0.0.5", read_fixture("nuclei_output.jsonl"))


def test_one_finding_per_valid_json_line_stray_lines_skipped():
    # 3 valid JSON objects; the banner line and any blanks are skipped.
    assert len(_findings()) == 3


def test_cve_and_cvss_extracted():
    by_id = {f.title.split("[")[1].rstrip("]"): f for f in _findings()}
    log4j = by_id["CVE-2021-41773"]
    assert log4j.cve == "CVE-2021-41773"
    assert log4j.cvss == 9.8
    assert log4j.severity == "Critical"


def test_empty_cve_list_yields_none_and_string_cvss_coerced():
    by_id = {f.title.split("[")[1].rstrip("]"): f for f in _findings()}
    tomcat = by_id["tomcat-manager"]
    assert tomcat.cve is None            # empty cve-id list -> None
    assert tomcat.cvss == 7.5            # "7.5" string coerced to float
    assert tomcat.severity == "High"


def test_info_severity_mapped_and_all_tagged_scanning():
    findings = _findings()
    assert all(f.tool == "nuclei" and f.phase == "scanning" for f in findings)
    info_hit = next(f for f in findings if "apache-detect" in f.title)
    assert info_hit.severity == "Info"
    assert info_hit.evidence == "http://10.0.0.5"
    assert info_hit.raw.startswith("{")   # per-finding raw retained


def test_malformed_input_returns_empty_not_raises():
    assert _parse("http://10.0.0.5", "garbage\nmore garbage") == []
