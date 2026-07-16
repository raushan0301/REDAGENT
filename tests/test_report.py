"""Report engine tests — pure aggregation/mapping offline, narrative with a fake
LLM, and a real PDF render asserted by its %PDF header."""

from __future__ import annotations

from reports.generator import (
    build_report_context,
    generate_narrative,
    generate_report,
    mitre_map,
    rank_findings,
    risk_rating,
    severity_of,
    summarize_severities,
)
from agent.tools.schema import Finding


def _findings():
    return [
        Finding(tool="nmap", phase="recon", target="10.0.0.5",
                title="Open port 21/tcp — vsftpd 2.3.4", detail="ftp"),
        Finding(tool="cve_rag", phase="scanning", target="10.0.0.5",
                title="CVE-2011-2523", detail="vsftpd backdoor",
                cve="CVE-2011-2523", cvss=10.0, severity="Critical"),
        Finding(tool="nuclei", phase="exploitation", target="10.0.0.5",
                title="Tomcat Manager Exposed", detail="high", cvss=7.5),  # severity via CVSS
    ]


def test_severity_derived_from_cvss_when_missing():
    tomcat = _findings()[2]
    assert tomcat.severity is None
    assert severity_of(tomcat) == "High"


def test_severity_counts_and_risk_rating():
    counts = summarize_severities(_findings())
    assert counts["Critical"] == 1 and counts["High"] == 1
    assert risk_rating(_findings()) == "Critical"


def test_recon_finding_without_severity_not_counted():
    counts = summarize_severities(_findings())
    # the bare recon port finding has no severity/cvss -> excluded
    assert sum(counts.values()) == 2


def test_rank_orders_critical_first():
    ranked = rank_findings(_findings())
    assert ranked[0].cve == "CVE-2011-2523"      # Critical/10.0 first
    assert severity_of(ranked[1]) == "High"


def test_mitre_map_from_phase_unique_sorted():
    techniques = mitre_map(_findings())
    ids = [t["id"] for t in techniques]
    assert ids == sorted(ids)
    assert "T1046" in ids and "T1190" in ids     # recon + exploitation phases


def test_mitre_explicit_field_overrides_phase():
    f = Finding(tool="x", phase="recon", target="t", title="y", detail="z", mitre="T1110")
    assert mitre_map([f]) == [{"id": "T1110", "name": ""}]


# --- narrative + PDF -------------------------------------------------------

class FakeLLM:
    def __init__(self):
        self.calls = 0

    def invoke(self, messages):
        self.calls += 1
        class _Msg:
            content = f"Generated narrative section {'A' if messages else 'B'}."
        return _Msg()


def test_generate_narrative_two_llm_calls():
    llm = FakeLLM()
    out = generate_narrative(_findings(), llm)
    assert llm.calls == 2
    assert out["summary"] and out["remediation"]


def test_generate_report_writes_pdf(tmp_path):
    out = tmp_path / "report.pdf"
    path = generate_report("sess-1", _findings(), str(out), llm=FakeLLM(), target="10.0.0.5")
    assert path == str(out)
    assert out.exists()
    assert out.read_bytes()[:5] == b"%PDF-"     # a real PDF was rendered
    assert out.stat().st_size > 1000


def test_build_context_shape():
    ctx = build_report_context("s", "10.0.0.5", _findings(),
                               {"summary": "s", "remediation": "r"})
    assert ctx["risk"] == "Critical"
    assert ctx["total"] == 3
    assert ctx["target"] == "10.0.0.5"
    assert len(ctx["findings"]) == 3
