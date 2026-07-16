"""Attack-chain planner tests — deterministic, offline."""

from __future__ import annotations

from agent.planner import (
    EXPLOIT_MAP,
    build_plan,
    next_candidate,
    plan_next,
    _key,
)
from agent.tools.schema import Finding


def _nmap(service, version="", target="10.0.0.5"):
    return Finding(tool="nmap", phase="recon", target=target,
                   title=f"Open port — {service}", detail="x",
                   service=service, version=version)


def test_empty_findings_plans_recon_first():
    step = plan_next("10.0.0.5", [])
    assert step.tool == "nmap_scan" and step.phase == "recon"
    assert step.args == {"target": "10.0.0.5"}


def test_after_recon_plans_cve_lookup_for_each_service():
    findings = [_nmap("ftp", ""), _nmap("vsftpd", "2.3.4")]
    plan = build_plan("10.0.0.5", findings)
    queries = [s.args["query"] for s in plan if s.tool == "search_cve_database"]
    assert "vsftpd 2.3.4" in queries


def test_http_service_plans_nuclei_and_sqlmap():
    findings = [_nmap("http", "2.4.49")]
    plan = build_plan("10.0.0.5", findings)
    tools = [s.tool for s in plan]
    assert "nuclei_scan" in tools and "sqlmap_scan" in tools
    nuclei = next(s for s in plan if s.tool == "nuclei_scan")
    assert nuclei.args["target"] == "http://10.0.0.5"


def test_known_cve_plans_metasploit_module():
    findings = [
        _nmap("vsftpd", "2.3.4"),
        Finding(tool="cve_rag", phase="scanning", target="vsftpd 2.3.4",
                title="CVE-2011-2523", detail="backdoor",
                cve="CVE-2011-2523", cvss=10.0, severity="Critical"),
    ]
    plan = build_plan("10.0.0.5", findings)
    msf = [s for s in plan if s.tool == "metasploit_run"]
    assert msf and msf[0].args["module"] == EXPLOIT_MAP["CVE-2011-2523"]


def test_plan_next_skips_already_tried_step():
    findings = [_nmap("vsftpd", "2.3.4")]
    first = plan_next("10.0.0.5", findings)
    assert first.tool == "search_cve_database"
    # Mark that exact step as seen -> planner moves past it.
    seen = frozenset({_key(first.tool, first.args)})
    nxt = plan_next("10.0.0.5", findings, seen)
    assert nxt is None or _key(nxt.tool, nxt.args) not in seen


def test_cve_lookup_not_replanned_once_queried():
    findings = [
        _nmap("vsftpd", "2.3.4"),
        Finding(tool="cve_rag", phase="scanning", target="vsftpd 2.3.4",
                title="none", detail="x"),
    ]
    plan = build_plan("10.0.0.5", findings)
    assert not any(s.tool == "search_cve_database" for s in plan)


def test_next_candidate_fallback_picks_untried_module():
    mods = ["exploit/a", "exploit/b", "exploit/c"]
    seen = frozenset({_key("metasploit_run", {"target": "10.0.0.5", "module": "exploit/a"})})
    assert next_candidate(mods, seen, target="10.0.0.5") == "exploit/b"


def test_next_candidate_none_when_all_tried():
    mods = ["exploit/a"]
    seen = frozenset({_key("metasploit_run", {"target": "10.0.0.5", "module": "exploit/a"})})
    assert next_candidate(mods, seen, target="10.0.0.5") is None
