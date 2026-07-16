"""Attack chain planner.

A deterministic, rule-based planner that turns the current findings into an
ordered plan of next steps (recon -> scanning -> exploitation). It complements
the ReAct loop: the loop reasons freely, while the planner gives an explicit,
inspectable chain for the dashboard viz and a fallback when reasoning stalls.

Pure and LLM-free, so it is fully unit-tested. `plan_next` returns the first
step not already tried; `next_candidate` picks the next fallback module.
"""

from __future__ import annotations

import json
from typing import Optional

from pydantic import BaseModel

from agent.tools.schema import Finding

# Known lab CVE -> Metasploit module (Metasploitable-era easy wins).
EXPLOIT_MAP = {
    "CVE-2011-2523": "exploit/unix/ftp/vsftpd_234_backdoor",
    "CVE-2004-2687": "exploit/unix/misc/distcc_exec",
    "CVE-2007-2447": "exploit/multi/samba/usermap_script",
    "CVE-2010-2075": "exploit/unix/irc/unreal_ircd_3281_backdoor",
}


class PlanStep(BaseModel):
    phase: str          # recon | scanning | exploitation
    tool: str           # tool name, e.g. "nmap_scan"
    args: dict          # tool arguments
    rationale: str      # why this step, human-readable


def _key(tool: str, args: dict) -> str:
    """Match the graph's action-key format so seen_actions filtering lines up."""
    return f"{tool}:{json.dumps(args, sort_keys=True, default=str)}"


def _is_http(service: Optional[str]) -> bool:
    return bool(service) and ("http" in service.lower())


def build_plan(target: str, findings: list[Finding]) -> list[PlanStep]:
    """Compute the ordered list of remaining recommended steps from findings."""
    tools_seen = {f.tool for f in findings}

    # Phase 1 — recon must happen first; nothing else can be planned without it.
    if "nmap" not in tools_seen:
        return [PlanStep(phase="recon", tool="nmap_scan", args={"target": target},
                         rationale="Enumerate open ports and service versions.")]

    plan: list[PlanStep] = []
    services = [(f.service, f.version) for f in findings
                if f.tool == "nmap" and f.service]

    # Phase 2a — CVE lookup for each detected service+version not yet queried.
    queried = {f.target for f in findings if f.tool == "cve_rag"}
    for svc, ver in services:
        query = f"{svc} {ver}".strip()
        if query and query not in queried:
            plan.append(PlanStep(
                phase="scanning", tool="search_cve_database", args={"query": query},
                rationale=f"Find version-specific CVEs for {query}."))

    # Phase 2b — web scanning if any HTTP service is present.
    if any(_is_http(svc) for svc, _ in services):
        url = f"http://{target}"
        if "nuclei" not in tools_seen:
            plan.append(PlanStep(phase="scanning", tool="nuclei_scan",
                                 args={"target": url},
                                 rationale="Template-scan the web service for known vulns."))
        if "sqlmap" not in tools_seen:
            plan.append(PlanStep(phase="exploitation", tool="sqlmap_scan",
                                 args={"target": url},
                                 rationale="Test web parameters for SQL injection (detection only)."))

    # Phase 3 — exploitation for any CVE we have a known module for.
    attempted = {f.evidence for f in findings if f.tool == "metasploit"}
    for f in findings:
        module = EXPLOIT_MAP.get(f.cve or "")
        if module and module not in (attempted or set()):
            plan.append(PlanStep(
                phase="exploitation", tool="metasploit_run",
                args={"target": target, "module": module},
                rationale=f"{f.cve} maps to {module}; verify with check (safe default)."))
    return plan


def plan_next(target: str, findings: list[Finding],
              seen_actions: frozenset[str] = frozenset()) -> Optional[PlanStep]:
    """Return the first planned step not already tried, or None when the chain
    is exhausted."""
    for step in build_plan(target, findings):
        if _key(step.tool, step.args) not in seen_actions:
            return step
    return None


def next_candidate(candidates: list[str], seen_actions: frozenset[str] = frozenset(),
                   tool: str = "metasploit_run", arg_key: str = "module",
                   target: str = "") -> Optional[str]:
    """Fallback selection: return the first candidate (e.g. exploit module) not
    yet tried. Used when an exploit fails and the agent needs the next option."""
    for cand in candidates:
        args = {"target": target, arg_key: cand} if target else {arg_key: cand}
        if _key(tool, args) not in seen_actions:
            return cand
    return None
