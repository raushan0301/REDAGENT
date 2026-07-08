"""Nmap wrapper — recon. Service/version scan, parsed from XML (-oX -).

Follows the five-stage wrapper contract (see the redagent-tool-wrapper skill):
validate -> scope gate -> subprocess w/ timeout -> parse to Finding -> return.
Feed detected service+version straight into the CVE RAG tool.
"""

from __future__ import annotations

import subprocess
import xml.etree.ElementTree as ET

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "nmap"
PHASE = "recon"
TIMEOUT_S = 300


def _run(args: list[str]) -> str:
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_S)
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _parse(target: str, raw: str) -> list[Finding]:
    findings: list[Finding] = []
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return findings

    for host in root.findall("host"):
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            portid = port.get("portid")
            svc = port.find("service")
            service = svc.get("name") if svc is not None else None
            version = svc.get("version") if svc is not None else None
            product = svc.get("product") if svc is not None else None
            label = " ".join(p for p in (product, version) if p) or service or "unknown"
            findings.append(
                Finding(
                    tool=TOOL_NAME,
                    phase=PHASE,
                    target=target,
                    title=f"Open port {portid}/{port.get('protocol')} — {label}",
                    detail=f"{service or 'unknown'} on port {portid} ({label})",
                    service=service,
                    version=version,
                    evidence=f"port {portid} open; product={product} version={version}",
                    raw=raw,
                )
            )
    return findings


@tool
def nmap_scan(target: str) -> list[Finding]:
    """Run an Nmap service/version scan against an in-scope lab target and return
    normalized findings. Use during recon to enumerate open ports and detect
    service versions."""
    if not in_scope(target):
        return [
            Finding(
                tool=TOOL_NAME,
                phase=PHASE,
                target=target,
                title="Out of scope",
                detail="Target not in operator scope list; not executed.",
            )
        ]
    raw = _run(["nmap", "-sV", "-oX", "-", target])
    findings = _parse(target, raw)
    return findings or [
        Finding(
            tool=TOOL_NAME,
            phase=PHASE,
            target=target,
            title="No findings",
            detail="Scan returned no open ports.",
            raw=raw,
        )
    ]
