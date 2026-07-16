"""Subfinder wrapper — recon. Subdomain enumeration -> Findings (phase=recon).

Follows the five-stage wrapper contract (see the redagent-tool-wrapper skill):
validate -> scope gate -> subprocess w/ timeout -> parse to Finding -> return.
Uses `-silent` (one host per line); each discovered subdomain becomes a Finding.
"""

from __future__ import annotations

import re
import subprocess

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "subfinder"
PHASE = "recon"
TIMEOUT_S = 300

# A plausible hostname: dotted, no whitespace, valid label chars.
_HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9_-]+\.)+[A-Za-z0-9_-]+$")


def _run(target: str) -> str:
    proc = subprocess.run(
        ["subfinder", "-d", target, "-silent"],
        capture_output=True, text=True, timeout=TIMEOUT_S,
    )
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _parse(target: str, raw: str) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        host = line.strip().lower()
        if not host or host in seen or not _HOST_RE.match(host):
            continue
        seen.add(host)
        findings.append(Finding(
            tool=TOOL_NAME, phase=PHASE, target=target,
            title=f"Subdomain: {host}",
            detail=f"Discovered subdomain {host} for {target}.",
            evidence=host, raw=raw,
        ))
    return findings


@tool
def subfinder_scan(target: str) -> list[Finding]:
    """Enumerate subdomains of an in-scope lab domain and return one finding per
    discovered subdomain. Use during recon to widen the attack surface."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    raw = _run(target)
    findings = _parse(target, raw)
    return findings or [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                               title="No subdomains found",
                               detail="Subfinder returned nothing.", raw=raw)]
