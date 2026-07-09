"""Nuclei wrapper — scanning. Template-based vuln detection, one Finding per hit.

Follows the five-stage wrapper contract (see the redagent-tool-wrapper skill):
validate -> scope gate -> subprocess w/ timeout -> parse to Finding -> return.
Uses `-jsonl` (one JSON object per line); each template match becomes a Finding.
Keep `detail` concise (token lever) — the full JSON line goes in `raw`.
"""

from __future__ import annotations

import json
import subprocess

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding, severity_from_cvss

TOOL_NAME = "nuclei"
PHASE = "scanning"
TIMEOUT_S = 600

# Nuclei severity string -> schema band.
_SEV_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": None,
}


def _run(target: str) -> str:
    proc = subprocess.run(
        ["nuclei", "-u", target, "-jsonl", "-silent"],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _first(value):
    """Nuclei classification fields are often lists; take the first, or None."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _parse(target: str, raw: str) -> list[Finding]:
    findings: list[Finding] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            hit = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = hit.get("info", {}) or {}
        classification = info.get("classification", {}) or {}

        cve = _first(classification.get("cve-id"))
        cvss = classification.get("cvss-score")
        try:
            cvss = float(cvss) if cvss is not None else None
        except (TypeError, ValueError):
            cvss = None

        sev = _SEV_MAP.get(str(info.get("severity", "")).lower())
        if sev is None:
            sev = severity_from_cvss(cvss)

        template_id = hit.get("template-id") or hit.get("templateID") or "unknown"
        name = info.get("name") or template_id
        matched_at = hit.get("matched-at") or hit.get("matched") or hit.get("host") or target

        findings.append(
            Finding(
                tool=TOOL_NAME,
                phase=PHASE,
                target=target,
                title=f"{name} [{template_id}]",
                detail=f"{info.get('severity', 'unknown')} — matched at {matched_at}",
                cve=cve,
                cvss=cvss,
                severity=sev,
                evidence=matched_at,
                raw=line,
            )
        )
    return findings


@tool
def nuclei_scan(target: str) -> list[Finding]:
    """Run Nuclei template-based vulnerability detection against an in-scope lab
    target and return one normalized finding per template match. Use during
    scanning after recon has identified live web services."""
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
    raw = _run(target)
    findings = _parse(target, raw)
    return findings or [
        Finding(
            tool=TOOL_NAME,
            phase=PHASE,
            target=target,
            title="No findings",
            detail="Nuclei matched no templates.",
            raw=raw,
        )
    ]
