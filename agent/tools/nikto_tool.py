"""Nikto wrapper — scanning. Web-server misconfiguration and known-vuln detection.

Follows the five-stage wrapper contract (see the redagent-tool-wrapper skill):
validate -> scope gate -> subprocess w/ timeout -> parse to Finding -> return.

Nikto is invoked with `-Format csv` so the output is machine-parseable without a
third-party library. Each non-header CSV row becomes one Finding.  The full raw
CSV is stored in Finding.raw for the report appendix; the agent only sees the
normalised schema.

OSVDB IDs from older Nikto builds are preserved in Finding.evidence; CVSS is not
natively emitted by Nikto so severity is inferred from Nikto's internal numeric
OSVDB references (rough heuristic) or left at Medium for unclassified hits.
"""

from __future__ import annotations

import csv
import io
import subprocess

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.exec_guard import EXEC_ERRORS, exec_error_finding
from agent.tools.schema import Finding

TOOL_NAME = "nikto"
PHASE = "scanning"
TIMEOUT_S = 90

# Nikto CSV header (as emitted by `nikto -Format csv`):
# "Nikto version","host","ip","port","osvdb","method","path","description"
_FIELD_HOST = "host"
_FIELD_OSVDB = "osvdb"
_FIELD_METHOD = "method"
_FIELD_PATH = "path"
_FIELD_DESC = "description"
_FIELD_PORT = "port"

# Rough severity mapping based on Nikto's own description keywords.
# Nikto doesn't emit CVSS — we classify by well-known indicator phrases.
_CRITICAL_KEYWORDS = ("remote code execution", "rce", "command injection", "shell upload")
_HIGH_KEYWORDS = ("sql injection", "sqli", "directory traversal", "path traversal",
                  "authentication bypass", "xss", "cross-site scripting",
                  "arbitrary file", "sensitive file")
_LOW_KEYWORDS = ("server banner", "server version", "x-powered-by", "etag",
                 "index of /", "directory listing")


def _classify_severity(description: str) -> str:
    desc_lower = description.lower()
    for kw in _CRITICAL_KEYWORDS:
        if kw in desc_lower:
            return "Critical"
    for kw in _HIGH_KEYWORDS:
        if kw in desc_lower:
            return "High"
    for kw in _LOW_KEYWORDS:
        if kw in desc_lower:
            return "Low"
    return "Medium"


def _run(target: str, port: int) -> str:
    """Run nikto against target:port, returning full CSV stdout+stderr."""
    proc = subprocess.run(
        [
            "nikto", "-h", target, "-p", str(port),
            "-Format", "csv", "-nointeractive",
            "-maxtime", "45",   # hard cap: stop after 45 seconds regardless
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT_S,
    )
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _parse(target: str, raw: str) -> list[Finding]:
    """Parse Nikto CSV output into normalised Findings.

    Nikto CSV rows look like:
        "Nikto v2.1.6","10.0.0.5","10.0.0.5","80","0","GET","/","Apache/2.4.49 appears..."

    Rows beginning with '"Nikto' (the self-identifying header rows Nikto emits
    before and after scan blocks) are skipped. Empty rows are skipped.
    """
    findings: list[Finding] = []
    reader = csv.DictReader(
        io.StringIO(raw),
        fieldnames=["nikto_ver", _FIELD_HOST, "ip", _FIELD_PORT,
                    _FIELD_OSVDB, _FIELD_METHOD, _FIELD_PATH, _FIELD_DESC],
    )
    for row in reader:
        # Skip footer sentinel rows ("Nikto v2.1.6 - End Time") and blank rows.
        # NOTE: every normal data row also has "Nikto v2.1.6" in nikto_ver, so we
        # must NOT skip on that prefix alone — only skip when the description is empty
        # (which is the End Time row) or the first field contains "- End Time".
        if not row:
            continue
        first = (row.get("nikto_ver") or "").strip().strip('"')
        if "- End Time" in first or "- Start Time" in first:
            continue
        desc = (row.get(_FIELD_DESC) or "").strip().strip('"')
        if not desc:
            continue

        osvdb = (row.get(_FIELD_OSVDB) or "").strip().strip('"')
        method = (row.get(_FIELD_METHOD) or "GET").strip().strip('"')
        path = (row.get(_FIELD_PATH) or "/").strip().strip('"')
        port = (row.get(_FIELD_PORT) or "80").strip().strip('"')

        severity = _classify_severity(desc)
        cve = None
        # Nikto occasionally embeds CVE IDs directly in the description.
        # Tokens may be wrapped in parens: (CVE-2021-41773): — strip both ends.
        for token in desc.split():
            token_clean = token.lstrip("(").rstrip(".,;):")
            if token_clean.startswith("CVE-"):
                cve = token_clean
                break

        evidence = f"{method} {path}"
        if osvdb and osvdb != "0":
            evidence += f" (OSVDB-{osvdb})"

        findings.append(
            Finding(
                tool=TOOL_NAME,
                phase=PHASE,
                target=target,
                title=f"Nikto: {desc[:80]}{'…' if len(desc) > 80 else ''}",
                detail=f"port {port} — {desc}",
                severity=severity,
                cve=cve,
                evidence=evidence,
                mitre="T1190",   # Exploit Public-Facing Application
                raw=raw,
            )
        )
    return findings


@tool
def nikto_scan(target: str, port: int = 80) -> list[Finding]:
    """Run a Nikto web-server scan against an in-scope lab target and return
    normalised findings. Use during scanning after Nmap has confirmed an HTTP
    service is open. Reports misconfigurations, outdated software, and dangerous
    HTTP methods. Defaults to port 80; pass port=443 for HTTPS targets."""
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
    try:
        raw = _run(target, port)
    except EXEC_ERRORS as exc:
        return [exec_error_finding(TOOL_NAME, PHASE, target, exc)]
    findings = _parse(target, raw)
    return findings or [
        Finding(
            tool=TOOL_NAME,
            phase=PHASE,
            target=target,
            title="No findings",
            detail="Nikto scan returned no issues.",
            raw=raw,
        )
    ]
