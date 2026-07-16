"""SQLMap wrapper — exploitation. Detection ONLY by default (safe mode).

NON-NEGOTIABLE (CLAUDE.md): default is detection (`--batch`, no `--dump`).
Destructive extraction requires an explicit operator opt-in arg passed through
the API — never hardcoded, never defaulted on. Follows the five-stage wrapper
contract (see the redagent-tool-wrapper skill).
"""

from __future__ import annotations

import re
import subprocess

from langchain_core.tools import tool

from agent.scope import in_scope
from agent.tools.schema import Finding

TOOL_NAME = "sqlmap"
PHASE = "exploitation"
TIMEOUT_S = 900

_PARAM_RE = re.compile(r"([^\s(]+)\s*(?:\(([^)]+)\))?")
_DBMS_RE = re.compile(r"back-end DBMS:\s*(?:is\s*)?([^\n]+)", re.IGNORECASE)


def _run(target: str, allow_dump: bool) -> str:
    args = ["sqlmap", "-u", target, "--batch", "-v", "0"]
    if allow_dump:
        args.append("--dump")  # destructive extraction — operator opt-in only
    proc = subprocess.run(args, capture_output=True, text=True, timeout=TIMEOUT_S)
    return proc.stdout + ("\n" + proc.stderr if proc.stderr else "")


def _parse(target: str, raw: str) -> list[Finding]:
    if "Parameter:" not in raw:
        return []
    findings: list[Finding] = []
    dbms_match = _DBMS_RE.search(raw)
    dbms = dbms_match.group(1).strip() if dbms_match else None

    # Each injectable parameter is introduced by a "Parameter:" line.
    for block in re.split(r"\nParameter:\s*", raw)[1:]:
        header = block.splitlines()[0] if block.splitlines() else ""
        m = _PARAM_RE.match(header)
        if not m:
            continue
        param, place = m.group(1), (m.group(2) or "")
        types = re.findall(r"Type:\s*([^\n]+)", block)
        titles = re.findall(r"Title:\s*([^\n]+)", block)
        where = f" ({place})" if place else ""
        detail = (f"Parameter '{param}'{where} is injectable"
                  + (f" [{', '.join(t.strip() for t in types)}]" if types else "")
                  + (f"; back-end DBMS {dbms}" if dbms else ""))
        findings.append(
            Finding(
                tool=TOOL_NAME, phase=PHASE, target=target,
                title=f"SQL injection in parameter '{param}'",
                detail=detail,
                service=dbms,
                severity="High",
                mitre="T1190",
                evidence="; ".join(t.strip() for t in titles) or None,
                raw=raw,
            )
        )
    return findings


@tool
def sqlmap_scan(target: str, allow_dump: bool = False) -> list[Finding]:
    """Test an in-scope lab URL for SQL injection. Detection only by default;
    set allow_dump=True only with explicit operator authorization (destructive
    data extraction). Use during exploitation on web targets with parameters."""
    if not in_scope(target):
        return [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                        title="Out of scope",
                        detail="Target not in operator scope list; not executed.")]
    raw = _run(target, allow_dump)
    findings = _parse(target, raw)
    return findings or [Finding(tool=TOOL_NAME, phase=PHASE, target=target,
                               title="No SQL injection found",
                               detail="SQLMap detected no injectable parameters.",
                               raw=raw)]
