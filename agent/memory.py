"""Agent memory.

Short-term: a COMPACT running state summary fed to the agent each step (never the
raw transcript — this is the main token lever for Groq's free tier).
Long-term: findings persisted to PostgreSQL across sessions (Chunk 5 / Week 2).
"""

from __future__ import annotations

from agent.tools.schema import Finding

# Keep the summary bounded so it never blows the TPM budget.
_MAX_ITEMS_PER_SECTION = 12
_STATUS_TITLES = {"Out of scope", "No findings", "Not implemented"}


def _dedupe(items: list[str]) -> list[str]:
    """Order-preserving de-duplication."""
    seen: set[str] = set()
    out: list[str] = []
    for it in items:
        if it not in seen:
            seen.add(it)
            out.append(it)
    return out


def _cap(items: list[str]) -> list[str]:
    if len(items) <= _MAX_ITEMS_PER_SECTION:
        return items
    extra = len(items) - _MAX_ITEMS_PER_SECTION
    return items[:_MAX_ITEMS_PER_SECTION] + [f"(+{extra} more)"]


def _is_signal(f: Finding) -> bool:
    """Filter out status/placeholder findings (out-of-scope, no-result, stubs)."""
    return f.title not in _STATUS_TITLES


def _is_vuln(f: Finding) -> bool:
    return bool(f.cve) or (f.severity in ("High", "Critical"))


def _vuln_line(f: Finding) -> str:
    label = f.cve or f.title
    bits = []
    if f.severity:
        bits.append(f.severity)
    if f.cvss is not None:
        bits.append(f"CVSS {f.cvss}")
    return f"{label} ({', '.join(bits)})" if bits else label


def summarize_state(findings: list[Finding], seen_actions: set[str]) -> str:
    """Return a short, bounded state summary for the next agent step.

    Sections (omitted when empty): target, open services (recon), vulnerabilities
    (has CVE or High/Critical), and actions already tried. Status/placeholder
    findings are excluded so the agent reasons only over real signal.
    """
    signal = [f for f in findings if _is_signal(f)]

    lines: list[str] = []

    targets = _dedupe([f.target for f in signal])
    if len(targets) == 1:
        lines.append(f"Target: {targets[0]}")
    elif len(targets) > 1:
        lines.append(f"Targets: {', '.join(_cap(targets))}")

    services = _dedupe([f.title for f in signal if f.phase == "recon"])
    if services:
        lines.append("Open services: " + "; ".join(_cap(services)))

    vulns = _dedupe([_vuln_line(f) for f in signal if _is_vuln(f)])
    if vulns:
        lines.append("Vulnerabilities: " + "; ".join(_cap(vulns)))

    if seen_actions:
        lines.append("Tried: " + ", ".join(_cap(sorted(seen_actions))))

    return "\n".join(lines) if lines else "No findings yet."


def persist_findings(session_id: str, findings: list[Finding]) -> None:
    """Write findings to PostgreSQL long-term store. STUB (Chunk 5 / Week 2)."""
    raise NotImplementedError("persist_findings stub — wire PostgreSQL (Chunk 5).")
