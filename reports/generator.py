"""Report engine — CVSS aggregation + LLM narrative + MITRE ATT&CK + PDF.

Pure aggregation/mapping helpers are unit-tested offline. The LLM is injectable
(fake in tests — no Groq). reportlab is imported lazily inside render_pdf so the
pure helpers import without it. Raw tool output stays in Finding.raw (appendix),
never in the agent loop.
"""

from __future__ import annotations

import time
from typing import Optional

from agent.tools.schema import Finding, severity_from_cvss

# Severity ordering, high -> low (Info/None last).
_SEV_ORDER = ["Critical", "High", "Medium", "Low", "Info"]
_SEV_RANK = {s: i for i, s in enumerate(_SEV_ORDER)}

# Minimal phase -> MITRE ATT&CK technique mapping (finding.mitre overrides).
_PHASE_MITRE = {
    "recon": ("T1046", "Network Service Discovery"),
    "scanning": ("T1595", "Active Scanning"),
    "exploitation": ("T1190", "Exploit Public-Facing Application"),
    "post-exploit": ("T1059", "Command and Scripting Interpreter"),
}
_MITRE_NAMES = {tid: name for tid, name in _PHASE_MITRE.values()}


def severity_of(f: Finding) -> Optional[str]:
    """Effective severity: explicit field, else derived from CVSS."""
    sev = f.severity or severity_from_cvss(f.cvss)
    if sev in ("None", None):
        return None
    return sev if sev in _SEV_RANK else "Info"


def summarize_severities(findings: list[Finding]) -> dict[str, int]:
    counts = {s: 0 for s in _SEV_ORDER}
    for f in findings:
        sev = severity_of(f)
        if sev:
            counts[sev] += 1
    return counts


def risk_rating(findings: list[Finding]) -> str:
    counts = summarize_severities(findings)
    for sev in _SEV_ORDER:
        if counts[sev]:
            return sev if sev != "Info" else "Informational"
    return "Informational"


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort by severity (Critical first) then CVSS desc."""
    def key(f: Finding):
        sev = severity_of(f)
        return (_SEV_RANK.get(sev, len(_SEV_ORDER)), -(f.cvss or 0.0))
    return sorted(findings, key=key)


def mitre_map(findings: list[Finding]) -> list[dict]:
    """Unique ATT&CK techniques touched, sorted by id."""
    techniques: dict[str, str] = {}
    for f in findings:
        if f.mitre:
            techniques.setdefault(f.mitre, _MITRE_NAMES.get(f.mitre, ""))
        elif f.phase in _PHASE_MITRE:
            tid, name = _PHASE_MITRE[f.phase]
            techniques.setdefault(tid, name)
    return [{"id": tid, "name": name} for tid, name in sorted(techniques.items())]


# --- LLM narrative ----------------------------------------------------------

def _digest(findings: list[Finding]) -> str:
    counts = summarize_severities(findings)
    line = ", ".join(f"{k}: {v}" for k, v in counts.items() if v)
    top = rank_findings(findings)[:8]
    bullets = "\n".join(
        f"- {severity_of(f) or 'Info'} | {f.title}"
        + (f" ({f.cve}, CVSS {f.cvss})" if f.cve else "")
        for f in top
    )
    return f"Severity counts: {line or 'none'}\nTop findings:\n{bullets or '(none)'}"


def _ask(llm, instruction: str, context: str) -> str:
    from langchain_core.messages import HumanMessage, SystemMessage
    msgs = [
        SystemMessage("You write concise, professional penetration-test report prose."),
        HumanMessage(f"{instruction}\n\nEngagement findings:\n{context}"),
    ]
    return llm.invoke(msgs).content.strip()


def generate_narrative(findings: list[Finding], llm) -> dict[str, str]:
    """Return {'summary', 'remediation'} written by the LLM from a compact digest."""
    context = _digest(findings)
    summary = _ask(llm, "Write a 3-5 sentence executive summary for leadership.", context)
    remediation = _ask(llm, "Write prioritized remediation steps as short bullets.", context)
    return {"summary": summary, "remediation": remediation}


# --- Context + PDF ----------------------------------------------------------

def build_report_context(session_id: str, target: str, findings: list[Finding],
                         narrative: dict[str, str]) -> dict:
    return {
        "session_id": session_id,
        "target": target,
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "risk": risk_rating(findings),
        "counts": summarize_severities(findings),
        "total": len(findings),
        "findings": rank_findings(findings),
        "mitre": mitre_map(findings),
        "summary": narrative.get("summary", ""),
        "remediation": narrative.get("remediation", ""),
    }


def render_pdf(context: dict, out_path: str) -> str:
    """Render the report context to a PDF at out_path (reportlab)."""
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import (Paragraph, SimpleDocTemplate, Spacer,
                                    Table, TableStyle)

    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("RedAgent — Penetration Test Report", styles["Title"]))
    story.append(Paragraph(
        f"Target: {context['target']} &nbsp;|&nbsp; Session: {context['session_id']} "
        f"&nbsp;|&nbsp; Generated: {context['generated_at']}", styles["Normal"]))
    story.append(Paragraph(f"Overall risk rating: <b>{context['risk']}</b>", styles["Heading2"]))
    story.append(Spacer(1, 10))

    # Severity summary table
    counts = context["counts"]
    sev_rows = [["Severity", "Count"]] + [[s, str(counts[s])] for s in counts]
    sev_table = Table(sev_rows, colWidths=[200, 80])
    sev_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
    ]))
    story.append(sev_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("Executive Summary", styles["Heading2"]))
    story.append(Paragraph(context["summary"] or "(none)", styles["Normal"]))
    story.append(Spacer(1, 12))

    # Findings table
    story.append(Paragraph("Findings", styles["Heading2"]))
    rows = [["Severity", "Title", "CVE", "CVSS", "Tool"]]
    for f in context["findings"]:
        rows.append([severity_of(f) or "Info", f.title, f.cve or "-",
                     "" if f.cvss is None else str(f.cvss), f.tool])
    findings_table = Table(rows, colWidths=[60, 230, 90, 45, 60])
    findings_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
    ]))
    story.append(findings_table)
    story.append(Spacer(1, 12))

    if context["mitre"]:
        story.append(Paragraph("MITRE ATT&CK Techniques", styles["Heading2"]))
        for t in context["mitre"]:
            story.append(Paragraph(f"{t['id']} — {t['name']}", styles["Normal"]))
        story.append(Spacer(1, 12))

    story.append(Paragraph("Remediation", styles["Heading2"]))
    story.append(Paragraph((context["remediation"] or "(none)").replace("\n", "<br/>"),
                           styles["Normal"]))

    SimpleDocTemplate(out_path, pagesize=letter).build(story)
    return out_path


def generate_report(session_id: str, findings: list[Finding], out_path: str,
                    llm=None, target: Optional[str] = None) -> str:
    """Full report: LLM narrative -> context -> PDF at out_path."""
    if llm is None:
        from agent.config import get_llm
        llm = get_llm()
    if target is None:
        target = findings[0].target if findings else "unknown"
    narrative = generate_narrative(findings, llm)
    context = build_report_context(session_id, target, findings, narrative)
    return render_pdf(context, out_path)
