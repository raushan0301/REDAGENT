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
        "findings": [{"title": f.title, "cve": f.cve, "cvss": f.cvss, "tool": f.tool, "severity": severity_of(f)} for f in rank_findings(findings)],
        "mitre": mitre_map(findings),
        "summary": narrative.get("summary", ""),
        "remediation": narrative.get("remediation", ""),
    }


def render_pdf(context: dict, out_path: str) -> str:
    """Render the report context to a PDF at out_path using Jinja2 and xhtml2pdf."""
    import os
    from jinja2 import Environment, FileSystemLoader
    from xhtml2pdf import pisa

    template_dir = os.path.join(os.path.dirname(__file__), "templates")
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template("report.html.j2")
    
    html_out = template.render(context)
    
    with open(out_path, "wb") as pdf_file:
        pisa_status = pisa.CreatePDF(html_out, dest=pdf_file)
        
    if pisa_status.err:
        raise RuntimeError(f"PDF generation failed with errors: {pisa_status.err}")
        
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
