"""Agent memory.

Short-term: a COMPACT running state summary fed to the agent each step (never the
raw transcript — this is the main token lever for Groq's free tier).
Long-term: findings persisted to PostgreSQL across sessions.

STUB (Month 1, Week 2/4).
"""

from __future__ import annotations

from agent.tools.schema import Finding


def summarize_state(findings: list[Finding], seen_actions: set[str]) -> str:
    """Return a short natural-language state summary for the next agent step.
    Keep this tight — it is resent on every iteration."""
    # TODO: compress to a few lines (open ports, confirmed vulns, what's been tried).
    raise NotImplementedError("summarize_state stub — implement compact summary (Week 2).")


def persist_findings(session_id: str, findings: list[Finding]) -> None:
    """Write findings to PostgreSQL long-term store. STUB (Week 2)."""
    raise NotImplementedError("persist_findings stub — wire PostgreSQL (Week 2).")
