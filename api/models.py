"""Pydantic API models. STUB (Month 1, Week 4).

Re-exports the shared Finding and adds request/response envelopes. The API must
re-validate scope server-side — never trust a client-supplied target.
"""

from __future__ import annotations

from pydantic import BaseModel

from agent.tools.schema import Finding  # noqa: F401  (shared schema, re-exported)


class EngagementRequest(BaseModel):
    target: str
    allow_destructive: bool = False   # explicit operator opt-in; default safe


class ScopeEntry(BaseModel):
    entry: str                        # IP or CIDR, e.g. "10.0.0.0/24"


class ScopeList(BaseModel):
    scope: list[str]


class EngagementStatus(BaseModel):
    id: str
    target: str
    state: str                        # queued | running | done | error
    findings: list[Finding] = []
    error: str | None = None
