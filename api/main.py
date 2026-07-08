"""FastAPI backend — routes + WebSocket. Agent orchestration entry point.

STUB (Month 1, Week 4). The dashboard talks to this over WebSocket for the live
reasoning stream and findings feed. Run: uvicorn api.main:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from agent.scope import scope_summary

app = FastAPI(title="RedAgent", version="0.1.0")


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "scope": scope_summary()}


# TODO (Week 4):
#   POST /engagements        -> start an engagement against an in-scope target
#   GET  /engagements/{id}   -> status + findings
#   WS   /ws/{id}            -> live reasoning stream + findings feed
#   scope management routes (add/remove/list) — server-side re-validation
