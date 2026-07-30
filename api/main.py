"""FastAPI backend — routes + WebSocket. Agent orchestration entry point.

Endpoints:
  GET  /health                -> status + active scope
  POST /engagements           -> start an engagement against an in-scope lab target
  GET  /engagements/{id}       -> status + findings
  WS   /ws/{id}                -> live status stream (initial + final)

The engagement runner is held on `app.state.runner` (defaults to
graph.run_engagement) so tests can inject a fake runner — no Groq key, no real
tool subprocesses. Scope is re-validated server-side; never trust the client.

Persistence: findings are written to PostgreSQL (via FindingStore) on engagement
completion and reloaded from DB on GET /engagements/{id} if the in-memory cache
has lost them (e.g. after a server restart). DB is optional — if Postgres is
unreachable at startup the server continues with in-memory-only mode and logs a
warning. Tests set app.state.db = None to stay fully offline.

Run: uvicorn api.main:app --reload
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from uuid import uuid4

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Request, WebSocket, Depends, Security
from fastapi.responses import FileResponse
from fastapi.security import APIKeyHeader
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from agent.graph import run_engagement
from agent.scope import (
    add_scope, in_scope, list_scope, remove_scope, scope_summary,
    add_public_scope, list_public_scope, remove_public_scope,
)
from api.models import EngagementList, EngagementRequest, EngagementStatus, ScopeEntry, ScopeList

log = logging.getLogger("redagent.api")


# ── Lifespan (replaces deprecated @app.on_event) ─────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Connect to PostgreSQL on startup; yield; nothing to tear down."""
    try:
        from api.db import get_store
        app.state.db = await asyncio.to_thread(get_store)
        log.info("[DB] PostgreSQL connected — findings will be persisted.")
    except Exception as exc:  # noqa: BLE001
        log.warning("[DB] PostgreSQL unavailable (%s) — running in-memory only.", exc)
    yield


app = FastAPI(title="RedAgent", version="0.1.0", lifespan=lifespan)

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

API_KEY = os.environ.get("REDAGENT_API_KEY", "redagent-dev-key")
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=True)


def verify_api_key(api_key: str = Security(api_key_header)):
    if api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return api_key


# Default engagement runner; overridable in tests via app.state.runner.
app.state.runner = run_engagement
# Optional report LLM override (tests inject a fake; None -> configured Groq).
app.state.report_llm = None
# PostgreSQL FindingStore — None until startup; stays None if DB unreachable.
app.state.db = None

REPORT_DIR = "reports/out"

# In-memory engagement registry — live session cache (survives for the process
# lifetime). PostgreSQL is the durable store; this is the hot path.
ENGAGEMENTS: dict[str, dict] = {}


def _status(eng: dict) -> EngagementStatus:
    return EngagementStatus(
        id=eng["id"], target=eng["target"], state=eng["state"],
        findings=eng["findings"], error=eng["error"],
    )


def _emit(eng: dict, ev: dict) -> None:
    """Record an event and fan it out to all live WebSocket subscribers.
    Must run on the event loop thread (see _run's call_soon_threadsafe)."""
    eng["log"].append(ev)
    for q in list(eng["subscribers"]):
        q.put_nowait(ev)


def _call_runner(runner, target: str, on_event):
    """Call the engagement runner, passing on_event only if it accepts it (so
    plain test fakes taking just `target` still work)."""
    import inspect
    try:
        params = inspect.signature(runner).parameters
        if "on_event" in params or any(p.kind == p.VAR_KEYWORD for p in params.values()):
            return runner(target, on_event=on_event)
    except (TypeError, ValueError):
        pass
    return runner(target)


async def _run(eng: dict, runner) -> None:
    loop = asyncio.get_running_loop()

    def on_event(ev: dict) -> None:
        # Called from the worker thread; hop back onto the loop to touch state.
        loop.call_soon_threadsafe(_emit, eng, ev)

    try:
        findings = await asyncio.to_thread(_call_runner, runner, eng["target"], on_event)
        eng["findings"] = list(findings)
        eng["state"] = "done"
        # Persist to PostgreSQL (write-through). Fire-and-forget in a thread so
        # we don't block the event loop; errors are logged, not re-raised.
        if app.state.db is not None and eng["findings"]:
            try:
                await asyncio.to_thread(app.state.db.save, eng["id"], eng["findings"])
                log.info("[DB] Saved %d findings for engagement %s.",
                         len(eng["findings"]), eng["id"][:8])
            except Exception as db_exc:  # noqa: BLE001
                log.warning("[DB] Failed to persist findings: %s", db_exc)
    except Exception as exc:  # noqa: BLE001 - surface failure to the operator, don't crash
        eng["state"] = "error"
        eng["error"] = str(exc)
    finally:
        eng["event"].set()
        _emit(eng, {"type": "end"})  # already on the loop thread here


# ── Health ────────────────────────────────────────────────────────────────────

@app.get("/health", dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
def health(request: Request) -> dict:
    return {"status": "ok", "scope": scope_summary()}


# ── Engagements ───────────────────────────────────────────────────────────────

@app.post("/engagements", response_model=EngagementStatus, dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def create_engagement(req: EngagementRequest, request: Request) -> EngagementStatus:
    # Server-side scope gate — defense in depth on top of the per-tool gate.
    if not in_scope(req.target):
        raise HTTPException(status_code=403, detail=f"Target {req.target!r} not in scope; refused.")
    eid = uuid4().hex
    eng = {
        "id": eid, "target": req.target, "state": "running",
        "findings": [], "error": None, "event": asyncio.Event(),
        "log": [], "subscribers": [],
    }
    ENGAGEMENTS[eid] = eng
    asyncio.create_task(_run(eng, request.app.state.runner))
    return _status(eng)


@app.get("/engagements", response_model=EngagementList, dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def list_engagements(request: Request) -> EngagementList:
    if request.app.state.db is None:
        return EngagementList(engagements=[])
    try:
        sessions = await asyncio.to_thread(request.app.state.db.list_sessions)
        return EngagementList(engagements=sessions)
    except Exception as db_exc:
        log.warning("[DB] list_sessions failed: %s", db_exc)
        return EngagementList(engagements=[])


@app.get("/engagements/{engagement_id}", response_model=EngagementStatus, dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
async def get_engagement(engagement_id: str, request: Request) -> EngagementStatus:
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        # Not in the live cache — try to restore from PostgreSQL (e.g. after a
        # server restart). Returns a static snapshot; WebSocket is not available.
        if app.state.db is not None:
            try:
                findings = await asyncio.to_thread(app.state.db.load, engagement_id)
                if findings:
                    return EngagementStatus(
                        id=engagement_id, target=findings[0].target,
                        state="done", findings=findings, error=None,
                    )
            except Exception as db_exc:  # noqa: BLE001
                log.warning("[DB] load failed for %s: %s", engagement_id[:8], db_exc)
        raise HTTPException(status_code=404, detail="Unknown engagement.")
    return _status(eng)


# ── Scope — Authorized Public (must be registered BEFORE /scope to avoid
#    FastAPI path shadowing: /scope/public would be shadowed by /scope/{...}) ──

@app.get("/scope/public", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
def get_public_scope(request: Request) -> ScopeList:
    """List all authorized-public scope entries (env + runtime)."""
    return ScopeList(scope=list_public_scope())


@app.post("/scope/public", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
def add_public_scope_entry(body: ScopeEntry, request: Request) -> ScopeList:
    """Add a public IP/CIDR/hostname you own to the authorized-public allowlist.
    The operator asserts they are authorized to test this target."""
    if not add_public_scope(body.entry):
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scope entry (unresolvable IP/CIDR/hostname): {body.entry!r}",
        )
    return ScopeList(scope=list_public_scope())


@app.delete("/scope/public", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
def delete_public_scope_entry(body: ScopeEntry, request: Request) -> ScopeList:
    """Remove a runtime authorized-public scope entry."""
    if not remove_public_scope(body.entry):
        raise HTTPException(status_code=404, detail=f"Public scope entry not found: {body.entry!r}")
    return ScopeList(scope=list_public_scope())


# ── Scope — Lab (private / loopback only) ─────────────────────────────────────

@app.get("/scope", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("60/minute")
def get_scope(request: Request) -> ScopeList:
    return ScopeList(scope=list_scope())


@app.post("/scope", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
def add_scope_entry(body: ScopeEntry, request: Request) -> ScopeList:
    # add_scope enforces lab-only (private/loopback) and rejects malformed entries.
    if not add_scope(body.entry):
        raise HTTPException(status_code=400,
                            detail=f"Invalid or non-lab scope entry: {body.entry!r}")
    return ScopeList(scope=list_scope())


@app.delete("/scope", response_model=ScopeList, dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
def delete_scope_entry(body: ScopeEntry, request: Request) -> ScopeList:
    if not remove_scope(body.entry):
        raise HTTPException(status_code=404, detail=f"Scope entry not found: {body.entry!r}")
    return ScopeList(scope=list_scope())


# ── Report export ─────────────────────────────────────────────────────────────

@app.post("/engagements/{engagement_id}/report", dependencies=[Depends(verify_api_key)])
@limiter.limit("5/minute")
async def export_report(engagement_id: str, request: Request):
    eng = ENGAGEMENTS.get(engagement_id)
    findings = None
    target = None

    if eng is not None:
        findings = eng.get("findings", [])
        target = eng.get("target")
    elif request.app.state.db is not None:
        try:
            db_findings = await asyncio.to_thread(request.app.state.db.load, engagement_id)
            if db_findings:
                findings = db_findings
                target = db_findings[0].target
        except Exception as db_exc:  # noqa: BLE001
            log.warning("[DB] load failed for report %s: %s", engagement_id[:8], db_exc)

    if findings is None:
        raise HTTPException(status_code=404, detail="Unknown engagement.")
    if not findings:
        raise HTTPException(status_code=400, detail="No findings to report yet.")

    from reports.generator import generate_report

    os.makedirs(REPORT_DIR, exist_ok=True)
    out_path = os.path.join(REPORT_DIR, f"{engagement_id}.pdf")
    # offload report generation to thread since it's synchronous and CPU-bound
    await asyncio.to_thread(
        generate_report, engagement_id, findings, out_path,
        llm=request.app.state.report_llm, target=target
    )
    return FileResponse(out_path, media_type="application/pdf",
                        filename=f"redagent-{engagement_id}.pdf")


# ── WebSocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/{engagement_id}")
async def engagement_ws(websocket: WebSocket, engagement_id: str, token: str | None = None) -> None:
    await websocket.accept()
    if token != API_KEY:
        await websocket.close(code=1008, reason="Unauthorized")
        return
    eng = ENGAGEMENTS.get(engagement_id)
    if eng is None:
        await websocket.send_json({"error": "unknown engagement"})
        await websocket.close()
        return

    # Register + snapshot the log in one synchronous section (no await) so no
    # event can interleave and be duplicated or missed.
    q: asyncio.Queue = asyncio.Queue()
    pending = list(eng["log"])
    eng["subscribers"].append(q)
    ended = any(e.get("type") == "end" for e in pending)

    try:
        await websocket.send_json({"type": "status", **_status(eng).model_dump()})
        for ev in pending:
            if ev.get("type") != "end":
                await websocket.send_json(ev)
        if not ended:
            while True:
                ev = await q.get()
                if ev.get("type") == "end":
                    break
                await websocket.send_json(ev)
        await websocket.send_json({"type": "status", **_status(eng).model_dump()})
    finally:
        if q in eng["subscribers"]:
            eng["subscribers"].remove(q)
        await websocket.close()
