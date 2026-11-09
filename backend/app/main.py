"""FastAPI application: REST API + WebSocket stream for the SOC dashboard.

Run locally:  uvicorn app.main:app --reload --port 8000   (from the backend/ folder)
API docs:     http://localhost:8000/docs
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import simulator
from .auth import Auth
from .config import get_settings
from .intel import importer
from .llm import check_llm
from .service import SOCService

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
settings = get_settings()
auth = Auth(settings)
state: dict[str, Any] = {}


def svc() -> SOCService:
    return state["service"]


@asynccontextmanager
async def lifespan(_: FastAPI):
    service = SOCService(settings)
    state["service"] = service
    loaded = await asyncio.to_thread(service.bootstrap_intel)
    logging.getLogger("soc").info("Loaded %d intel records into %s", loaded, service.rag.backend)
    yield


app = FastAPI(title="Agentic SOC API", version="1.0.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins or ["*"], allow_credentials=True,
                   allow_methods=["*"], allow_headers=["*"])


# ------------------------------------------------------------------ auth
def analyst(authorization: Optional[str] = Header(default=None)) -> str:
    token = authorization.split(" ", 1)[1] if authorization and authorization.lower().startswith("bearer ") else None
    user = auth.verify(token)
    if not user:
        raise HTTPException(status_code=401, detail="Not signed in")
    return user


class LoginIn(BaseModel):
    username: str = "analyst"
    password: str = ""


@app.post("/api/auth/login")
def login(body: LoginIn):
    token = auth.login(body.username, body.password)
    if not token:
        raise HTTPException(status_code=401, detail="Wrong username or password")
    return {"token": token, "username": body.username}


# ------------------------------------------------------------------ status
@app.get("/api/health")
async def health():
    s = svc()
    return {
        "status": "ok",
        "auth_required": auth.enabled,
        "demo_mode": settings.demo_mode,
        "llm": await check_llm(settings),
        "vector_store": s.rag.backend,
        "intel_records": s.rag.count(),
        "firewall_provider": settings.firewall_provider,
        "identity_provider": settings.identity_provider,
        "auto_approve": settings.auto_approve,
    }


@app.get("/api/stats")
def stats(_: str = Depends(analyst)):
    return svc().db.stats()


# ------------------------------------------------------------------ alerts
class AlertIn(BaseModel):
    title: str = Field(..., max_length=300)
    description: str = Field("", max_length=5000)
    category: str = "network"
    severity: str = "medium"
    source: str = "api"
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    username: Optional[str] = None
    raw: dict = Field(default_factory=dict)


@app.post("/api/alerts", status_code=201)
async def ingest_alert(body: AlertIn, x_api_key: Optional[str] = Header(default=None),
                       authorization: Optional[str] = Header(default=None)):
    """Webhook for your SIEM / IDS. Send header X-API-Key: <INGEST_API_KEY>."""
    if not auth.check_ingest_key(x_api_key):
        analyst(authorization)  # fall back to an analyst bearer token
    payload = body.model_dump()
    if payload["severity"] not in {"low", "medium", "high", "critical"}:
        payload["severity"] = "medium"
    return svc().ingest_alert(payload)


@app.get("/api/alerts")
def list_alerts(status: Optional[str] = None, limit: int = Query(100, le=500), _: str = Depends(analyst)):
    return svc().db.list_alerts(limit=limit, status=status)


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str, _: str = Depends(analyst)):
    s = svc()
    alert = s.db.get_alert(alert_id)
    if not alert:
        raise HTTPException(404, "Alert not found")
    return {"alert": alert, "traces": s.db.list_traces(alert_id), "actions": s.db.list_actions(alert_id=alert_id)}


@app.post("/api/alerts/{alert_id}/rerun")
async def rerun(alert_id: str, user: str = Depends(analyst)):
    s = svc()
    if not s.db.get_alert(alert_id):
        raise HTTPException(404, "Alert not found")
    s.db.audit(user, "rerun_triage", {"alert_id": alert_id})
    s.start_pipeline(alert_id)
    return {"status": "started"}


@app.post("/api/simulate", status_code=201)
async def simulate(scenario: Optional[int] = None, _: str = Depends(analyst)):
    return svc().ingest_alert(simulator.random_alert(scenario))


@app.get("/api/simulate/scenarios")
def scenarios(_: str = Depends(analyst)):
    return [{"index": i, "title": s["title"], "category": s["category"]} for i, s in enumerate(simulator.SCENARIOS)]


# ------------------------------------------------------------------ approvals / SOAR
@app.get("/api/actions")
def list_actions(status: Optional[str] = None, _: str = Depends(analyst)):
    return svc().db.list_actions(status=status)


async def _decide(action_id: str, approve: bool, user: str):
    try:
        return await svc().decide(action_id, approve, user)
    except KeyError:
        raise HTTPException(404, "Action not found")
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.post("/api/actions/{action_id}/approve")
async def approve(action_id: str, user: str = Depends(analyst)):
    return await _decide(action_id, True, user)


@app.post("/api/actions/{action_id}/reject")
async def reject(action_id: str, user: str = Depends(analyst)):
    return await _decide(action_id, False, user)


@app.get("/api/blocklist")
def blocklist(_: str = Depends(analyst)):
    return svc().db.list_blocks()


@app.delete("/api/blocklist/{target}")
async def unblock(target: str, user: str = Depends(analyst)):
    try:
        return await svc().unblock(target, user)
    except KeyError:
        raise HTTPException(404, "Not on the blocklist")
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ------------------------------------------------------------------ threat intel (RAG)
@app.get("/api/intel/search")
def intel_search(q: str = Query(..., min_length=2), k: int = Query(8, le=25), _: str = Depends(analyst)):
    s = svc()
    exact = s.db.find_intel_by_value(q.strip())
    return {"exact": exact, "semantic": s.rag.search(q, k=k)}


@app.get("/api/intel/stats")
def intel_stats(_: str = Depends(analyst)):
    s = svc()
    return {"by_source": s.db.intel_counts(), "vector_store": s.rag.backend, "vectors": s.rag.count()}


class IntelImportIn(BaseModel):
    filename: str = Field(..., max_length=200)
    content: str = Field(..., max_length=20_000_000)
    source: Optional[str] = None


@app.post("/api/intel/import")
async def intel_import(body: IntelImportIn, user: str = Depends(analyst)):
    try:
        records = importer.parse_intel(body.content, body.filename, default_source=body.source or "import")
    except Exception as exc:
        raise HTTPException(400, f"Could not parse file: {exc}")
    count = await asyncio.to_thread(svc().add_intel, records)
    svc().db.audit(user, "intel_import", {"file": body.filename, "records": count})
    return {"imported": count}


@app.get("/api/audit")
def audit(_: str = Depends(analyst)):
    return svc().db.list_audit()


# ------------------------------------------------------------------ live stream
@app.websocket("/ws")
async def stream(ws: WebSocket, token: Optional[str] = None):
    if not auth.verify(token):
        await ws.close(code=4401)
        return
    await ws.accept()
    queue = svc().broker.subscribe()
    try:
        await ws.send_json({"type": "hello", "payload": {"ok": True}})
        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=25)
                await ws.send_json(event)
            except asyncio.TimeoutError:
                await ws.send_json({"type": "ping", "payload": {}})
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        svc().broker.unsubscribe(queue)
