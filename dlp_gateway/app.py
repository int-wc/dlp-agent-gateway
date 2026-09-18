"""Authenticated upload enforcement, audit and operations API."""

import hashlib
import hmac
import json
import re
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import Depends, FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from .config import Config, MAX_BYTES
from .db import Store, now
from .inspection import inspect


class PolicyInput(BaseModel):
    keyword: str = Field(min_length=2, max_length=64)
    action: str = Field(pattern="^(block|review)$")
    scope: str = Field(pattern="^(all|internal|external)$")
    enabled: bool = True


class UserInput(BaseModel):
    status: str = Field(pattern="^(normal|privileged|departing)$")


class ExceptionInput(BaseModel):
    audit_id: int
    justification: str = Field(min_length=8, max_length=240)


class ApprovalInput(BaseModel):
    hours: int = Field(default=1, ge=1, le=24)


class FeedbackInput(BaseModel):
    verdict: str = Field(pattern="^(true_positive|false_positive)$")
    note: str = Field(default="", max_length=240)


def create_app(config: Config) -> FastAPI:
    store = Store(config.db_path)
    app = FastAPI(title="DLP Agent Gateway", version="0.1.0",
        description="Reference implementation; not a production-ready DLP control")
    app.state.store = store

    def bearer(request: Request) -> str:
        value = request.headers.get("Authorization", "")
        if not value.startswith("Bearer "):
            raise HTTPException(401, "Bearer token required")
        return value[7:]

    def client(request: Request) -> str:
        token = bearer(request)
        for actor, key in config.client_keys.items():
            if hmac.compare_digest(token, key):
                return actor
        raise HTTPException(401, "Invalid client token")

    def admin(request: Request) -> None:
        if not hmac.compare_digest(bearer(request), config.admin_key):
            raise HTTPException(401, "Invalid admin token")

    @app.get("/health")
    def health():
        return {"status": "ok", "model_enabled": bool(config.ollama_model)}

    @app.get("/console", response_class=HTMLResponse, include_in_schema=False)
    def console():
        from importlib.resources import files
        return files("dlp_gateway").joinpath("console.html").read_text(encoding="utf-8")

    @app.get("/v1/destinations")
    def destinations(actor: str = Depends(client)):
        return {name: {"kind": dest.kind, "forwarding_configured": bool(dest.url)}
                for name, dest in config.destinations.items()}

    async def check_upload(destination: str, file: UploadFile, actor: str, forward: bool):
        dest = config.destinations.get(destination)
        if dest is None:
            raise HTTPException(404, "Unknown destination")
        # Multipart is spooled by the framework; bounded reads prevent an unbounded
        # in-memory payload. A reverse proxy must enforce the whole request limit.
        data = await file.read(MAX_BYTES + 1)
        measured_size = file.size if file.size is not None else len(data)
        filename = re.sub(r"[\x00-\x1f\x7f]", "_",
            (file.filename or "unnamed").replace("\\", "/").split("/")[-1])[:180]
        digest = hashlib.sha256(data).hexdigest() if len(data) <= MAX_BYTES else ""
        if not data or len(data) > MAX_BYTES:
            reason = "empty_file" if not data else "file_too_large"
            audit_id = store.audit(actor=actor, destination=destination, filename=filename,
                sha256=digest, size=measured_size, action="block", reasons=[reason],
                signals=[], model_status="skipped")
            raise HTTPException(400 if not data else 413, {"audit_id": audit_id, "reason": reason})
        verdict = await inspect(data, filename, dest, store.user_status(actor), store.policies(),
            store.approved(actor, destination, digest), config)
        audit_id = store.audit(actor=actor, destination=destination, filename=filename,
            sha256=digest, size=measured_size, **verdict)
        result = {"audit_id": audit_id, "destination": destination, "sha256": digest,
            **verdict, "forwarded": False}
        if not forward or verdict["action"] != "allow":
            return result
        if not dest.url:
            raise HTTPException(503, {"audit_id": audit_id, "reason": "forwarding_not_configured"})
        try:
            async with httpx.AsyncClient(timeout=10, trust_env=False, follow_redirects=False,
                    transport=getattr(app.state, "upstream_transport", None)) as upstream:
                response = await upstream.post(dest.url, files={"file": (filename, data,
                    "application/octet-stream")}, headers={"X-DLP-Audit-ID": str(audit_id)})
            if response.is_redirect or not 200 <= response.status_code < 300:
                store.execute("UPDATE audits SET upstream_status=? WHERE id=?",
                    (response.status_code, audit_id))
                raise HTTPException(502, {"audit_id": audit_id, "reason": "upstream_rejected"})
            store.execute("UPDATE audits SET forwarded=1, upstream_status=? WHERE id=?",
                (response.status_code, audit_id))
            result["forwarded"] = True
            result["upstream_status"] = response.status_code
            return result
        except httpx.HTTPError:
            raise HTTPException(502, {"audit_id": audit_id, "reason": "upstream_unavailable"})

    @app.post("/v1/check/{destination}")
    async def check(destination: str, file: UploadFile = File(...), actor: str = Depends(client)):
        return await check_upload(destination, file, actor, False)

    @app.post("/v1/forward/{destination}")
    async def forward(destination: str, file: UploadFile = File(...), actor: str = Depends(client)):
        return await check_upload(destination, file, actor, True)

    @app.post("/v1/exceptions", status_code=201)
    def request_exception(payload: ExceptionInput, actor: str = Depends(client)):
        audit = store.one("SELECT * FROM audits WHERE id=? AND actor=?", (payload.audit_id, actor))
        if not audit or audit["action"] not in {"block", "review"}:
            raise HTTPException(404, "Eligible audit not found")
        reasons = json.loads(audit["reasons"])
        if not any(reason.startswith("policy_") for reason in reasons):
            raise HTTPException(400, "Only policy decisions can receive a scoped exception")
        existing = store.one("SELECT id FROM exceptions WHERE audit_id=?", (payload.audit_id,))
        if existing:
            raise HTTPException(409, "Exception already requested")
        exception_id = store.execute("""INSERT INTO exceptions
            (audit_id,actor,destination,sha256,justification,created_at)
            VALUES(?,?,?,?,?,?)""", (payload.audit_id, actor, audit["destination"],
            audit["sha256"], payload.justification, now()))
        return {"id": exception_id, "status": "pending"}

    @app.get("/v1/admin/audits")
    def audits(limit: int = 50, _: None = Depends(admin)):
        if not 1 <= limit <= 200:
            raise HTTPException(400, "limit must be 1..200")
        return store.rows("SELECT * FROM audits ORDER BY id DESC LIMIT ?", (limit,))

    @app.get("/v1/admin/policies")
    def policies(_: None = Depends(admin)):
        return store.policies()

    @app.post("/v1/admin/policies", status_code=201)
    def add_policy(payload: PolicyInput, _: None = Depends(admin)):
        if not payload.keyword.strip():
            raise HTTPException(400, "Empty keyword")
        policy_id = store.execute("INSERT INTO policies(keyword,action,scope,enabled) VALUES(?,?,?,?)",
            (payload.keyword, payload.action, payload.scope, int(payload.enabled)))
        store.event("policy_created", str(policy_id))
        return {"id": policy_id}

    @app.put("/v1/admin/policies/{policy_id}")
    def update_policy(policy_id: int, payload: PolicyInput, _: None = Depends(admin)):
        if not store.one("SELECT id FROM policies WHERE id=?", (policy_id,)):
            raise HTTPException(404, "Policy not found")
        if not payload.keyword.strip():
            raise HTTPException(400, "Empty keyword")
        store.execute("UPDATE policies SET keyword=?,action=?,scope=?,enabled=? WHERE id=?",
            (payload.keyword, payload.action, payload.scope, int(payload.enabled), policy_id))
        store.event("policy_updated", str(policy_id))
        return {"id": policy_id, "updated": True}

    @app.put("/v1/admin/users/{actor}")
    def update_user(actor: str, payload: UserInput, _: None = Depends(admin)):
        if actor not in config.client_keys:
            raise HTTPException(404, "Unknown actor")
        store.execute("INSERT INTO users(actor,status) VALUES(?,?) ON CONFLICT(actor) DO UPDATE SET status=excluded.status",
            (actor, payload.status))
        store.event("user_status_updated", actor)
        return {"actor": actor, "status": payload.status}

    @app.get("/v1/admin/users")
    def users(_: None = Depends(admin)):
        return [{"actor": actor, "status": store.user_status(actor)} for actor in config.client_keys]

    @app.get("/v1/admin/exceptions")
    def exceptions(_: None = Depends(admin)):
        return store.rows("SELECT * FROM exceptions ORDER BY id DESC LIMIT 100")

    @app.post("/v1/admin/exceptions/{exception_id}/approve")
    def approve(exception_id: int, payload: ApprovalInput, _: None = Depends(admin)):
        exception = store.one("SELECT * FROM exceptions WHERE id=?", (exception_id,))
        if not exception or exception["status"] != "pending":
            raise HTTPException(404, "Pending exception not found")
        expires = (datetime.now(timezone.utc) + timedelta(hours=payload.hours)).isoformat(timespec="seconds")
        store.execute("UPDATE exceptions SET status='approved',expires_at=? WHERE id=?",
            (expires, exception_id))
        store.event("exception_approved", str(exception_id))
        return {"id": exception_id, "status": "approved", "expires_at": expires}

    @app.post("/v1/admin/exceptions/{exception_id}/reject")
    def reject(exception_id: int, _: None = Depends(admin)):
        exception = store.one("SELECT id FROM exceptions WHERE id=? AND status='pending'", (exception_id,))
        if not exception:
            raise HTTPException(404, "Pending exception not found")
        store.execute("UPDATE exceptions SET status='rejected' WHERE id=?", (exception_id,))
        store.event("exception_rejected", str(exception_id))
        return {"id": exception_id, "status": "rejected"}

    @app.put("/v1/admin/audits/{audit_id}/feedback")
    def feedback(audit_id: int, payload: FeedbackInput, _: None = Depends(admin)):
        if not store.one("SELECT id FROM audits WHERE id=?", (audit_id,)):
            raise HTTPException(404, "Audit not found")
        store.execute("""INSERT INTO feedback(audit_id,verdict,note,created_at) VALUES(?,?,?,?)
            ON CONFLICT(audit_id) DO UPDATE SET verdict=excluded.verdict,
            note=excluded.note,created_at=excluded.created_at""",
            (audit_id, payload.verdict, payload.note, now()))
        store.event("feedback_recorded", str(audit_id))
        return {"audit_id": audit_id, "verdict": payload.verdict}

    @app.get("/v1/admin/report")
    def report(days: int = 7, _: None = Depends(admin)):
        if not 1 <= days <= 90:
            raise HTTPException(400, "days must be 1..90")
        since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat(timespec="seconds")
        counts = store.rows("SELECT action,COUNT(*) AS count FROM audits WHERE created_at>=? GROUP BY action", (since,))
        top_reasons: dict[str, int] = {}
        for audit in store.rows("SELECT reasons FROM audits WHERE created_at>=?", (since,)):
            for reason in json.loads(audit["reasons"]):
                top_reasons[reason] = top_reasons.get(reason, 0) + 1
        fp = store.rows("""SELECT a.reasons FROM feedback f JOIN audits a ON a.id=f.audit_id
            WHERE f.verdict='false_positive' AND f.created_at>=?""", (since,))
        suggestions: dict[str, int] = {}
        for row in fp:
            for reason in json.loads(row["reasons"]):
                if reason.startswith("policy_"):
                    suggestions[reason] = suggestions.get(reason, 0) + 1
        return {"days": days, "counts": counts, "top_reasons": top_reasons,
                "false_positive_policy_candidates": suggestions,
                "note": "Feedback generates suggestions only; no automatic policy changes."}

    @app.get("/v1/admin/events")
    def events(_: None = Depends(admin)):
        return store.rows("SELECT * FROM admin_events ORDER BY id DESC LIMIT 100")

    return app
