import io
from pathlib import Path

import httpx
import pytest
from docx import Document
from fastapi.testclient import TestClient

from dlp_gateway.app import create_app
from dlp_gateway.config import Config, Destination, MAX_BYTES


CLIENT_KEY = "client-" + "c" * 40
ADMIN_KEY = "admin-" + "a" * 40


@pytest.fixture
def gateway(tmp_path: Path):
    config = Config(ADMIN_KEY, {"demo-user": CLIENT_KEY}, {
        "internal": Destination("internal", "http://127.0.0.1:9000/upload"),
        "external": Destination("external", "https://example.invalid/upload"),
    }, tmp_path / "audit.db")
    app = create_app(config)
    with TestClient(app) as client:
        yield client, app


def upload(client, destination="external", content=b"Hello public world", filename="demo.txt", forward=False):
    path = "forward" if forward else "check"
    return client.post(f"/v1/{path}/{destination}", headers={"Authorization": "Bearer " + CLIENT_KEY},
        files={"file": (filename, content)})


def admin(client, method, path, **kwargs):
    return client.request(method, path, headers={"Authorization": "Bearer " + ADMIN_KEY}, **kwargs)


def test_auth_and_basic_audit(gateway):
    client, _ = gateway
    assert "DLP 智能上传网关" in client.get("/console").text
    assert client.post("/v1/check/external", files={"file": ("a.txt", b"hi")}).status_code == 401
    result = upload(client).json()
    assert result["action"] == "allow" and result["forwarded"] is False
    assert result["model_status"] == "disabled"
    audit = admin(client, "GET", "/v1/admin/audits").json()[0]
    assert audit["sha256"] == result["sha256"]
    assert "Hello public world" not in str(audit)
    assert client.get("/v1/admin/audits", headers={"Authorization": "Bearer " + CLIENT_KEY}).status_code == 401


def test_secret_guard_and_personnel(gateway):
    client, _ = gateway
    secret = upload(client, content=b"-----BEGIN PRIVATE KEY-----\nsynthetic test only").json()
    assert secret["action"] == "block" and "secret_external" in secret["reasons"]
    assert upload(client, content=b"Call 13800138000").json()["action"] == "review"
    assert admin(client, "PUT", "/v1/admin/users/demo-user", json={"status": "departing"}).status_code == 200
    assert "departing_external" in upload(client).json()["reasons"]
    assert upload(client, destination="internal").json()["action"] == "allow"


def test_policy_exception_is_scoped_and_cannot_bypass_hard_guard(gateway):
    client, _ = gateway
    assert admin(client, "POST", "/v1/admin/policies", json={
        "keyword": "project canary", "action": "block", "scope": "external"}).status_code == 201
    original = upload(client, content=b"project canary: harmless synthetic demo").json()
    assert original["action"] == "block"
    request = client.post("/v1/exceptions", headers={"Authorization": "Bearer " + CLIENT_KEY},
        json={"audit_id": original["audit_id"], "justification": "Synthetic demo approval"})
    assert request.status_code == 201
    exception_id = request.json()["id"]
    assert admin(client, "POST", f"/v1/admin/exceptions/{exception_id}/approve",
        json={"hours": 1}).status_code == 200
    assert upload(client, content=b"project canary: harmless synthetic demo").json()["action"] == "allow"
    assert upload(client, content=b"project canary: changed bytes").json()["action"] == "block"
    assert upload(client, content=b"project canary: harmless synthetic demo\nAKIAABCDEFGHIJKLMNOP").json()["action"] == "block"
    admin(client, "PUT", "/v1/admin/users/demo-user", json={"status": "departing"})
    assert upload(client, content=b"project canary: harmless synthetic demo").json()["action"] == "block"


def test_unparseable_and_size_fail_closed(gateway):
    client, _ = gateway
    assert upload(client, content=b"not a pdf", filename="x.pdf").json()["action"] == "review"
    assert upload(client, content=b"\x89PNG\r\n\x1a\nnot a real image", filename="x.png").json()["action"] == "review"
    assert upload(client, content=b"x" * (MAX_BYTES + 1)).status_code == 413
    assert upload(client, content=b"a" * 100_001).json()["action"] == "review"
    assert upload(client, destination="unknown").status_code == 404


def test_docx_and_forwarding_only_after_allow(gateway):
    client, app = gateway
    doc = Document()
    doc.add_paragraph("Public synthetic document")
    buffer = io.BytesIO()
    doc.save(buffer)
    assert upload(client, content=buffer.getvalue(), filename="demo.docx").json()["action"] == "allow"
    forwarded = []

    def receiver(request):
        forwarded.append(request.content)
        return httpx.Response(201, text="downstream data is never returned")

    app.state.upstream_transport = httpx.MockTransport(receiver)
    result = upload(client, content=b"safe file", forward=True).json()
    assert result["forwarded"] and result["upstream_status"] == 201
    assert len(forwarded) == 1 and b"safe file" in forwarded[0]
    blocked = upload(client, content=b"Call 13800138000", forward=True).json()
    assert blocked["action"] == "review" and not blocked["forwarded"]
    assert len(forwarded) == 1
    app.state.upstream_transport = httpx.MockTransport(lambda request: httpx.Response(302, headers={"Location": "https://elsewhere.invalid"}))
    rejected = upload(client, content=b"safe file", forward=True)
    assert rejected.status_code == 502
    audit = admin(client, "GET", "/v1/admin/audits").json()[0]
    assert audit["forwarded"] == 0
    assert audit["upstream_status"] == 302


def test_feedback_report_never_auto_mutates_policy(gateway):
    client, _ = gateway
    policy = admin(client, "POST", "/v1/admin/policies", json={
        "keyword": "canary", "action": "review", "scope": "external"}).json()
    audit = upload(client, content=b"canary synthetic").json()
    assert admin(client, "PUT", f"/v1/admin/audits/{audit['audit_id']}/feedback",
        json={"verdict": "false_positive"}).status_code == 200
    report = admin(client, "GET", "/v1/admin/report").json()
    assert report["false_positive_policy_candidates"][f"policy_{policy['id']}"] == 1
    assert admin(client, "GET", "/v1/admin/policies").json()[0]["enabled"] == 1


def test_invalid_configuration(tmp_path):
    with pytest.raises(ValueError):
        Config("replace-with-a-random-admin-secret", {"actor": CLIENT_KEY}, {}, tmp_path / "db")
    with pytest.raises(ValueError):
        Config(ADMIN_KEY, {"actor": CLIENT_KEY}, {"bad": Destination("external", "http://example.com")}, tmp_path / "db")


def test_enabled_model_outage_requires_review(tmp_path):
    config = Config(ADMIN_KEY, {"demo-user": CLIENT_KEY}, {"external": Destination("external")},
        tmp_path / "db", ollama_model="unavailable-demo-model", ollama_url="http://127.0.0.1:1/api/generate")
    with TestClient(create_app(config)) as client:
        result = upload(client).json()
    assert result["action"] == "review"
    assert result["model_status"] == "unavailable"
