"""HTTP API tests (FastAPI TestClient)."""
import time

from fastapi.testclient import TestClient


def test_api_flow():
    from app.main import app

    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert health["status"] == "ok" and health["auth_required"] is True
        assert health["intel_records"] >= 10

        assert client.get("/api/alerts").status_code == 401
        assert client.post("/api/auth/login", json={"username": "analyst", "password": "nope"}).status_code == 401
        token = client.post("/api/auth/login", json={"username": "analyst", "password": "test-password"}).json()["token"]
        h = {"Authorization": f"Bearer {token}"}

        # SIEM webhook with the ingest key
        r = client.post("/api/alerts", headers={"X-API-Key": "ingest-key"},
                        json={"title": "Port scan from 8.8.4.4", "src_ip": "8.8.4.4", "severity": "low"})
        assert r.status_code == 201

        alert = client.post("/api/simulate?scenario=0", headers=h).json()
        detail = {}
        for _ in range(50):
            detail = client.get(f"/api/alerts/{alert['id']}", headers=h).json()
            if detail["alert"]["status"] not in ("new", "triaging"):
                break
            time.sleep(0.1)
        assert detail["alert"]["status"] == "awaiting_approval"
        pending = [a for a in detail["actions"] if a["status"] == "pending"]
        assert pending

        done = client.post(f"/api/actions/{pending[0]['id']}/approve", headers=h).json()
        assert done["status"] == "executed"
        assert client.post(f"/api/actions/{pending[0]['id']}/approve", headers=h).status_code == 409

        found = client.get("/api/intel/search", params={"q": "ransomware encrypting files"}, headers=h).json()
        assert found["semantic"]

        imp = client.post("/api/intel/import", headers=h,
                          json={"filename": "mine.csv", "content": "value,title\n192.0.2.77,Test entry\n"}).json()
        assert imp["imported"] == 1

        with client.websocket_connect(f"/ws?token={token}") as ws:
            assert ws.receive_json()["type"] == "hello"
