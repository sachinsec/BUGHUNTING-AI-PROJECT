import time

from fastapi.testclient import TestClient

from app.core import database
from app.main import app


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "orchestration.sqlite3")


def wait_for_job(client, job_id):
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        response = client.get(f"/api/recon/scans/{job_id}")
        assert response.status_code == 200
        job = response.json()
        if job["status"] in {"completed", "failed", "cancelled"}:
            return job
        time.sleep(.02)
    raise AssertionError("reconnaissance workflow did not finish")


def test_orchestrator_runs_mock_stages_and_skips_unapproved_crawl(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        scope = client.post("/api/scopes", json={"program_name": "Full pipeline test", "root_domain": "example.test",
            "include_subdomains": True, "included_assets": [], "excluded_subdomains": [],
            "authorization_notes": "Authorized test fixture", "authorization_confirmed": True}).json()
        response = client.post("/api/recon/start", json={"scope_id": scope["id"], "active_crawl_approved": False})
        assert response.status_code == 202
        job = wait_for_job(client, response.json()["id"])
        assert job["status"] == "completed"
        assert job["simulated"] is True
        stages = {item["name"]: item["status"] for item in job["stages"]}
        assert stages == {"subdomains": "completed", "live_hosts": "completed", "urls": "completed",
                          "endpoints": "skipped", "technologies": "completed", "parameters": "completed"}
        subdomains = client.get(f"/api/recon/subdomains?scope_id={scope['id']}").json()
        assert subdomains["results"][0]["simulated"] is True
        assert client.get(f"/api/recon/urls?scope_id={scope['id']}").json()["results"][0]["simulated"] is True


def test_orchestrator_requires_registered_program(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        response = client.post("/api/recon/start", json={"scope_id": 999})
        assert response.status_code == 404

