import threading
import time

from fastapi.testclient import TestClient

from app.core import database
from app.main import app
from app.services import url_recon as urls


class Adapter:
    def __init__(self, behavior=None, available=True):
        self.behavior = behavior
        self.available = available

    def detect(self):
        return {"name": "mock-url-tool", "available": self.available, "simulated": False}

    def run(self, target, scope, cancel_event=None):
        if self.behavior:
            return self.behavior(target, scope, cancel_event)
        return {"returncode": 0, "stdout": f"https://api.{target}/v1?source={self.executable_source}\n"}

    executable_source = "archive"


class Manager:
    def __init__(self, adapter=None, gau_available=True, wayback_available=True):
        self.adapters = {"gau": adapter or Adapter(), "waybackurls": adapter or Adapter()}
        self.adapters["gau"].executable_source = "gau"
        self.adapters["waybackurls"].executable_source = "waybackurls"
        self.adapters["gau"].available = gau_available
        self.adapters["waybackurls"].available = wayback_available


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "urls.sqlite3")


def add_scope(client):
    response = client.post("/api/scopes", json={"program_name": "URL test", "root_domain": "example.test",
        "include_subdomains": True, "included_assets": [], "excluded_subdomains": ["private.example.test"],
        "authorization_notes": "Authorized test fixture", "authorization_confirmed": True})
    assert response.status_code == 201
    return response.json()


def approve_scope(client, scope):
    review = client.post(f"/api/scopes/{scope['id']}/authorization-reviews", json={
        "program_name": scope["program_name"], "platform_name": "Test platform",
        "authorized_asset": scope["root_domain"], "allow_subdomains": True,
        "policy_url": "https://program.example/policy", "excluded_assets": [],
        "evidence_notes": "Reviewed archive test authorization",
    })
    assert review.status_code == 201
    decision = client.put(f"/api/authorization-reviews/{review.json()['id']}", json={
        "status": "APPROVED", "reviewer": "Test reviewer", "decision": "Reviewed test policy."})
    assert decision.status_code == 200


def wait_for_scan(client, scan_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(f"/api/recon/urls/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        if data["status"] in {"completed", "failed", "cancelled"}:
            return data
        time.sleep(.01)
    raise AssertionError("URL intelligence job did not finish")


def test_parser_deduplicates_sources_and_rejects_out_of_scope_urls():
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.test", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=["private.example.test"],
                        authorization_notes="authorized", authorization_confirmed=True,
                        local_lab_mode=False, created_at="2026-01-01T00:00:00+00:00")
    results, rejected = urls.parse_historical_urls({
        "gau": "https://api.example.test/v1?a=1\nhttps://private.example.test/hidden\nhttp://127.0.0.1/",
        "waybackurls": "https://api.example.test/v1?a=1\nhttps://elsewhere.net/",
    }, scope)
    assert results == [{"url": "https://api.example.test/v1?a=1", "sources": ["gau", "waybackurls"]}]
    assert rejected == 3


def test_url_api_persists_labeled_mock_archive_results(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(urls, "get_scan_mode", lambda: "mock")
    monkeypatch.setattr(urls, "ToolManager", lambda mode="mock": Manager())
    with TestClient(app) as client:
        scope = add_scope(client)
        started = client.post("/api/recon/urls/start", json={"scope_id": scope["id"]})
        assert started.status_code == 202
        scan = wait_for_scan(client, started.json()["id"])
        assert scan["status"] == "completed"
        assert scan["simulated"] is True
        assert scan["results"][0]["simulated"] is True
        listing = client.get(f"/api/recon/urls?scope_id={scope['id']}").json()
        assert len(listing["results"]) == 1
        assert listing["results"][0]["simulated"] is True


def test_url_api_requires_registered_scope_and_archive_provider(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(urls, "get_scan_mode", lambda: "real")
    monkeypatch.setattr(urls, "validate_real_network_access", lambda _scope, host, **_kwargs: host)
    monkeypatch.setattr(urls, "ToolManager", lambda mode: Manager(gau_available=False, wayback_available=False))
    with TestClient(app) as client:
        assert client.post("/api/recon/urls/start", json={"scope_id": 123}).status_code == 404
        scope = add_scope(client)
        approve_scope(client, scope)
        response = client.post("/api/recon/urls/start", json={"scope_id": scope["id"]})
        assert response.status_code == 503
        assert "GAU and/or Waybackurls" in response.json()["detail"]


def test_url_job_cancellation(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(urls, "get_scan_mode", lambda: "real")
    monkeypatch.setattr(urls, "validate_real_network_access", lambda _scope, host, **_kwargs: host)
    started_event, release_event = threading.Event(), threading.Event()

    def blocking(*_args):
        started_event.set()
        release_event.wait(2)
        return {"cancelled": True, "returncode": None, "stdout": ""}

    monkeypatch.setattr(urls, "ToolManager", lambda mode: Manager(Adapter(blocking)))
    try:
        with TestClient(app) as client:
            scope = add_scope(client)
            approve_scope(client, scope)
            started = client.post("/api/recon/urls/start", json={"scope_id": scope["id"]})
            assert started.status_code == 202
            assert started_event.wait(1)
            assert client.post(f"/api/recon/urls/{started.json()['id']}/cancel").status_code == 202
            release_event.set()
            assert wait_for_scan(client, started.json()["id"])["status"] == "cancelled"
    finally:
        release_event.set()
