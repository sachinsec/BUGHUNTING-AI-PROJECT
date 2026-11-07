import json
import threading
import time

from fastapi.testclient import TestClient

from app.core import database
from app.main import app
from app.services import live_host_recon as live
from app.services.tool_manager import HttpxAdapter


class Adapter:
    def __init__(self, behavior=None, available=True):
        self.behavior = behavior
        self.available = available

    def detect(self):
        return {"name": "ProjectDiscovery httpx", "available": self.available, "simulated": False}

    def run_many(self, targets, scope, cancel_event=None):
        if self.behavior:
            return self.behavior(targets, scope, cancel_event)
        return {"returncode": 0, "stdout": json.dumps({"url": "https://api.example.test", "status_code": 200,
                                                          "title": "API", "content_type": "application/json",
                                                          "a": ["203.0.113.10"]})}


class Manager:
    def __init__(self, adapter=None):
        self.adapters = {"httpx": adapter or Adapter()}


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "live-hosts.sqlite3")


def add_scope(client):
    response = client.post("/api/scopes", json={"program_name": "Host probe test", "root_domain": "example.test",
        "include_subdomains": True, "included_assets": ["api.example.test"], "excluded_subdomains": [],
        "authorization_notes": "Authorized test fixture", "authorization_confirmed": True})
    assert response.status_code == 201
    return response.json()


def approve_scope(client, scope):
    review = client.post(f"/api/scopes/{scope['id']}/authorization-reviews", json={
        "program_name": scope["program_name"], "platform_name": "Test platform",
        "authorized_asset": scope["root_domain"], "allow_subdomains": True,
        "policy_url": "https://program.example/policy", "excluded_assets": [],
        "evidence_notes": "Reviewed live-host test authorization",
    })
    assert review.status_code == 201
    decision = client.put(f"/api/authorization-reviews/{review.json()['id']}", json={
        "status": "APPROVED", "reviewer": "Test reviewer", "decision": "Reviewed test policy."})
    assert decision.status_code == 200


def wait_for_scan(client, scan_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = client.get(f"/api/recon/live-hosts/{scan_id}").json()
        if result["status"] in {"completed", "failed", "cancelled"}:
            return result
        time.sleep(.01)
    raise AssertionError("live-host job did not finish")


def test_httpx_parser_validates_scope_deduplicates_and_rejects_private_ips():
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.test", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=["private.example.test"],
                        authorization_notes="authorized", authorization_confirmed=True,
                        local_lab_mode=False, created_at="2026-01-01T00:00:00+00:00")
    output = "\n".join([
        json.dumps({"url": "https://api.example.test", "status_code": 200, "title": "API", "content_type": "application/json", "a": ["8.8.8.8"]}),
        json.dumps({"url": "https://api.example.test", "status_code": 200, "a": ["8.8.8.8"]}),
        json.dumps({"url": "https://private.example.test", "status_code": 200}),
        json.dumps({"url": "http://elsewhere.net", "status_code": 200}),
        json.dumps({"url": "https://api.example.test", "status_code": 200, "a": ["127.0.0.1"]}),
    ])
    results, rejected = live.parse_httpx_output(output, scope)
    assert len(results) == 1
    assert results[0]["hostname"] == "api.example.test"
    assert results[0]["status_code"] == 200
    assert rejected == 3


def test_httpx_adapter_rejects_unrelated_python_httpx_executable(monkeypatch):
    import shutil
    import subprocess

    monkeypatch.setattr(shutil, "which", lambda name: "python-httpx.exe" if name == "httpx-toolkit" else None)
    monkeypatch.setattr(subprocess, "run", lambda *_args, **_kwargs: subprocess.CompletedProcess(
        args=[], returncode=0, stdout="Usage: httpx [OPTIONS] URL", stderr=""))
    result = HttpxAdapter().detect()
    assert result["available"] is False
    assert "unrelated tools named httpx are rejected" in result["install_hint"]


def test_httpx_adapter_prefers_httpx_toolkit_and_falls_back_to_pd_httpx(monkeypatch):
    import shutil
    import subprocess

    calls = []
    monkeypatch.setattr(shutil, "which", lambda name: f"/tools/{name}" if name in {"httpx-toolkit", "httpx"} else None)

    def version(args, **kwargs):
        calls.append(args[0])
        return subprocess.CompletedProcess(args=args, returncode=0,
            stdout="projectdiscovery.io\nCurrent Version: v1.6.2", stderr="")

    monkeypatch.setattr(subprocess, "run", version)
    adapter = HttpxAdapter()
    detected = adapter.detect()
    assert detected["available"] is True
    assert detected["command"] == "httpx-toolkit"
    assert detected["command"] == "httpx-toolkit"
    assert calls[0] == "/tools/httpx-toolkit"

    monkeypatch.setattr(shutil, "which", lambda name: "/tools/httpx" if name == "httpx" else None)
    fallback = HttpxAdapter().detect()
    assert fallback["available"] is True
    assert fallback["command"] == "httpx"


def test_live_host_api_persists_simulated_results_with_label(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(live, "get_scan_mode", lambda: "mock")
    monkeypatch.setattr(live, "ToolManager", lambda mode="mock": Manager(Adapter()))
    with TestClient(app) as client:
        scope = add_scope(client)
        response = client.post("/api/recon/live-hosts/start", json={"scope_id": scope["id"]})
        assert response.status_code == 202
        scan = wait_for_scan(client, response.json()["id"])
        assert scan["status"] == "completed"
        assert scan["simulated"] is True
        assert scan["results"][0]["simulated"] is True
        listing = client.get(f"/api/recon/live-hosts?scope_id={scope['id']}").json()
        assert listing["results"][0]["url"].startswith("https://mock.")
        assert listing["results"][0]["status_code"] is None


def test_live_host_api_rejects_missing_program_and_missing_tool(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(live, "get_scan_mode", lambda: "real")
    monkeypatch.setattr(live, "validate_real_network_access", lambda _scope, host, **_kwargs: host)
    monkeypatch.setattr(live, "ToolManager", lambda mode: Manager(Adapter(available=False)))
    with TestClient(app) as client:
        assert client.post("/api/recon/live-hosts/start", json={"scope_id": 99}).status_code == 404
        scope = add_scope(client)
        approve_scope(client, scope)
        response = client.post("/api/recon/live-hosts/start", json={"scope_id": scope["id"]})
        assert response.status_code == 503
        assert "httpx is not installed" in response.json()["detail"]


def test_live_host_scan_cancellation(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(live, "get_scan_mode", lambda: "real")
    monkeypatch.setattr(live, "validate_real_network_access", lambda _scope, host, **_kwargs: host)
    started_event, release_event = threading.Event(), threading.Event()

    def slow_probe(_targets, _scope, _event):
        started_event.set()
        release_event.wait(2)
        return {"cancelled": True, "returncode": None, "stdout": ""}

    monkeypatch.setattr(live, "ToolManager", lambda mode: Manager(Adapter(slow_probe)))
    try:
        with TestClient(app) as client:
            scope = add_scope(client)
            approve_scope(client, scope)
            started = client.post("/api/recon/live-hosts/start", json={"scope_id": scope["id"]})
            assert started.status_code == 202
            assert started_event.wait(1)
            assert client.post(f"/api/recon/live-hosts/{started.json()['id']}/cancel").status_code == 202
            release_event.set()
            assert wait_for_scan(client, started.json()["id"])["status"] == "cancelled"
    finally:
        release_event.set()
