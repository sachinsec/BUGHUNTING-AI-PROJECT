import json
import threading
import time

from fastapi.testclient import TestClient

from app.core import database
from app.main import app
from app.services import endpoint_recon as endpoints
from app.services.tool_manager import KatanaAdapter


class Adapter:
    def __init__(self, behavior=None, available=True):
        self.behavior = behavior
        self.available = available

    def detect(self):
        return {"name": "Katana", "available": self.available, "simulated": False}

    def run(self, target, scope, approval_confirmed=False, cancel_event=None):
        assert approval_confirmed is True
        if self.behavior:
            return self.behavior(target, scope, cancel_event)
        return {"returncode": 0, "stdout": json.dumps({"url": f"https://{target}/account?token=secret-value",
                                                          "method": "GET", "source": ["href"]})}


class Manager:
    def __init__(self, adapter=None):
        self.adapters = {"katana": adapter or Adapter()}


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "endpoints.sqlite3")


def add_scope(client):
    response = client.post("/api/scopes", json={"program_name": "Endpoint test", "root_domain": "example.test",
        "include_subdomains": True, "included_assets": ["app.example.test"], "excluded_subdomains": [],
        "authorization_notes": "Authorized test fixture", "authorization_confirmed": True})
    assert response.status_code == 201
    return response.json()


def approve_scope(client, scope):
    review = client.post(f"/api/scopes/{scope['id']}/authorization-reviews", json={
        "program_name": scope["program_name"], "platform_name": "Test platform",
        "authorized_asset": scope["root_domain"], "allow_subdomains": True,
        "policy_url": "https://program.example/policy", "excluded_assets": [],
        "evidence_notes": "Reviewed crawl test authorization",
    })
    assert review.status_code == 201
    decision = client.put(f"/api/authorization-reviews/{review.json()['id']}", json={
        "status": "APPROVED", "reviewer": "Test reviewer", "decision": "Reviewed test policy."})
    assert decision.status_code == 200


def wait_for_scan(client, scan_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        response = client.get(f"/api/recon/endpoints/{scan_id}")
        assert response.status_code == 200
        scan = response.json()
        if scan["status"] in {"completed", "failed", "cancelled"}:
            return scan
        time.sleep(.01)
    raise AssertionError("Katana job did not finish")


def test_katana_parser_scope_filters_deduplicates_and_redacts_secrets():
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.test", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=[], authorization_notes="authorized",
                        authorization_confirmed=True, local_lab_mode=False,
                        created_at="2026-01-01T00:00:00+00:00")
    output = "\n".join([
        json.dumps({"url": "https://app.example.test/account?token=secret-value", "method": "GET", "source": "href"}),
        json.dumps({"url": "https://app.example.test/account?token=other-value", "method": "GET", "source": "href"}),
        json.dumps({"url": "https://outside.test/private", "method": "GET"}),
        json.dumps({"url": "https://127.0.0.1/internal", "method": "GET"}),
    ])
    found, rejected = endpoints.parse_katana_output(output, scope)
    assert len(found) == 1
    assert "secret-value" not in found[0]["url"]
    assert "%5BREDACTED%5D" in found[0]["url"]
    assert rejected == 2


def test_endpoint_api_requires_active_crawl_approval(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(endpoints, "get_scan_mode", lambda: "mock")
    monkeypatch.setattr(endpoints, "ToolManager", lambda mode="mock": Manager())
    with TestClient(app) as client:
        scope = add_scope(client)
        response = client.post("/api/recon/endpoints/start", json={"scope_id": scope["id"],
            "target_host": "app.example.test", "approval_confirmed": False})
        assert response.status_code == 400
        assert "approval" in response.json()["detail"].casefold()


def test_endpoint_mock_scan_persists_labeled_and_redacted_result(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(endpoints, "get_scan_mode", lambda: "mock")
    monkeypatch.setattr(endpoints, "ToolManager", lambda mode="mock": Manager())
    with TestClient(app) as client:
        scope = add_scope(client)
        response = client.post("/api/recon/endpoints/start", json={"scope_id": scope["id"],
            "target_host": "app.example.test", "approval_confirmed": True})
        assert response.status_code == 202
        scan = wait_for_scan(client, response.json()["id"])
        assert scan["status"] == "completed"
        assert scan["results"][0]["simulated"] is True
        assert "sample-secret" not in scan["results"][0]["url"]
        listing = client.get(f"/api/recon/endpoints?scope_id={scope['id']}").json()
        assert listing["results"][0]["simulated"] is True


def test_endpoint_scan_rejects_out_of_scope_and_missing_katana(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(endpoints, "get_scan_mode", lambda: "real")
    def check_scope(host, scope, **_kwargs):
        if host != scope.root_domain and not host.endswith("." + scope.root_domain):
            raise endpoints.ScopeError("Target is outside the registered scope")
        return host
    monkeypatch.setattr(endpoints, "validate_real_network_access", lambda scope, host, **kwargs: check_scope(host, scope))
    monkeypatch.setattr(endpoints, "ToolManager", lambda mode: Manager(Adapter(available=False)))
    with TestClient(app) as client:
        scope = add_scope(client)
        approve_scope(client, scope)
        out = client.post("/api/recon/endpoints/start", json={"scope_id": scope["id"], "target_host": "outside.test", "approval_confirmed": True})
        assert out.status_code == 422
        missing = client.post("/api/recon/endpoints/start", json={"scope_id": scope["id"], "target_host": "example.test", "approval_confirmed": True})
        assert missing.status_code == 503


def test_katana_adapter_enforces_approval_and_crawl_limits():
    adapter = KatanaAdapter()
    assert "-rl" in adapter.arguments("example.test")
    assert "2m" in adapter.arguments("example.test")
    try:
        adapter.run("example.test", object(), approval_confirmed=False)
    except PermissionError:
        return
    raise AssertionError("Katana started without human approval")

