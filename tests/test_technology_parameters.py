import json

from fastapi.testclient import TestClient

from app.core import database
from app.core.scope_manager import ScopeError
from app.main import app
from app.models.scope import ScopeRecord
from app.services import technology_recon
from app.services.tool_manager import WhatWebAdapter


class Adapter:
    def __init__(self, available=True):
        self.available = available

    def detect(self):
        return {"name": "WhatWeb", "available": self.available, "simulated": False}


class Manager:
    def __init__(self, available=True):
        self.adapters = {"whatweb": Adapter(available)}


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "tech-params.sqlite3")


def add_scope(client):
    response = client.post("/api/scopes", json={"program_name": "Tech test", "root_domain": "example.test",
        "include_subdomains": True, "included_assets": [], "excluded_subdomains": [],
        "authorization_notes": "Authorized test fixture", "authorization_confirmed": True})
    assert response.status_code == 201
    return response.json()


def test_whatweb_parser_keeps_technology_versions_and_ignores_sensitive_fields():
    scope = ScopeRecord(id=1, root_domain="example.test", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=[], authorization_notes="authorized",
                        authorization_confirmed=True, local_lab_mode=False,
                        created_at="2026-01-01T00:00:00+00:00")
    payload = {"target": "https://app.example.test", "plugins": {
        "Apache": {"version": ["2.4.58"]}, "PHP": {"version": ["8.2.4"]},
        "Title": {"string": ["Do not store page body content"]}, "IP": {"string": ["8.8.8.8"]}}}
    results = technology_recon.parse_whatweb_output(json.dumps(payload), scope, "app.example.test")
    assert results == [
        {"hostname": "app.example.test", "technology": "Apache", "version": "2.4.58"},
        {"hostname": "app.example.test", "technology": "PHP", "version": "8.2.4"},
    ]


def test_whatweb_invocation_disables_redirects_and_aggressive_mode():
    args = WhatWebAdapter().arguments("example.test")
    assert "--follow-redirect=never" in args
    assert "--aggression=1" in args
    assert "--max-threads=1" in args


def test_technology_api_persists_only_simulated_marked_results(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(technology_recon, "SCAN_MODE", "mock")
    monkeypatch.setattr(technology_recon, "ToolManager", lambda mode: Manager())
    with TestClient(app) as client:
        scope = add_scope(client)
        response = client.post("/api/recon/technologies/start", json={"scope_id": scope["id"]})
        assert response.status_code == 202
        scan_id = response.json()["id"]
        result = client.get(f"/api/recon/technologies/{scan_id}")
        for _ in range(100):
            if result.json()["status"] in {"completed", "failed"}:
                break
            result = client.get(f"/api/recon/technologies/{scan_id}")
        assert result.json()["status"] == "completed"
        assert result.json()["results"][0]["simulated"] is True


def test_technology_api_rejects_out_of_scope_and_missing_whatweb(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(technology_recon, "SCAN_MODE", "real")

    def scope_check(host, scope, **_kwargs):
        if host != scope.root_domain and not host.endswith("." + scope.root_domain):
            raise ScopeError("Target is outside the registered scope")
        return host

    monkeypatch.setattr(technology_recon, "validate_domain_in_scope", scope_check)
    monkeypatch.setattr(technology_recon, "ToolManager", lambda mode: Manager(available=False))
    with TestClient(app) as client:
        scope = add_scope(client)
        out = client.post("/api/recon/technologies/start", json={"scope_id": scope["id"], "target_host": "outside.test"})
        assert out.status_code == 422
        missing = client.post("/api/recon/technologies/start", json={"scope_id": scope["id"]})
        assert missing.status_code == 503


def test_parameter_engine_derives_names_without_retaining_query_values(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        scope = add_scope(client)
        with database.connect() as db:
            scan = db.execute("INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'urls', 'completed', 'completed', 100, 0, '2026-01-01T00:00:00+00:00')", (scope["id"],)).lastrowid
            db.execute("INSERT INTO historical_urls(scope_id, scan_id, url, source, simulated, discovered_at) VALUES (?, ?, ?, 'gau', 0, '2026-01-01T00:00:00+00:00')",
                       (scope["id"], scan, "https://api.example.test/search?term=alice&token=secret"))
            db.execute("INSERT INTO discovered_endpoints(scope_id, scan_id, url, method, simulated, discovered_at) VALUES (?, ?, ?, 'GET', 0, '2026-01-01T00:00:00+00:00')",
                       (scope["id"], scan, "https://api.example.test/search?term=alice&token=%5BREDACTED%5D"))
        response = client.get(f"/api/recon/parameters?scope_id={scope['id']}")
        assert response.status_code == 200
        data = response.json()
        assert data["count"] == 2
        assert {item["parameter_name"] for item in data["results"]} == {"term", "token"}
        assert all("alice" not in item["parameterized_url"] and "secret" not in item["parameterized_url"] for item in data["results"])
