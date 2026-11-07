import json
import sqlite3
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app import config
from app.ai import ollama_client
from app.core import database
from app.main import app
from app.models.scope import ScopeRecord
from app.services.tool_manager import MockToolAdapter, ToolManager


def test_relative_sqlite_url_resolves_under_project(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./data/sample.db")
    assert config._database_path("sqlite:///./data/sample.db") == config.BASE_DIR / "data" / "sample.db"


def test_production_mode_cannot_enable_simulated_scan_results():
    assert config._scan_mode("production", "mock") == "real"
    assert config._scan_mode("development", "mock") == "mock"


def test_database_adds_target_metadata_to_existing_scope_table(tmp_path, monkeypatch):
    legacy_path = tmp_path / "legacy.sqlite3"
    with sqlite3.connect(legacy_path) as legacy:
        legacy.execute("""CREATE TABLE scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT, root_domain TEXT NOT NULL UNIQUE,
            include_subdomains INTEGER NOT NULL, excluded_subdomains TEXT NOT NULL DEFAULT '[]',
            authorization_notes TEXT NOT NULL, authorization_confirmed INTEGER NOT NULL,
            created_at TEXT NOT NULL)""")
        legacy.execute("INSERT INTO scopes(root_domain, include_subdomains, excluded_subdomains, authorization_notes, authorization_confirmed, created_at) VALUES ('legacy.example', 1, '[]', 'existing authorization', 1, '2026-01-01T00:00:00+00:00')")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", legacy_path)
    database.initialize_database()
    with database.connect() as migrated:
        row = migrated.execute("SELECT program_name, included_assets, local_lab_mode FROM scopes").fetchone()
    assert tuple(row) == ("", "[]", 0)


def test_api_health_and_scope_database_operations(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr("app.api.routes.ollama_health", lambda: "unavailable")
    with TestClient(app) as client:
        page = client.get("/")
        assert page.status_code == 200
        assert "AI BugHunter" in page.text
        assert client.get("/assets/js/dashboard.js").status_code == 200
        assert client.get("/assets/css/style.css").status_code == 200
        assert client.get("/assets/css/recon.css").status_code == 200
        health = client.get("/api/health").json()
        assert health["database"] == "ok"
        assert health["ai_install_hint"].startswith("Install Ollama")
        response = client.post("/api/scopes", json={
            "root_domain": "example.test", "program_name": "Example Program", "include_subdomains": True,
            "included_assets": ["api.example.test"], "local_lab_mode": False,
            "excluded_subdomains": ["private.example.test"],
            "authorization_notes": "Test lab authorization", "authorization_confirmed": True,
        })
        assert response.status_code == 201
        scope = client.get("/api/scopes").json()[0]
        assert scope["root_domain"] == "example.test"
        assert scope["program_name"] == "Example Program"
        assert scope["included_assets"] == ["api.example.test"]
        assert client.delete(f"/api/scopes/{response.json()['id']}").status_code == 204


def test_mock_adapter_outputs_are_always_marked_simulated():
    scope = ScopeRecord(id=1, root_domain="example.test", include_subdomains=True,
                        excluded_subdomains=[], authorization_notes="test", authorization_confirmed=True,
                        created_at=datetime.now(timezone.utc))
    output = MockToolAdapter("sample").run("example.test", scope)
    assert output["simulated"] is True
    assert output["results"][0]["simulated"] is True
    assert all(item.get("simulated") for item in ToolManager(mode="mock").availability() if item["mode"] == "mock")


def test_ollama_client_supports_mock_response(monkeypatch):
    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def read(self, _limit):
            return json.dumps({"response": "mock analysis"}).encode()

    monkeypatch.setattr(ollama_client, "urlopen", lambda *_args, **_kwargs: FakeResponse())
    assert ollama_client.generate("test prompt") == "mock analysis"
