import json
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


def test_api_health_and_scope_database_operations(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "test.sqlite3")
    monkeypatch.setattr("app.api.routes.ollama_health", lambda: "unavailable")
    with TestClient(app) as client:
        health = client.get("/api/health").json()
        assert health["database"] == "ok"
        assert health["ai_install_hint"].startswith("Install Ollama")
        response = client.post("/api/scopes", json={
            "root_domain": "example.test", "include_subdomains": True,
            "excluded_subdomains": ["private.example.test"],
            "authorization_notes": "Test lab authorization", "authorization_confirmed": True,
        })
        assert response.status_code == 201
        assert client.get("/api/scopes").json()[0]["root_domain"] == "example.test"
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
