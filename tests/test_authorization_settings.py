from fastapi.testclient import TestClient

from app.core import database, runtime_settings
from app.core.scope_manager import ScopeError, validate_real_network_access
from app.main import app
from app.models.scope import ScopeRecord
from app.services import subdomain_recon


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "authorization-settings.sqlite3")


def add_scope(client, root="public.example.test", local_lab=False):
    return client.post("/api/scopes", json={
        "program_name": "Authorization test", "root_domain": root,
        "include_subdomains": True, "included_assets": [], "excluded_subdomains": [],
        "authorization_notes": "Operator-confirmed test scope", "authorization_confirmed": True,
        "authorization_reference": "https://program.example/policy", "local_lab_mode": local_lab,
    })


def test_public_real_scan_requires_separate_manual_program_review(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(subdomain_recon, "get_scan_mode", lambda: "real")
    with TestClient(app) as client:
        response = add_scope(client)
        assert response.status_code == 201
        scope = response.json()
        assert scope["authorization_status"] == "unverified"
        blocked = client.post("/api/recon/subdomains/start", json={"scope_id": scope["id"]})
        assert blocked.status_code == 422
        assert "separately reviewed" in blocked.json()["detail"]

        verified = client.post(f"/api/scopes/{scope['id']}/verify-authorization", json={
            "verified": True, "verified_by": "Researcher", "review_notes": "I reviewed the active program policy and target scope.",
        })
        assert verified.status_code == 200
        assert verified.json()["authorization_status"] == "verified"
        assert verified.json()["authorization_verified_by"] == "Researcher"


def test_local_lab_requires_exact_loopback_host_and_configured_port(monkeypatch):
    scope = ScopeRecord(id=1, root_domain="localhost", program_name="Local lab",
                        include_subdomains=False, included_assets=[], excluded_subdomains=[], local_lab_ports=[8080],
                        authorization_notes="Local lab authorization", authorization_confirmed=True,
                        authorization_reference="", local_lab_mode=True,
                        created_at="2026-01-01T00:00:00+00:00")
    import app.core.scope_manager as scope_manager
    monkeypatch.setattr(scope_manager.socket, "getaddrinfo", lambda *_args, **_kwargs: [
        (None, None, None, None, ("127.0.0.1", 0))])
    assert validate_real_network_access(scope, "http://localhost:8080", resolve=True) == "http://localhost:8080"
    for target in ("http://localhost:8081", "http://example.com:8080", "localhost"):
        try:
            validate_real_network_access(scope, target, resolve=False)
        except ScopeError:
            pass
        else:
            raise AssertionError(f"Local Lab accepted an unconfigured destination: {target}")

    public_lab = ScopeRecord(id=2, root_domain="example.com", program_name="Invalid lab",
                             include_subdomains=True, included_assets=[], excluded_subdomains=[], local_lab_ports=[8080],
                             authorization_notes="Not a local target", authorization_confirmed=True,
                             local_lab_mode=True, created_at="2026-01-01T00:00:00+00:00")
    try:
        validate_real_network_access(public_lab, "http://example.com:8080", resolve=False)
    except ScopeError:
        pass
    else:
        raise AssertionError("Local Lab mode accepted a public DNS domain")


def test_settings_api_persists_real_mock_choice_and_production_blocks_mock(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        settings = client.get("/api/settings").json()
        assert settings["scan_mode"] == "mock"
        changed = client.put("/api/settings/scan-mode", json={"scan_mode": "real"})
        assert changed.status_code == 200
        assert runtime_settings.get_scan_mode() == "real"
        assert client.get("/api/settings").json()["scan_mode"] == "real"
        assert client.put("/api/settings/scan-mode", json={"scan_mode": "mock"}).status_code == 200

    monkeypatch.setattr(runtime_settings, "APP_PROFILE", "PRODUCTION_KALI")
    try:
        runtime_settings.set_scan_mode("mock")
    except ValueError as exc:
        assert "disabled" in str(exc)
    else:
        raise AssertionError("Production allowed mock tool results")


def test_tool_and_system_status_endpoints_report_mode_and_platform():
    with TestClient(app) as client:
        info = client.get("/api/system/info")
        assert info.status_code == 200
        assert info.json()["platform"] in {"Windows", "Linux", "Darwin"}
        status = client.get("/api/tools/status")
        assert status.status_code == 200
        assert status.json()["execution_mode"] in {"mock", "real"}
        assert all(item["status"] == "MOCK" and item["simulated"] for item in status.json()["tools"] if item["name"] != "scanner")
        checked = client.post("/api/tools/check")
        assert checked.status_code == 200
        assert all("status" in item for item in checked.json()["tools"] if item["name"] != "scanner")


def test_local_lab_registration_requires_loopback_and_configured_ports(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        payload = {"root_domain": "localhost", "program_name": "Local test", "include_subdomains": False,
                   "included_assets": [], "excluded_subdomains": [], "local_lab_ports": [8080],
                   "authorization_notes": "Operator-controlled local service", "authorization_confirmed": True,
                   "local_lab_mode": True}
        response = client.post("/api/scopes", json=payload)
        assert response.status_code == 201
        assert response.json()["local_lab_ports"] == [8080]
        payload["root_domain"] = "example.com"
        assert client.post("/api/scopes", json=payload).status_code == 422
