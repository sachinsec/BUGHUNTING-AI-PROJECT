import threading
import time
import subprocess
import shutil

from fastapi.testclient import TestClient

from app.core import database
from app.core.scope_manager import ScopeError, validate_domain_in_scope
from app.main import app
from app.services import subdomain_recon as recon
from app.services.tool_manager import SubfinderAdapter


class FakeAdapter:
    def __init__(self, behavior=None):
        self.behavior = behavior

    def detect(self):
        return {"name": "Subfinder", "available": True, "version": "test"}

    def run(self, target, scope, cancel_event=None):
        if self.behavior:
            return self.behavior(target, scope, cancel_event)
        return {"simulated": True, "results": [
            {"value": "api." + target, "simulated": True},
            {"value": "api." + target, "simulated": True},
        ]}


class FakeManager:
    def __init__(self, mode, adapter=None):
        self.adapters = {"subfinder": adapter or FakeAdapter()}


def setup_database(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "recon.sqlite3")


def create_scope(client, root="example.test"):
    response = client.post("/api/scopes", json={
        "program_name": "Recon test program", "root_domain": root,
        "include_subdomains": True, "included_assets": [], "excluded_subdomains": [],
        "authorization_notes": "Authorized test fixture", "authorization_confirmed": True,
    })
    assert response.status_code == 201
    return response.json()


def wait_for_scan(client, scan_id):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        result = client.get(f"/api/recon/subdomains/{scan_id}")
        assert result.status_code == 200
        if result.json()["status"] in {"completed", "failed", "cancelled"}:
            return result.json()
        time.sleep(0.01)
    raise AssertionError("recon scan did not finish in time")


def test_parser_deduplicates_jsonl_and_discards_out_of_scope_hosts():
    from app.core.scope_manager import normalize_domain
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.test", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=["private.example.test"],
                        authorization_notes="authorized", authorization_confirmed=True,
                        local_lab_mode=False, created_at="2026-01-01T00:00:00+00:00")
    output = "\n".join([
        '{"host":"api.example.test","source":"crtsh"}',
        '{"host":"api.example.test","source":"other"}',
        '{"host":"private.example.test","source":"crtsh"}',
        '{"host":"evil.example.net","source":"crtsh"}',
        "not a valid hostname",
    ])
    results, rejected = recon.parse_subfinder_output(output, scope)
    assert results == [{"hostname": "api.example.test", "source": "crtsh"}]
    assert rejected == 3
    assert normalize_domain(results[0]["hostname"]) == "api.example.test"


def test_subfinder_arguments_are_bounded_and_never_shell_composed():
    adapter = SubfinderAdapter()
    assert adapter.arguments("example.com") == ["subfinder", "-d", "example.com", "-json", "-silent",
                                                 "-rl", "2", "-timeout", "15", "-max-time", "5",
                                                 "-max-results", "1000", "-duc"]


def test_subfinder_adapter_executes_with_argument_array_and_captures_json(monkeypatch):
    import app.services.tool_manager as tool_module
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.com", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=[], authorization_notes="authorized",
                        authorization_confirmed=True, local_lab_mode=False,
                        created_at="2026-01-01T00:00:00+00:00")

    class Process:
        returncode = 0

        def communicate(self, timeout=None):
            return ('{"host":"api.example.com","source":"crtsh"}\n', "provider error with secret")

    def fake_popen(args, **kwargs):
        assert isinstance(args, list)
        assert args[1:3] == ["-d", "example.com"]
        assert kwargs["shell"] is False
        return Process()

    monkeypatch.setattr(shutil, "which", lambda _name: "subfinder")
    monkeypatch.setattr(subprocess, "Popen", fake_popen)
    monkeypatch.setattr(tool_module, "validate_domain_in_scope", lambda host, *_args, **_kwargs: host)
    adapter = SubfinderAdapter()
    adapter.min_interval = 0
    result = adapter.run("example.com", scope)
    assert result["returncode"] == 0
    assert "api.example.com" in result["stdout"]
    assert "secret" not in result


def test_subfinder_adapter_terminates_running_process_on_cancel(monkeypatch):
    import subprocess
    import app.services.tool_manager as tool_module
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.com", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=[], authorization_notes="authorized",
                        authorization_confirmed=True, local_lab_mode=False,
                        created_at="2026-01-01T00:00:00+00:00")

    class Process:
        returncode = -15
        terminated = False

        def communicate(self, timeout=None):
            return ("", "")

        def terminate(self):
            self.terminated = True

    process = Process()
    monkeypatch.setattr(shutil, "which", lambda _name: "subfinder")
    monkeypatch.setattr(subprocess, "Popen", lambda *_args, **_kwargs: process)
    monkeypatch.setattr(tool_module, "validate_domain_in_scope", lambda host, *_args, **_kwargs: host)
    event = threading.Event()
    event.set()
    adapter = SubfinderAdapter()
    adapter.min_interval = 0
    result = adapter.run("example.com", scope, cancel_event=event)
    assert result["cancelled"] is True
    assert process.terminated is True


def test_scope_dns_resolution_rejects_private_answers(monkeypatch):
    import app.core.scope_manager as scope_manager
    from app.models.scope import ScopeRecord

    scope = ScopeRecord(id=1, root_domain="example.com", program_name="test", include_subdomains=True,
                        included_assets=[], excluded_subdomains=[], authorization_notes="authorized",
                        authorization_confirmed=True, local_lab_mode=False,
                        created_at="2026-01-01T00:00:00+00:00")
    monkeypatch.setattr(scope_manager.socket, "getaddrinfo", lambda *_args, **_kwargs: [(None, None, None, None, ("127.0.0.1", 0))])
    try:
        validate_domain_in_scope("example.com", scope, resolve=True)
    except ScopeError:
        return
    raise AssertionError("private DNS response was accepted")


def test_api_scan_persists_simulated_results_and_history(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(recon, "SCAN_MODE", "mock")
    monkeypatch.setattr(recon, "ToolManager", lambda mode: FakeManager(mode))
    with TestClient(app) as client:
        scope = create_scope(client)
        started = client.post("/api/recon/subdomains/start", json={"scope_id": scope["id"]})
        assert started.status_code == 202
        scan = wait_for_scan(client, started.json()["id"])
        assert scan["status"] == "completed"
        assert scan["simulated"] is True
        assert scan["results"][0]["hostname"] == "api.example.test"
        assert scan["results"][0]["simulated"] is True
        listing = client.get(f"/api/recon/subdomains?scope_id={scope['id']}").json()
        assert len(listing["scans"]) == 1
        assert len(listing["results"]) == 1
        assert listing["results"][0]["simulated"] is True


def test_api_rejects_unknown_program_and_reports_missing_tool(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    with TestClient(app) as client:
        missing = client.post("/api/recon/subdomains/start", json={"scope_id": 1234})
        assert missing.status_code == 404
        scope = create_scope(client)
        monkeypatch.setattr(recon, "SCAN_MODE", "real")
        monkeypatch.setattr(recon, "validate_domain_in_scope", lambda *_args, **_kwargs: "example.test")

        class MissingManager:
            def __init__(self, mode):
                self.adapters = {"subfinder": type("Adapter", (), {"detect": lambda _self: {"available": False}})()}

        monkeypatch.setattr(recon, "ToolManager", MissingManager)
        response = client.post("/api/recon/subdomains/start", json={"scope_id": scope["id"]})
        assert response.status_code == 503
        assert "not installed" in response.json()["detail"]


def test_cancellation_marks_running_job_cancelled(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(recon, "SCAN_MODE", "mock")
    started_event, release_event = threading.Event(), threading.Event()

    def slow_result(target, _scope, _cancel_event):
        started_event.set()
        release_event.wait(2)
        return {"simulated": True, "results": [{"value": "api." + target, "simulated": True}]}

    monkeypatch.setattr(recon, "ToolManager", lambda mode: FakeManager(mode, FakeAdapter(slow_result)))
    try:
        with TestClient(app) as client:
            scope = create_scope(client)
            started = client.post("/api/recon/subdomains/start", json={"scope_id": scope["id"]})
            assert started.status_code == 202
            assert started_event.wait(1)
            cancelled = client.post(f"/api/recon/subdomains/{started.json()['id']}/cancel")
            assert cancelled.status_code == 202
            release_event.set()
            result = wait_for_scan(client, started.json()["id"])
            assert result["status"] == "cancelled"
    finally:
        release_event.set()


def test_scan_errors_are_sanitized_and_scope_filter_never_returns_external_hosts(tmp_path, monkeypatch):
    setup_database(tmp_path, monkeypatch)
    monkeypatch.setattr(recon, "SCAN_MODE", "mock")

    def error_result(*_args):
        raise RuntimeError("provider token=supersecret")

    monkeypatch.setattr(recon, "ToolManager", lambda mode: FakeManager(mode, FakeAdapter(error_result)))
    with TestClient(app) as client:
        scope = create_scope(client)
        started = client.post("/api/recon/subdomains/start", json={"scope_id": scope["id"]})
        result = wait_for_scan(client, started.json()["id"])
        assert result["status"] == "failed"
        assert "supersecret" not in result["error"]

