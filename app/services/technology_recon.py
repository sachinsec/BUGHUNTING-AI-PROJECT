import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.config import SCAN_MODE
from app.core.database import connect
from app.core.scope_manager import ScopeError, validate_domain_in_scope
from app.models.scope import ScopeRecord
from app.services.tool_manager import ToolManager, ToolUnavailable

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="whatweb")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}
_NON_TECH = {"title", "ip", "country", "redirectlocation", "httpserver"}


class TechnologyReconError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scope(scope_id: int) -> ScopeRecord:
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise TechnologyReconError("Registered program was not found", 404)
    if not row["authorization_confirmed"]:
        raise TechnologyReconError("Explicit authorization is required before reconnaissance", 403)
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=True, local_lab_mode=bool(row["local_lab_mode"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


def parse_whatweb_output(output: str, scope: ScopeRecord, expected_host: str) -> list[dict]:
    try:
        payload = json.loads(output)
    except (json.JSONDecodeError, TypeError):
        payload = [json.loads(line) for line in output.splitlines() if line.strip()]
    records = payload if isinstance(payload, list) else [payload]
    results = {}
    for record in records[:100]:
        if not isinstance(record, dict):
            continue
        target = record.get("target") or "https://" + expected_host
        parsed = urlsplit(target)
        host = validate_domain_in_scope(parsed.hostname or "", scope, resolve=False)
        if host != expected_host:
            continue
        plugins = record.get("plugins")
        if not isinstance(plugins, dict):
            continue
        for name, details in plugins.items():
            technology = str(name).strip()[:120]
            if not technology or technology.casefold() in _NON_TECH:
                continue
            version = None
            if isinstance(details, dict):
                raw_version = details.get("version")
                if isinstance(raw_version, list):
                    raw_version = ", ".join(str(item) for item in raw_version[:5])
                if raw_version:
                    version = str(raw_version)[:120]
            results.setdefault((host, technology, version), {"hostname": host, "technology": technology, "version": version})
    return [results[key] for key in sorted(results)]


def _update(scan_id: int, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE recon_scans SET {columns} WHERE id = ?", (*values.values(), scan_id))


def _scan(scan_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM recon_scans WHERE id = ? AND module = 'technologies'", (scan_id,)).fetchone()
    if row is None:
        raise TechnologyReconError("Technology scan was not found", 404)
    return dict(row)


def start_technology_scan(scope_id: int, target_host: str | None = None) -> dict:
    scope = _scope(scope_id)
    simulated = SCAN_MODE == "mock"
    host = target_host or scope.root_domain
    try:
        host = validate_domain_in_scope(host, scope, resolve=not simulated)
    except ScopeError as exc:
        raise TechnologyReconError(str(exc), 422) from exc
    adapter = ToolManager(mode=SCAN_MODE).adapters["whatweb"]
    if not simulated and not adapter.detect().get("available"):
        raise TechnologyReconError("WhatWeb is not installed or is unavailable on PATH", 503)
    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active:
                raise TechnologyReconError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute("INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'technologies', 'queued', 'queued', 0, ?, ?)",
                                (scope_id, int(simulated), _now()))
            scan_id = cursor.lastrowid
        event = threading.Event()
        _cancellations[scan_id] = event
        _executor.submit(_run, scan_id, scope, host, adapter, event, simulated)
    return _scan(scan_id)


def _run(scan_id: int, scope: ScopeRecord, host: str, adapter, cancel_event: threading.Event, simulated: bool):
    try:
        _update(scan_id, status="running", stage="validating_scope", progress=0, started_at=_now())
        validate_domain_in_scope(host, scope, resolve=not simulated)
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update(scan_id, stage="whatweb_fingerprint", progress=0)
        if simulated:
            results = [{"hostname": host, "technology": "Sample fingerprint", "version": None}]
        else:
            output = []
            response = adapter.run(host, scope, cancel_event=cancel_event)
            if response.get("cancelled") or cancel_event.is_set():
                _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
                return
            if response.get("timed_out"):
                raise TimeoutError
            if response.get("returncode") != 0:
                raise RuntimeError("WhatWeb process failed")
            output = response.get("stdout", "")
            results = parse_whatweb_output(output, scope, host)
        detected_at = _now()
        with connect() as db:
            db.executemany("INSERT OR IGNORE INTO detected_technologies(scope_id, scan_id, hostname, technology, version, simulated, detected_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           [(scope.id, scan_id, item["hostname"], item["technology"], item["version"], int(simulated), detected_at)
                            for item in results])
        _update(scan_id, status="completed", stage="completed", progress=100, finished_at=_now())
    except ScopeError as exc:
        _update(scan_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except TimeoutError:
        _update(scan_id, status="failed", stage="timed_out", error="WhatWeb exceeded the configured timeout", finished_at=_now())
    except ToolUnavailable:
        _update(scan_id, status="failed", stage="tool_unavailable", error="WhatWeb is unavailable", finished_at=_now())
    except Exception:
        _update(scan_id, status="failed", stage="failed", error="Technology detection failed; inspect local application logs", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(scan_id, None)


def get_technology_scan(scan_id: int):
    scan = _scan(scan_id)
    with connect() as db:
        rows = db.execute("SELECT hostname, technology, version, simulated, detected_at FROM detected_technologies WHERE scan_id = ? ORDER BY hostname, technology", (scan_id,)).fetchall()
    scan["simulated"] = bool(scan["simulated"])
    scan["results"] = [dict(row) | {"simulated": bool(row["simulated"])} for row in rows]
    return scan


def list_technologies(scope_id: int | None = None):
    with connect() as db:
        scans = db.execute("SELECT * FROM recon_scans WHERE module = 'technologies'" + (" AND scope_id = ?" if scope_id else "") + " ORDER BY id DESC LIMIT 100",
                           ((scope_id,) if scope_id else ())).fetchall()
        rows = db.execute("SELECT hostname, technology, version, simulated, MAX(detected_at) AS detected_at FROM detected_technologies" +
                          (" WHERE scope_id = ?" if scope_id else "") + " GROUP BY hostname, technology, version, simulated ORDER BY hostname, technology LIMIT 5000",
                          ((scope_id,) if scope_id else ())).fetchall()
    return {"scans": [get_technology_scan(row["id"]) for row in scans],
            "results": [dict(row) | {"simulated": bool(row["simulated"])} for row in rows],
            "tool": ToolManager(mode=SCAN_MODE).adapters["whatweb"].detect()}


def cancel_technology_scan(scan_id: int):
    scan = _scan(scan_id)
    if scan["status"] not in {"queued", "running"}:
        raise TechnologyReconError("Only queued or running scans can be cancelled", 409)
    with _lock:
        event = _cancellations.get(scan_id)
        if event:
            event.set()
    return {"id": scan_id, "status": "cancellation_requested"}
