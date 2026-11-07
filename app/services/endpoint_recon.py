import json
import re
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.core.runtime_settings import get_scan_mode
from app.core.database import connect
from app.core.redaction import redact_url
from app.core.scope_manager import ScopeError, validate_domain_in_scope, validate_real_network_access, validate_url_in_scope
from app.models.scope import ScopeRecord
from app.services.tool_manager import ToolManager, ToolUnavailable

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="katana-crawl")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}
_METHOD = re.compile(r"^[A-Z]{1,12}$")


class EndpointReconError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scope(scope_id: int) -> ScopeRecord:
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise EndpointReconError("Registered program was not found", 404)
    if not row["authorization_confirmed"]:
        raise EndpointReconError("Explicit authorization is required before reconnaissance", 403)
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       authorization_reference=row["authorization_reference"], authorization_status=row["authorization_status"],
                       authorization_verified_by=row["authorization_verified_by"],
                       authorization_verified_at=datetime.fromisoformat(row["authorization_verified_at"]) if row["authorization_verified_at"] else None,
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=True, local_lab_mode=bool(row["local_lab_mode"]), local_lab_ports=json.loads(row["local_lab_ports"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


def parse_katana_output(output: str, scope: ScopeRecord) -> tuple[list[dict], int]:
    found: dict[tuple[str, str], dict] = {}
    rejected = 0
    for line in output[:5_000_000].splitlines()[:50_000]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            url = item.get("url")
            if not isinstance(url, str):
                raise ValueError("Missing endpoint URL")
            validate_url_in_scope(url, scope, resolve=False)
            method = str(item.get("method") or "GET").upper()
            if not _METHOD.fullmatch(method):
                raise ValueError("Invalid HTTP method")
            source = item.get("source")
            if isinstance(source, list):
                source = ", ".join(str(value)[:50] for value in source[:5])
            source = str(source)[:100] if source else None
            safe_url = redact_url(url)
            found.setdefault((safe_url, method), {"url": safe_url, "method": method, "source": source})
        except (ValueError, TypeError, AttributeError, ScopeError, json.JSONDecodeError):
            rejected += 1
    return [found[key] for key in sorted(found)], rejected


def _update(scan_id: int, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE recon_scans SET {columns} WHERE id = ?", (*values.values(), scan_id))


def _scan(scan_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM recon_scans WHERE id = ? AND module = 'endpoints'", (scan_id,)).fetchone()
    if row is None:
        raise EndpointReconError("Endpoint crawl was not found", 404)
    return dict(row)


def start_endpoint_scan(scope_id: int, target_host: str, approval_confirmed: bool) -> dict:
    if not approval_confirmed:
        raise EndpointReconError("Explicit approval is required before active crawling", 400)
    scope = _scope(scope_id)
    mode = get_scan_mode()
    simulated = mode == "mock"
    try:
        if simulated:
            target = validate_domain_in_scope(target_host, scope, resolve=False)
            validate_domain_in_scope(scope.root_domain, scope, resolve=False)
        else:
            target = validate_real_network_access(scope, target_host, resolve=True)
            validate_real_network_access(scope, scope.root_domain, resolve=True)
    except ScopeError as exc:
        raise EndpointReconError(str(exc), 422) from exc
    adapter = ToolManager(mode=mode).adapters["katana"]
    if not simulated and not adapter.detect().get("available"):
        raise EndpointReconError("Katana is not installed or is unavailable on PATH", 503)
    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active:
                raise EndpointReconError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute("INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'endpoints', 'queued', 'queued', 0, ?, ?)",
                                (scope_id, int(simulated), _now()))
            scan_id = cursor.lastrowid
        event = threading.Event()
        _cancellations[scan_id] = event
        _executor.submit(_run, scan_id, scope, target, adapter, event, simulated)
    return _scan(scan_id)


def _run(scan_id: int, scope: ScopeRecord, target: str, adapter, cancel_event: threading.Event, simulated: bool):
    try:
        _update(scan_id, status="running", stage="validating_scope", progress=0, started_at=_now())
        if simulated:
            validate_domain_in_scope(target, scope, resolve=False)
        else:
            validate_real_network_access(scope, target, resolve=True)
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update(scan_id, stage="katana_crawl", progress=0)
        if simulated:
            output = json.dumps({"url": f"https://{target}/mock-endpoint?token=sample-secret", "method": "GET", "source": "simulated"})
        else:
            result = adapter.run(target, scope, approval_confirmed=True, cancel_event=cancel_event)
            if result.get("cancelled") or cancel_event.is_set():
                _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
                return
            if result.get("timed_out"):
                raise TimeoutError
            if result.get("returncode") != 0:
                raise RuntimeError("Katana process failed")
            output = result.get("stdout", "")
        _update(scan_id, stage="validating_endpoints", progress=0)
        endpoints, rejected = parse_katana_output(output, scope)
        discovered_at = _now()
        with connect() as db:
            db.executemany("INSERT OR IGNORE INTO discovered_endpoints(scope_id, scan_id, url, method, source, simulated, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                           [(scope.id, scan_id, item["url"], item["method"], item["source"], int(simulated), discovered_at) for item in endpoints])
        _update(scan_id, status="completed", stage="completed_with_filtered_results" if rejected else "completed",
                progress=100, finished_at=_now())
    except ScopeError as exc:
        _update(scan_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except TimeoutError:
        _update(scan_id, status="failed", stage="timed_out", error="Katana exceeded the configured crawl timeout", finished_at=_now())
    except ToolUnavailable:
        _update(scan_id, status="failed", stage="tool_unavailable", error="Katana is unavailable", finished_at=_now())
    except Exception:
        _update(scan_id, status="failed", stage="failed", error="Endpoint crawling failed; inspect local application logs", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(scan_id, None)


def get_endpoint_scan(scan_id: int):
    scan = _scan(scan_id)
    with connect() as db:
        rows = db.execute("SELECT url, method, source, simulated, discovered_at FROM discovered_endpoints WHERE scan_id = ? ORDER BY url, method", (scan_id,)).fetchall()
    scan["simulated"] = bool(scan["simulated"])
    scan["results"] = [dict(row) | {"simulated": bool(row["simulated"])} for row in rows]
    return scan


def list_endpoints(scope_id: int | None = None):
    with connect() as db:
        scans = db.execute("SELECT * FROM recon_scans WHERE module = 'endpoints'" + (" AND scope_id = ?" if scope_id else "") + " ORDER BY id DESC LIMIT 100",
                           ((scope_id,) if scope_id else ())).fetchall()
        rows = db.execute("SELECT url, method, source, simulated, MAX(discovered_at) AS discovered_at FROM discovered_endpoints" +
                          (" WHERE scope_id = ?" if scope_id else "") + " GROUP BY url, method, source, simulated ORDER BY url LIMIT 5000",
                          ((scope_id,) if scope_id else ())).fetchall()
    return {"scans": [get_endpoint_scan(row["id"]) for row in scans],
            "results": [dict(row) | {"simulated": bool(row["simulated"])} for row in rows],
            "tool": ToolManager().adapters["katana"].detect()}


def cancel_endpoint_scan(scan_id: int):
    scan = _scan(scan_id)
    if scan["status"] not in {"queued", "running"}:
        raise EndpointReconError("Only queued or running crawls can be cancelled", 409)
    with _lock:
        event = _cancellations.get(scan_id)
        if event:
            event.set()
    return {"id": scan_id, "status": "cancellation_requested"}
