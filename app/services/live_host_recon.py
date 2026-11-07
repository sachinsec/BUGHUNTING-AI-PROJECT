import json
import ipaddress
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from app.config import SCAN_MODE
from app.core.database import connect
from app.core.scope_manager import ScopeError, normalize_domain, validate_domain_in_scope, validate_url_in_scope
from app.models.scope import ScopeRecord
from app.services.tool_manager import ToolManager, ToolUnavailable

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="httpx-probe")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}


class LiveHostError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _load_scope(scope_id: int) -> ScopeRecord:
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise LiveHostError("Registered program was not found", 404)
    if not row["authorization_confirmed"]:
        raise LiveHostError("Explicit authorization is required before reconnaissance", 403)
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=True, local_lab_mode=bool(row["local_lab_mode"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


def parse_httpx_output(output: str, scope: ScopeRecord) -> tuple[list[dict], int]:
    results: dict[str, dict] = {}
    rejected = 0
    for line in output[:5_000_000].splitlines()[:50_000]:
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            raw_url = item.get("url") or item.get("input")
            if not isinstance(raw_url, str):
                raise ValueError("Missing URL")
            validate_url_in_scope(raw_url, scope, resolve=False)
            parsed = urlsplit(raw_url)
            hostname = normalize_domain(parsed.hostname or "")
            raw_ips = item.get("a") or []
            if isinstance(raw_ips, str):
                raw_ips = [raw_ips]
            ip_address = None
            if raw_ips:
                ip_address = str(ipaddress.ip_address(str(raw_ips[0])))
                if not ipaddress.ip_address(ip_address).is_global:
                    raise ValueError("Non-public destination address")
            status_code = item.get("status_code")
            if status_code is not None:
                status_code = int(status_code)
                if status_code < 100 or status_code > 599:
                    raise ValueError("Invalid HTTP status")
            candidate = {"hostname": hostname, "url": raw_url, "status_code": status_code,
                         "title": str(item.get("title") or "")[:500] or None,
                         "content_type": str(item.get("content_type") or "")[:200] or None,
                         "ip_address": ip_address}
            results.setdefault(raw_url, candidate)
        except (ValueError, TypeError, AttributeError, ScopeError, json.JSONDecodeError):
            rejected += 1
    return [results[key] for key in sorted(results)], rejected


def _update(scan_id: int, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE recon_scans SET {columns} WHERE id = ?", (*values.values(), scan_id))


def _read_scan(scan_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM recon_scans WHERE id = ? AND module = 'live_hosts'", (scan_id,)).fetchone()
    if row is None:
        raise LiveHostError("Live-host scan was not found", 404)
    return dict(row)


def start_live_host_scan(scope_id: int) -> dict:
    scope = _load_scope(scope_id)
    simulated = SCAN_MODE == "mock"
    try:
        validate_domain_in_scope(scope.root_domain, scope, resolve=not simulated)
    except ScopeError as exc:
        raise LiveHostError(str(exc), 422) from exc
    adapter = ToolManager(mode=SCAN_MODE).adapters["httpx"]
    if not simulated and not adapter.detect().get("available"):
        raise LiveHostError("ProjectDiscovery httpx is not installed or is unavailable on PATH", 503)
    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active:
                raise LiveHostError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute("INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'live_hosts', 'queued', 'queued', 0, ?, ?)",
                                (scope_id, int(simulated), _now()))
            scan_id = cursor.lastrowid
        event = threading.Event()
        _cancellations[scan_id] = event
        _executor.submit(_run, scan_id, scope, adapter, event, simulated)
    return _read_scan(scan_id)


def _run(scan_id: int, scope: ScopeRecord, adapter, cancel_event: threading.Event, simulated: bool):
    try:
        _update(scan_id, status="running", stage="validating_scope", progress=0, started_at=_now())
        validate_domain_in_scope(scope.root_domain, scope, resolve=not simulated)
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        with connect() as db:
            discovered = db.execute("SELECT hostname FROM discovered_subdomains WHERE scope_id = ? AND simulated = 0 ORDER BY hostname LIMIT 1000", (scope.id,)).fetchall()
        targets = sorted({scope.root_domain, *scope.included_assets, *(row["hostname"] for row in discovered)})
        targets = [validate_domain_in_scope(host, scope, resolve=not simulated) for host in targets]
        _update(scan_id, stage="httpx_probe", progress=0)
        if simulated:
            candidates = [{"hostname": "mock." + scope.root_domain, "url": "https://mock." + scope.root_domain,
                           "status_code": None, "title": None, "content_type": None, "ip_address": None}]
        else:
            result = adapter.run_many(targets, scope, cancel_event=cancel_event)
            if result.get("cancelled") or cancel_event.is_set():
                _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
                return
            if result.get("timed_out"):
                raise TimeoutError
            if result.get("returncode") != 0:
                raise RuntimeError("httpx process failed")
            _update(scan_id, stage="processing_results", progress=0)
            candidates, _rejected = parse_httpx_output(result.get("stdout", ""), scope)
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        found_at = _now()
        with connect() as db:
            db.executemany("INSERT OR IGNORE INTO live_hosts(scope_id, scan_id, hostname, url, status_code, title, content_type, ip_address, simulated, discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                           [(scope.id, scan_id, item["hostname"], item["url"], item.get("status_code"), item.get("title"),
                             item.get("content_type"), item.get("ip_address"), int(simulated), found_at) for item in candidates])
        _update(scan_id, status="completed", stage="completed", progress=100, finished_at=_now())
    except ScopeError as exc:
        _update(scan_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except ToolUnavailable:
        _update(scan_id, status="failed", stage="tool_unavailable", error="ProjectDiscovery httpx is unavailable", finished_at=_now())
    except TimeoutError:
        _update(scan_id, status="failed", stage="timed_out", error="HTTP probing exceeded the configured timeout", finished_at=_now())
    except Exception:
        _update(scan_id, status="failed", stage="failed", error="Live-host probing failed; inspect local application logs", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(scan_id, None)


def get_live_host_scan(scan_id: int) -> dict:
    scan = _read_scan(scan_id)
    with connect() as db:
        rows = db.execute("SELECT hostname, url, status_code, title, content_type, ip_address, simulated, discovered_at FROM live_hosts WHERE scan_id = ? ORDER BY hostname, url", (scan_id,)).fetchall()
    scan["simulated"] = bool(scan["simulated"])
    scan["results"] = [dict(row) | {"simulated": bool(row["simulated"])} for row in rows]
    return scan


def list_live_hosts(scope_id: int | None = None):
    with connect() as db:
        scans = db.execute("SELECT * FROM recon_scans WHERE module = 'live_hosts'" + (" AND scope_id = ?" if scope_id else "") + " ORDER BY id DESC LIMIT 100",
                           ((scope_id,) if scope_id else ())).fetchall()
        rows = db.execute("SELECT hostname, url, status_code, title, content_type, ip_address, simulated, MAX(discovered_at) AS discovered_at FROM live_hosts" +
                          (" WHERE scope_id = ?" if scope_id else "") + " GROUP BY hostname, url, simulated ORDER BY hostname, url LIMIT 5000",
                          ((scope_id,) if scope_id else ())).fetchall()
    return {"scans": [get_live_host_scan(row["id"]) for row in scans],
            "results": [dict(row) | {"simulated": bool(row["simulated"])} for row in rows],
            "tool": ToolManager(mode=SCAN_MODE).adapters["httpx"].detect()}


def cancel_live_host_scan(scan_id: int):
    scan = _read_scan(scan_id)
    if scan["status"] not in {"queued", "running"}:
        raise LiveHostError("Only queued or running scans can be cancelled", 409)
    with _lock:
        event = _cancellations.get(scan_id)
        if event:
            event.set()
    return {"id": scan_id, "status": "cancellation_requested"}
