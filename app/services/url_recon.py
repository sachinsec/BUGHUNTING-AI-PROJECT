import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.config import SCAN_MODE
from app.core.database import connect
from app.core.scope_manager import ScopeError, validate_domain_in_scope, validate_url_in_scope
from app.core.redaction import redact_url
from app.models.scope import ScopeRecord
from app.services.tool_manager import ToolManager, ToolUnavailable

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="url-intelligence")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}


class URLReconError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scope(scope_id: int) -> ScopeRecord:
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise URLReconError("Registered program was not found", 404)
    if not row["authorization_confirmed"]:
        raise URLReconError("Explicit authorization is required before reconnaissance", 403)
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=True, local_lab_mode=bool(row["local_lab_mode"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


def parse_historical_urls(outputs: dict[str, str], scope: ScopeRecord) -> tuple[list[dict], int]:
    accepted: dict[str, set[str]] = {}
    rejected = 0
    count = 0
    for source, output in outputs.items():
        for line in output[:5_000_000].splitlines():
            count += 1
            if count > 100_000:
                return ([{"url": url, "sources": sorted(sources)} for url, sources in sorted(accepted.items())], rejected + 1)
            candidate = line.strip()
            if not candidate or len(candidate) > 4096:
                rejected += int(bool(candidate))
                continue
            try:
                validate_url_in_scope(candidate, scope, resolve=False)
            except (ScopeError, ValueError):
                rejected += 1
                continue
            accepted.setdefault(redact_url(candidate), set()).add(source)
    return ([{"url": url, "sources": sorted(sources)} for url, sources in sorted(accepted.items())], rejected)


def _update(scan_id: int, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE recon_scans SET {columns} WHERE id = ?", (*values.values(), scan_id))


def _scan(scan_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM recon_scans WHERE id = ? AND module = 'urls'", (scan_id,)).fetchone()
    if row is None:
        raise URLReconError("Historical URL scan was not found", 404)
    return dict(row)


def start_url_scan(scope_id: int) -> dict:
    scope = _scope(scope_id)
    simulated = SCAN_MODE == "mock"
    try:
        validate_domain_in_scope(scope.root_domain, scope, resolve=not simulated)
    except ScopeError as exc:
        raise URLReconError(str(exc), 422) from exc
    adapters = ToolManager(mode=SCAN_MODE).adapters
    selected = {name: adapters[name] for name in ("gau", "waybackurls")}
    available = {name: adapter.detect().get("available", False) for name, adapter in selected.items()}
    if not simulated and not any(available.values()):
        raise URLReconError("Install GAU and/or Waybackurls before collecting historical URLs", 503)
    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active:
                raise URLReconError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute("INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'urls', 'queued', 'queued', 0, ?, ?)",
                                (scope_id, int(simulated), _now()))
            scan_id = cursor.lastrowid
        event = threading.Event()
        _cancellations[scan_id] = event
        _executor.submit(_run, scan_id, scope, selected, available, event, simulated)
    return _scan(scan_id)


def _run(scan_id: int, scope: ScopeRecord, adapters: dict, available: dict, cancel_event: threading.Event, simulated: bool):
    try:
        _update(scan_id, status="running", stage="validating_scope", progress=0, started_at=_now())
        validate_domain_in_scope(scope.root_domain, scope, resolve=not simulated)
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update(scan_id, stage="collecting_archives", progress=0)
        if simulated:
            outputs = {"mock": f"https://mock.{scope.root_domain}/archive?source=simulated\n"}
        else:
            outputs = {}
            for name, adapter in adapters.items():
                if not available[name]:
                    continue
                try:
                    result = adapter.run(scope.root_domain, scope, cancel_event=cancel_event)
                    if result.get("cancelled") or cancel_event.is_set():
                        _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
                        return
                    if result.get("timed_out"):
                        continue
                    if result.get("returncode") == 0:
                        outputs[name] = result.get("stdout", "")
                except ToolUnavailable:
                    continue
            if not outputs:
                raise RuntimeError("Historical URL providers did not return results")
        if cancel_event.is_set():
            _update(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update(scan_id, stage="validating_urls", progress=0)
        urls, rejected = parse_historical_urls(outputs, scope)
        discovered_at = _now()
        with connect() as db:
            db.executemany("INSERT OR IGNORE INTO historical_urls(scope_id, scan_id, url, source, simulated, discovered_at) VALUES (?, ?, ?, ?, ?, ?)",
                           [(scope.id, scan_id, item["url"], source, int(simulated), discovered_at)
                            for item in urls for source in item["sources"]])
        _update(scan_id, status="completed", stage="completed_with_filtered_results" if rejected else "completed",
                progress=100, finished_at=_now())
    except ScopeError as exc:
        _update(scan_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except TimeoutError:
        _update(scan_id, status="failed", stage="timed_out", error="Historical URL collection exceeded the configured timeout", finished_at=_now())
    except Exception:
        _update(scan_id, status="failed", stage="failed", error="Historical URL collection failed; inspect local application logs", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(scan_id, None)


def get_url_scan(scan_id: int) -> dict:
    scan = _scan(scan_id)
    with connect() as db:
        rows = db.execute("SELECT url, source, simulated, discovered_at FROM historical_urls WHERE scan_id = ? ORDER BY url, source", (scan_id,)).fetchall()
    grouped: dict[str, dict] = {}
    for row in rows:
        grouped.setdefault(row["url"], {"url": row["url"], "sources": [], "simulated": bool(row["simulated"]), "discovered_at": row["discovered_at"]})["sources"].append(row["source"])
    scan["simulated"] = bool(scan["simulated"])
    scan["results"] = list(grouped.values())
    return scan


def list_historical_urls(scope_id: int | None = None):
    with connect() as db:
        scans = db.execute("SELECT * FROM recon_scans WHERE module = 'urls'" + (" AND scope_id = ?" if scope_id else "") + " ORDER BY id DESC LIMIT 100",
                           ((scope_id,) if scope_id else ())).fetchall()
        rows = db.execute("SELECT url, source, simulated, MAX(discovered_at) AS discovered_at FROM historical_urls" +
                          (" WHERE scope_id = ?" if scope_id else "") + " GROUP BY url, source, simulated ORDER BY url LIMIT 5000",
                          ((scope_id,) if scope_id else ())).fetchall()
    grouped: dict[tuple[str, bool], dict] = {}
    for row in rows:
        key = (row["url"], bool(row["simulated"]))
        grouped.setdefault(key, {"url": row["url"], "sources": [], "simulated": bool(row["simulated"]), "discovered_at": row["discovered_at"]})["sources"].append(row["source"])
    tools = ToolManager(mode=SCAN_MODE).adapters
    return {"scans": [get_url_scan(row["id"]) for row in scans], "results": list(grouped.values()),
            "tools": {name: tools[name].detect() for name in ("gau", "waybackurls")}}


def cancel_url_scan(scan_id: int):
    scan = _scan(scan_id)
    if scan["status"] not in {"queued", "running"}:
        raise URLReconError("Only queued or running scans can be cancelled", 409)
    with _lock:
        event = _cancellations.get(scan_id)
        if event:
            event.set()
    return {"id": scan_id, "status": "cancellation_requested"}
