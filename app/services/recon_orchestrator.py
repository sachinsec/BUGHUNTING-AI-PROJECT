import json
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.core.runtime_settings import get_scan_mode
from app.core.database import connect
from app.core.scope_manager import ScopeError, validate_domain_in_scope, validate_real_network_access
from app.models.scope import ScopeRecord
from app.services.live_host_recon import (cancel_live_host_scan, get_live_host_scan, list_live_hosts,
                                           start_live_host_scan)
from app.services.subdomain_recon import cancel_subdomain_scan, get_subdomain_scan, start_subdomain_scan
from app.services.url_recon import cancel_url_scan, get_url_scan, start_url_scan
from app.services.endpoint_recon import cancel_endpoint_scan, get_endpoint_scan, start_endpoint_scan
from app.services.technology_recon import cancel_technology_scan, get_technology_scan, start_technology_scan
from app.services.parameter_recon import list_parameters

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="recon-orchestrator")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}
_STAGES = [
    ("subdomains", 0, 20), ("live_hosts", 20, 20), ("urls", 40, 20),
    ("endpoints", 60, 20), ("technologies", 80, 15), ("parameters", 95, 5),
]
_CHILD_APIS = {
    "subdomains": (start_subdomain_scan, get_subdomain_scan, cancel_subdomain_scan),
    "live_hosts": (start_live_host_scan, get_live_host_scan, cancel_live_host_scan),
    "urls": (start_url_scan, get_url_scan, cancel_url_scan),
    "endpoints": (None, get_endpoint_scan, cancel_endpoint_scan),
    "technologies": (start_technology_scan, get_technology_scan, cancel_technology_scan),
}


class OrchestrationError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now():
    return datetime.now(timezone.utc).isoformat()


def _scope_record(row) -> ScopeRecord:
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       authorization_reference=row["authorization_reference"], authorization_status=row["authorization_status"],
                       authorization_verified_by=row["authorization_verified_by"],
                       authorization_verified_at=datetime.fromisoformat(row["authorization_verified_at"]) if row["authorization_verified_at"] else None,
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=bool(row["authorization_confirmed"]), local_lab_mode=bool(row["local_lab_mode"]), local_lab_ports=json.loads(row["local_lab_ports"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


def _update_job(job_id: int, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE orchestration_jobs SET {columns} WHERE id = ?", (*values.values(), job_id))


def _update_stage(job_id: int, stage: str, **values):
    if not values:
        return
    columns = ", ".join(f"{key} = ?" for key in values)
    with connect() as db:
        db.execute(f"UPDATE orchestration_stages SET {columns} WHERE job_id = ? AND name = ?",
                   (*values.values(), job_id, stage))


def _job(job_id: int) -> dict:
    with connect() as db:
        job = db.execute("SELECT * FROM orchestration_jobs WHERE id = ?", (job_id,)).fetchone()
        if job is None:
            raise OrchestrationError("Reconnaissance job was not found", 404)
        stages = db.execute("SELECT name, status, child_scan_id, error, started_at, finished_at FROM orchestration_stages WHERE job_id = ? ORDER BY id", (job_id,)).fetchall()
    result = dict(job)
    result["simulated"] = bool(result["simulated"])
    result["active_crawl_approved"] = bool(result["active_crawl_approved"])
    result["stages"] = [dict(row) for row in stages]
    return result


def start_reconnaissance(scope_id: int, active_crawl_approved: bool = False) -> dict:
    with connect() as db:
        scope = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if scope is None:
        raise OrchestrationError("Registered program was not found", 404)
    if not scope["authorization_confirmed"]:
        raise OrchestrationError("Explicit authorization is required before reconnaissance", 403)
    try:
        if get_scan_mode() == "mock":
            validate_domain_in_scope(scope["root_domain"], _scope_record(scope), resolve=False)
        else:
            validate_real_network_access(_scope_record(scope), scope["root_domain"], resolve=True)
    except ScopeError as exc:
        raise OrchestrationError(str(exc), 422) from exc
    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM orchestration_jobs WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            child_active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active or child_active:
                raise OrchestrationError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute("INSERT INTO orchestration_jobs(scope_id, status, stage, progress, simulated, active_crawl_approved, created_at) VALUES (?, 'queued', 'queued', 0, ?, ?, ?)",
                                (scope_id, int(get_scan_mode() == "mock"), int(active_crawl_approved), _now()))
            job_id = cursor.lastrowid
            db.executemany("INSERT INTO orchestration_stages(job_id, name, status) VALUES (?, ?, 'queued')",
                           [(job_id, name) for name, _, _ in _STAGES])
        event = threading.Event()
        _cancellations[job_id] = event
        _executor.submit(_run_job, job_id, scope_id, active_crawl_approved, event)
    return _job(job_id)


def _child_status(module: str, scan_id: int):
    return _CHILD_APIS[module][1](scan_id)


def _cancel_child(module: str, scan_id: int):
    try:
        _CHILD_APIS[module][2](scan_id)
    except Exception:
        pass


def _run_child(job_id: int, scope_id: int, module: str, start, event: threading.Event, base: int, weight: int, **kwargs):
    if event.is_set():
        raise InterruptedError
    _update_job(job_id, stage=module, current_child_module=module, current_child_scan_id=None)
    _update_stage(job_id, module, status="running", started_at=_now())
    try:
        if module == "endpoints":
            child = start_endpoint_scan(scope_id, kwargs["target_host"], approval_confirmed=True)
        elif module == "technologies":
            child = start_technology_scan(scope_id)
        else:
            child = start(scope_id)
    except Exception:
        _update_stage(job_id, module, status="failed", error=f"{module.replace('_', ' ')} could not start", finished_at=_now())
        raise
    child_id = child["id"]
    _update_job(job_id, current_child_scan_id=child_id)
    _update_stage(job_id, module, child_scan_id=child_id)
    while True:
        if event.is_set():
            _cancel_child(module, child_id)
            _update_stage(job_id, module, status="cancelled", finished_at=_now())
            raise InterruptedError
        child = _child_status(module, child_id)
        mapped = 100 if child["status"] == "completed" else 0
        _update_job(job_id, progress=base + (weight * mapped // 100))
        if child["status"] not in {"queued", "running"}:
            break
        time.sleep(0.1)
    if child["status"] != "completed":
        reason = child.get("error") or f"{module.replace('_', ' ')} stage {child['status']}"
        _update_stage(job_id, module, status="failed" if child["status"] == "failed" else "cancelled",
                      error=reason[:300], finished_at=_now())
        raise RuntimeError(reason)
    _update_stage(job_id, module, status="completed", finished_at=_now())
    _update_job(job_id, current_child_module=None, current_child_scan_id=None, progress=base + weight)
    return child


def _run_job(job_id: int, scope_id: int, crawl_approved: bool, event: threading.Event):
    try:
        _update_job(job_id, status="running", stage="scope_validation", progress=0, started_at=_now())
        with connect() as db:
            scope = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
        if scope is None or not scope["authorization_confirmed"]:
            raise OrchestrationError("Registered authorization is missing")
        if get_scan_mode() == "mock":
            validate_domain_in_scope(scope["root_domain"], _scope_record(scope), resolve=False)
        else:
            validate_real_network_access(_scope_record(scope), scope["root_domain"], resolve=True)
        is_local_lab = bool(scope["local_lab_mode"])
        if is_local_lab and get_scan_mode() == "real":
            _update_stage(job_id, "subdomains", status="skipped", error="Passive public source lookups are disabled for local lab scopes")
            _update_job(job_id, stage="subdomains_skipped_local_lab", progress=20)
        else:
            _run_child(job_id, scope_id, "subdomains", start_subdomain_scan, event, 0, 20)
        _run_child(job_id, scope_id, "live_hosts", start_live_host_scan, event, 20, 20)
        if is_local_lab and get_scan_mode() == "real":
            _update_stage(job_id, "urls", status="skipped", error="External archive lookups are disabled for local lab scopes")
            _update_job(job_id, stage="urls_skipped_local_lab", progress=60)
        else:
            _run_child(job_id, scope_id, "urls", start_url_scan, event, 40, 20)
        if crawl_approved and not (is_local_lab and get_scan_mode() == "real"):
            target_host = scope["root_domain"]
            with connect() as db:
                host = db.execute("SELECT hostname FROM live_hosts WHERE scope_id = ? AND simulated = 0 ORDER BY discovered_at DESC LIMIT 1", (scope_id,)).fetchone()
            if host:
                target_host = host["hostname"]
            _run_child(job_id, scope_id, "endpoints", None, event, 60, 20, target_host=target_host)
        else:
            reason = "Local lab crawling is disabled by the private-IP crawler policy" if is_local_lab and get_scan_mode() == "real" else "Explicit active-crawl approval was not provided"
            _update_stage(job_id, "endpoints", status="skipped", error=reason)
            _update_job(job_id, stage="endpoints_skipped_no_approval", progress=80)
        _run_child(job_id, scope_id, "technologies", start_technology_scan, event, 80 if crawl_approved else 80, 15)
        if event.is_set():
            raise InterruptedError
        _update_stage(job_id, "parameters", status="running", started_at=_now())
        list_parameters(scope_id)
        _update_stage(job_id, "parameters", status="completed", finished_at=_now())
        _update_job(job_id, status="completed", stage="completed", progress=100,
                    current_child_module=None, current_child_scan_id=None, finished_at=_now())
    except InterruptedError:
        _update_job(job_id, status="cancelled", stage="cancelled", finished_at=_now(),
                    current_child_module=None, current_child_scan_id=None)
    except ScopeError as exc:
        _update_job(job_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except Exception:
        _update_job(job_id, status="failed", stage="failed", error="Reconnaissance workflow failed; inspect individual stage statuses", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(job_id, None)


def get_reconnaissance_job(job_id: int) -> dict:
    return _job(job_id)


def list_reconnaissance_jobs(scope_id: int | None = None) -> list[dict]:
    with connect() as db:
        rows = db.execute("SELECT id FROM orchestration_jobs" + (" WHERE scope_id = ?" if scope_id else "") +
                          " ORDER BY id DESC LIMIT 100", ((scope_id,) if scope_id else ())).fetchall()
    return [_job(row["id"]) for row in rows]


def cancel_reconnaissance_job(job_id: int):
    job = _job(job_id)
    if job["status"] not in {"queued", "running"}:
        raise OrchestrationError("Only queued or running jobs can be cancelled", 409)
    with _lock:
        event = _cancellations.get(job_id)
        if event:
            event.set()
    return {"id": job_id, "status": "cancellation_requested"}
