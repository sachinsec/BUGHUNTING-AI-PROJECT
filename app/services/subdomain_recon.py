import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from app.core.runtime_settings import get_scan_mode
from app.core.database import connect
from app.core.scope_manager import ScopeError, normalize_domain, validate_domain_in_scope, validate_real_network_access
from app.models.scope import ScopeRecord
from app.services.tool_manager import ToolManager, ToolUnavailable

_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="subfinder")
_lock = threading.Lock()
_cancellations: dict[int, threading.Event] = {}


class ReconError(RuntimeError):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_scope(scope_id: int) -> ScopeRecord:
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise ReconError("Registered program was not found", 404)
    if not row["authorization_confirmed"]:
        raise ReconError("Explicit authorization is required before reconnaissance", 403)
    return ScopeRecord(
        id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
        authorization_reference=row["authorization_reference"], authorization_status=row["authorization_status"],
        authorization_verified_by=row["authorization_verified_by"],
        authorization_verified_at=datetime.fromisoformat(row["authorization_verified_at"]) if row["authorization_verified_at"] else None,
        include_subdomains=bool(row["include_subdomains"]),
        included_assets=json.loads(row["included_assets"]),
        excluded_subdomains=json.loads(row["excluded_subdomains"]),
        authorization_notes=row["authorization_notes"], authorization_confirmed=True,
        local_lab_mode=bool(row["local_lab_mode"]), local_lab_ports=json.loads(row["local_lab_ports"]), created_at=datetime.fromisoformat(row["created_at"]),
    )


def parse_subfinder_output(output: str, scope: ScopeRecord) -> tuple[list[dict], int]:
    """Parse JSONL or plain Subfinder output; discard malformed, duplicate, and out-of-scope hosts."""
    results: dict[str, str | None] = {}
    rejected = 0
    for line in output[:5_000_000].splitlines()[:100_000]:
        line = line.strip()
        if not line or len(line) > 2048:
            if line:
                rejected += 1
            continue
        source = None
        candidate = line
        if line.startswith("{"):
            try:
                record = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                rejected += 1
                continue
            candidate = record.get("host", "") if isinstance(record, dict) else ""
            raw_source = record.get("source") if isinstance(record, dict) else None
            source = str(raw_source)[:100] if raw_source else None
        try:
            host = normalize_domain(candidate)
            validate_domain_in_scope(host, scope, resolve=False)
        except (ScopeError, AttributeError, TypeError):
            rejected += 1
            continue
        results.setdefault(host, source)
    return ([{"hostname": hostname, "source": source} for hostname, source in sorted(results.items())], rejected)


def _update_scan(scan_id: int, **values) -> None:
    if not values:
        return
    assignments = ", ".join(f"{column} = ?" for column in values)
    with connect() as db:
        db.execute(f"UPDATE recon_scans SET {assignments} WHERE id = ?", (*values.values(), scan_id))


def _scan_row(scan_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM recon_scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        raise ReconError("Subdomain scan was not found", 404)
    return dict(row)


def start_subdomain_scan(scope_id: int) -> dict:
    scope = _load_scope(scope_id)
    mode = get_scan_mode()
    simulated = mode == "mock"
    try:
        # Mock mode performs no network lookups; real mode checks every DNS answer before launch.
        if simulated:
            validate_domain_in_scope(scope.root_domain, scope, resolve=False)
        else:
            validate_real_network_access(scope, scope.root_domain, resolve=True, allow_local_lab=False)
    except ScopeError as exc:
        raise ReconError(str(exc), 422) from exc

    manager = ToolManager(mode=mode)
    adapter = manager.adapters["subfinder"]
    if not simulated:
        tool = adapter.detect()
        if not tool.get("available"):
            raise ReconError("Subfinder is not installed or is unavailable on PATH", 503)

    with _lock:
        with connect() as db:
            active = db.execute("SELECT id FROM recon_scans WHERE status IN ('queued', 'running') LIMIT 1").fetchone()
            if active:
                raise ReconError("A reconnaissance job is already queued or running", 409)
            cursor = db.execute(
                "INSERT INTO recon_scans(scope_id, module, status, stage, progress, simulated, created_at) VALUES (?, 'subdomains', 'queued', 'queued', 0, ?, ?)",
                (scope_id, int(simulated), _now()),
            )
            scan_id = cursor.lastrowid
        event = threading.Event()
        _cancellations[scan_id] = event
        _executor.submit(_run_scan, scan_id, scope, adapter, event, simulated)
    return _scan_row(scan_id)


def _run_scan(scan_id: int, scope: ScopeRecord, adapter, cancel_event: threading.Event, simulated: bool) -> None:
    try:
        if cancel_event.is_set():
            _update_scan(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update_scan(scan_id, status="running", stage="validating_scope", progress=0, started_at=_now())
        if simulated:
            validate_domain_in_scope(scope.root_domain, scope, resolve=False)
        else:
            validate_real_network_access(scope, scope.root_domain, resolve=True, allow_local_lab=False)
        if cancel_event.is_set():
            _update_scan(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return
        _update_scan(scan_id, stage="subfinder", progress=0)
        if simulated:
            result = adapter.run(scope.root_domain, scope)
            output = "\n".join(item["value"] for item in result.get("results", []) if item.get("simulated"))
        else:
            result = adapter.run(scope.root_domain, scope, cancel_event=cancel_event)
            if result.get("cancelled"):
                _update_scan(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
                return
            if result.get("timed_out"):
                raise TimeoutError("Subfinder exceeded the configured scan timeout")
            if result.get("returncode") != 0:
                raise RuntimeError(f"Subfinder exited with status {result.get('returncode')}")
            output = result.get("stdout", "")

        if cancel_event.is_set():
            _update_scan(scan_id, status="cancelled", stage="cancelled", finished_at=_now())
            return

        _update_scan(scan_id, stage="processing_results", progress=0)
        assets, rejected = parse_subfinder_output(output, scope)
        discovered_at = _now()
        with connect() as db:
            db.executemany(
                "INSERT OR IGNORE INTO discovered_subdomains(scope_id, scan_id, hostname, source, simulated, discovered_at) VALUES (?, ?, ?, ?, ?, ?)",
                [(scope.id, scan_id, asset["hostname"], asset["source"], int(simulated), discovered_at) for asset in assets],
            )
        stage = "completed_with_filtered_results" if rejected else "completed"
        _update_scan(scan_id, status="completed", stage=stage, progress=100, finished_at=_now())
    except ScopeError as exc:
        _update_scan(scan_id, status="failed", stage="scope_validation_failed", error=str(exc)[:300], finished_at=_now())
    except ToolUnavailable:
        _update_scan(scan_id, status="failed", stage="tool_unavailable", error="Subfinder is unavailable", finished_at=_now())
    except TimeoutError:
        _update_scan(scan_id, status="failed", stage="timed_out", error="Subfinder exceeded the configured scan timeout", finished_at=_now())
    except Exception:
        # Do not persist arbitrary tool stderr, environment details, or credentials in errors.
        _update_scan(scan_id, status="failed", stage="failed", error="Subdomain enumeration failed; inspect local application logs", finished_at=_now())
    finally:
        with _lock:
            _cancellations.pop(scan_id, None)


def get_subdomain_scan(scan_id: int) -> dict:
    scan = _scan_row(scan_id)
    with connect() as db:
        rows = db.execute("SELECT hostname, source, simulated, discovered_at FROM discovered_subdomains WHERE scan_id = ? ORDER BY hostname", (scan_id,)).fetchall()
    scan["results"] = [dict(row) | {"simulated": bool(row["simulated"])} for row in rows]
    for field in ("simulated",):
        scan[field] = bool(scan[field])
    return scan


def list_subdomains(scope_id: int | None = None, scan_id: int | None = None) -> dict:
    clauses = []
    params: list[int] = []
    if scope_id is not None:
        clauses.append("scope_id = ?")
        params.append(scope_id)
    if scan_id is not None:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    with connect() as db:
        scans = db.execute("SELECT * FROM recon_scans" + (" WHERE scope_id = ?" if scope_id is not None else "") + " ORDER BY id DESC LIMIT 100", ((scope_id,) if scope_id is not None else ())).fetchall()
        rows = db.execute(
            "SELECT hostname, MAX(source) AS source, simulated, MAX(discovered_at) AS discovered_at FROM discovered_subdomains" + where +
            " GROUP BY hostname, simulated ORDER BY hostname LIMIT 5000", params,
        ).fetchall()
    tool = ToolManager().adapters["subfinder"].detect()
    return {"scans": [get_subdomain_scan(row["id"]) for row in scans],
            "results": [dict(row) | {"simulated": bool(row["simulated"])} for row in rows], "tool": tool}


def cancel_subdomain_scan(scan_id: int) -> dict:
    scan = _scan_row(scan_id)
    if scan["status"] not in {"queued", "running"}:
        raise ReconError("Only queued or running scans can be cancelled", 409)
    with _lock:
        event = _cancellations.get(scan_id)
        if event is not None:
            event.set()
    return {"id": scan_id, "status": "cancellation_requested"}
