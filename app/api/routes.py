import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status

from app.core.database import connect
from app.core.scope_manager import ScopeError, normalize_domain
from app.models.scope import AuthorizationVerification, ScanModeUpdate, ScopeCreate, ScopeRecord
from app.core.runtime_settings import get_scan_mode, set_scan_mode
from app.config import APP_ENV, APP_PROFILE, CURRENT_PLATFORM, HTTPX_EXECUTABLE, OLLAMA_BASE_URL, OLLAMA_MODEL
from app.ai.ollama_client import ollama_health
from app.services.tool_manager import ToolManager

router = APIRouter()


def _record(row) -> ScopeRecord:
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       authorization_reference=row["authorization_reference"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       local_lab_ports=json.loads(row["local_lab_ports"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=bool(row["authorization_confirmed"]), local_lab_mode=bool(row["local_lab_mode"]),
                       authorization_status=row["authorization_status"], authorization_verified_by=row["authorization_verified_by"],
                       authorization_verified_at=datetime.fromisoformat(row["authorization_verified_at"]) if row["authorization_verified_at"] else None,
                       created_at=datetime.fromisoformat(row["created_at"]))


@router.get("/health")
def health():
    try:
        with connect() as db:
            db.execute("SELECT 1").fetchone()
        ai_status = ollama_health()
        return {"status": "ok", "database": "ok", "ai": ai_status, "scan_mode": get_scan_mode(), "ollama_model": OLLAMA_MODEL,
                "ollama_endpoint": OLLAMA_BASE_URL,
                "ai_install_hint": None if ai_status == "connected" else
                "Install Ollama, start its local service, then run: ollama pull " + OLLAMA_MODEL,
                "tools": ToolManager().availability()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.get("/system/info")
def system_info():
    return {"platform": CURRENT_PLATFORM, "profile": APP_PROFILE, "app_env": APP_ENV,
            "execution_mode": get_scan_mode(), "python": __import__("sys").version.split()[0],
            "database": "sqlite", "ollama_endpoint": OLLAMA_BASE_URL, "ollama_model": OLLAMA_MODEL}


@router.get("/tools/status")
def tools_status():
    return {"execution_mode": get_scan_mode(), "tools": ToolManager().availability()}


@router.post("/tools/check")
def tools_check():
    # Detection performs bounded version checks only; it never runs a scan.
    return {"execution_mode": get_scan_mode(), "tools": ToolManager().availability(),
            "checked_at": datetime.now(timezone.utc).isoformat()}


@router.post("/scopes", response_model=ScopeRecord, status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeCreate):
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required")
    try:
        root = normalize_domain(payload.root_domain, allow_lab_hosts=payload.local_lab_mode)
        if payload.local_lab_mode:
            from app.core.scope_manager import validate_lab_destination
            validate_lab_destination(root, resolve=False)
        included = sorted({normalize_domain(item, allow_lab_hosts=payload.local_lab_mode) for item in payload.included_assets})
        excluded = sorted({normalize_domain(item, allow_lab_hosts=payload.local_lab_mode) for item in payload.excluded_subdomains})
        if any(item != root and not item.endswith("." + root) for item in included + excluded):
            raise ScopeError("Included and excluded assets must belong to the authorized root domain")
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    if payload.local_lab_mode and not payload.local_lab_ports:
        raise HTTPException(status_code=422, detail="Local Lab mode requires one or more explicitly approved ports")
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with connect() as db:
            cursor = db.execute("INSERT INTO scopes(root_domain, program_name, include_subdomains, included_assets, excluded_subdomains, authorization_notes, authorization_confirmed, authorization_reference, local_lab_mode, local_lab_ports, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)",
                                (root, payload.program_name.strip() or root, int(payload.include_subdomains), json.dumps(included),
                                 json.dumps(excluded), payload.authorization_notes.strip(), payload.authorization_reference.strip(), int(payload.local_lab_mode), json.dumps(sorted(set(payload.local_lab_ports))), created_at))
            row = db.execute("SELECT * FROM scopes WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(status_code=409, detail="A scope for this root domain already exists") from exc
        raise
    return _record(row)


@router.post("/scopes/{scope_id}/verify-authorization", response_model=ScopeRecord)
def verify_scope_authorization(scope_id: int, payload: AuthorizationVerification):
    if not payload.verified:
        raise HTTPException(status_code=400, detail="Manual authorization review was not confirmed")
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Scope not found")
        if row["local_lab_mode"]:
            raise HTTPException(status_code=400, detail="Local lab scopes use local-only validation and cannot verify public authorization")
        reference = payload.authorization_reference.strip() or row["authorization_reference"].strip()
        parsed_reference = urlsplit(reference)
        if parsed_reference.scheme not in {"https", "http"} or not parsed_reference.hostname or parsed_reference.username or parsed_reference.password:
            raise HTTPException(status_code=422, detail="A program policy or authorization reference URL is required")
        verified_at = datetime.now(timezone.utc).isoformat()
        db.execute("UPDATE scopes SET authorization_reference = ?, authorization_status = 'verified', authorization_verified_by = ?, authorization_verified_at = ?, authorization_review_notes = ? WHERE id = ?",
                   (reference, payload.verified_by.strip(), verified_at, payload.review_notes.strip(), scope_id))
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    return _record(row)


@router.get("/settings")
def get_settings():
    return {"scan_mode": get_scan_mode(), "allowed_modes": ["mock", "real", "local_lab"] if APP_PROFILE != "PRODUCTION_KALI" else ["real"],
            "app_env": APP_ENV, "app_profile": APP_PROFILE, "platform": CURRENT_PLATFORM,
            "httpx_executable": HTTPX_EXECUTABLE}


@router.put("/settings/scan-mode")
def update_scan_mode(payload: ScanModeUpdate):
    try:
        mode = set_scan_mode(payload.scan_mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    return {"scan_mode": mode, "message": "Mode updated. Running jobs retain their start-time mode."}


@router.get("/scopes", response_model=list[ScopeRecord])
def list_scopes():
    with connect() as db:
        return [_record(row) for row in db.execute("SELECT * FROM scopes ORDER BY id DESC").fetchall()]


@router.delete("/scopes/{scope_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_scope(scope_id: int):
    with connect() as db:
        result = db.execute("DELETE FROM scopes WHERE id = ?", (scope_id,))
        if not result.rowcount:
            raise HTTPException(status_code=404, detail="Scope not found")
