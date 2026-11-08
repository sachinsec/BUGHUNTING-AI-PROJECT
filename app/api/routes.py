import json
from datetime import datetime, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, HTTPException, status

from app.core.database import connect
from app.core.scope_manager import ScopeError, normalize_domain
from app.models.scope import (AuthorizationReviewCreate, AuthorizationReviewDecision,
                              AuthorizationVerification, ScanModeUpdate, ScopeCreate, ScopeRecord)
from app.core.runtime_settings import get_scan_mode, set_scan_mode
from app.config import APP_ENV, APP_PROFILE, CURRENT_PLATFORM, HTTPX_EXECUTABLE, OLLAMA_BASE_URL, OLLAMA_MODEL
from app.ai.ollama_client import ollama_health
from app.services.tool_manager import ToolManager

router = APIRouter()


def _record(row) -> ScopeRecord:
    status_value = row["authorization_status"]
    if not row["local_lab_mode"]:
        with connect() as db:
            review = db.execute("SELECT * FROM authorization_reviews WHERE scope_id=? ORDER BY id DESC LIMIT 1", (row["id"],)).fetchone()
        status_value = review["status"] if review else "PENDING"
        if review and review["status"] == "APPROVED" and review["expires_at"]:
            expiry = datetime.fromisoformat(review["expires_at"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                status_value = "EXPIRED"
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       authorization_reference=row["authorization_reference"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       local_lab_ports=json.loads(row["local_lab_ports"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=bool(row["authorization_confirmed"]), local_lab_mode=bool(row["local_lab_mode"]),
                       authorization_status=status_value, authorization_verified_by=row["authorization_verified_by"],
                       authorization_verified_at=datetime.fromisoformat(row["authorization_verified_at"]) if row["authorization_verified_at"] else None,
                       created_at=datetime.fromisoformat(row["created_at"]))


def _authorization_review(row) -> dict:
    review = dict(row)
    review["allow_subdomains"] = bool(review["allow_subdomains"])
    review["excluded_assets"] = json.loads(review.get("excluded_assets") or "[]")
    if review["status"] == "APPROVED" and review["expires_at"]:
        expiry = datetime.fromisoformat(review["expires_at"])
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        if expiry <= datetime.now(timezone.utc):
            review["status"] = "EXPIRED"
    return review


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
    # Kept as a compatibility route, but a single legacy verification request
    # cannot create an approval. The full review API captures platform, exact
    # asset, subdomain permission, exclusions, evidence, and a separate decision.
    with connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id = ?", (scope_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Scope not found")
    if row["local_lab_mode"]:
        raise HTTPException(status_code=400, detail="Local Lab scopes use explicit loopback host and port configuration")
    raise HTTPException(status_code=409, detail=(
        "Legacy authorization verification cannot approve public reconnaissance. "
        "Submit complete evidence through POST /api/scopes/{scope_id}/authorization-reviews, "
        "then record a separate reviewer decision through PUT /api/authorization-reviews/{review_id}."
    ))


@router.get("/scopes/{scope_id}/authorization-reviews")
def list_authorization_reviews(scope_id: int):
    with connect() as db:
        if not db.execute("SELECT 1 FROM scopes WHERE id=?", (scope_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Scope not found")
        rows = db.execute("SELECT * FROM authorization_reviews WHERE scope_id=? ORDER BY id DESC", (scope_id,)).fetchall()
    return [_authorization_review(row) for row in rows]


@router.post("/scopes/{scope_id}/authorization-reviews", status_code=201)
def create_authorization_review(scope_id: int, payload: AuthorizationReviewCreate):
    with connect() as db:
        scope = db.execute("SELECT * FROM scopes WHERE id=?", (scope_id,)).fetchone()
        if not scope:
            raise HTTPException(status_code=404, detail="Scope not found")
        if scope["local_lab_mode"]:
            raise HTTPException(status_code=400, detail="Local Lab authorization is managed by its explicit host and port configuration")
        try:
            asset = normalize_domain(payload.authorized_asset)
            excluded = sorted({normalize_domain(item) for item in payload.excluded_assets})
        except ScopeError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        root = scope["root_domain"]
        if any(item != root and not item.endswith("." + root) for item in [asset, *excluded]):
            raise HTTPException(status_code=422, detail="Authorized and excluded assets must be within the registered root")
        try:
            parsed = urlsplit(payload.policy_url)
            policy_hostname = parsed.hostname
            _policy_port = parsed.port
        except ValueError as exc:
            raise HTTPException(status_code=422, detail="A valid HTTPS program policy URL is required") from exc
        if parsed.scheme != "https" or not policy_hostname or parsed.username or parsed.password:
            raise HTTPException(status_code=422, detail="A valid HTTPS program policy URL is required")
        now = datetime.now(timezone.utc).isoformat()
        expires_at = payload.expires_at
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at and expires_at <= datetime.now(timezone.utc):
            raise HTTPException(status_code=422, detail="Authorization expiration must be in the future")
        cursor = db.execute("INSERT INTO authorization_reviews(scope_id,status,program_name,platform_name,authorized_asset,allow_subdomains,policy_url,excluded_assets,evidence_notes,expires_at,created_at) VALUES (?, 'PENDING', ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                            (scope_id, payload.program_name.strip(), payload.platform_name.strip(), asset, int(payload.allow_subdomains), payload.policy_url.strip(),
                             json.dumps(excluded), payload.evidence_notes.strip(), expires_at.isoformat() if expires_at else None, now))
        return _authorization_review(db.execute("SELECT * FROM authorization_reviews WHERE id=?", (cursor.lastrowid,)).fetchone())


@router.put("/authorization-reviews/{review_id}")
def decide_authorization_review(review_id: int, payload: AuthorizationReviewDecision):
    decision = payload.status.upper()
    if decision not in {"APPROVED", "REJECTED", "EXPIRED"}:
        raise HTTPException(status_code=422, detail="Decision must be APPROVED, REJECTED, or EXPIRED")
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        row = db.execute("SELECT * FROM authorization_reviews WHERE id=?", (review_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Authorization review not found")
        if decision == "APPROVED" and row["expires_at"]:
            expiry = datetime.fromisoformat(row["expires_at"])
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
            if expiry <= datetime.now(timezone.utc):
                raise HTTPException(status_code=422, detail="Expired evidence cannot be approved")
        db.execute("UPDATE authorization_reviews SET status=?, reviewer=?, decision=?, reviewed_at=? WHERE id=?",
                   (decision, payload.reviewer.strip(), payload.decision.strip(), now, review_id))
        return _authorization_review(db.execute("SELECT * FROM authorization_reviews WHERE id=?", (review_id,)).fetchone())


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
