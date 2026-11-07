import json
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status

from app.core.database import connect
from app.core.scope_manager import ScopeError, normalize_domain
from app.models.scope import ScopeCreate, ScopeRecord
from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL
from app.ai.ollama_client import ollama_health
from app.services.tool_manager import ToolManager

router = APIRouter()


def _record(row) -> ScopeRecord:
    return ScopeRecord(id=row["id"], root_domain=row["root_domain"], program_name=row["program_name"],
                       include_subdomains=bool(row["include_subdomains"]), included_assets=json.loads(row["included_assets"]),
                       excluded_subdomains=json.loads(row["excluded_subdomains"]), authorization_notes=row["authorization_notes"],
                       authorization_confirmed=bool(row["authorization_confirmed"]), local_lab_mode=bool(row["local_lab_mode"]),
                       created_at=datetime.fromisoformat(row["created_at"]))


@router.get("/health")
def health():
    try:
        with connect() as db:
            db.execute("SELECT 1").fetchone()
        ai_status = ollama_health()
        return {"status": "ok", "database": "ok", "ai": ai_status, "ollama_model": OLLAMA_MODEL,
                "ollama_endpoint": OLLAMA_BASE_URL,
                "ai_install_hint": None if ai_status == "connected" else
                "Install Ollama, start its local service, then run: ollama pull " + OLLAMA_MODEL,
                "tools": ToolManager().availability()}
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Database unavailable") from exc


@router.post("/scopes", response_model=ScopeRecord, status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeCreate):
    if not payload.authorization_confirmed:
        raise HTTPException(status_code=400, detail="Explicit authorization confirmation is required")
    try:
        root = normalize_domain(payload.root_domain)
        included = sorted({normalize_domain(item) for item in payload.included_assets})
        excluded = sorted({normalize_domain(item) for item in payload.excluded_subdomains})
        if any(item != root and not item.endswith("." + root) for item in included + excluded):
            raise ScopeError("Included and excluded assets must belong to the authorized root domain")
    except ScopeError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    created_at = datetime.now(timezone.utc).isoformat()
    try:
        with connect() as db:
            cursor = db.execute("INSERT INTO scopes(root_domain, program_name, include_subdomains, included_assets, excluded_subdomains, authorization_notes, authorization_confirmed, local_lab_mode, created_at) VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?)",
                                (root, payload.program_name.strip() or root, int(payload.include_subdomains), json.dumps(included),
                                 json.dumps(excluded), payload.authorization_notes.strip(), int(payload.local_lab_mode), created_at))
            row = db.execute("SELECT * FROM scopes WHERE id = ?", (cursor.lastrowid,)).fetchone()
    except Exception as exc:
        if "UNIQUE" in str(exc):
            raise HTTPException(status_code=409, detail="A scope for this root domain already exists") from exc
        raise
    return _record(row)


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
