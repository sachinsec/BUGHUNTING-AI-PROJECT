import json
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, HTTPException, Query

from app.core.database import connect
from app.core.runtime_settings import get_scan_mode
from app.models.vulnerability import FindingCreate, FindingRecord, FindingStatusUpdate
from app.services.web_test_catalog import get_web_test_catalog

router = APIRouter(tags=["vulnerabilities"])
_SEVERITIES = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")


@router.get("/techniques")
def list_web_testing_techniques():
    """Return the built-in, non-destructive web security review catalog."""
    return {"source": "web-application-security-review", "categories": get_web_test_catalog()}


def _record(row) -> FindingRecord:
    return FindingRecord(
        id=row["id"], scope_id=row["scope_id"], scan_id=row["scan_id"],
        title=row["title"], description=row["description"], target=row["target"],
        severity=row["severity"], status=row["status"], source=row["source"],
        evidence=json.loads(row["evidence_json"]), reviewer=row["reviewer"],
        reviewer_notes=row["reviewer_notes"], execution_mode=row["execution_mode"],
        simulated=bool(row["simulated"]), created_at=datetime.fromisoformat(row["created_at"]),
        updated_at=datetime.fromisoformat(row["updated_at"]),
    )


@router.post("", response_model=FindingRecord, status_code=201)
def create_finding(payload: FindingCreate):
    mode = get_scan_mode()
    execution_mode = {"real": "REAL", "mock": "MOCK", "local_lab": "LOCAL_LAB"}[mode]
    simulated = mode == "mock"
    now = datetime.now(timezone.utc).isoformat()
    scope_id = payload.scope_id
    with connect() as db:
        if scope_id is not None and not db.execute("SELECT 1 FROM scopes WHERE id=?", (scope_id,)).fetchone():
            raise HTTPException(status_code=404, detail="Finding scope was not found")
        if payload.scan_id is not None:
            scan = db.execute("SELECT scope_id,simulated FROM recon_scans WHERE id=?", (payload.scan_id,)).fetchone()
            if not scan:
                raise HTTPException(status_code=404, detail="Finding scan was not found")
            if payload.scope_id is not None and payload.scope_id != scan["scope_id"]:
                raise HTTPException(status_code=422, detail="Finding scope does not match its reconnaissance scan")
            scope_id = scan["scope_id"]
            if scan["simulated"]:
                execution_mode, simulated = "MOCK", True
            elif scope_id is not None:
                linked_scope = db.execute("SELECT local_lab_mode FROM scopes WHERE id=?", (scope_id,)).fetchone()
                if linked_scope and linked_scope["local_lab_mode"]:
                    execution_mode = "LOCAL_LAB"
        cursor = db.execute(
            "INSERT INTO vulnerability_findings(scope_id,scan_id,title,description,target,severity,status,source,evidence_json,execution_mode,simulated,created_at,updated_at) VALUES (?,?,?,?,?,?,'POTENTIAL','manual',?,?,?,?,?)",
            (scope_id, payload.scan_id, payload.title.strip(), payload.description.strip(), payload.target.strip(),
             payload.severity, json.dumps(payload.evidence), execution_mode, int(simulated), now, now),
        )
        row = db.execute("SELECT * FROM vulnerability_findings WHERE id=?", (cursor.lastrowid,)).fetchone()
    return _record(row)


@router.get("/stats")
def vulnerability_stats():
    with connect() as db:
        rows = db.execute("SELECT severity,status,execution_mode,simulated,COUNT(*) AS count FROM vulnerability_findings GROUP BY severity,status,execution_mode,simulated").fetchall()
    stats = {
        "total": 0, "real_total": 0, "potential": 0, "verified": 0, "false_positive": 0, "resolved": 0,
        "simulated": 0, "by_severity": {severity: 0 for severity in _SEVERITIES},
        "simulated_by_severity": {severity: 0 for severity in _SEVERITIES},
    }
    for row in rows:
        count = row["count"]
        stats["total"] += count
        if row["simulated"]:
            stats["simulated"] += count
            stats["simulated_by_severity"][row["severity"]] += count
        else:
            stats["real_total"] += count
            stats["by_severity"][row["severity"]] += count
            if row["status"] == "POTENTIAL":
                stats["potential"] += count
            elif row["status"] == "VERIFIED":
                stats["verified"] += count
            elif row["status"] == "FALSE_POSITIVE":
                stats["false_positive"] += count
            elif row["status"] == "RESOLVED":
                stats["resolved"] += count
    return stats


@router.get("", response_model=list[FindingRecord])
def list_findings(
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"] | None = None,
    status: Literal["POTENTIAL", "VERIFIED", "FALSE_POSITIVE", "RESOLVED"] | None = None,
    target: str | None = Query(default=None, max_length=2048),
    limit: int = Query(default=100, ge=1, le=500),
):
    clauses, values = [], []
    if severity:
        clauses.append("severity=?")
        values.append(severity)
    if status:
        clauses.append("status=?")
        values.append(status)
    if target and target.strip():
        clauses.append("target LIKE ? ESCAPE '\\'")
        escaped = target.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        values.append(f"%{escaped}%")
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    with connect() as db:
        rows = db.execute(f"SELECT * FROM vulnerability_findings {where} ORDER BY id DESC LIMIT ?", (*values, limit)).fetchall()
    return [_record(row) for row in rows]


@router.get("/{finding_id}", response_model=FindingRecord)
def get_finding(finding_id: int):
    with connect() as db:
        row = db.execute("SELECT * FROM vulnerability_findings WHERE id=?", (finding_id,)).fetchone()
    if row is None:
        raise HTTPException(status_code=404, detail="Finding was not found")
    return _record(row)


@router.patch("/{finding_id}", response_model=FindingRecord)
def update_finding(finding_id: int, payload: FindingStatusUpdate):
    now = datetime.now(timezone.utc).isoformat()
    with connect() as db:
        row = db.execute("SELECT * FROM vulnerability_findings WHERE id=?", (finding_id,)).fetchone()
        if row is None:
            raise HTTPException(status_code=404, detail="Finding was not found")
        if payload.status == "VERIFIED" and row["simulated"]:
            raise HTTPException(status_code=409, detail="Simulated findings cannot be marked as verified scanner findings")
        if payload.status == "VERIFIED" and not (payload.reviewer or "").strip():
            raise HTTPException(status_code=422, detail="A reviewer name is required to verify a finding")
        reviewer = payload.reviewer.strip() if payload.reviewer else row["reviewer"]
        db.execute("UPDATE vulnerability_findings SET status=?, reviewer=?, reviewer_notes=?, updated_at=? WHERE id=?",
                   (payload.status, reviewer, payload.reviewer_notes.strip(), now, finding_id))
        updated = db.execute("SELECT * FROM vulnerability_findings WHERE id=?", (finding_id,)).fetchone()
    return _record(updated)
