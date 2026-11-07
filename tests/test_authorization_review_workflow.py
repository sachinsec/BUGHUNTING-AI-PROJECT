from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core import database
from app.core.scope_manager import ScopeError, validate_real_network_access
from app.main import app


def _scope(client):
    response = client.post("/api/scopes", json={
        "root_domain": "example.com", "program_name": "Example Program",
        "included_assets": ["api.example.com"], "excluded_subdomains": ["private.example.com"],
        "authorization_notes": "Submitted for independent review", "authorization_confirmed": True,
    })
    assert response.status_code == 201
    return response.json()


def _review(client, scope_id, asset="api.example.com", allow_subdomains=False, expires_at=None, excluded_assets=None):
    return client.post(f"/api/scopes/{scope_id}/authorization-reviews", json={
        "program_name": "Example Program", "platform_name": "Bugcrowd", "authorized_asset": asset,
        "allow_subdomains": allow_subdomains, "policy_url": "https://example.com/policy",
        "excluded_assets": excluded_assets or [],
        "evidence_notes": "Program policy includes this asset", "expires_at": expires_at,
    })


@pytest.fixture
def client_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DATABASE_PATH", tmp_path / "reviews.sqlite3")
    monkeypatch.setattr(database, "DATA_DIR", tmp_path)
    database.initialize_database()
    with TestClient(app) as client:
        yield client


def test_pending_review_blocks_until_explicit_approval_and_exact_target(client_db):
    scope = _scope(client_db)
    review = _review(client_db, scope["id"]).json()
    assert review["status"] == "PENDING"
    with database.connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id=?", (scope["id"],)).fetchone()
    from app.api.routes import _record
    record = _record(row)
    with pytest.raises(ScopeError, match="pending"):
        validate_real_network_access(record, "api.example.com", resolve=False)
    decided = client_db.put(f"/api/authorization-reviews/{review['id']}", json={
        "status": "APPROVED", "reviewer": "Independent Reviewer", "decision": "Policy confirms the listed asset."})
    assert decided.status_code == 200
    assert decided.json()["status"] == "APPROVED"
    assert validate_real_network_access(record, "api.example.com", resolve=False) == "api.example.com"
    with pytest.raises(ScopeError, match="outside the exact asset"):
        validate_real_network_access(record, "www.example.com", resolve=False)
    with pytest.raises(ScopeError, match="outside the registered scope"):
        validate_real_network_access(record, "outside.test", resolve=False)
    with pytest.raises(ScopeError, match="exclusion"):
        validate_real_network_access(record, "private.example.com", resolve=False)


@pytest.mark.parametrize("status, message", [("REJECTED", "rejected"), ("EXPIRED", "expired")])
def test_rejected_and_expired_reviews_block(client_db, status, message):
    scope = _scope(client_db)
    expiry = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat() if status == "EXPIRED" else None
    review = _review(client_db, scope["id"], asset="example.com", allow_subdomains=True, expires_at=expiry).json()
    decision = "APPROVED" if status == "EXPIRED" else status
    decided = client_db.put(f"/api/authorization-reviews/{review['id']}", json={
        "status": decision, "reviewer": "Independent Reviewer", "decision": "Review decision recorded."})
    assert decided.status_code == 200
    if status == "EXPIRED":
        with database.connect() as db:
            db.execute("UPDATE authorization_reviews SET expires_at=? WHERE id=?",
                       ((datetime.now(timezone.utc) - timedelta(days=1)).isoformat(), review["id"]))
    with database.connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id=?", (scope["id"],)).fetchone()
    from app.api.routes import _record
    with pytest.raises(ScopeError, match=message):
        validate_real_network_access(_record(row), "api.example.com", resolve=False)


def test_approved_subdomains_are_explicitly_limited_to_approved_asset(client_db):
    scope = _scope(client_db)
    review = _review(client_db, scope["id"], asset="api.example.com", allow_subdomains=True).json()
    client_db.put(f"/api/authorization-reviews/{review['id']}", json={
        "status": "APPROVED", "reviewer": "Independent Reviewer", "decision": "Reviewed."})
    with database.connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id=?", (scope["id"],)).fetchone()
    from app.api.routes import _record
    record = _record(row)
    assert validate_real_network_access(record, "v2.api.example.com", resolve=False) == "v2.api.example.com"
    with pytest.raises(ScopeError, match="outside the exact asset"):
        validate_real_network_access(record, "example.com", resolve=False)


def test_review_exclusion_blocks_target_and_new_rejection_supersedes_old_approval(client_db):
    scope = _scope(client_db)
    approved = _review(client_db, scope["id"], asset="example.com", allow_subdomains=True,
                       excluded_assets=["admin.example.com"]).json()
    client_db.put(f"/api/authorization-reviews/{approved['id']}", json={
        "status": "APPROVED", "reviewer": "Independent Reviewer", "decision": "Policy reviewed."})
    with database.connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id=?", (scope["id"],)).fetchone()
    from app.api.routes import _record
    record = _record(row)
    with pytest.raises(ScopeError, match="authorization review exclusion"):
        validate_real_network_access(record, "admin.example.com", resolve=False)

    newer = _review(client_db, scope["id"], asset="example.com", allow_subdomains=True).json()
    client_db.put(f"/api/authorization-reviews/{newer['id']}", json={
        "status": "REJECTED", "reviewer": "Independent Reviewer", "decision": "Program authorization was withdrawn."})
    with pytest.raises(ScopeError, match="rejected"):
        validate_real_network_access(record, "api.example.com", resolve=False)


def test_discovery_results_are_filtered_to_reviewed_assets(client_db):
    from app.services.subdomain_recon import parse_subfinder_output

    scope = _scope(client_db)
    review = _review(client_db, scope["id"], asset="example.com", allow_subdomains=False).json()
    client_db.put(f"/api/authorization-reviews/{review['id']}", json={
        "status": "APPROVED", "reviewer": "Independent Reviewer", "decision": "Root only."})
    with database.connect() as db:
        row = db.execute("SELECT * FROM scopes WHERE id=?", (scope["id"],)).fetchone()
    from app.api.routes import _record
    results, rejected = parse_subfinder_output("api.example.com\n", _record(row), require_approved=True)
    assert results == []
    assert rejected == 1
