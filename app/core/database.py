import sqlite3
from contextlib import contextmanager

from app.config import DATABASE_PATH, DATA_DIR


def initialize_database() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript("""
        PRAGMA journal_mode = WAL;
        PRAGMA foreign_keys = ON;
        CREATE TABLE IF NOT EXISTS scopes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            root_domain TEXT NOT NULL UNIQUE,
            program_name TEXT NOT NULL DEFAULT '',
            include_subdomains INTEGER NOT NULL CHECK (include_subdomains IN (0, 1)),
            included_assets TEXT NOT NULL DEFAULT '[]',
            excluded_subdomains TEXT NOT NULL DEFAULT '[]',
            authorization_notes TEXT NOT NULL,
            authorization_confirmed INTEGER NOT NULL CHECK (authorization_confirmed = 1),
            authorization_reference TEXT NOT NULL DEFAULT '',
            authorization_status TEXT NOT NULL DEFAULT 'unverified' CHECK (authorization_status IN ('unverified', 'verified')),
            authorization_verified_by TEXT,
            authorization_verified_at TEXT,
            authorization_review_notes TEXT NOT NULL DEFAULT '',
            local_lab_mode INTEGER NOT NULL DEFAULT 0 CHECK (local_lab_mode IN (0, 1)),
            local_lab_ports TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS recon_scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            module TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
            stage TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            error TEXT,
            started_at TEXT,
            finished_at TEXT,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_recon_scans_scope ON recon_scans(scope_id, id DESC);
        CREATE TABLE IF NOT EXISTS discovered_subdomains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            source TEXT,
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            discovered_at TEXT NOT NULL,
            UNIQUE(scan_id, hostname, simulated)
        );
        CREATE INDEX IF NOT EXISTS idx_subdomains_scope ON discovered_subdomains(scope_id, hostname);
        CREATE TABLE IF NOT EXISTS live_hosts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            title TEXT,
            content_type TEXT,
            ip_address TEXT,
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            discovered_at TEXT NOT NULL,
            UNIQUE(scan_id, url, simulated)
        );
        CREATE INDEX IF NOT EXISTS idx_live_hosts_scope ON live_hosts(scope_id, hostname);
        CREATE TABLE IF NOT EXISTS historical_urls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            source TEXT NOT NULL,
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            discovered_at TEXT NOT NULL,
            UNIQUE(scan_id, url, source, simulated)
        );
        CREATE INDEX IF NOT EXISTS idx_historical_urls_scope ON historical_urls(scope_id);
        CREATE TABLE IF NOT EXISTS discovered_endpoints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
            url TEXT NOT NULL,
            method TEXT NOT NULL DEFAULT 'GET',
            source TEXT,
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            discovered_at TEXT NOT NULL,
            UNIQUE(scan_id, url, method, simulated)
        );
        CREATE INDEX IF NOT EXISTS idx_endpoints_scope ON discovered_endpoints(scope_id, url);
        CREATE TABLE IF NOT EXISTS detected_technologies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            scan_id INTEGER NOT NULL REFERENCES recon_scans(id) ON DELETE CASCADE,
            hostname TEXT NOT NULL,
            technology TEXT NOT NULL,
            version TEXT,
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            detected_at TEXT NOT NULL,
            UNIQUE(scan_id, hostname, technology, version, simulated)
        );
        CREATE INDEX IF NOT EXISTS idx_technologies_scope ON detected_technologies(scope_id, hostname);
        CREATE TABLE IF NOT EXISTS orchestration_jobs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scope_id INTEGER NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
            status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
            stage TEXT NOT NULL,
            progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
            simulated INTEGER NOT NULL DEFAULT 0 CHECK (simulated IN (0, 1)),
            active_crawl_approved INTEGER NOT NULL DEFAULT 0 CHECK (active_crawl_approved IN (0, 1)),
            current_child_module TEXT,
            current_child_scan_id INTEGER,
            error TEXT,
            created_at TEXT NOT NULL,
            started_at TEXT,
            finished_at TEXT
        );
        CREATE TABLE IF NOT EXISTS orchestration_stages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id INTEGER NOT NULL REFERENCES orchestration_jobs(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'skipped', 'failed', 'cancelled')),
            child_scan_id INTEGER,
            error TEXT,
            started_at TEXT,
            finished_at TEXT,
            UNIQUE(job_id, name)
        );
        CREATE INDEX IF NOT EXISTS idx_orchestration_jobs_scope ON orchestration_jobs(scope_id, id DESC);
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """)
        # Additive migrations preserve existing scope rows from earlier versions.
        columns = {row["name"] for row in db.execute("PRAGMA table_info(scopes)")}
        if "program_name" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN program_name TEXT NOT NULL DEFAULT ''")
        if "included_assets" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN included_assets TEXT NOT NULL DEFAULT '[]'")
        if "local_lab_mode" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN local_lab_mode INTEGER NOT NULL DEFAULT 0")
        if "authorization_reference" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN authorization_reference TEXT NOT NULL DEFAULT ''")
        if "authorization_status" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN authorization_status TEXT NOT NULL DEFAULT 'unverified'")
        if "authorization_verified_by" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN authorization_verified_by TEXT")
        if "authorization_verified_at" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN authorization_verified_at TEXT")
        if "authorization_review_notes" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN authorization_review_notes TEXT NOT NULL DEFAULT ''")
        if "local_lab_ports" not in columns:
            db.execute("ALTER TABLE scopes ADD COLUMN local_lab_ports TEXT NOT NULL DEFAULT '[]'")


@contextmanager
def connect():
    db = sqlite3.connect(str(DATABASE_PATH), timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
