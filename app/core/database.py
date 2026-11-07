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
            local_lab_mode INTEGER NOT NULL DEFAULT 0 CHECK (local_lab_mode IN (0, 1)),
            created_at TEXT NOT NULL
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
