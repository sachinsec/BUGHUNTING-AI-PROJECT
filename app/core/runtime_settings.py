from threading import RLock

from app.config import APP_PROFILE, SCAN_MODE as DEFAULT_SCAN_MODE

_lock = RLock()
_scan_mode = DEFAULT_SCAN_MODE


def get_scan_mode() -> str:
    with _lock:
        return _scan_mode


def initialize_runtime_settings() -> None:
    """Load persisted operator settings after SQLite has been initialized."""
    global _scan_mode
    from app.core.database import connect

    with connect() as db:
        profile_row = db.execute("SELECT value FROM app_settings WHERE key = 'app_profile'").fetchone()
        row = db.execute("SELECT value FROM app_settings WHERE key = 'scan_mode'").fetchone()
        # A copied database must not carry a Windows mock setting into Linux/Kali
        # or silently retain a real-mode operator choice from a different profile.
        if profile_row is None or profile_row["value"] != APP_PROFILE or row is None:
            mode = DEFAULT_SCAN_MODE
            db.execute("INSERT INTO app_settings(key, value, updated_at) VALUES ('scan_mode', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))", (mode,))
            db.execute("INSERT INTO app_settings(key, value, updated_at) VALUES ('app_profile', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at", (APP_PROFILE,))
        else:
            mode = row["value"]
        if mode not in {"mock", "real", "local_lab"} or (APP_PROFILE == "PRODUCTION_KALI" and mode != "real"):
            mode = DEFAULT_SCAN_MODE
            db.execute("UPDATE app_settings SET value = ?, updated_at = strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE key = 'scan_mode'", (mode,))
    with _lock:
        _scan_mode = mode


def set_scan_mode(mode: str) -> str:
    global _scan_mode
    mode = mode.strip().lower()
    if mode not in {"mock", "real", "local_lab"}:
        raise ValueError("Scan mode must be 'mock', 'real', or 'local_lab'")
    if APP_PROFILE == "PRODUCTION_KALI" and mode != "real":
        raise ValueError("PRODUCTION_KALI permits REAL execution mode only")
    from app.core.database import connect

    with connect() as db:
        db.execute("INSERT INTO app_settings(key, value, updated_at) VALUES ('scan_mode', ?, strftime('%Y-%m-%dT%H:%M:%fZ','now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at", (mode,))
    with _lock:
        _scan_mode = mode
    return mode
