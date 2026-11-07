from pathlib import Path
import os
from urllib.parse import unquote, urlparse


BASE_DIR = Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    """Load simple KEY=VALUE entries without requiring a platform-specific dotenv package."""
    env_file = BASE_DIR / ".env"
    if not env_file.is_file():
        return
    for line in env_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip("\"'"))


_load_env_file()


def _database_path(database_url: str) -> Path:
    parsed = urlparse(database_url)
    if parsed.scheme != "sqlite":
        raise ValueError("Phase 1 supports SQLite DATABASE_URL values only")
    raw_path = unquote(parsed.path)
    if raw_path in {"", "/", ":memory:"}:
        if raw_path == ":memory:":
            return Path(":memory:")
        raise ValueError("DATABASE_URL must include a SQLite database file")
    if raw_path.startswith("/./"):
        raw_path = raw_path[3:]
    path = Path(raw_path)
    if parsed.netloc and parsed.netloc != "localhost":
        path = Path(f"//{parsed.netloc}") / raw_path.lstrip("/")
    elif raw_path.startswith("/") and os.name == "nt" and len(raw_path) > 2 and raw_path[2] == ":":
        path = Path(raw_path[1:])
    return (BASE_DIR / path).resolve() if not path.is_absolute() else path.resolve()


DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./data/bughunter.db")
DATABASE_PATH = _database_path(DATABASE_URL)
DATA_DIR = DATABASE_PATH.parent
APP_ENV = os.environ.get("APP_ENV", "development")
APP_HOST = os.environ.get("APP_HOST", "127.0.0.1")
APP_PORT = int(os.environ.get("APP_PORT", "8000"))
OLLAMA_BASE_URL = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen3:4b")
AI_MAX_CONCURRENCY = max(1, int(os.environ.get("AI_MAX_CONCURRENCY", "1")))
AI_CONTEXT_LENGTH = max(512, int(os.environ.get("AI_CONTEXT_LENGTH", "4096")))
SCAN_MODE = os.environ.get("SCAN_MODE", "real" if APP_ENV == "production" else "mock").lower()
SCAN_TIMEOUT = max(1, int(os.environ.get("SCAN_TIMEOUT", "300")))
