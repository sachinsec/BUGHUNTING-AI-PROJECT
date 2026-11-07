from importlib.util import find_spec
import json
from pathlib import Path
import shutil
import sys
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from app.config import OLLAMA_BASE_URL, OLLAMA_MODEL, TOOL_EXECUTABLES  # noqa: E402
from app.services.tool_manager import ToolManager  # noqa: E402

def main() -> int:
    print(f"Python: {sys.version.split()[0]} ({sys.executable})")
    for module in ("fastapi", "pydantic", "uvicorn", "pytest"):
        print(f"Python package {module}: {'available' if find_spec(module) else 'missing'}")
    print(f"Ollama executable: {shutil.which('ollama') or 'not found'}")
    for name, binary in TOOL_EXECUTABLES.items():
        print(f"Tool {name}: {shutil.which(binary) or 'not found'} (configured: {binary})")
    for tool in ToolManager(mode="real").availability():
        print(f"Adapter {tool['name']}: {tool.get('status', 'ERROR')}"
              + (f" | {tool['path']}" if tool.get("path") else "")
              + (f" | {tool['version']}" if tool.get("version") else "")
              + (f" | {tool['error']}" if tool.get("error") else ""))
    try:
        with urlopen(f"{OLLAMA_BASE_URL}/api/tags", timeout=2) as response:
            payload = json.loads(response.read(256_000).decode("utf-8"))
            print(f"Ollama API: HTTP {response.status} at {OLLAMA_BASE_URL}")
            installed = {item.get("name") for item in payload.get("models", [])}
            if OLLAMA_MODEL in installed:
                print(f"Ollama model {OLLAMA_MODEL}: installed")
            else:
                print(f"Ollama model {OLLAMA_MODEL}: missing; run `ollama pull {OLLAMA_MODEL}`")
    except OSError as exc:
        print(f"Ollama API: unavailable ({exc})")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
