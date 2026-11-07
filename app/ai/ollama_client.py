import json
import threading
from urllib.error import URLError
from urllib.request import Request, urlopen

from app.config import AI_CONTEXT_LENGTH, AI_MAX_CONCURRENCY, OLLAMA_BASE_URL, OLLAMA_MODEL

_inference_gate = threading.BoundedSemaphore(AI_MAX_CONCURRENCY)


def ollama_health(timeout: float = 1.5) -> str:
    try:
        with urlopen(f"{OLLAMA_BASE_URL}/api/tags", timeout=timeout) as response:
            payload = json.loads(response.read(256_000).decode("utf-8"))
        models = {item.get("name") for item in payload.get("models", [])}
        return "connected" if OLLAMA_MODEL in models else "connected_model_missing"
    except (OSError, ValueError, URLError):
        return "unavailable"


def generate(prompt: str, timeout: int = 120) -> str:
    """Run one bounded local inference; prompt content is treated as untrusted data by callers."""
    body = json.dumps({"model": OLLAMA_MODEL, "prompt": prompt[:12_000], "stream": False,
                       "options": {"num_ctx": AI_CONTEXT_LENGTH, "num_predict": 768}}).encode("utf-8")
    request = Request(f"{OLLAMA_BASE_URL}/api/generate", data=body, headers={"Content-Type": "application/json"})
    if not _inference_gate.acquire(timeout=timeout):
        raise TimeoutError("Timed out waiting for the local AI inference slot")
    try:
        with urlopen(request, timeout=timeout) as response:
            result = json.loads(response.read(2_000_000).decode("utf-8"))
        return str(result.get("response", ""))[:12_000]
    finally:
        _inference_gate.release()
