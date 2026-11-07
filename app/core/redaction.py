import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

_SENSITIVE_KEY = re.compile(r"(?:pass(?:word)?|secret|token|auth|session|credential|api[_-]?key|signature|jwt|code)", re.I)


def redact_url(url: str) -> str:
    """Redact likely credential values from URLs before persistence or display."""
    parsed = urlsplit(url)
    query = [(key, "[REDACTED]" if _SENSITIVE_KEY.search(key) else value) for key, value in parse_qsl(parsed.query, keep_blank_values=True)]
    # Fragments are client-side and may contain OAuth tokens; they are not needed for asset identity.
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(query, doseq=True), ""))
