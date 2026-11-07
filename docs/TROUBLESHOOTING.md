# Troubleshooting

## Tools show MOCK

Check `/api/system/info` for profile and execution mode. Windows development defaults to visibly simulated MOCK. Choose REAL in Settings to test binary detection; missing tools remain unavailable and do not produce samples. Restart after `.env` changes. Database mode is tied to its profile and reset to the profile default when profiles change.

## Tool is NOT_INSTALLED or ERROR

Run the configured executable name as the same user that launches FastAPI. Check PATH and set the corresponding `*_EXECUTABLE` variable, then select Tool Management → Check again or call `POST /api/tools/check`. ERROR means a binary was found but its bounded version check failed.

## httpx is rejected

The Python package named `httpx` may provide an unrelated CLI. AI BugHunter accepts a ProjectDiscovery version banner only. On Kali, set `HTTPX_EXECUTABLE=httpx-toolkit`; for another install, configure its executable name or full path and ensure the backend service user can access it.

## Ollama unavailable

Check `OLLAMA_BASE_URL`, start Ollama, and run `ollama pull qwen3:4b`. `/api/health` returns its connectivity state and setup hint. Startup does not install or launch Ollama.

## Authorization or Local Lab is rejected

An authorization checkbox in SQLite is not sufficient for public traffic. Record a separate manual review with reviewer and policy URL. Local Lab accepts loopback only and enforces exact configured ports; it rejects public DNS and LAN targets.

## Pytest cannot import app

From the repository root run `python -m pytest -q` (or the active virtual environment's Python). Kali integration testing must run on Kali; Windows passing tests do not establish Linux compatibility.
