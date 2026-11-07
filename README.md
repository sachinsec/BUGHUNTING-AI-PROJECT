# AI BugHunter

Local-first security reconnaissance and finding management for Windows development and Kali Linux deployment. The service binds to `127.0.0.1` by default and requires explicit authorization before a scope can be registered.

## Phase plan

1. **Foundation (implemented):** portable configuration, SQLite persistence, explicit authorization records, scope validation, and health endpoint.
2. **Adapters (initial implementation):** local Ollama health/inference client, explicitly simulated mock adapters, and optional real tool detection/invocation wrappers.
3. **Asset and scan persistence:** scan lifecycle, discovered asset models, job cancellation, and bounded background execution.
4. **Recon and findings:** full stage orchestration, parsing, deduplication, persistence, and verification workflow.
5. **AI analysis and reports:** evidence-grounded finding analysis and Markdown/JSON report generation.
6. **Dashboard:** responsive frontend connected to real APIs and end-to-end verification.

Each phase should be reviewed and verified before starting the next. No scan execution endpoint or orchestration is exposed yet. Real tool wrappers are initial infrastructure and are not a complete or audited scanner workflow.

## Requirements and setup

Python 3.10+ is required. On Windows, run:

```powershell
.\scripts\setup_windows.ps1
.\scripts\start_windows.ps1
```

On Kali:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python run.py
```

The API documentation is at `http://127.0.0.1:8000/docs`; `/api/health` reports database, Ollama, and tool availability. Keep the service on localhost until authentication is implemented.

SQLite defaults to `data/bughunter.db` through `DATABASE_URL=sqlite:///./data/bughunter.db`. Configuration can come from environment variables or `.env`; see [.env.example](./.env.example). Phase 1 uses Python's built-in SQLite driver; SQLAlchemy is included for the planned repository layer.

## Registering an authorized scope

`POST /api/scopes` accepts a root domain, whether subdomains are included, excluded subdomains, authorization notes, and `authorization_confirmed: true`. Only public DNS domain names are accepted. Scope registration does not itself run a scan. Scope checks reject local/private/reserved destinations and check DNS answers when validating a destination immediately before a future network operation.

## Phase 1 verification

Run `python -m pytest`. Tests cover scope boundaries, database/API operations, simulated tool labeling, and mock Ollama responses. The environment checker is `python scripts/check_environment.py` (use `.venv/bin/python` on Kali).

## Platform guides

- [Windows development](./docs/WINDOWS_DEVELOPMENT.md)
- [Kali installation](./docs/KALI_INSTALLATION.md)
- [Deployment guide](./docs/DEPLOYMENT_GUIDE.md)
- [Tool installation](./docs/TOOL_INSTALLATION.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)
