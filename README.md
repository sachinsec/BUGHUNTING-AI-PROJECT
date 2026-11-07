# AI BugHunter

Local-first security reconnaissance and finding management for Windows development and Kali Linux deployment. The service binds to `127.0.0.1` by default and requires explicit authorization before a scope can be registered.

## Phase plan

1. **Foundation (implemented):** portable configuration, SQLite persistence, explicit authorization records, scope validation, and health endpoint.
2. **Adapters (initial implementation):** local Ollama health/inference client, explicitly simulated mock adapters, and optional real tool detection/invocation wrappers.
3. **Reconnaissance (implemented):** background Subfinder, HTTPX, GAU/Waybackurls, approval-gated Katana, parameter extraction, WhatWeb, scan status/cancellation, and orchestration.
4. **Findings:** SQLite-backed potential and manually verified finding records, evidence details, status updates, and severity statistics.
5. **AI analysis and reports:** evidence-grounded finding analysis and Markdown/JSON report generation.
6. **Dashboard:** responsive reconnaissance, authorization review, vulnerability finding, and tool-status views connected to APIs.

The reconnaissance adapters are modular and use local binaries only in `SCAN_MODE=real`. On Windows, default mock results are marked `simulated`; the dashboard excludes them from real finding statistics. Katana requires explicit approval. Finding records are stored with their execution mode and simulated provenance. The Nuclei view currently reports live tool availability; it does not launch a scan.

## Current reconnaissance API: Subfinder

All reconnaissance APIs are under `/api/recon`:

- Subdomains: `POST /subdomains/start`, `GET /subdomains`, `GET /subdomains/{scan_id}`
- Live hosts: `POST /live-hosts/start`, `GET /live-hosts`
- Historical URLs: `POST /urls/start`, `GET /urls`
- Endpoints: `POST /endpoints/start` (requires `approval_confirmed: true`), `GET /endpoints`
- Parameters: `GET /parameters`
- Technologies: `POST /technologies/start`, `GET /technologies`
- Full workflow: `POST /start` (Katana is skipped unless `active_crawl_approved: true`), `GET /scans`, `GET /scans/{job_id}`, `POST /scans/{job_id}/cancel`

Start requests take a registered `scope_id`. Poll an individual module's `GET` scan resource for status and results. Results include `simulated: true` in mock mode; they are separately persisted and visibly labeled. For real runs, install the appropriate tools and set `SCAN_MODE=real`. HTTPX results use pre-resolved public IPs and do not follow redirects. Katana crawling requires explicit approval and a low request limit.

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

SQLite defaults to `data/bughunter.db` through `DATABASE_URL=sqlite:///./data/bughunter.db`. Configuration can come from environment variables or `.env`; see [.env.example](./.env.example). Set `HTTPX_EXECUTABLE=httpx-toolkit` (the default preference) or another verified ProjectDiscovery binary name to configure the HTTP probing executable.

## Registering an authorized scope

`POST /api/scopes` accepts a root domain, whether subdomains are included, excluded subdomains, authorization notes, and `authorization_confirmed: true`. Only public DNS domain names are accepted. Scope registration does not itself run a scan. Scope checks reject local/private/reserved destinations and check DNS answers when validating a destination immediately before a future network operation.

Public scan approval is recorded separately from the scope. Submit evidence with `POST /api/scopes/{scope_id}/authorization-reviews`, inspect it with `GET /api/scopes/{scope_id}/authorization-reviews`, and record an explicit `APPROVED`, `REJECTED`, or `EXPIRED` decision with `PUT /api/authorization-reviews/{review_id}`. A request remains `PENDING` until a reviewer decides. An approval applies only to its exact asset and explicitly permitted subdomains, and still enforces exclusions and expiration. Local Lab uses exact loopback hosts and configured ports without public reviews.

## Vulnerability findings API

- `POST /api/vulnerabilities` creates a persistent potential finding with evidence. The backend assigns `execution_mode` and `simulated`; clients cannot self-report real provenance.
- `GET /api/vulnerabilities` supports `severity`, `status`, and partial `target` filters; `GET /api/vulnerabilities/{finding_id}` returns finding details and evidence.
- `PATCH /api/vulnerabilities/{finding_id}` updates the status. Marking a finding `VERIFIED` requires a reviewer, and simulated findings cannot be labeled as verified scanner findings.
- `GET /api/vulnerabilities/stats` returns real and simulated severity counts separately.

## Verification

Run `python -m pytest`. Tests cover scope boundaries, API behavior, parsing, persistence, mock labeling, tool detection, cancellation, and orchestrator stages. The environment checker is `python scripts/check_environment.py` (use `.venv/bin/python` on Kali).

## Platform guides

- [Windows development](./docs/WINDOWS_DEVELOPMENT.md)
- [Kali installation](./docs/KALI_INSTALLATION.md)
- [Deployment guide](./docs/DEPLOYMENT_GUIDE.md)
- [Tool installation](./docs/TOOL_INSTALLATION.md)
- [Troubleshooting](./docs/TROUBLESHOOTING.md)
