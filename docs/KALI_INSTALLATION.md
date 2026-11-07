# Kali Linux installation

The setup script installs Python dependencies only, reports optional tools and never starts a scan.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-full python3-venv python3-pip git curl ca-certificates nodejs
git clone <repository-url> AI-BugHunter
cd AI-BugHunter
bash scripts/setup_kali.sh
```

Setup copies `.env.kali.example`. Review `APP_PROFILE=PRODUCTION_KALI`, `APP_ENV=production`, and `SCAN_MODE=real`. Production rejects mock mode. Install approved security tools and ensure the service user's PATH includes their executable names; overrides are available in `.env`. No paths such as `/usr/bin` or `/root/go/bin` are assumed.

Install Ollama using its official Linux instructions. Then:

```bash
ollama pull qwen3:4b
ollama serve
```

In another terminal, verify installation and service state:

```bash
.venv/bin/python scripts/check_environment.py
.venv/bin/python -m pytest -q
node --check frontend/assets/js/dashboard.js
curl -fsS http://127.0.0.1:8000/api/system/info
curl -fsS http://127.0.0.1:8000/api/tools/status
curl -fsS http://127.0.0.1:8000/api/health
bash scripts/start_kali.sh
```

These Kali commands have not been run from the current Windows workspace. Do not infer Linux compatibility until these checks pass on Kali. Only run scans against authorized targets. Local Lab requires localhost/literal loopback and exact configured ports; it cannot authorize public or LAN targets.

## Windows-to-Kali migration checklist

- [ ] Commit source/docs/manifests only; keep `.env`, secrets, `.venv`, DB user data, logs and reports out of Git.
- [ ] Clone the same revision and create a fresh Kali `.venv`.
- [ ] Copy the Kali profile via setup and verify REAL mode.
- [ ] Install tools and Ollama/model on Kali; never copy Windows binaries or `.venv`.
- [ ] Inspect resolved tool paths and versions through `/api/tools/status`.
- [ ] Back up/review SQLite separately and re-review program authorization.
- [ ] Run portable and local-lab tests on Kali; record OS and tool versions.
- [ ] Confirm bind address, exact scope, authorization and rate limits before scans.
