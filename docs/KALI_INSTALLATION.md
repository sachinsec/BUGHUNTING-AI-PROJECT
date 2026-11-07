# Kali Linux installation

Use a project-local virtual environment. Kali marks system Python as externally managed; do not install app dependencies into system Python. See the [Kali Python packaging guidance](https://www.kali.org/docs/general-use/python3-external-packages/).

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-full python3-venv python3-pip git curl ca-certificates
git clone <your-repository-url> AI-BugHunter
cd AI-BugHunter
bash scripts/setup_kali.sh
```

The script checks Python/pip, installs requirements into `.venv`, creates data directories, copies `.env.example` if needed, and reports optional tool availability. It never starts scans. Enable production tool detection only after installing and reviewing tools:

```bash
sed -i 's/^APP_ENV=.*/APP_ENV=production/; s/^SCAN_MODE=.*/SCAN_MODE=real/' .env
.venv/bin/python scripts/check_environment.py
bash scripts/start_kali.sh
```

For local AI, install Ollama using its [official Linux instructions](https://ollama.com/download/linux), then fetch the configured model:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen3:4b
ollama serve
```

Keep Ollama on its localhost default. In another terminal, visit `http://127.0.0.1:8000/docs` and check `/api/health`. Set `SCAN_MODE=real` only after installing/reviewing tools, registering authorized scope, and setting program exclusions and rate limits. This phase does not yet provide complete scan orchestration, output parsers, or persistent findings.

## Windows-to-Kali migration checklist

- Commit source, requirements, docs, and scripts; do not copy `.venv`, `.env`, DB files, logs, or reports unless you intend to migrate that data.
- Clone the same revision on Kali and follow the setup above. Recreate `.venv`; virtual environments are OS-specific.
- Set `APP_ENV=production`, keep the bind address on loopback, and explicitly set `SCAN_MODE=real` after review.
- Install Ollama and pull its model on Kali; weights are not transferred with the app.
- Re-register/verify authorization records and exclusions. Review SQLite migration separately.
- Run environment checks and tests, inspect `/api/health`, and confirm authorization before approved security testing.
