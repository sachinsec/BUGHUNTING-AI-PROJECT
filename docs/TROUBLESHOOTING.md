# Troubleshooting

## `externally-managed-environment` on Kali

Run `bash scripts/setup_kali.sh`; packages belong in `.venv`. If virtual environment support is missing, install `python3-full python3-venv` with apt and retry. Do not use `--break-system-packages`.

## `/api/health` reports database unavailable

Check that `DATABASE_URL` is a SQLite file URL and its parent directory is writable. The default `sqlite:///./data/bughunter.db` resolves from the project root.

## Ollama unavailable or model missing

Run `ollama serve` and `ollama list`. Pull the configured model with `ollama pull qwen3:4b`, then check `OLLAMA_BASE_URL` and `OLLAMA_MODEL`. Missing AI does not prevent backend startup.

## A tool is unavailable

Run `python scripts/check_environment.py` and ensure the binary is on `PATH`. Verify `httpx` is ProjectDiscovery's CLI, not an unrelated program. Missing binaries remain optional.

## Target rejected

Check registered root, subdomain inclusion, exclusions, DNS, and public destination addresses. Private, loopback, reserved, link-local, and metadata destinations are blocked. Local lab exceptions are not implemented yet.

## PowerShell script policy

Use `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` for the current terminal, then retry. Alternatively: `powershell -ExecutionPolicy Bypass -File .\scripts\setup_windows.ps1`.

## Mock output appears in development

Mock responses carry `simulated: true`; no requests are made and results are not discovered assets/findings. For Kali production detection, set `APP_ENV=production` and `SCAN_MODE=real` after setup and authorization review.
