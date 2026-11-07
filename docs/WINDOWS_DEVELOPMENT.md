# Windows development

Use PowerShell from the project root:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup_windows.ps1
.\scripts\start_windows.ps1
```

Setup creates `.venv`, installs requirements, creates `data`, `logs`, and `reports`, and copies `.env.example` to `.env` only when `.env` does not exist. It never launches scanners. Default `SCAN_MODE=mock` uses clearly labeled sample data and makes no network requests.

Open `http://127.0.0.1:8000/docs` and `/api/health`. `python scripts/check_environment.py` reports Python packages, optional tools, and local Ollama status. Run `python -m pytest` for the portable suite.

Mock mode supports backend development. It does not validate Kali command-line tool execution on Windows. Keep `.env` local; it is ignored by Git.
