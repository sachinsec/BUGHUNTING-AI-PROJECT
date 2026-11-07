# Windows development

Run setup from PowerShell at the repository root:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\setup_windows.ps1
.\scripts\start_windows.ps1
```

Setup copies `.env.windows.example` if `.env` does not exist. This profile explicitly selects MOCK. Mock output is labeled simulated and is not a finding. Change `SCAN_MODE=real` to verify real tool detection; missing tools report `NOT_INSTALLED` and never fall back to examples.

Inspect `/api/system/info`, `/api/tools/status`, `/api/health`, and `/docs`. Run tests and JavaScript syntax checks from the repository root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
node --check frontend/assets/js/dashboard.js
node --check frontend/assets/js/api.js
```

Windows tests do not establish Kali command-line compatibility. Recreate `.venv` on Kali and do not commit `.env`, database user data, logs, reports, or secrets.
