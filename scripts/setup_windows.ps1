$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) { throw 'Python 3 was not found. Install Python 3 and reopen PowerShell.' }
python --version
if (-not (Test-Path '.venv')) { python -m venv .venv }
& .\.venv\Scripts\python.exe -m pip install --upgrade pip
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
New-Item -ItemType Directory -Force -Path data, logs, reports | Out-Null
if (-not (Test-Path '.env')) { Copy-Item '.env.example' '.env' }
Write-Host 'Setup complete. Run .\scripts\start_windows.ps1; no scans are started by setup.'
