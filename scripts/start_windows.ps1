$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
Set-Location $ProjectRoot
if (-not (Test-Path '.venv\Scripts\python.exe')) { throw 'Run .\scripts\setup_windows.ps1 first.' }
& .\.venv\Scripts\python.exe run.py
