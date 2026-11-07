#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
if ! command -v python3 >/dev/null 2>&1; then
  echo 'Python 3 is required. Install it with: sudo apt-get update && sudo apt-get install -y python3 python3-full python3-venv python3-pip'
  exit 1
fi
if ! python3 -m venv --help >/dev/null 2>&1; then
  echo 'The venv module is missing. Install it with: sudo apt-get install -y python3-full python3-venv'
  exit 1
fi
if ! command -v pip3 >/dev/null 2>&1; then
  echo 'pip3 is missing. Install it with: sudo apt-get install -y python3-pip'
  exit 1
fi
python3 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
mkdir -p data logs reports
if [[ ! -f .env ]]; then cp .env.example .env; fi
echo 'Optional tools detected on this system:'
for tool in ollama subfinder amass httpx-toolkit httpx katana nuclei zaproxy; do
  if command -v "$tool" >/dev/null 2>&1; then printf '  %-12s %s\n' "$tool" "$(command -v "$tool")"; else printf '  %-12s not installed\n' "$tool"; fi
done
echo 'Setup complete. Review .env, then run ./scripts/start_kali.sh. Setup never starts a scan.'
