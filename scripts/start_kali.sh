#!/usr/bin/env bash
set -euo pipefail
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"
if [[ ! -x .venv/bin/python ]]; then echo 'Run ./scripts/setup_kali.sh first.' >&2; exit 1; fi
exec .venv/bin/python run.py
