#!/usr/bin/env bash
# Aegis launcher for macOS / Linux. Needs Python 3.10+.
set -e
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
. .venv/bin/activate
python -m pip install -q -r requirements.txt
[ -f .env ] || cp .env.example .env
echo "Aegis is starting: open http://127.0.0.1:8000   (Engineer PIN 2468)"
python -m aegis.server
