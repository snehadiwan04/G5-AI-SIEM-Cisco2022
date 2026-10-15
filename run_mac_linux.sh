#!/usr/bin/env bash
# G5 AI-SIEM prototype - one-command run on macOS / Linux (needs Python 3.9+)
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
. .venv/bin/activate
pip install --quiet -r requirements.txt
python main.py "$@"
