#!/usr/bin/env bash
# Linux / Mac / EC2. Usage: ./run.sh          (local)
#                          HOST=0.0.0.0 ./run.sh  (EC2, reachable from internet)
cd "$(dirname "$0")"
[ -d .venv ] || python3 -m venv .venv
source .venv/bin/activate
pip install -q -r requirements.txt
echo "Trailock running on http://${HOST:-127.0.0.1}:${PORT:-8000}"
exec python -m uvicorn app.main:app --host "${HOST:-127.0.0.1}" --port "${PORT:-8000}"
