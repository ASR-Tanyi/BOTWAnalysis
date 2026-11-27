#!/usr/bin/env bash
# Runs botwdiff from the project virtual environment, creating it on first use.
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
VENV="$ROOT/.venv"

if [[ ! -x "$VENV/bin/python" ]]; then
    PY="${PYTHON:-$(command -v python3.14 || command -v python3.13 || command -v python3.12 || command -v python3)}"
    "$PY" -m venv "$VENV"
    "$VENV/bin/python" -m pip install -q --upgrade pip
    "$VENV/bin/python" -m pip install -q -r "$ROOT/requirements.txt"
fi

export PYTHONPATH="$ROOT${PYTHONPATH:+:$PYTHONPATH}"
exec "$VENV/bin/python" -m botwdiff "$@"
