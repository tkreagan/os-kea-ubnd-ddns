#!/bin/sh
# Deploy to the OPNsense box and run integration tests.
#
# Connection info comes from tests/.env (copy .env.example and fill it in).
# Requires: paramiko in the active Python venv (pip install paramiko).
#
# The deploy step (uploading source + make upgrade) is handled inside
# the pytest deploy fixture — this script just sources the env and runs pytest.

set -e

REPO="$(cd "$(dirname "$0")/.." && pwd)"

# Load .env if present
if [ -f "$REPO/tests/.env" ]; then
    set -a
    # shellcheck disable=SC1090
    . "$REPO/tests/.env"
    set +a
fi

if [ -z "$OPNSENSE_HOST" ]; then
    echo "ERROR: OPNSENSE_HOST not set."
    echo "       Copy tests/.env.example to tests/.env and fill it in."
    exit 1
fi

echo "==> Running integration tests against $OPNSENSE_HOST..."
python3 -m pytest tests/integration/ -v --tb=short -m integration "$@"
