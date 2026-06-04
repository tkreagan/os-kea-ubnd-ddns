#!/bin/sh
# Run unit tests locally (macOS or any host — no live services needed).
set -e
cd "$(dirname "$0")/.."
python3 -m pytest tests/unit/ -v --tb=short -m unit "$@"
