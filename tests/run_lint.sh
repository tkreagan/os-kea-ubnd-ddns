#!/bin/sh
# Run linting checks. Wrapper for tests/lint/run_lint.sh.
set -e
cd "$(dirname "$0")/.."
sh tests/lint/run_lint.sh "$@"
