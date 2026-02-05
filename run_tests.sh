#!/usr/bin/env bash
set -euo pipefail

# run_tests.sh
# Simple test runner for the lab workspace. This script ensures tests are
# executed from the repository root (the script directory) so that relative
# imports and file paths in the tests resolve consistently.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
echo "Running unit tests in ${SCRIPT_DIR}/tests..."
python3 -m unittest discover -v tests
echo "All tests passed."
