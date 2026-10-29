#!/bin/bash
# Helper script to build and run the access-control logger tests on Linux/WSL
# Usage: ./run_tests.sh

set -euo pipefail
cwd="$(pwd)"

echo "Building..."
make all

echo "Running test program with LD_PRELOAD to generate log entries..."
LD_PRELOAD=./logger.so ./test_aclog

echo "Contents of file_logging.log (tail)"

tail -n 60 file_logging.log || true

echo "Running acmonitor: malicious users (-m)"
./acmonitor -m || true

echo "Running acmonitor: encrypted files (-e)"
./acmonitor -e || true

echo "Sample: list modifications for file 'file_0' (-i)"
./acmonitor -i file_0 || true

echo "Done. If you run this on WSL, check the printed output above for any errors."