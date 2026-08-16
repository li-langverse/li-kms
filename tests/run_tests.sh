#!/bin/sh
# Build the runtime externs + run the pure-Li KMS selftests.
# Usage: LIC=... LI_RT_LIB=... LI_NATIVE_RT=1 ./tests/run_tests.sh
set -e
cd "$(dirname "$0")/.."
make test
