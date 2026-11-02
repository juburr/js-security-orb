#!/bin/bash
#
# Runs the Node.js helper's unit tests (tests/helper/*.test.mjs, node:test,
# offline; the registry tests run curl against tests/fake_registry.mjs on
# 127.0.0.1), after checking that every helper module parses and stays under
# 120,000 bytes: each module reaches its step as one environment variable, and
# Linux limits a single environment string to 128 KiB.
#
#   bash tests/helper_test.sh [node --test options...]

set -euo pipefail

cd "$(dirname "$0")/.."

MAX_BYTES=120000

if ! command -v node > /dev/null 2>&1; then
    echo "ERROR: node is not on the PATH; the helper's tests need Node.js 22 or newer." >&2
    exit 1
fi
major=$(node -p 'process.versions.node.split(".")[0]')
if ((major < 22)); then
    echo "ERROR: node is Node.js $(node --version); the helper's tests need Node.js 22 or newer." >&2
    exit 1
fi

status=0
for module in src/helper/*.mjs; do
    size=$(wc -c < "${module}")
    size=$((size))
    if ((size >= MAX_BYTES)); then
        echo "ERROR: ${module} is ${size} bytes; every helper module must stay under ${MAX_BYTES}." >&2
        status=1
    else
        echo "${module}: ${size} bytes (limit ${MAX_BYTES})"
    fi
    if ! node --check "${module}"; then
        echo "ERROR: ${module} does not parse." >&2
        status=1
    fi
done

# node 22's --test takes files or globs, not a directory.
tests=(tests/helper/*.test.mjs)
if [[ ! -e "${tests[0]}" ]]; then
    echo "ERROR: There are no tests in tests/helper." >&2
    exit 1
fi
if ! node --test "$@" "${tests[@]}"; then
    echo "ERROR: The helper's unit tests failed." >&2
    status=1
fi
exit "${status}"
