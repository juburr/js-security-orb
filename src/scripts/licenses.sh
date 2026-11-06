#!/bin/bash
#
# Checks the licenses of a project's locked dependencies against an SPDX
# allowlist, for the licenses command, reading each package's license from
# the registry.
#
# The checks are in the orb's Node.js helper (src/helper/licenses.mjs, with the
# modules it imports), which this script writes to a private work directory
# and runs with the Node.js js_run finds; see src/scripts/lib/js_security.sh.

set -euo pipefail

if [[ -z "${SCRIPT_JS_SECURITY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_JS_SECURITY_LIB is not set; run this script through the orb's licenses command." >&2
    exit 1
fi
eval "${SCRIPT_JS_SECURITY_LIB}"

js_run licenses core registries
