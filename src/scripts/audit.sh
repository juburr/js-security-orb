#!/bin/bash
#
# Audits a project's locked dependencies for known vulnerabilities, for the
# audit command, against the GitHub advisories the npm registry's bulk
# advisory endpoint serves, matching each locked version itself.
#
# The checks are in the orb's Node.js helper (src/helper/audit.mjs, with the
# modules it imports), which this script writes to a private work directory
# and runs with the Node.js js_run finds; see src/scripts/lib/js_security.sh.

set -euo pipefail

if [[ -z "${SCRIPT_JS_SECURITY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_JS_SECURITY_LIB is not set; run this script through the orb's audit command." >&2
    exit 1
fi
eval "${SCRIPT_JS_SECURITY_LIB}"

js_run audit core
