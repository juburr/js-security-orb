#!/bin/bash
#
# Verifies the npm registry's signature on every locked package, bound to
# the integrity the lockfile records, and the Sigstore attestations
# (provenance) the registry has for it, for the signatures command, with
# provenance policies: required provenance, the source repository it must
# name, and no downgrade from earlier versions.
#
# The checks are in the orb's Node.js helper (src/helper/signatures.mjs, with the
# modules it imports), which this script writes to a private work directory
# and runs with the Node.js js_run finds; see src/scripts/lib/js_security.sh.

set -euo pipefail

if [[ -z "${SCRIPT_JS_SECURITY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_JS_SECURITY_LIB is not set; run this script through the orb's signatures command." >&2
    exit 1
fi
eval "${SCRIPT_JS_SECURITY_LIB}"

js_run signatures core registries sigstore
