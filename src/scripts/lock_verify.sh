#!/bin/bash
#
# Checks a project's lockfiles for supply-chain hygiene, for the lock_verify command:
# integrity hashes, where every package comes from, git, tarball and local
# dependencies, install scripts, and, from the registry, how long ago each
# locked version was published, whether it is still published, and whether
# it is deprecated.
#
# The checks are in the orb's Node.js helper (src/helper/lock_verify.mjs, with the
# modules it imports), which this script writes to a private work directory
# and runs with the Node.js js_run finds; see src/scripts/lib/js_security.sh.

set -euo pipefail

if [[ -z "${SCRIPT_JS_SECURITY_LIB:-}" ]]; then
    echo "ERROR: SCRIPT_JS_SECURITY_LIB is not set; run this script through the orb's lock_verify command." >&2
    exit 1
fi
eval "${SCRIPT_JS_SECURITY_LIB}"

js_run lock_verify core
