#!/bin/bash

# Shared helpers for the js-security-orb commands. Each command passes this
# file to its step as SCRIPT_JS_SECURITY_LIB, and its script evals it after
# set -euo pipefail, so it only defines functions and variables. The helpers
# keep their state in JS_ variables.
#
# The checks themselves are in the orb's Node.js helper (src/helper/*.mjs),
# which each command passes to its step as SCRIPT_JS_HELPER_<MODULE>
# variables. js_run writes those modules to a private work directory and
# runs the command's module with the Node.js it finds: the helper reads the
# parameters from the PARAM_ variables, writes the reports, and exits with
# the step's exit code. It uses nothing from the project's node_modules.

# js_subst VALUE: prints VALUE with environment variables expanded. The value
# is piped in on stdin: passed as an argument, a value starting with "-" would
# be parsed as a flag. Without the CircleCI CLI (GitHub Actions and local
# runs), the value is used as is.
js_subst() {
    if command -v circleci > /dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

# js_params: expands environment variables in every PARAM_ variable, in
# place, for the helper to read. output_dir and report_name are left as
# given, since the steps that store the reports read them as given.
js_params() {
    local name value
    for name in $(compgen -v PARAM_ || true); do
        case "${name}" in
            PARAM_OUTPUT_DIR | PARAM_REPORT_NAME) continue ;;
        esac
        value=$(js_subst "${!name}")
        export "${name}=${value}"
    done
}

# JS_MIN_NODE_MAJOR: the oldest Node.js the helper runs on.
JS_MIN_NODE_MAJOR=22

# js_node: sets JS_NODE to the Node.js to run the helper with: the
# js-security-node launcher the orb's install command puts on the PATH, else
# node. It must be Node.js JS_MIN_NODE_MAJOR or newer.
js_node() {
    local version major
    JS_NODE=$(command -v js-security-node || command -v node || true)
    if [[ -z "${JS_NODE}" ]]; then
        echo "ERROR: There is no Node.js on the PATH. Run the orb's install command first, or use an image with" >&2
        echo "  Node.js ${JS_MIN_NODE_MAJOR} or newer, such as cimg/node." >&2
        exit 1
    fi
    version=$(env -u NODE_OPTIONS "${JS_NODE}" --version 2> /dev/null || true)
    major=${version#v}
    major=${major%%.*}
    if [[ ! "${major}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: ${JS_NODE} did not report a Node.js version (it printed '${version}')." >&2
        exit 1
    fi
    if ((major < JS_MIN_NODE_MAJOR)); then
        echo "ERROR: ${JS_NODE} is Node.js ${version}, but the checks need ${JS_MIN_NODE_MAJOR} or newer. Run the" >&2
        echo "  orb's install command first, which installs a checksum-verified Node.js without replacing this one." >&2
        exit 1
    fi
}

# js_run COMMAND MODULE...: runs the helper's COMMAND module, with the other
# MODULEs it imports beside it, and exits with its exit code. Each module
# comes from the SCRIPT_JS_HELPER_<MODULE> variable, in upper case.
js_run() {
    local command=$1 module variable status=0
    shift
    js_params
    js_node
    JS_WORK=$(mktemp -d)
    trap 'rm -rf "${JS_WORK}"' EXIT
    mkdir "${JS_WORK}/helper"
    for module in "${command}" "$@"; do
        variable="SCRIPT_JS_HELPER_${module^^}"
        if [[ -z "${!variable:-}" ]]; then
            echo "ERROR: ${variable} is not set; run this script through the orb's ${command} command." >&2
            exit 1
        fi
        printf '%s\n' "${!variable}" > "${JS_WORK}/helper/${module}.mjs"
    done
    # NODE_OPTIONS and NODE_PATH could load other code into the helper, and
    # nothing in the project's node_modules is meant to be loaded.
    env -u NODE_OPTIONS -u NODE_PATH JS_SECURITY_WORK="${JS_WORK}" \
        "${JS_NODE}" "${JS_WORK}/helper/${command}.mjs" || status=$?
    exit "${status}"
}
