#!/usr/bin/env bash
#
# Runs a command's script the way the command's step runs it: with every
# PARAM_ variable set from the command's parameter defaults, overridden by
# NAME=VALUE arguments, a PARAM_ variable the step sets to a fixed value
# (such as an install command's PARAM_TOOL) set to that value, and every
# variable the step sets to an included file (the shared helpers, a tool's
# locks) set to that file. test-deploy.yml uses it to check steps that must
# fail, since a failing orb step would fail the test job itself. working_dir,
# like the step's working_directory, is where the script runs.
#
# Usage, from a checkout:
#   bash tests/run_command.sh COMMAND [NAME=VALUE ...]
#
# Exits with the script's exit code.

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
if [[ $# -lt 1 ]]; then
    echo "ERROR: Usage: bash tests/run_command.sh COMMAND [NAME=VALUE ...]" >&2
    exit 2
fi
COMMAND=$1
shift
YML="${ROOT}/src/commands/${COMMAND}.yml"
if [[ ! -f "${YML}" ]]; then
    echo "ERROR: There is no command ${COMMAND} (${YML})." >&2
    exit 2
fi
# The step's script: an install command's install/<tool>/install.sh or
# scripts/install_tool.sh (its cache key scripts only prepare cache keys), or
# else its one script.
SCRIPT=$(grep -oE '<< include\((install/[a-z0-9-]+/install|scripts/[a-z_]+)\.sh\) >>' "${YML}" \
    | grep -v -e 'scripts/lib/' -e 'scripts/cache_key.sh' -e 'scripts/python_cache_key.sh' \
    | sed -E 's/<< include\((.*)\) >>/\1/' | head -n 1)

# Every parameter, as NAME<TAB>DEFAULT, without the quotes YAML allows; a
# parameter without a default has the value "<required>" until it is given.
declare -A VALUES=()
while IFS=$'\t' read -r name value; do
    VALUES[${name}]=${value}
done < <(awk '
    function flush() { if (name != "") { printf "%s\t%s\n", name, value } }
    /^parameters:/ { p = 1; next }
    /^[^ ]/ { if (p) { flush() } p = 0; name = "" }
    p && /^  [a-z_0-9]+:$/ { flush(); name = $1; sub(/:$/, "", name); value = "<required>" }
    p && /^    default:/ {
        value = $0
        sub(/^    default: */, "", value)
        if (value ~ /^".*"$/) { value = substr(value, 2, length(value) - 2) }
    }' "${YML}")
# Bash 4.0 takes an empty "$@" for an unbound variable, so the settings are
# copied only when there are some.
SETTINGS=()
if [[ $# -gt 0 ]]; then
    SETTINGS=("$@")
fi
for setting in ${SETTINGS[@]+"${SETTINGS[@]}"}; do
    name=${setting%%=*}
    if [[ "${setting}" != *=* || -z "${VALUES[${name}]+set}" ]]; then
        echo "ERROR: ${COMMAND} has no parameter ${name}." >&2
        exit 2
    fi
    VALUES[${name}]=${setting#*=}
done
for name in "${!VALUES[@]}"; do
    if [[ "${VALUES[${name}]}" == "<required>" ]]; then
        echo "ERROR: ${COMMAND} needs ${name}=VALUE." >&2
        exit 2
    fi
done

ENVIRONMENT=()
while IFS= read -r line; do
    var=${line%%:*}
    name=${line##*parameters.}
    name=${name% >>}
    ENVIRONMENT+=("${var}=${VALUES[${name}]}")
done < <(grep -oE 'PARAM_[A-Z0-9_]+: << parameters\.[a-z0-9_]+ >>' "${YML}" | sort -u)
SHOWN=("${ENVIRONMENT[@]}")
# Fixed values, such as PARAM_TOOL: bandit, and included files, such as the
# shared helpers and a tool's locks.
while IFS= read -r line; do
    var=${line%%:*}
    value=${line#*: }
    if [[ "${value}" =~ ^\<\<\ include\((.*)\)\ \>\>$ ]]; then
        ENVIRONMENT+=("${var}=$(cat "${ROOT}/src/${BASH_REMATCH[1]}")")
        SHOWN+=("${var}=<${BASH_REMATCH[1]}>")
    else
        value=${value#\"}
        ENVIRONMENT+=("${var}=${value%\"}")
        SHOWN+=("${var}=${value%\"}")
    fi
done < <(sed -n '/^steps:/,$p' "${YML}" | grep -E '^ +(PARAM|SCRIPT|PS)_[A-Z0-9_]+: ' | sed -E 's/^ +//' \
    | grep -v '^PARAM_[A-Z0-9_]*: << parameters\.' | sort -u)

DIR=${VALUES[working_dir]:-.}
echo "Running ${SCRIPT} in ${DIR} with ${SHOWN[*]-}"
cd "${DIR}"
STATUS=0
env ${ENVIRONMENT[@]+"${ENVIRONMENT[@]}"} \
    bash "${ROOT}/src/${SCRIPT}" || STATUS=$?
echo "${SCRIPT} exited with ${STATUS}."
exit "${STATUS}"
