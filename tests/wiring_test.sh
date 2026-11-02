#!/usr/bin/env bash
#
# Checks how the command YAML, the scripts and the Node.js helper fit
# together, offline:
#
#   - every parameter a check command declares (but working_dir, which is
#     the step's working_directory, and store_artifacts, which only the YAML
#     reads) is passed as its PARAM_ variable, and every PARAM_ variable the
#     YAML sets is a parameter;
#   - every parameter the helper reads for a command (core's common ones and
#     the command module's own) is one the command declares, and every
#     parameter it declares is read;
#   - each script runs its command's module with exactly the modules the
#     command's YAML passes as SCRIPT_JS_HELPER_ variables, and those are
#     the modules it imports;
#   - a check command stores its JUnit report with store_test_results and
#     output_dir as artifacts under js-security-reports/, with when: always;
#   - every run step has a name, as orb-tools review's RC008 asks;
#   - install and its action default to the newest Node.js in the checksum
#     table;
#   - the run record schema names every check command;
#   - the README documents every command and names its GitHub Action.
#
# Run from a checkout:
#   bash tests/wiring_test.sh

set -euo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "${ROOT}"
FAILURES=0
fail() {
    printf 'FAIL: %s\n' "$*"
    FAILURES=$((FAILURES + 1))
}

# params YML: the parameters YML declares, one per line.
params() {
    awk '/^parameters:/ { p = 1; next } /^[^ ]/ { p = 0 } p && /^  [a-z_0-9]+:$/ { sub(/^  /, ""); sub(/:$/, ""); print }' "$1"
}

# helper_reads MODULE: the parameters MODULE reads with the context's
# readers (ctx.str('name', ...) and the like, or params.str(...) in core).
# Comment lines (// and JSDoc *) are left out: core's top comment shows an
# example command module.
helper_reads() {
    grep -vE '^[[:space:]]*(//|\*)' "$1" \
        | grep -oE "\b(ctx|params)\.(str|bool|int|list|lines|choice|envVarName|patterns)\('[a-z_0-9]+'" \
        | sed -E "s/.*\('([a-z_0-9]+)'/\1/" | sort -u || true
}

# imports MODULE: the orb modules MODULE imports, without .mjs.
imports() {
    grep -oE "from '\./[a-z_]+\.mjs'" "$1" | sed -E "s/from '\.\/([a-z_]+)\.mjs'/\1/" | sort -u || true
}

CORE_READS=$(helper_reads src/helper/core.mjs)
CHECKS=()
for yml in src/commands/*.yml; do
    command=$(basename "${yml}" .yml)
    [[ "${command}" == install ]] && continue
    CHECKS+=("${command}")
    script="src/scripts/${command}.sh"
    module="src/helper/${command}.mjs"
    if [[ ! -f "${script}" ]]; then
        fail "${command}: there is no ${script}"
        continue
    fi
    if [[ ! -f "${module}" ]]; then
        fail "${command}: there is no ${module}"
        continue
    fi
    declared=$(params "${yml}")
    passed=$(grep -oE 'PARAM_[A-Z0-9_]+: << parameters\.[a-z0-9_]+ >>' "${yml}" || true)
    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        case "${name}" in working_dir | store_artifacts) continue ;; esac
        var="PARAM_${name^^}"
        grep -qxF "${var}: << parameters.${name} >>" <<< "${passed}" \
            || fail "${command}: parameter ${name} is not passed as ${var}"
    done <<< "${declared}"
    while IFS= read -r line; do
        [[ -z "${line}" ]] && continue
        name=${line##*parameters.}
        name=${name% >>}
        var=${line%%:*}
        [[ "${var}" == "PARAM_${name^^}" ]] || fail "${command}: ${var} is set from parameters.${name}"
        grep -qxF "${name}" <<< "${declared}" || fail "${command}: ${var} names a parameter it doesn't declare"
    done <<< "${passed}"
    reads=$(printf '%s\n%s\n' "${CORE_READS}" "$(helper_reads "${module}")" | sort -u | sed '/^$/d')
    while IFS= read -r name; do
        grep -qxF "${name}" <<< "${declared}" || fail "${command}: the helper reads ${name}, which the command doesn't declare"
    done <<< "${reads}"
    while IFS= read -r name; do
        [[ -z "${name}" ]] && continue
        case "${name}" in working_dir | store_artifacts) continue ;; esac
        grep -qxF "${name}" <<< "${reads}" || fail "${command}: parameter ${name} is never read by the helper"
    done <<< "${declared}"
    # The modules: js_run's list, the YAML's SCRIPT_JS_HELPER_ variables and
    # the command module's imports must agree.
    run_line=$(grep -E '^js_run ' "${script}" || true)
    [[ "$(awk '{ print $2 }' <<< "${run_line}")" == "${command}" ]] || fail "${command}: ${script} doesn't run js_run ${command}"
    run_modules=$(awk '{ for (i = 3; i <= NF; i++) print $i }' <<< "${run_line}" | sort -u)
    yml_modules=$(grep -oE 'SCRIPT_JS_HELPER_[A-Z_]+: << include\(helper/[a-z_]+\.mjs\) >>' "${yml}" \
        | sed -E 's/.*helper\/([a-z_]+)\.mjs.*/\1/' | grep -vxF "${command}" | sort -u || true)
    [[ "${run_modules}" == "${yml_modules}" ]] \
        || fail "${command}: js_run passes [${run_modules//$'\n'/ }], the YAML [${yml_modules//$'\n'/ }]"
    grep -qF "SCRIPT_JS_HELPER_${command^^}: << include(helper/${command}.mjs) >>" "${yml}" \
        || fail "${command}: the YAML doesn't pass its own module as SCRIPT_JS_HELPER_${command^^}"
    grep -qF 'SCRIPT_JS_SECURITY_LIB: << include(scripts/lib/js_security.sh) >>' "${yml}" \
        || fail "${command}: the YAML doesn't pass SCRIPT_JS_SECURITY_LIB"
    grep -qF "command: << include(scripts/${command}.sh) >>" "${yml}" || fail "${command}: the YAML doesn't run ${script}"
    needed=$( (imports "${module}"; for m in ${run_modules}; do imports "src/helper/${m}.mjs"; done) | sort -u)
    [[ "${needed}" == "${run_modules}" ]] \
        || fail "${command}: its modules import [${needed//$'\n'/ }], but js_run passes [${run_modules//$'\n'/ }]"
    # The reports are stored, whether or not the step fails.
    grep -qF "path: << parameters.output_dir >>/junit/<< parameters.report_name >>.xml" "${yml}" \
        || fail "${command}: doesn't store its JUnit report"
    grep -qF 'destination: js-security-reports' "${yml}" || fail "${command}: doesn't store output_dir under js-security-reports/"
    [[ "$(grep -c 'when: always' "${yml}")" -ge 2 ]] || fail "${command}: its store steps don't run when: always"
done

# Every run step has a name.
for yml in src/commands/*.yml; do
    while IFS= read -r line; do
        fail "${yml}:${line}"
    done < <(awk '
        /^ *- run:/ { if (open && !named) print start ": this run step has no name"; open = 1; named = 0; start = FNR; next }
        open && /^ +name:/ { named = 1 }
        open && /^ *- / { if (!named) print start ": this run step has no name"; open = 0 }
        END { if (open && !named) print start ": this run step has no name" }' "${yml}")
done

# install defaults to the newest Node.js in the table.
newest=$(grep -oE '\["[0-9]+\.[0-9]+\.[0-9]+/amd64"\]' src/scripts/install.sh | sed -E 's/\["([^/]*)\/.*/\1/' | sort -V | tail -n 1)
default=$(awk '/^  version:/ { p = 1 } p && /^    default:/ { gsub(/"/, "", $2); print $2; exit }' src/commands/install.yml)
[[ "${default}" == "${newest}" ]] || fail "install defaults to ${default}, but the newest Node.js in the table is ${newest}"
action_default=$(awk '/^  version:/ { p = 1 } p && /^    default:/ { gsub(/"/, "", $2); print $2; exit }' actions/install/action.yml)
[[ "${action_default}" == "${newest}" ]] || fail "actions/install defaults to ${action_default}, not ${newest}"

# The run record schema names every check command.
for command in "${CHECKS[@]}"; do
    grep -qF "\"${command}\"" schemas/run-record.v1.json || fail "schemas/run-record.v1.json doesn't name ${command}"
done

# The README documents every command and names its action.
if [[ -f README.md ]]; then
    for yml in src/commands/*.yml; do
        command=$(basename "${yml}" .yml)
        grep -qF "js-security/${command}" README.md || fail "the README doesn't document ${command}"
        grep -qF "juburr/js-security-orb/actions/${command}@" README.md || fail "the README doesn't name actions/${command}"
    done
else
    fail "there is no README.md"
fi

if [[ "${FAILURES}" -gt 0 ]]; then
    printf '%s wiring check(s) failed.\n' "${FAILURES}"
    exit 1
fi
echo "ok: every command passes and reads the same parameters, runs and imports the same helper modules, stores its reports and names its run steps; install defaults to the newest Node.js."
