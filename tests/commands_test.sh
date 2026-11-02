#!/usr/bin/env bash
#
# Tests the command scripts the way the steps run them, through
# tests/run_command.sh (so with every parameter's default from the command's
# YAML and the helper modules the YAML includes), against
# tests/fake_registry.mjs on 127.0.0.1. The helper's own tests
# (tests/helper_test.sh) cover what each check decides; this one covers the
# shell layer around it:
#
#   - each command runs, writes its reports, and passes the helper's exit code
#     through: 0 passed (or report_only), 1 findings or no verdict, 2 a
#     parameter that can't work;
#   - parameters are expanded with the CircleCI CLI when there is one (a
#     stand-in expands $ORB_TEST_VAR), and used as they are without it, but
#     output_dir and report_name never are;
#   - the Node.js js_node picks: the install command's js-security-node first,
#     else node; none, one older than 22, or one that reports no version
#     fails the step before anything runs;
#   - NODE_OPTIONS and NODE_PATH never reach the helper;
#   - the modules come from the SCRIPT_JS_HELPER_ variables, and a missing one
#     fails the step;
#   - the work directory is removed, whether the check passes or fails;
#   - a registry token reaches the registry and nothing else.
#
# The scripts run with the bash first on the PATH, so putting an older bash
# there checks them with it. The helper and the stand-in registry run on the
# node on the PATH, which must be Node.js 22 or newer.
#
# Run from a checkout:
#   bash tests/commands_test.sh

# The checks run small scripts in single quotes, which expand their own
# arguments.
# shellcheck disable=SC2016

set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
FIXTURES="${ROOT}/tests/fixtures"
WORK=$(mktemp -d)
REGISTRY_PID=""
cleanup() {
    if [[ -n "${REGISTRY_PID}" ]]; then
        kill "${REGISTRY_PID}" 2> /dev/null
        wait "${REGISTRY_PID}" 2> /dev/null
    fi
    rm -rf "${WORK}"
}
trap cleanup EXIT
OUT="${WORK}/reports"
JOB="${WORK}/job"
mkdir -p "${WORK}/bin" "${WORK}/home" "${WORK}/cache" "${WORK}/tmp" "${JOB}"

NODE=$(command -v node || true)
if [[ -z "${NODE}" ]]; then
    echo "ERROR: commands_test.sh needs Node.js 22 or newer on the PATH." >&2
    exit 1
fi

# Like `circleci env subst`, expands $NAME and ${NAME} references, from stdin,
# and appends every value it was given to circleci.log.
cat > "${WORK}/bin/circleci" << 'EOF'
#!/usr/bin/env bash
if [[ "$*" != "env subst" ]]; then
    echo "circleci stub: expected 'env subst' with the value on stdin, got: $*" >&2
    exit 1
fi
input=$(cat)
printf '%s\n' "${input}" >> "${STUB_DIR}/circleci.log"
output=""
re='^([^$]*)\$(\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))(.*)$'
while [[ "${input}" =~ ${re} ]]; do
    name=${BASH_REMATCH[3]:-${BASH_REMATCH[4]}}
    output+="${BASH_REMATCH[1]}${!name-}"
    input=${BASH_REMATCH[5]}
done
printf '%s' "${output}${input}"
EOF
chmod +x "${WORK}/bin/circleci"
STUB_DIR="${WORK}/stub"
mkdir -p "${STUB_DIR}"

# path_without NAME...: the PATH, with each directory that holds one of NAMEs
# replaced by links to everything else in it. CircleCI's images have a
# circleci, and a machine can have an older js-security-node.
path_without() {
    local result="" dir file name shadow skip
    local -a dirs
    IFS=: read -ra dirs <<< "${PATH}"
    for dir in "${dirs[@]}"; do
        [[ -d "${dir}" ]] || continue
        skip=false
        for name in "$@"; do
            [[ -e "${dir}/${name}" ]] && skip=true
        done
        if [[ "${skip}" == true ]]; then
            shadow=$(mktemp -d "${WORK}/path.XXXXXX")
            for file in "${dir}"/*; do
                skip=false
                for name in "$@"; do
                    [[ "${file##*/}" == "${name}" ]] && skip=true
                done
                [[ "${skip}" == true ]] || ln -s "${file}" "${shadow}/"
            done
            dir=${shadow}
        fi
        result+="${result:+:}${dir}"
    done
    printf '%s' "${result}"
}
CLEAN_PATH=$(path_without circleci js-security-node)
# Without any Node.js: the steps' own tools, bash and coreutils, stay.
NO_NODE_PATH=$(PATH="${CLEAN_PATH}" path_without node nodejs)

# The registry: real metadata of semver 7.5.1 (its registry signature and its
# provenance bundle, recorded in tests/fixtures/signatures and
# tests/fixtures/attestations, so they verify against the keys and roots the
# helper pins), minimist 1.2.0 without a signature, and the audit fixtures'
# advisories for both.
REGISTRY="${WORK}/registry"
"${NODE}" --input-type=module - "${FIXTURES}" "${REGISTRY}" << 'EOF'
import fs from 'node:fs';
import path from 'node:path';
const [fixtures, dir] = process.argv.slice(2);
const read = (file) => JSON.parse(fs.readFileSync(path.join(fixtures, file), 'utf8'));
const write = (file, data) => {
  fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
  fs.writeFileSync(path.join(dir, file), JSON.stringify(data));
};
const semver = read('signatures/semver@7.5.1.json');
write('packuments/semver.json', {
  _id: 'semver', name: 'semver', 'dist-tags': { latest: '7.5.1' },
  versions: { '7.5.1': { name: 'semver', version: '7.5.1', license: 'ISC', dist: semver.dist } },
  time: { created: '2011-02-12T00:20:25.690Z', '7.5.1': semver.time },
});
write('attestations/semver@7.5.1.json', read('attestations/semver@7.5.1.json'));
write('packuments/minimist.json', {
  _id: 'minimist', name: 'minimist', 'dist-tags': { latest: '1.2.0' },
  versions: {
    '1.2.0': {
      name: 'minimist', version: '1.2.0', license: 'MIT',
      dist: {
        integrity: 'sha512-kZrcVFFp3hGvROhHafpNZ9U1tB3jLr4ptfq7hZiJ1g18VSy817gWxfm8FQhNUC1jXcCBoMsrg3os434eYU2M4g==',
        tarball: 'https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz',
      },
    },
  },
  time: { created: '2013-06-25T08:17:32.465Z', '1.2.0': '2015-08-24T04:39:45.418Z' },
});
const advisories = read('audit/registry/advisories.json');
write('advisories.json', { semver: advisories.semver, minimist: advisories.minimist });
EOF
REGISTRY_LOG="${WORK}/registry.log"
"${NODE}" "${ROOT}/tests/fake_registry.mjs" "${REGISTRY}" "${REGISTRY_LOG}" > "${WORK}/port" &
REGISTRY_PID=$!
for _ in $(seq 100); do
    [[ -s "${WORK}/port" ]] && break
    sleep 0.1
done
PORT=$(tr -d '[:space:]' < "${WORK}/port")
if [[ ! "${PORT}" =~ ^[0-9]+$ ]]; then
    echo "ERROR: tests/fake_registry.mjs didn't start." >&2
    exit 1
fi
REGISTRY_URL="http://127.0.0.1:${PORT}"

# The projects: vulnerable locks minimist 1.2.0 and semver 7.5.1, signed only
# semver 7.5.1, both from registry.npmjs.org as npm records them.
lockfile() {
    local name=$1
    shift
    "${NODE}" --input-type=module - "${name}" "$@" << 'EOF'
const [name, ...wanted] = process.argv.slice(2);
const all = {
  minimist: {
    version: '1.2.0', license: 'MIT',
    resolved: 'https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz',
    integrity: 'sha512-kZrcVFFp3hGvROhHafpNZ9U1tB3jLr4ptfq7hZiJ1g18VSy817gWxfm8FQhNUC1jXcCBoMsrg3os434eYU2M4g==',
  },
  semver: {
    version: '7.5.1', license: 'ISC',
    resolved: 'https://registry.npmjs.org/semver/-/semver-7.5.1.tgz',
    integrity: 'sha512-Wvss5ivl8TMRZXXESstBA4uR5iXgEN/VC5/sOcuXdVLzcdkz4HWetIoRfG5gb5X+ij/G9rw9YoGn3QoQ8OCSpw==',
  },
};
const lock = {
  name, version: '1.0.0', lockfileVersion: 3, requires: true,
  packages: { '': { name, version: '1.0.0', dependencies: Object.fromEntries(wanted.map((p) => [p, all[p].version])) } },
};
for (const p of wanted) lock.packages[`node_modules/${p}`] = all[p];
process.stdout.write(`${JSON.stringify(lock, null, 2)}\n`);
EOF
}
mkdir -p "${JOB}/vulnerable" "${JOB}/signed" "${JOB}/empty"
lockfile vulnerable minimist semver > "${JOB}/vulnerable/package-lock.json"
lockfile signed semver > "${JOB}/signed/package-lock.json"

FAILURES=0
RC=0
OUTPUT=""
RUN_PATH="${WORK}/bin:${CLEAN_PATH}"

# run COMMAND PROJECT [NAME=VALUE ...] [-- VAR=value ...]: runs COMMAND's
# script in JOB/PROJECT through tests/run_command.sh, against the stand-in
# registry, with the parameters given and the environment settings after --.
# The PATH is RUN_PATH unless the settings change it.
run() {
    local command=$1 project=$2 params=() envs=()
    shift 2
    while [[ $# -gt 0 && "$1" != -- ]]; do
        params+=("$1")
        shift
    done
    if [[ $# -gt 0 ]]; then
        shift
        envs=("$@")
    fi
    rm -rf "${OUT}" "${STUB_DIR:?}"/*
    OUTPUT=$(env -u NODE_OPTIONS -u NODE_PATH -u CIRCLECI -u GITHUB_ACTIONS HOME="${WORK}/home" \
        XDG_CACHE_HOME="${WORK}/cache" TMPDIR="${WORK}/tmp" PATH="${RUN_PATH}" STUB_DIR="${STUB_DIR}" \
        ${envs[@]+"${envs[@]}"} \
        bash "${ROOT}/tests/run_command.sh" "${command}" "working_dir=${JOB}/${project}" \
        "registry=${REGISTRY_URL}" "output_dir=${OUT}" ${params[@]+"${params[@]}"} 2>&1)
    RC=$?
}

check() {
    local description=$1
    shift
    if "$@"; then
        printf 'ok: %s\n' "${description}"
    else
        printf 'FAIL: %s\n' "${description}"
        while IFS= read -r line; do
            printf '    | %s\n' "${line}"
        done <<< "${OUTPUT}"
        FAILURES=$((FAILURES + 1))
    fi
}
rc_is() { [[ "${RC}" -eq "$1" ]]; }
says() { grep -qF -- "$1" <<< "${OUTPUT}"; }
not_says() { ! grep -qF -- "$1" <<< "${OUTPUT}"; }
# report NAME FILTER: the jq FILTER is true of OUT/NAME.json.
report() { [[ -f "${OUT}/$1.json" ]] && [[ "$(jq -r "$2" "${OUT}/$1.json" 2> /dev/null)" == true ]]; }
# outcome_is NAME OUTCOME: OUT/NAME.json's outcome is OUTCOME (passed, findings,
# findings-reported or error).
outcome_is() { report "$1" ".outcome == \"$2\""; }
reports_written() {
    [[ -f "${OUT}/$1.json" && -f "${OUT}/$1.sarif" && -f "${OUT}/junit/$1.xml" ]]
}
# work_dir_gone: nothing is left in TMPDIR, where js_run's work directory and
# the helper's temporary files go.
work_dir_gone() { [[ -z "$(ls -A "${WORK}/tmp")" ]]; }

echo "== Each command, its reports and its exit codes"
run audit vulnerable
check "audit: findings fail the step with exit 1" rc_is 1
check "  as findings" outcome_is audit findings
check "audit: writes the JSON, SARIF and JUnit reports" reports_written audit
check "audit: the report has minimist's and semver's advisories" \
    report audit '[.findings[].package.name] | (index("minimist") != null) and (index("semver") != null)'
check "audit: the work directory is removed after findings" work_dir_gone
check "audit: asks the registry's bulk advisory endpoint" grep -qF '/-/npm/v1/security/advisories/bulk' "${REGISTRY_LOG}"

run audit vulnerable report_only=true
check "audit report_only: passes with exit 0" rc_is 0
check "  as findings-reported" outcome_is audit findings-reported
check "audit report_only: still reports the findings" report audit '.findings | length > 0'

run audit vulnerable fail_on=nonsense
check "audit: a fail_on it doesn't know is a usage error, exit 2" rc_is 2
check "audit: names the parameter" says "fail_on"
check "audit: the work directory is removed after a usage error" work_dir_gone

run licenses vulnerable
check "licenses: MIT and ISC pass by default" rc_is 0
check "  as passed" outcome_is licenses passed
check "licenses: writes the JSON, SARIF and JUnit reports" reports_written licenses
check "licenses: the work directory is removed after a pass" work_dir_gone

run licenses vulnerable allowed_licenses=MIT
check "licenses: ISC outside allowed_licenses fails with exit 1" rc_is 1
check "  as findings" outcome_is licenses findings
check "licenses: the finding is semver's" report licenses '[.findings[].package.name] == ["semver"]'

run lock_verify vulnerable
check "lock_verify: two locked, hashed, month-old registry packages pass" rc_is 0
check "  as passed" outcome_is lock_verify passed
check "lock_verify: writes the JSON, SARIF and JUnit reports" reports_written lock_verify

run lock_verify empty
check "lock_verify: a directory without a lockfile has no verdict, exit 1" rc_is 1
check "  as error" outcome_is lock_verify error
run lock_verify empty allow_empty=true
check "lock_verify: allow_empty passes it" rc_is 0

run signatures signed
check "signatures: semver 7.5.1's registry signature verifies" rc_is 0
check "  as passed" outcome_is signatures passed
check "signatures: writes the JSON, SARIF and JUnit reports" reports_written signatures
run signatures signed require_provenance=semver
check "signatures: its provenance verifies" rc_is 0
check "  as passed" outcome_is signatures passed
run signatures signed "provenance_sources=semver=https://github.com/example/other"
check "signatures: provenance naming another repository fails with exit 1" rc_is 1
check "  as findings" outcome_is signatures findings
run signatures vulnerable
check "signatures: minimist without a registry signature fails with exit 1" rc_is 1
check "  as findings" outcome_is signatures findings
check "signatures: the finding is minimist's" report signatures '[.findings[].package.name] | index("minimist") != null'

run signatures signed run_record=true report_name=sig-record
check "run_record: writes <report_name>.run-record.json" test -f "${OUT}/sig-record.run-record.json"
check "report_name: names every report" reports_written sig-record

echo "== Parameters and the CircleCI CLI"
run licenses vulnerable 'lockfiles=$ORB_TEST_VAR' -- ORB_TEST_VAR=package-lock.json
check "expands parameters with the CircleCI CLI" rc_is 0
check "  as passed" outcome_is licenses passed
check "  and the report names the lockfile it found" report licenses '.lockfiles[0].path | endswith("package-lock.json")'
check "  passing each value on stdin" grep -qxF '$ORB_TEST_VAR' "${STUB_DIR}/circleci.log"
check "  but never output_dir" bash -c '! grep -qF "$1" "$2"' _ "${OUT}" "${STUB_DIR}/circleci.log"

run licenses vulnerable 'report_name=$ORB_TEST_VAR' -- ORB_TEST_VAR=expanded
check "never expands report_name, which store_test_results reads as given" bash -c '! test -e "$1"' _ "${OUT}/expanded.json"
check "  so the expanded name isn't used" bash -c '! grep -qxF "\$ORB_TEST_VAR" "$1"' _ "${STUB_DIR}/circleci.log"

RUN_PATH="${CLEAN_PATH}"
run licenses vulnerable lockfiles=package-lock.json
check "without the CircleCI CLI, uses the values as they are" rc_is 0
check "  as passed" outcome_is licenses passed
run licenses vulnerable 'lockfiles=$ORB_TEST_VAR' -- ORB_TEST_VAR=package-lock.json
check "  so \$ORB_TEST_VAR stays a pattern that matches nothing" rc_is 1
check "  as error" outcome_is licenses error
RUN_PATH="${WORK}/bin:${CLEAN_PATH}"

echo "== The Node.js js_node picks"
mkdir -p "${WORK}/old" "${WORK}/broken" "${WORK}/launcher"
printf '#!/bin/sh\necho v20.18.1\n' > "${WORK}/old/node"
printf '#!/bin/sh\necho "not node"\n' > "${WORK}/broken/node"
# The install command's launcher: records that it ran, then runs node.
cat > "${WORK}/launcher/js-security-node" << EOF
#!/bin/sh
echo "\$@" >> "${WORK}/launcher.log"
exec "${NODE}" "\$@"
EOF
chmod +x "${WORK}/old/node" "${WORK}/broken/node" "${WORK}/launcher/js-security-node"

run licenses vulnerable -- PATH="${WORK}/bin:${WORK}/old:${NO_NODE_PATH}"
check "Node.js 20 fails the step with exit 1" rc_is 1
check "  saying it needs 22 or newer" says "but the checks need 22 or newer"
check "  and writes no report" bash -c '! test -e "$1"' _ "${OUT}/licenses.json"

run licenses vulnerable -- PATH="${WORK}/bin:${WORK}/broken:${NO_NODE_PATH}"
check "a node that reports no version fails the step" rc_is 1
check "  saying what it printed" says "it printed 'not node'"

run licenses vulnerable -- PATH="${WORK}/bin:${NO_NODE_PATH}"
check "no Node.js at all fails the step" rc_is 1
check "  pointing to the install command" says "There is no Node.js on the PATH"

rm -f "${WORK}/launcher.log"
run licenses vulnerable -- PATH="${WORK}/bin:${WORK}/launcher:${WORK}/old:${NO_NODE_PATH}"
check "the install command's js-security-node comes before node" rc_is 0
check "  as passed" outcome_is licenses passed
check "  and runs the helper" grep -qF "/helper/licenses.mjs" "${WORK}/launcher.log"

echo "== The helper's environment"
mkdir -p "${WORK}/inject"
printf 'throw new Error("NODE_OPTIONS reached the helper");\n' > "${WORK}/inject/inject.cjs"
run licenses vulnerable -- NODE_OPTIONS="--require ${WORK}/inject/inject.cjs" NODE_PATH="${WORK}/inject"
check "NODE_OPTIONS and NODE_PATH never reach the helper" rc_is 0
check "  as passed" outcome_is licenses passed
check "  so the code they name never runs" not_says "NODE_OPTIONS reached the helper"

run licenses vulnerable token=TEST_REGISTRY_TOKEN -- TEST_REGISTRY_TOKEN=s3cr3t-registry-token
check "a token: the check runs" rc_is 0
check "  as passed" outcome_is licenses passed
check "  sending it to the registry" grep -qF 'Bearer s3cr3t-registry-token' "${REGISTRY_LOG}"
check "  and never printing it" not_says "s3cr3t-registry-token"
check "  or writing it to a report" bash -c '! grep -rqF s3cr3t-registry-token "$1"' _ "${OUT}"

echo "== The modules come from the step's variables"
OUTPUT=$(cd "${JOB}/vulnerable" && env -u NODE_OPTIONS HOME="${WORK}/home" XDG_CACHE_HOME="${WORK}/cache" \
    TMPDIR="${WORK}/tmp" PATH="${CLEAN_PATH}" PARAM_OUTPUT_DIR="${OUT}" PARAM_REPORT_NAME=licenses \
    SCRIPT_JS_SECURITY_LIB="$(cat "${ROOT}/src/scripts/lib/js_security.sh")" \
    SCRIPT_JS_HELPER_LICENSES="$(cat "${ROOT}/src/helper/licenses.mjs")" \
    bash "${ROOT}/src/scripts/licenses.sh" 2>&1)
RC=$?
check "a module the step doesn't pass fails the step" rc_is 1
check "  naming its variable" says "SCRIPT_JS_HELPER_CORE is not set"
check "  and leaves no work directory behind" work_dir_gone

OUTPUT=$(cd "${JOB}/vulnerable" && env PATH="${CLEAN_PATH}" bash "${ROOT}/src/scripts/audit.sh" 2>&1)
RC=$?
check "without the shared helpers the script stops" rc_is 1
check "  with an ERROR line" says "ERROR:"

if [[ "${FAILURES}" -gt 0 ]]; then
    printf '%s check(s) failed.\n' "${FAILURES}"
    exit 1
fi
echo "All command checks passed."
