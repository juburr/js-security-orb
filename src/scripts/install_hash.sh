#!/bin/bash
#
# Prints checksum table entries for a Node.js release, ready to paste into the
# sha512sums table in install.sh. A development helper: the orb never runs
# it.
#
#   src/scripts/install_hash.sh -v <version> [-a "<arch> ..."] [-c <checksum>]
#
#   -a  architectures to hash (default: every one install.sh supports)
#   -c  a checksum for the asset from another official source, as
#       SHA-256:<hex> or SHA1:<hex>, for a release whose published checksums
#       don't cover it (verify_upstream finds nothing); or NONE to add an
#       entry that is not anchored to any published checksum. -c never
#       overrides a failure to fetch or verify what Node.js did publish:
#       re-run once the source is reachable.
#
# Each archive is checked against the SHASUMS256.txt Node.js publishes with
# the release, after gpgv verifies that list's signature by a Node.js
# releaser (see verify_upstream). Entries go to stdout and everything else to
# stderr, so the output can be pasted as is. Needs gpg and gpgv besides the
# shared logic's tools.

set -euo pipefail

# >>> upstream verification >>>
# A release whose checksums were signed fewer than this many days ago is
# refused, so a compromise has time to come to light before the release
# reaches the table. Set NODE_MIN_RELEASE_AGE_DAYS=0 to add a newer release
# after checking Node.js's security releases for it.
NODE_MIN_RELEASE_AGE_DAYS=${NODE_MIN_RELEASE_AGE_DAYS:-7}

# The releasers' keys come from github.com/nodejs/release-keys, pinned to a
# commit, and only the keys listed below are trusted: each file's fingerprint
# is checked, and a signature counts only when its key's primary fingerprint
# is listed. A retired key (with the date release-keys retired it) counts
# only for signatures made before that date.
#
# To move the pin: check that the new commits touching keys/ are signed by a
# key of the old list (git verify-commit, with those keys imported), compare
# the active keys with the "Release keys" section of the nodejs/node README,
# then update the commit and the list.
NODE_RELEASE_KEYS_COMMIT="481637f813e912c4aa3622d7964ab426c97b8e8d"
NODE_RELEASE_KEYS=(
    "5BE8A3F6C8A5C01D106C0AD820B1A390B168D356"            # Antoine du Hamel
    "DD792F5973C6DE52C432CBDAC77ABFA00DDBF2B7"            # Juan José Arboleda
    "CC68F5A3106FF448322E48ED27F5E38D5B0A215F"            # Marco Ippolito
    "890C08DB8579162FEE0DF9DB8BEAB4DFCF555EF4"            # Rafael Gonzaga
    "C82FA3AE1CBEDC6BE46B9360C43CEC45C17AB93C"            # Richard Lau
    "108F52B48DB57BB0CC439B2997B01419BD92F80A"            # Ruy Adorno
    "655F3B5C1FB3FA8D1A0CA6BDE4A7D232B936D2FD"            # Stewart X Addison
    "A363A499291CBBC940DD62E41F10027AF002F8B0"            # Ulises Gascón
    "C0D6248439F1D5604AAFFB4021D900FFDB233756 1752796800" # Antoine du Hamel's earlier key, retired 2025-07-18
    "8FCCA13FEF1D0C2E91008E09770F7A9A5AE15600 1787788800" # Michaël Zasso, retired 2026-08-27
)

# utc_day EPOCH: EPOCH as YYYY-MM-DD, for messages only.
utc_day() {
    date -u -d "@$1" +%Y-%m-%d 2> /dev/null || printf '@%s' "$1"
}

# node_release_date VERSION: prints the epoch of the day nodejs.org's
# release index (dist/index.json) dates Node.js VERSION to. It is a second
# clock beside the signature's own creation time, which whoever holds the
# signing key sets freely. Returns 1, after an ERROR, when it can't tell.
node_release_date() {
    local day epoch
    if ! hash_fetch "https://nodejs.org/dist/index.json" index.json > /dev/null; then
        echo "ERROR: could not fetch nodejs.org's release index (dist/index.json)." >&2
        return 1
    fi
    day=$(grep -oE "\"version\":\"v$1\",\"date\":\"[0-9]{4}-[0-9]{2}-[0-9]{2}\"" index.json | head -n 1 | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}' || true)
    if [[ -z "${day}" ]]; then
        echo "ERROR: nodejs.org's release index lists no date for Node.js $1." >&2
        return 1
    fi
    if ! epoch=$(date -u -d "${day}" +%s 2> /dev/null) || [[ ! "${epoch}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: could not convert ${day} to a time with this system's date (GNU date is needed)." >&2
        return 1
    fi
    printf '%s\n' "${epoch}"
}

# node_signed_list VERSION: fetches Node.js VERSION's SHASUMS256.txt and its
# detached signature (.sig) into the current directory, once, and verifies
# the signature with gpgv against the pinned keys: exactly one good signature
# (VALIDSIG), by a listed key, and no bad, expired or revoked one. gpgv's
# status lines decide, never its exit code alone. Both the signature's time
# and the release's date in nodejs.org's index must come before a retired
# key's retirement, and be at least NODE_MIN_RELEASE_AGE_DAYS days old: a
# back-dated signature alone gets past neither. Returns 0 when it verifies, 2
# when Node.js published no list, and 1 otherwise.
node_signed_list() {
    local base="https://nodejs.org/dist/v$1" entry fpr retired gnupg keyring rc=0 file status signer signed age
    local released now when
    local -A allowed=()
    if [[ -f SHASUMS256.txt.verified ]]; then
        return 0
    fi
    for tool in gpg gpgv; do
        if ! command -v "${tool}" > /dev/null; then
            echo "ERROR: ${tool} is required to verify the signature on SHASUMS256.txt."
            return 1
        fi
    done
    hash_fetch "${base}/SHASUMS256.txt" SHASUMS256.txt || rc=$?
    if [[ "${rc}" -eq 2 ]]; then
        echo "Node.js $1 publishes no SHASUMS256.txt."
        return 2
    elif [[ "${rc}" -ne 0 ]]; then
        return 1
    fi
    # Every release lists signs its checksums, so a missing signature is an
    # error, never "not published".
    rc=0
    hash_fetch "${base}/SHASUMS256.txt.sig" SHASUMS256.txt.sig || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "ERROR: could not fetch the signature on Node.js $1's SHASUMS256.txt."
        return 1
    fi
    gnupg=$(mktemp -d "${PWD}/gnupg.XXXXXX")
    chmod 700 "${gnupg}"
    keyring="${PWD}/release-keys.gpg"
    : > "${keyring}"
    for entry in "${NODE_RELEASE_KEYS[@]}"; do
        fpr=${entry%% *}
        retired=""
        if [[ "${entry}" == *" "* ]]; then
            retired=${entry#* }
        fi
        allowed[${fpr}]=${retired:-active}
        file="${PWD}/${fpr}.asc"
        rc=0
        hash_fetch "https://raw.githubusercontent.com/nodejs/release-keys/${NODE_RELEASE_KEYS_COMMIT}/keys/${fpr}.asc" \
            "${file}" || rc=$?
        if [[ "${rc}" -ne 0 ]]; then
            echo "ERROR: could not fetch key ${fpr} from nodejs/release-keys at ${NODE_RELEASE_KEYS_COMMIT}."
            return 1
        fi
        # The file must hold exactly the key it is named after.
        if [[ "$(gpg --homedir "${gnupg}" --batch --show-keys --with-colons "${file}" 2> /dev/null \
            | awk -F: '$1 == "fpr" { print $10; exit }')" != "${fpr}" ]]; then
            echo "ERROR: keys/${fpr}.asc in nodejs/release-keys holds another key."
            return 1
        fi
        gpg --homedir "${gnupg}" --batch --dearmor < "${file}" >> "${keyring}"
    done
    rc=0
    gpgv --keyring "${keyring}" --status-fd 3 SHASUMS256.txt.sig SHASUMS256.txt 3> gpgv.status 2> gpgv.log || rc=$?
    if grep -qE '^\[GNUPG:\] (BADSIG|ERRSIG|EXPKEYSIG|REVKEYSIG|NO_PUBKEY|EXPSIG) ' gpgv.status \
        || [[ "$(grep -c '^\[GNUPG:\] VALIDSIG ' gpgv.status)" -ne 1 ]] || [[ "${rc}" -ne 0 ]]; then
        echo "ERROR: the signature on Node.js $1's SHASUMS256.txt is not one good signature by a pinned release key:"
        sed 's/^/  /' gpgv.status gpgv.log
        return 1
    fi
    # VALIDSIG <fingerprint> <date> <timestamp> <expires> <version> <reserved>
    # <pubkey-algo> <hash-algo> <class> <primary-fingerprint>
    status=$(grep '^\[GNUPG:\] VALIDSIG ' gpgv.status)
    signer=$(awk '{ print ($12 != "" ? $12 : $3) }' <<< "${status}")
    signed=$(awk '{ print $5 }' <<< "${status}")
    if [[ -z "${allowed[${signer}]+set}" ]]; then
        echo "ERROR: Node.js $1's SHASUMS256.txt is signed by ${signer}, which is not a pinned release key."
        return 1
    fi
    if [[ ! "${signed}" =~ ^[0-9]+$ ]]; then
        echo "ERROR: could not read when Node.js $1's SHASUMS256.txt was signed."
        return 1
    fi
    if ! released=$(node_release_date "$1"); then
        return 1
    fi
    retired=${allowed[${signer}]}
    if [[ "${retired}" != active ]]; then
        if [[ ! "${retired}" =~ ^[0-9]+$ ]]; then
            echo "ERROR: NODE_RELEASE_KEYS gives ${signer} a retirement time that isn't a number of seconds."
            return 1
        fi
        for when in "${signed}" "${released}"; do
            if ((when >= retired)); then
                echo "ERROR: Node.js $1's SHASUMS256.txt is signed by ${signer}, which retired on" \
                    "$(utc_day "${retired}"), before the release (signed $(utc_day "${signed}")," \
                    "dated $(utc_day "${released}") in nodejs.org's index)."
                return 1
            fi
        done
    fi
    echo "ok: Node.js $1's SHASUMS256.txt is signed by release key ${signer}."
    now=$(date -u +%s)
    for when in "${signed}" "${released}"; do
        age=$(((now - when) / 86400))
        if ((age < NODE_MIN_RELEASE_AGE_DAYS)); then
            echo "ERROR: Node.js $1 was released ${age} day(s) ago (signed $(utc_day "${signed}")," \
                "dated $(utc_day "${released}") in nodejs.org's index), and releases younger than" \
                "${NODE_MIN_RELEASE_AGE_DAYS} days are not added. Try again later, or set NODE_MIN_RELEASE_AGE_DAYS=0" \
                "after checking Node.js's security releases."
            return 1
        fi
    done
    echo "ok: it was signed on $(utc_day "${signed}") and is dated $(utc_day "${released}") in nodejs.org's index," \
        "at least ${NODE_MIN_RELEASE_AGE_DAYS} days ago."
    touch SHASUMS256.txt.verified
}

# verify_upstream VERSION ARCH ASSET: checks ASSET against the SHA-256 that
# Node.js's signed SHASUMS256.txt lists for it. Returns 0 when it matches, 2
# when nothing was published, and 1 otherwise. The list is fetched and
# verified once per run, in the first architecture's directory.
verify_upstream() {
    local name=${3##*/} published actual rc=0 dir
    dir="${HASH_WORK_DIR}/upstream"
    mkdir -p "${dir}"
    (cd "${dir}" && node_signed_list "$1") || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        return "${rc}"
    fi
    published=$(awk -v name="${name}" '$2 == name { print $1; exit }' "${dir}/SHASUMS256.txt")
    if [[ -z "${published}" ]]; then
        echo "Node.js $1's SHASUMS256.txt does not list ${name}."
        return 2
    fi
    actual=$(sha256sum "$3" | awk '{ print $1 }')
    if [[ "${actual}" != "${published}" ]]; then
        echo "ERROR: ${name} has SHA-256 ${actual}, but ${published} was published."
        return 1
    fi
    echo "ok: ${name} matches the published SHA-256."
}
# <<< upstream verification <<<

# >>> shared install_hash logic >>>
# Everything from here to the end marker is identical in the install_hash.sh
# of every juburr orb. The tool definition, and with it the asset names and
# URLs, is read from install.sh so the two scripts cannot disagree.

hash_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

hash_usage() {
    printf 'Usage: %s -v <version> [-a "<arch> ..."] [-c SHA-256:<hex> | -c SHA1:<hex> | -c NONE]\n' "$0" >&2
    exit 1
}

# hash_fetch URL DEST [CURL_ARG...]: downloads URL to DEST for verify_upstream.
# Returns 0 on success, 2 when the server says there is no such file (404),
# and 1 on any other failure, which must never be read as "not published".
hash_fetch() {
    local url=$1 dest=$2 code rc=0
    shift 2
    # Without -f, curl exits 0 on an HTTP error, so a non-zero exit is a
    # transfer failure, such as a connection that closed partway.
    code=$(curl -sSL --proto '=https' --proto-redir '=https' --retry 5 --connect-timeout 30 \
        -o "${dest}" -w '%{http_code}' "$@" "${url}") || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        echo "ERROR: could not download ${url} (curl exit code ${rc})."
        return 1
    fi
    case "${code}" in
        200) return 0 ;;
        404) return 2 ;;
        *)
            echo "ERROR: could not download ${url} (HTTP status ${code:-none})."
            return 1
            ;;
    esac
}

# hash_version_le A B: succeeds if version A sorts at or before version B.
hash_version_le() {
    [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$1" ]]
}

# Loads install.sh's tool definition and shared functions, without its
# checksum table or main call.
INSTALL_SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/install.sh"
# shellcheck source=/dev/null
source <(sed -n '/^# >>> tool definition >>>$/,/^# <<< shared install logic <<<$/p' "${INSTALL_SCRIPT}")
if ! declare -F tool_asset_name > /dev/null; then
    hash_die "Could not load the tool definition from ${INSTALL_SCRIPT}."
fi

VERSION=""
ARCHES=""
UPSTREAM_CHECKSUM=""
while getopts ':v:a:c:' flag; do
    case "${flag}" in
        v) VERSION=${OPTARG} ;;
        a) ARCHES=${OPTARG} ;;
        c) UPSTREAM_CHECKSUM=${OPTARG} ;;
        *) hash_usage ;;
    esac
done
VERSION=${VERSION#v}
if [[ -z "${VERSION}" ]]; then
    hash_usage
fi
if [[ ! "${VERSION}" =~ ^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
    hash_die "Invalid version '${VERSION}'."
fi
ARCHES=${ARCHES:-${TOOL_ARCHES}}
read -r -a ARCH_LIST <<< "${ARCHES}"
if [[ "${#ARCH_LIST[@]}" -eq 0 ]]; then
    hash_die "-a names no architecture. Supported: ${TOOL_ARCHES}."
fi
for arch in "${ARCH_LIST[@]}"; do
    if [[ " ${TOOL_ARCHES} " != *" ${arch} "* ]]; then
        hash_die "Unsupported architecture '${arch}'. Supported: ${TOOL_ARCHES}."
    fi
done
if [[ -n "${UPSTREAM_CHECKSUM}" && "${UPSTREAM_CHECKSUM}" != "NONE" ]]; then
    if [[ ! "${UPSTREAM_CHECKSUM}" =~ ^(SHA-256:[0-9a-f]{64}|SHA1:[0-9a-f]{40})$ ]]; then
        hash_die "-c must be SHA-256:<hex>, SHA1:<hex>, or NONE."
    fi
    if [[ "${#ARCH_LIST[@]}" -gt 1 ]]; then
        hash_die "-c describes one asset, so pick its architecture with -a."
    fi
fi
REQUIRED_TOOLS=(curl sha256sum sha512sum tar gzip)
if [[ "${UPSTREAM_CHECKSUM}" == SHA1:* ]]; then
    REQUIRED_TOOLS+=(sha1sum)
fi
for tool in "${REQUIRED_TOOLS[@]}"; do
    command -v "${tool}" > /dev/null || hash_die "${tool} is required."
done

HASH_WORK_DIR=$(mktemp -d)
trap 'rm -rf "${HASH_WORK_DIR}"' EXIT

# check_upstream VERSION ARCH ASSET: anchors ASSET to what the project
# published, via verify_upstream (which returns 2 when nothing was published)
# and any checksum supplied with -c.
check_upstream() {
    local rc=0 expected actual
    (cd "${3%/*}" && verify_upstream "$1" "$2" "$3") >&2 || rc=$?
    if [[ "${rc}" -ne 0 && "${rc}" -ne 2 ]]; then
        hash_die "${3##*/} could not be verified against what ${TOOL_NAME} published for ${1}."
    fi
    # NONE only stands in for a checksum that was never published.
    if [[ "${UPSTREAM_CHECKSUM}" == "NONE" ]]; then
        if [[ "${rc}" -eq 2 ]]; then
            printf 'WARN: -c NONE: %s is not checked against any published checksum.\n' "${3##*/}" >&2
        fi
        return 0
    fi
    if [[ -n "${UPSTREAM_CHECKSUM}" ]]; then
        expected=${UPSTREAM_CHECKSUM#*:}
        case "${UPSTREAM_CHECKSUM%%:*}" in
            SHA-256) actual=$(sha256sum "$3" | awk '{ print $1 }') ;;
            SHA1) actual=$(sha1sum "$3" | awk '{ print $1 }') ;;
        esac
        if [[ "${actual}" != "${expected}" ]]; then
            hash_die "${3##*/} does not match the checksum given with -c (${actual})."
        fi
        printf 'ok: %s matches the checksum given with -c.\n' "${3##*/}" >&2
    elif [[ "${rc}" -eq 2 ]]; then
        hash_die "${TOOL_NAME} published no checksum for ${3##*/}. Supply one from another official source with -c," \
            "or pass -c NONE to add the entry unanchored."
    fi
}

ENTRIES=()
for arch in "${ARCH_LIST[@]}"; do
    # orb_extract works in ORB_WORK_DIR and names ORB_ASSET_NAME in messages.
    ORB_WORK_DIR="${HASH_WORK_DIR}/${arch}"
    ORB_ASSET_NAME=$(tool_asset_name "${VERSION}" "${arch}")
    member=$(tool_archive_member "${VERSION}" "${arch}")
    mkdir -p "${ORB_WORK_DIR}"
    mapfile -t urls < <(tool_asset_urls "${VERSION}" "${arch}" "${ORB_ASSET_NAME}")
    if ! orb_download "${ORB_WORK_DIR}/${ORB_ASSET_NAME}" "${urls[@]}" >&2; then
        hash_die "Could not download ${ORB_ASSET_NAME}. If ${TOOL_NAME} ${VERSION} has no ${arch} build," \
            "leave ${arch} out with -a."
    fi
    check_upstream "${VERSION}" "${arch}" "${ORB_WORK_DIR}/${ORB_ASSET_NAME}"
    # Hashes the same file install.sh verifies, with the same checks on it.
    if ! orb_extract "${ORB_WORK_DIR}/${ORB_ASSET_NAME}" "${member}" >&2; then
        hash_die "Could not take ${member} from ${ORB_ASSET_NAME}."
    fi
    ENTRIES+=("$(printf '    ["%s/%s"]="%s"' "${VERSION}" "${arch}" "$(sha512sum "${ORB_VERIFIED_FILE}" | awk '{ print $1 }')")")
done
# Nothing is printed until every architecture has passed.
printf '%s\n' "${ENTRIES[@]}"
# <<< shared install_hash logic <<<
