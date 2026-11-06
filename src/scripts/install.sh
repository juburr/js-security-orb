#!/bin/bash
#
# Installs Node.js for js-security-orb's commands: the official release
# archive for this machine's architecture (Linux amd64 or arm64), verified
# against the checksum table in this file before it is unpacked. The commands
# run their checks with this Node.js; the job's own Node.js, which builds and
# tests the project, is left alone: bin, which goes on the PATH, holds only
# the js-security-node launcher, never node, npm or npx.
#
# Every juburr orb's install.sh has the same three parts:
#   1. tool definition: what to download and how to install it (Node.js only)
#   2. shared install logic: identical in every orb
#   3. checksum table: one SHA-512 per release and architecture
#
# Add the checksums for a new release with:
#   src/scripts/install_hash.sh -v <version>

# CircleCI runs steps with /bin/sh when the image has no bash, and macOS ships
# bash 3, which lacks associative arrays.
if [ -z "${BASH_VERSION:-}" ] || [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "ERROR: Installing Node.js needs bash 4 or newer. Use an executor image that has it." >&2
    exit 1
fi
set -euo pipefail

# >>> tool definition >>>
ORB_NAME="js-security-orb"
TOOL_NAME="Node.js"
TOOL_BINARY="js-security-node"
TOOL_ARCHES="amd64 arm64"
# The default install_path, under HOME. It is the installation's root: the
# release's tree goes in lib/node, and bin, which goes on the PATH, holds only
# the js-security-node launcher.
TOOL_DEFAULT_INSTALL_DIR=".js-security-orb"

# js_node_arch ARCH: Node.js's name for ARCH.
js_node_arch() {
    case "$1" in
        amd64) printf 'x64\n' ;;
        *) printf '%s\n' "$1" ;;
    esac
}

# tool_asset_name VERSION ARCH: the release archive to download. The .tar.xz
# is half the size of the .tar.gz.
tool_asset_name() {
    printf 'node-v%s-linux-%s.tar.xz\n' "$1" "$(js_node_arch "$2")"
}

# tool_asset_urls VERSION ARCH ASSET: where to download it, one URL per line,
# tried in order: nodejs.org, or the download_base_url mirror in its place.
tool_asset_urls() {
    printf '%s/v%s/%s\n' "${JS_DOWNLOAD_BASE_URL:-https://nodejs.org/dist}" "$1" "$3"
}

# tool_archive_member VERSION ARCH: empty, since the archive holds a whole
# tree: the checksum table holds the SHA-512 of the archive itself, the file
# Node.js's signed SHASUMS256.txt lists.
tool_archive_member() {
    :
}

# tool_version LAUNCHER: prints the installed version (v<version>) without
# using the network.
tool_version() {
    "$1" --version
}

# js_download_base_url: sets JS_DOWNLOAD_BASE_URL from the download_base_url
# parameter, which replaces https://nodejs.org/dist in the download URL, so
# the same file comes from an internal mirror such as Artifactory, Nexus or
# S3. The checksum table, not the mirror, decides what is installed.
js_download_base_url() {
    local authority
    JS_DOWNLOAD_BASE_URL=$(orb_subst "${PARAM_DOWNLOAD_BASE_URL:-}")
    JS_DOWNLOAD_BASE_URL=${JS_DOWNLOAD_BASE_URL%/}
    if [[ -z "${JS_DOWNLOAD_BASE_URL}" ]]; then
        return 0
    fi
    # Credentials in the URL would show in the log and on curl's command
    # line, so they are refused before the URL is printed anywhere.
    authority=${JS_DOWNLOAD_BASE_URL#*://}
    if [[ "${authority%%/*}" == *@* ]]; then
        orb_die "download_base_url must not hold credentials (user:password@ before the host): they would show in the log and on curl's command line."
    fi
    # Nor can a query or fragment, which can hold a token too, and would end
    # up in the middle of every download URL.
    if [[ "${JS_DOWNLOAD_BASE_URL}" == *[?#]* ]]; then
        orb_die "download_base_url must not have a query or fragment (? or #): it could hold a token, which would show in the log."
    fi
    if [[ ! "${JS_DOWNLOAD_BASE_URL}" =~ ^https://[^[:space:]\"\'\<\>\\]+$ ]]; then
        orb_die "download_base_url must be an https:// URL, not '${JS_DOWNLOAD_BASE_URL}'."
    fi
    orb_info "  download mirror:  ${JS_DOWNLOAD_BASE_URL} (in place of https://nodejs.org/dist)"
}

# js_tree DIR: whether DIR is an installation this script made, which it may
# replace: the launcher, the release's tree and the install record.
js_tree() {
    [[ -f "$1/.js-security-orb" && -f "$1/bin/js-security-node" && -f "$1/lib/node/bin/node" ]]
}

# js_tree_version DIR: the version the release tree in DIR declares in
# include/node/node_version.h, which every Node.js release archive has, as
# MAJOR.MINOR.PATCH, or nothing.
js_tree_version() {
    awk '$1 == "#define" && $2 ~ /^NODE_(MAJOR|MINOR|PATCH)_VERSION$/ && $3 ~ /^[0-9]+$/ { v[$2] = $3 }
        END {
            if (("NODE_MAJOR_VERSION" in v) && ("NODE_MINOR_VERSION" in v) && ("NODE_PATCH_VERSION" in v))
                printf "%s.%s.%s\n", v["NODE_MAJOR_VERSION"], v["NODE_MINOR_VERSION"], v["NODE_PATCH_VERSION"]
        }' "$1/include/node/node_version.h" 2> /dev/null || true
}

# Installs the verified archive as the Node.js installation in install_path:
# the release's tree (node-v<version>-linux-<arch>) as lib/node, and a
# launcher, bin/js-security-node, that runs its node. bin goes on the PATH
# and holds nothing else, so the node, npm and npx the job builds with stay
# first. The new installation is made in a private directory beside
# install_path, and its launcher run once (orb_smoke_test), before it takes
# install_path's place, so an archive that can't run here (Node.js 26 needs
# libatomic.so.1, and every release glibc 2.28) leaves an existing
# installation in place. install_path must be missing, hold no files (only
# empty directories, if any), or be an earlier installation, so that a
# mistyped install_path such as $HOME is never moved aside and deleted.
tool_install() {
    local dir=${ORB_INSTALL_PATH%/*} name=${ORB_INSTALL_PATH##*/} staging="" tree version
    js_download_base_url
    ORB_BIN_DIR="${ORB_INSTALL_PATH}/bin"
    if [[ -L "${ORB_INSTALL_PATH}" ]]; then
        orb_die "install_path ${ORB_INSTALL_PATH} is a symbolic link. Point install_path at the directory itself."
    fi
    if [[ -e "${ORB_INSTALL_PATH}" && ! -d "${ORB_INSTALL_PATH}" ]]; then
        orb_die "install_path ${ORB_INSTALL_PATH} exists and is not a directory."
    fi
    # Empty directories hold nothing to lose, such as a bin directory put on
    # the PATH before the install.
    if [[ -d "${ORB_INSTALL_PATH}" ]] && ! js_tree "${ORB_INSTALL_PATH}" \
        && [[ -n "$(find "${ORB_INSTALL_PATH}" -mindepth 1 ! -type d -print -quit 2>&1)" ]]; then
        orb_die "install_path ${ORB_INSTALL_PATH} holds something other than an installation of Node.js by this orb, which" \
            "this install would replace. Choose a new or empty directory, or one an earlier install installed into."
    fi
    orb_require_tools tar xz
    orb_fetch_verified
    dir=${dir:-/}
    if ! mkdir -p "${dir}"; then
        orb_die "Could not create ${dir}. Choose an install_path this job's user can write to without root."
    fi
    if staging=$(mktemp -d "${dir%/}/.${name}.XXXXXX"); then
        ORB_CLEANUP+=("${staging}")
    else
        orb_die "Could not install Node.js to ${ORB_INSTALL_PATH}. Choose an install_path this job's user can write to without root."
    fi
    mkdir -p "${staging}/package" "${staging}/new/bin" "${staging}/new/lib"
    # -o (don't restore the archive's owner) is spelled the same in GNU tar,
    # bsdtar and BusyBox tar.
    if ! tar -xJf "${ORB_VERIFIED_FILE}" -o -C "${staging}/package" 2> "${ORB_WORK_DIR}/tar.log"; then
        orb_die "Could not unpack ${ORB_ASSET_NAME}: $(head -c 300 "${ORB_WORK_DIR}/tar.log")"
    fi
    tree="${staging}/package/node-v${ORB_VERSION}-linux-$(js_node_arch "${ORB_ARCH}")"
    if [[ -L "${tree}" || ! -d "${tree}" || ! -f "${tree}/bin/node" || -L "${tree}/bin/node" ]]; then
        orb_die "${ORB_ASSET_NAME} does not hold Node.js (node-v${ORB_VERSION}-linux-$(js_node_arch "${ORB_ARCH}")/bin/node)."
    fi
    # Releases have no suffix; an unlisted version installed with
    # known_versions may, and the header only has the numbers.
    version=$(js_tree_version "${tree}")
    if [[ "${version}" != "${ORB_VERSION%%-*}" ]]; then
        orb_die "${ORB_ASSET_NAME} holds Node.js ${version:-of an unknown version}, not ${ORB_VERSION}."
    fi
    mv "${tree}" "${staging}/new/lib/node"
    # The launcher finds the installation from its own path, so it works
    # wherever install_path is, and through a symbolic link to it.
    cat > "${staging}/new/bin/js-security-node" << 'LAUNCHER'
#!/usr/bin/env bash
# Node.js for js-security-orb's commands, installed by its install command:
# runs the release's node, which is not on the PATH, so the node, npm and npx
# the job builds with stay first.
self=$(readlink -f -- "${BASH_SOURCE[0]}" 2> /dev/null || printf '%s' "${BASH_SOURCE[0]}")
root=${self%/bin/*}
exec "${root}/lib/node/bin/node" "$@"
LAUNCHER
    chmod 755 "${staging}/new/bin/js-security-node"
    # The install record, which the orb's run records include: what was
    # installed, from which archive, and how it was checked.
    printf '{"tool":"node","version":"%s","arch":"%s","asset":"%s","sha512":"%s","verify_checksums":"%s"}\n' \
        "${ORB_VERSION}" "${ORB_ARCH}" "${ORB_ASSET_NAME}" \
        "$(sha512sum "${ORB_VERIFIED_FILE}" | awk '{ print $1 }')" "${ORB_VERIFY_CHECKSUMS}" > "${staging}/new/.js-security-orb"
    orb_smoke_test "${staging}/new/bin/js-security-node"
    # The earlier installation moves into the staging directory, which the
    # EXIT trap removes, and comes back if the new one can't take its place.
    if [[ -d "${ORB_INSTALL_PATH}" ]] && ! mv "${ORB_INSTALL_PATH}" "${staging}/previous"; then
        orb_die "Could not replace ${ORB_INSTALL_PATH}. Choose an install_path this job's user can write to without root."
    fi
    if ! mv "${staging}/new" "${ORB_INSTALL_PATH}"; then
        if [[ -d "${staging}/previous" ]]; then
            mv "${staging}/previous" "${ORB_INSTALL_PATH}" || true
        fi
        orb_die "Could not install Node.js to ${ORB_INSTALL_PATH}. Choose an install_path this job's user can write to without root."
    fi
}
# <<< tool definition <<<

# >>> shared install logic >>>
# Everything from here to the end marker is identical in the install.sh of
# every juburr orb, so change it in all of them together. Tool-specific
# behavior belongs in the tool definition above.
#
# Parameters arrive as PARAM_VERSION, PARAM_VERIFY_CHECKSUMS,
# PARAM_INSTALL_PATH and PARAM_CACHING. The checksum table (sha512sums) is
# defined after this block.

orb_info() { printf '%s\n' "$*"; }
orb_warn() { printf 'WARN: %s\n' "$*" >&2; }
orb_die() {
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}

# Expands environment variables in a parameter value. The value is piped in
# on stdin: passed as an argument, a value starting with "-" would be parsed
# as a flag. Without the CircleCI CLI (local runs), the value is used as is.
orb_subst() {
    if command -v circleci > /dev/null 2>&1; then
        printf '%s' "$1" | circleci env subst
    else
        printf '%s\n' "$1"
    fi
}

# CircleCI passes boolean parameters as 1/0; local callers use true/false.
orb_bool() {
    case "$2" in
        1 | true) echo true ;;
        0 | false) echo false ;;
        *) orb_die "${1} must be true or false, not '${2}'." ;;
    esac
}

# Reads an absolute directory parameter: NAME VALUE HOME_SUBDIR. Environment
# variables and a leading ~/ are expanded, trailing slashes are removed, and
# an empty value means $HOME/HOME_SUBDIR.
orb_dir_param() {
    local value
    value=$(orb_subst "$2")
    if [[ -z "${value}" || "${value}" == \~ || "${value}" == \~/* ]]; then
        if [[ -z "${HOME:-}" ]]; then
            orb_die "HOME is not set, so ${1} has no default. Set ${1} to an absolute path."
        fi
        if [[ -z "${value}" ]]; then
            value="${HOME}/${3}"
        else
            value="${HOME}${value:1}"
        fi
    fi
    while [[ "${value}" == */ && "${value}" != "/" ]]; do
        value=${value%/}
    done
    if [[ "${value}" != /* ]]; then
        orb_die "${1} must be an absolute path, not '${value}'."
    fi
    # The directory may be added to the PATH, where ":" separates entries.
    if [[ "${value}" == *:* ]]; then
        orb_die "${1} can't contain ':', which separates PATH entries: '${value}'."
    fi
    printf '%s\n' "${value}"
}

orb_require_tools() {
    local tool package
    for tool in "$@"; do
        if ! command -v "${tool}" > /dev/null 2>&1; then
            case "${tool}" in
                tar | gzip) package=${tool} ;;
                *) package=coreutils ;;
            esac
            orb_die "Installing ${TOOL_NAME} needs '${tool}', which is not available. Install it in an earlier step," \
                "for example with 'microdnf install -y ${package}' on Red Hat UBI images."
        fi
    done
}

# Newest version in the checksum table.
orb_latest_version() {
    local key
    for key in "${!sha512sums[@]}"; do
        printf '%s\n' "${key%/*}"
    done | sort -uV | tail -n 1
}

orb_detect_arch() {
    local os machine
    os=$(uname -s)
    machine=$(uname -m)
    if [[ "${os}" != "Linux" ]]; then
        orb_die "This orb installs Linux builds of ${TOOL_NAME}, but this machine runs ${os}."
    fi
    if [[ "${TOOL_ARCHES}" == "noarch" ]]; then
        ORB_ARCH="noarch"
        orb_info "  platform:         noarch (${os} ${machine})"
        return 0
    fi
    case "${machine}" in
        x86_64 | amd64) ORB_ARCH="amd64" ;;
        aarch64 | arm64) ORB_ARCH="arm64" ;;
        *) orb_die "Unsupported CPU architecture '${machine}'. Supported: x86_64 (amd64), aarch64/arm64 (arm64)." ;;
    esac
    if [[ " ${TOOL_ARCHES} " != *" ${ORB_ARCH} "* ]]; then
        orb_die "${TOOL_NAME} is not published for ${ORB_ARCH}. Supported: ${TOOL_ARCHES}."
    fi
    orb_info "  platform:         linux/${ORB_ARCH} (uname -m: ${machine})"
}

# Decides how this install is verified, before anything is downloaded.
orb_lookup_checksum() {
    ORB_EXPECTED_SHA512=${sha512sums["${ORB_VERSION}/${ORB_ARCH}"]:-}
    if [[ -n "${ORB_EXPECTED_SHA512}" && ! "${ORB_EXPECTED_SHA512}" =~ ^[0-9a-f]{128}$ ]]; then
        orb_die "The checksum table entry for ${ORB_VERSION}/${ORB_ARCH} is malformed."
    fi
    if [[ "${ORB_VERIFY_CHECKSUMS}" == "false" ]]; then
        orb_warn "verify_checksums is false, so ${TOOL_NAME} will be installed WITHOUT checksum verification. This is not recommended."
        ORB_EXPECTED_SHA512=""
    elif [[ -z "${ORB_EXPECTED_SHA512}" ]]; then
        if [[ "${ORB_VERIFY_CHECKSUMS}" == "known_versions" ]]; then
            orb_warn "This orb has no checksum for ${TOOL_NAME} ${ORB_VERSION} (${ORB_ARCH}), and verify_checksums is known_versions."
            orb_warn "Installing an UNVERIFIED binary. Upgrade this orb, or submit a PR with the checksum."
        else
            orb_die "This orb has no checksum for ${TOOL_NAME} ${ORB_VERSION} (${ORB_ARCH}), so it cannot be verified (verify_checksums: strict)." \
                "Use a version this orb lists (the newest is $(orb_latest_version)), upgrade the orb, or opt out with verify_checksums: known_versions."
        fi
    fi
}

orb_init() {
    ORB_VERSION=$(orb_subst "${PARAM_VERSION:-}")
    ORB_VERSION=${ORB_VERSION#v}
    # The version is part of the download URL, so only release versions pass.
    if [[ ! "${ORB_VERSION}" =~ ^[0-9]+(\.[0-9]+){1,2}(-[0-9A-Za-z][0-9A-Za-z.-]*)?$ ]]; then
        orb_die "Invalid ${TOOL_NAME} version '${ORB_VERSION}'. Expected a release version such as $(orb_latest_version)."
    fi
    ORB_VERIFY_CHECKSUMS=${PARAM_VERIFY_CHECKSUMS:-strict}
    case "${ORB_VERIFY_CHECKSUMS}" in
        strict | known_versions | false) ;;
        *) orb_die "verify_checksums must be strict, known_versions or false, not '${ORB_VERIFY_CHECKSUMS}'." ;;
    esac
    ORB_INSTALL_PATH=$(orb_dir_param install_path "${PARAM_INSTALL_PATH:-}" "${TOOL_DEFAULT_INSTALL_DIR}")
    ORB_BIN_DIR=${ORB_INSTALL_PATH}
    ORB_CACHING=$(orb_bool caching "${PARAM_CACHING:-false}")

    orb_info "Installing ${TOOL_NAME} ${ORB_VERSION}"
    orb_info "  install_path:     ${ORB_INSTALL_PATH}"
    orb_info "  verify_checksums: ${ORB_VERIFY_CHECKSUMS}"
    orb_info "  caching:          ${ORB_CACHING}"
    orb_detect_arch
    orb_lookup_checksum

    ORB_ASSET_NAME=$(tool_asset_name "${ORB_VERSION}" "${ORB_ARCH}")
    ORB_ARCHIVE_MEMBER=$(tool_archive_member "${ORB_VERSION}" "${ORB_ARCH}")
    orb_require_tools mktemp
    # Only verification needs sha512sum, so the opt-out modes run without it.
    if [[ -n "${ORB_EXPECTED_SHA512}" ]]; then
        orb_require_tools sha512sum
    fi
    if [[ -n "${ORB_ARCHIVE_MEMBER}" ]]; then
        orb_require_tools tar gzip
    fi

    ORB_WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/${ORB_NAME}.XXXXXX")
    ORB_CLEANUP=("${ORB_WORK_DIR}")
    trap 'rm -rf "${ORB_CLEANUP[@]}"' EXIT

    # Restored and saved by install.yml. Files are stored by version and
    # architecture, so a cache restored for another version is never used.
    # Nothing is created here unless a verified asset is stored, so an
    # unverified install leaves nothing for save_cache to save.
    ORB_CACHE_FILE=""
    if [[ "${ORB_CACHING}" == "true" && -z "${HOME:-}" ]]; then
        orb_warn "HOME is not set, so the cache is not used."
        ORB_CACHING=false
    elif [[ "${ORB_CACHING}" == "true" ]]; then
        ORB_CACHE_FILE="${HOME}/.cache/${ORB_NAME}/${ORB_VERSION}/${ORB_ARCH}/${ORB_ASSET_NAME}"
    fi
}

# orb_download DEST URL...: downloads the first URL that works to DEST.
# Transient failures are retried with backoff; a 404 moves on to the next URL.
orb_download() {
    local dest=$1 url help option attempt rc
    local -a fetch
    shift
    if command -v curl > /dev/null 2>&1; then
        # A stalled transfer counts as a failure and is retried.
        fetch=(curl -fsSL --proto '=https' --proto-redir '=https' --retry 8 --retry-max-time 300
            --connect-timeout 30 --speed-limit 1 --speed-time 60)
        # curl added --retry-connrefused in 7.52, and lists it under --help all
        # since 7.73. The output is captured, not piped, so curl can't hit a
        # closed pipe.
        help=$({ curl --help all || curl --help; } 2>&1) || true
        if [[ "${help}" == *--retry-connrefused* ]]; then
            fetch+=(--retry-connrefused)
        fi
        fetch+=(-o)
    elif command -v wget > /dev/null 2>&1; then
        fetch=(wget -q)
        # Only the retry options this wget supports (BusyBox wget has none).
        help=$(wget --help 2>&1) || true
        for option in --tries=20 --waitretry=30 --retry-connrefused --timeout=60 --retry-on-http-error=429,500,502,503,504; do
            if [[ "${help}" == *"${option%%=*}"* ]]; then
                fetch+=("${option}")
            fi
        done
        fetch+=(-O)
    else
        orb_die "Neither curl nor wget is available. Install one of them in an earlier step."
    fi
    for url in "$@"; do
        # curl retries timeouts and HTTP 5xx itself, but not a connection
        # dropped partway through, so that gets two more attempts here. An
        # HTTP error such as a 404 (curl exit code 22) moves on to the next
        # URL. wget retries both itself.
        for attempt in 1 2 3; do
            orb_info "Downloading ${url}"
            rc=0
            "${fetch[@]}" "${dest}.partial" "${url}" || rc=$?
            if [[ "${rc}" -eq 0 ]]; then
                mv -f "${dest}.partial" "${dest}"
                return 0
            fi
            if [[ "${fetch[0]}" != "curl" || "${rc}" -eq 22 || "${attempt}" -eq 3 ]]; then
                break
            fi
            orb_warn "The download failed (curl exit code ${rc}). Retrying in $((attempt * 10)) seconds."
            sleep $((attempt * 10))
        done
        orb_warn "Could not download ${url}."
    done
    rm -f "${dest}.partial"
    return 1
}

# orb_extract ASSET MEMBER: sets ORB_VERIFIED_FILE to the file the checksum
# table describes, which is MEMBER extracted from ASSET, or ASSET itself
# when MEMBER is empty. An empty file is refused, which matters when there
# is no checksum to catch it.
orb_extract() {
    local asset=$1 member=$2 dir
    ORB_VERIFIED_FILE=${asset}
    if [[ -n "${member}" ]]; then
        dir="${ORB_WORK_DIR}/extract"
        rm -rf "${dir}"
        mkdir "${dir}"
        # -o (don't restore the archive's owner) is spelled the same in GNU
        # tar, bsdtar and BusyBox tar, even one built without long options.
        if ! tar -xzf "${asset}" -o -C "${dir}" -- "${member}" 2> "${ORB_WORK_DIR}/tar.log"; then
            orb_warn "Could not extract ${member} from ${ORB_ASSET_NAME}: $(head -c 300 "${ORB_WORK_DIR}/tar.log")"
            return 1
        fi
        ORB_VERIFIED_FILE="${dir}/${member}"
        if [[ ! -f "${ORB_VERIFIED_FILE}" || -L "${ORB_VERIFIED_FILE}" ]]; then
            orb_warn "${member} in ${ORB_ASSET_NAME} is not a regular file."
            return 1
        fi
    fi
    if [[ ! -s "${ORB_VERIFIED_FILE}" ]]; then
        orb_warn "${ORB_VERIFIED_FILE##*/} is empty."
        return 1
    fi
}

# orb_verify FILE: checks FILE against the checksum table, when verifying.
orb_verify() {
    local actual
    if [[ -z "${ORB_EXPECTED_SHA512}" ]]; then
        return 0
    fi
    actual=$(sha512sum "$1" | awk '{ print $1 }')
    orb_info "Verifying the SHA-512 checksum of ${1##*/}..."
    orb_info "  expected: ${ORB_EXPECTED_SHA512}"
    orb_info "  actual:   ${actual}"
    if [[ "${actual}" != "${ORB_EXPECTED_SHA512}" ]]; then
        orb_warn "Checksum verification failed."
        return 1
    fi
    orb_info "Checksum verification passed."
}

# orb_temp_beside FILE: sets ORB_TEMP to a new, empty file in FILE's
# directory, to be renamed over FILE, and registers it for cleanup. mktemp
# creates it exclusively, so a file planted in a shared directory isn't
# written through.
orb_temp_beside() {
    ORB_TEMP=$(mktemp "${1%/*}/.${1##*/}.XXXXXX") || return 1
    ORB_CLEANUP+=("${ORB_TEMP}")
}

# Saves a downloaded asset for save_cache. Only verified assets are kept, so
# the cache never supplies a file the checksum table didn't vouch for.
orb_store_cache() {
    if [[ "${ORB_CACHING}" != "true" ]]; then
        return 0
    fi
    if [[ -z "${ORB_EXPECTED_SHA512}" ]]; then
        orb_info "Not caching ${ORB_ASSET_NAME}, since it was not verified."
        return 0
    fi
    if mkdir -p "${ORB_CACHE_FILE%/*}" && orb_temp_beside "${ORB_CACHE_FILE}" \
        && cp "$1" "${ORB_TEMP}" && mv -f "${ORB_TEMP}" "${ORB_CACHE_FILE}"; then
        return 0
    fi
    orb_warn "Could not save ${ORB_ASSET_NAME} to ${ORB_CACHE_FILE%/*}; continuing without the cache."
}

# Fetches the release asset, from the cache when possible, and verifies it.
# Leaves the verified file in ORB_VERIFIED_FILE. A cached asset that fails
# verification is discarded and downloaded again. The cache is only read
# when there is a checksum to verify the cached asset against.
orb_fetch_verified() {
    local asset="${ORB_WORK_DIR}/${ORB_ASSET_NAME}" use_cache=${ORB_CACHING} from_cache urls
    if [[ -z "${ORB_EXPECTED_SHA512}" ]]; then
        use_cache=false
    fi
    while true; do
        from_cache=false
        rm -f "${asset}"
        if [[ "${use_cache}" == "true" && -f "${ORB_CACHE_FILE}" ]]; then
            if ! cp "${ORB_CACHE_FILE}" "${asset}"; then
                orb_warn "Could not read the cached ${ORB_ASSET_NAME}. Downloading it instead."
                use_cache=false
                continue
            fi
            orb_info "Using ${ORB_ASSET_NAME} from the cache."
            from_cache=true
        else
            mapfile -t urls < <(tool_asset_urls "${ORB_VERSION}" "${ORB_ARCH}" "${ORB_ASSET_NAME}")
            if ! orb_download "${asset}" "${urls[@]}"; then
                orb_die "Could not download ${TOOL_NAME} ${ORB_VERSION} (${ORB_ARCH}). Check that this version" \
                    "was published for ${ORB_ARCH}, or re-run the job if the download host was failing."
            fi
        fi
        if orb_extract "${asset}" "${ORB_ARCHIVE_MEMBER}" && orb_verify "${ORB_VERIFIED_FILE}"; then
            break
        fi
        if [[ "${from_cache}" == "true" ]]; then
            orb_warn "The cached ${ORB_ASSET_NAME} failed verification. Discarding it and downloading it again."
            orb_warn "CircleCI can't replace a saved cache, so later jobs will do the same until it expires." \
                "Set caching to false to skip it until then."
            # Like saving it, removing it is best-effort: a read-only cache
            # directory only means the download isn't cached.
            rm -f "${ORB_CACHE_FILE}" 2> /dev/null || true
            use_cache=false
            continue
        fi
        orb_die "The ${TOOL_NAME} ${ORB_VERSION} (${ORB_ARCH}) download was rejected and not installed."
    done
    if [[ "${from_cache}" == "false" ]]; then
        orb_store_cache "${asset}"
    fi
}

# orb_install_file SOURCE DEST: installs SOURCE as the executable DEST. The
# file is staged under DEST's name in a private directory beside DEST and run
# once (orb_smoke_test) before a single rename replaces DEST, so a binary
# that can't run here leaves an existing install in place.
orb_install_file() {
    local dir=${2%/*} name=${2##*/} staging=""
    if ! mkdir -p "${dir}"; then
        orb_die "Could not create ${dir}. Choose an install_path this job's user can write to without root."
    fi
    if [[ -d "$2" ]]; then
        orb_die "Cannot install to $2, which is a directory."
    fi
    if staging=$(mktemp -d "${dir}/.${name}.XXXXXX"); then
        ORB_CLEANUP+=("${staging}")
    fi
    if [[ -z "${staging}" ]] || ! { cp "$1" "${staging}/${name}" && chmod 0755 "${staging}/${name}"; }; then
        orb_die "Could not install ${TOOL_BINARY} to ${dir}. Choose an install_path this job's user can write to without root."
    fi
    orb_smoke_test "${staging}/${name}"
    if ! mv -f "${staging}/${name}" "$2"; then
        orb_die "Could not install ${TOOL_BINARY} to ${dir}. Choose an install_path this job's user can write to without root."
    fi
}

# The default for tools that ship a single binary.
orb_install_binary() {
    orb_fetch_verified
    orb_install_file "${ORB_VERIFIED_FILE}" "${ORB_INSTALL_PATH}/${TOOL_BINARY}"
}

# Adds DIR to the PATH of later steps, unless it is already there.
orb_export_path() {
    local found
    if [[ ":${PATH}:" == *":$1:"* ]]; then
        # Later steps see this PATH, so an earlier copy of the binary wins.
        # -ef accepts the same file reached through a symlinked directory.
        found=$(command -v "${TOOL_BINARY}" || true)
        if [[ -n "${found}" && ! "${found}" -ef "$1/${TOOL_BINARY}" ]]; then
            orb_warn "${found} comes before $1 on the PATH, so later steps will run it instead of the ${TOOL_BINARY} installed here."
        fi
        return 0
    fi
    if [[ -n "${BASH_ENV:-}" ]]; then
        # ${PATH} is expanded when BASH_ENV is sourced, not now.
        # shellcheck disable=SC2016
        printf 'export PATH=%q:"${PATH}"\n' "$1" >> "${BASH_ENV}"
        orb_info "Added $1 to the PATH for later steps."
    else
        orb_warn "$1 is not on the PATH. Add it to run ${TOOL_BINARY} by name."
    fi
}

# orb_smoke_test FILE: runs the new binary once, which catches a build that
# can't run here: one for another architecture (exit code 126), or one that
# crashes, such as with SIGILL on a CPU it doesn't support. tool_version
# needs no network, so any failure means the binary doesn't work.
orb_smoke_test() {
    local output rc=0 line
    if ! declare -F tool_version > /dev/null; then
        return 0
    fi
    output=$(tool_version "$1" 2>&1) || rc=$?
    if [[ "${rc}" -ne 0 ]]; then
        orb_die "The downloaded ${TOOL_BINARY} cannot run on this machine: asking it for its version" \
            "exited with code ${rc}. ${output}"
    fi
    orb_info "${TOOL_BINARY} reports:"
    while IFS= read -r line; do
        orb_info "  ${line}"
    done <<< "${output}"
}

orb_install_main() {
    orb_init
    if declare -F tool_install > /dev/null; then
        tool_install
    else
        orb_install_binary
    fi
    orb_export_path "${ORB_BIN_DIR}"
    orb_info "Installed ${TOOL_NAME} ${ORB_VERSION} to ${ORB_INSTALL_PATH}."
}
# <<< shared install logic <<<

# >>> checksum table >>>
# SHA-512 checksums keyed "<version>/<arch>", newest release first, where arch
# is amd64, arm64, or noarch for a release that is the same everywhere.
# tool_archive_member says which file each checksum covers.
declare -A sha512sums=(
    ["26.12.1/amd64"]="1ce0b743919b05387ee2789c3e3bd7255801b981c767bee291ba1696616731bfc60234de845b8adbf1bce378da58ca4c66ecdc0e25cd501a180950db889fa560"
    ["26.12.1/arm64"]="01684fa9ffb44f5f2505574d5c4b632ef3ff859996bb6e51478b6ff6b301156654eb52104244e82aec9c112f531cc4a9b4a797616c0ac0f87201064393ced6f4"
    ["26.12.0/amd64"]="71ed88a09c83bc5555572db0957ea95c7a3df7368f7c8a55c40fe57acecea862ee93c6eed5539127a7b89540a0b1273b911bf267510625309860431f3e99603f"
    ["26.12.0/arm64"]="1c7e917f83b5666bfb14a1e717daf09d773f58e2cebd80ef2511c54e1fb01c8a0d4e2f5b7ea3f26ab6eae2baae2344769ff3750c79022e5867b8f50dde44fe42"
    ["24.22.1/amd64"]="2232a5b537320e6aee804cd2b6e26769bb34abad9f90002559b12dc14f723c4436ccb8400dd6df4bdd12202c5d5841be711ba044265701359f203a28b620eb1c"
    ["24.22.1/arm64"]="d80682eed574946f59b132fb91b4c3132ad5b7e4e6e1453501785febcd5df08f9b85178a399185145c1e80d81d6664ea51cd2868c634dc508cb0952b16c759ce"
    ["24.22.0/amd64"]="28aaef64fa27c132b287af3129d70ca4ededf952274daa3e0720f5c852855245d4ace630ad8a4270af5e7cf8afad08f9f18ef1f102c3832997acb54457c04303"
    ["24.22.0/arm64"]="7e782021da0acdaa327a7f86df25ec36a88da98d21f044527416c1fb8583b0afd10442b04059f8f4845e1485961669c58a625c1d449e08f719305239bbfaaf76"
    ["22.23.4/amd64"]="fb72434120aec53aae61ac328bdf711bde4341208dd735a6e4d4004452e0f232ecac19b10d1c5e978c85d615b5ddd96e67f01134d9d39c89b46488415265ce48"
    ["22.23.4/arm64"]="f2fefd6781dfe26e2d881372cd28175825dd860d07b5f8e5a7e5393112e3ebb0e40f7e74ef36b01b3f5198f1bf539ff49a8fd1ba3149b1c560e4331369a65008"
    ["22.23.3/amd64"]="2328e1770768d2ed352d6434b4465cce0af280c41f5417224fbd1d81a2d6063eb4ed41938c2dec8e0dabcd38361695643796b8765c495cbf4bfefd020f81f925"
    ["22.23.3/arm64"]="f2228f44fef9ee48efd9c9d0c3bba0e78788cd931ec9b9a6ef0fbef5d2e909a711519f6b19ad325677d596f2130b6a481b05ece816c2e24d723b6d7d9220d87e"
)
# <<< checksum table <<<

orb_install_main
