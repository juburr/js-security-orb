# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an unofficial CircleCI orb, and set of GitHub Actions, that checks the dependency supply chain of JavaScript and TypeScript projects from their lockfiles alone, whatever the package manager (npm, pnpm, Yarn 1 or Berry, bun), without installing anything or running anything from `node_modules`. It installs a checksum-verified Node.js when the image has none, and wraps four checks in a Node.js helper of its own: `lock_verify` (lockfile hygiene and release age), `signatures` (npm registry signatures, Sigstore attestations and provenance policies), `audit` (the GitHub advisories npm audit uses) and `licenses` (strict SPDX policy). Code quality (ESLint, TypeScript, tests) is out of scope.

## Development Commands

```bash
# Pack the orb from source into a single file, and validate it
circleci orb pack src/ > orb.yml
circleci orb validate orb.yml

# Lint
yamllint .
shellcheck src/scripts/*.sh src/scripts/lib/*.sh actions/*.sh tests/*.sh

# Tests (offline; Node.js 22+, curl, jq, git)
for t in tests/*_test.sh; do bash "$t" || break; done

# The helper's unit tests alone, or one module's
bash tests/helper_test.sh
node --test tests/helper/audit.test.mjs

# Run one command's script with its YAML defaults (what test-deploy.yml uses for steps that must fail)
bash tests/run_command.sh audit working_dir=tests/projects/vulnerable

# Table entries for a new Node.js release (needs gpgv)
./src/scripts/install_hash.sh -v <version>
```

## Architecture

### Orb Structure (`src/`)

- `@orb.yml` - Orb metadata (version 2.1)
- `commands/` - `install`, and the checks `lock_verify`, `signatures`, `audit`, `licenses`
- `scripts/<command>.sh` - Each check's script: a header, the check that `SCRIPT_JS_SECURITY_LIB` is set, `eval`, and one `js_run <command> core [sigstore]` line
- `scripts/lib/js_security.sh` - The shell helpers (`js_subst`, `js_params`, `js_node`, `js_run`), passed to each step as `SCRIPT_JS_SECURITY_LIB`. Only defines functions and variables; no `set` line.
- `helper/*.mjs` - The Node.js helper (ESM, Node.js 22 or newer, standard library only): `core.mjs`, one module per check, and `sigstore.mjs`. Each command passes its modules to its step as `SCRIPT_JS_HELPER_<MODULE>: << include(helper/<module>.mjs) >>`.
- `examples/` - Usage examples, pinned to the orb's current version
- `../schemas/run-record.v1.json` - The run record's JSON Schema. Its URL is in every run record, so fields are only ever added within v1.
- `../actions/<command>/action.yml` - The GitHub Action for each command (see below)

### Running the helper (`js_run`)

`js_run COMMAND MODULE...`:

1. `js_params` expands environment variables in every `PARAM_` variable, in place, through `js_subst` (stdin `circleci env subst`, the value as is without the CLI), except `PARAM_OUTPUT_DIR` and `PARAM_REPORT_NAME`, which the store steps read as given.
2. `js_node` picks `js-security-node` (the install command's launcher), else `node`, and fails before anything runs when there is none, or it is older than `JS_MIN_NODE_MAJOR` (22), or it reports no version.
3. It writes each module from its `SCRIPT_JS_HELPER_<MODULE>` variable to `helper/<module>.mjs` in a `mktemp -d` work directory (one EXIT trap removes it), and runs `node helper/<command>.mjs` with `NODE_OPTIONS` and `NODE_PATH` unset and `JS_SECURITY_WORK` set to the work directory.
4. The step exits with the helper's exit code: 0 passed (or findings with `report_only`), 1 findings or no verdict, 2 a parameter that can't work, found before any network access.

Each module reaches its step as one environment variable, and Linux caps a single `NAME=value` string at 128 KiB, so every module must stay under 120,000 bytes (`tests/helper_test.sh` checks). When one grows past that, split a self-contained part into a new module and wire it everywhere modules are listed: the YAML's `SCRIPT_JS_HELPER_` variables, the script's `js_run` line, the action's arguments (`tests/wiring_test.sh` checks the first two against the imports).

### The helper (`src/helper/`)

- **`core.mjs`**: `main(command, run)` and `runCommand` (the CLI glue), `createContext` with the parameter readers (`str`, `bool`, `int`, `list`, `lines`, `choice`, `envVarName`, `patterns`; a bad value is a `UsageError`, exit 2), `isMain(import.meta.url)` (so tests can import a module without running it).
  - **Lockfiles.** `readLockfiles` finds `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock` and `bun.lock` in `working_dir`, or the paths and globs `lockfiles` names, and refuses `bun.lockb` with the command that converts it. The parsers are strict: npm v1 to v3 and shrinkwrap, pnpm 5.4, 6.0 and 9.0 (and pnpm 11's two-document form), yarn v1 (`yarn1`), Berry (`__metadata.version` 4 to 10), `bun.lock`, through a YAML-subset parser for pnpm and Berry. Anything outside the shapes the package managers write is a `LockfileError` naming the file and line (no verdict). Each package becomes an Entry: `name`, `version`, `alias`, `kind` (`registry`, `git`, `remote`, `local`, `link`, `workspace`), `source`, `sourceRecorded`, `integrity` and `integrityKind`, `dev`, `optional`, `hasInstallScript`, `license`, `deprecated`, `line`.
  - **Registries.** `registryConfig` reads `registry`, `scopes` (`@scope=URL` lines) and `@scope:registry=URL` lines of `working_dir/.npmrc` (no other line of it). `metadataRegistry(entry, registries)` decides where a package's metadata comes from: an entry without a recorded registry, or recorded from registry.npmjs.org, goes to the registry `registry` or its scope maps it to (a mirror); one recorded from `registry` or a scope's registry goes there; anything else is skipped, listed as not checked, never contacted. A 401 or 403 from another origin than `registry`'s skips its packages (`unauthorizedSkip`), since the token goes only to `registry`'s origin; from `registry`'s origin it is no verdict.
  - **HTTP.** All of it goes through curl (7.71 or newer), never Node's http: `createRegistryClient` runs `curl --parallel` with a 0600 config file in the work directory, `--proto =https` (or `=http` for loopback), `--compressed`, `--max-time timeout` and three retries, and puts the `Authorization` header (from the variable `token` names) only on requests to `registry`'s origin. Full packuments are cached with their ETags in `${XDG_CACHE_HOME:-~/.cache}/js-security-orb-registry/` (not `~/.cache/js-security-orb`, which holds the install command's Node.js releases); attestation responses are cached by name and version.
  - **Reports.** `writeReports` removes an earlier run's reports with the same `report_name` first, then writes `<report_name>.json` (`schema: js-security-orb/<command>/v1`, `outcome`: `passed`, `findings`, `findings-reported` or `error`), `<report_name>.sarif` (one run, rules by finding kind, locations in the lockfiles relative to the top of the checkout, `partialFingerprints`), `junit/<report_name>.xml` and with `run_record` `<report_name>.run-record.json`, each atomically. A finding is `{kind, rule, level, message, package, lockfile, line, details}`; level `error` findings fail the gate unless `report_only`.
- **`lock_verify.mjs`**: `no-integrity`, `weak-integrity` (SHA-1 only), `registry` (outside `allowed_registries`, whose default is `registry` and the scopes' registries; only where the lockfile records one), `git` and `git-unpinned`, `remote`, `local` (a path outside the checkout), `install-script` (the lockfile's `hasInstallScript`, else the packument version's install scripts or `gypfile`; `allow_scripts` patterns), then from the registry `too-new` (`min_release_age_days`, 7; `release_age_exclude`), `no-publish-time`, `unpublished` and `deprecated` (a finding only with `fail_on_deprecated`). `offline` skips the registry checks.
- **`signatures.mjs`** and **`sigstore.mjs`**: for each registry package, the lockfile's integrity must be the packument's `dist.integrity`, and every `dist.signatures` entry must verify, ECDSA P-256 over `name@version:integrity`, with npm's keys pinned in `sigstore.mjs` (`NPM_REGISTRY_KEYS`, each with the time it expired, checked against the version's publish time). An unknown key ID is no verdict (the orb needs an update); a missing signature from a registry that signs others is `unsigned`. Berry checksums and pnpm's `integrityTarget: tar` can't be bound to a signature: no verdict unless `allow_unbound`. Then every attestation the packument advertises is verified in `sigstore.mjs` with node:crypto against a pinned Sigstore trusted root (`TRUSTED_ROOT`): the Fulcio chain, the SCT, the Rekor entry (SET, inclusion proof, checkpoint) or RFC 3161 timestamps, the DSSE signature, and a subject equal to the integrity. The certificate's OIDs (1.3.6.1.4.1.57264.1.x) give the source repository, by URL and numeric ID, for `provenance_sources` (`id:` survives renames and transfers). Policies: `require_signatures`, `require_provenance`, `provenance_sources`, `no_downgrade` (pnpm 11.4's ranking: trusted publisher over provenance over none, against earlier versions; prereleases ignored for stable ones; `downgrade_exclude`).
- **`audit.mjs`**: `POST <registry>/-/npm/v1/security/advisories/bulk`, gzip, in batches, with every version locked and prerelease probes, only for packages from that registry (other packages' names are never sent). The server filters, but each locked version is matched locally with a strict comparator matcher that refuses ranges outside its grammar. A canary, `minimist@0.0.8`, must come back with its two advisories, or the registry doesn't serve npm's advisories and there is no verdict. `fail_on` (`low` to `critical`), `ignore` (GHSA IDs; unused ones are warned about); findings are deduplicated by name, version and GHSA.
- **`licenses.mjs`**: the license of the locked version from the packument (`license`, else the legacy `licenses` array, OR-ed), or with `offline` from an npm lockfile, parsed as a strict SPDX expression against the SPDX License List 3.29.0. `denied` and `unknown` (none, `UNLICENSED`, `SEE LICENSE IN`, not SPDX, a version the registry lacks) are findings; `clarify` sets a package's license (`name@version=`, `name=`, globs; checked before anything runs). `OR` needs one allowed side, `AND` every part, `WITH` its license.

### Install (`scripts/install.sh`, `install_hash.sh`)

`install.sh` follows the layout every juburr orb's install.sh shares: a tool definition, the shared install logic (byte-identical across the orbs; never edit it here alone), and the `sha512sums` table keyed `"<version>/<arch>"`, holding the SHA-512 of `node-v<version>-linux-<x64|arm64>.tar.xz`. `tests/install_test.sh` is the shared install contract, with this orb's tool fixture; `scripts/cache_key.sh` is shared too. The tool definition:

- **The installation.** `tool_install` unpacks the archive into a staging directory beside `install_path` (default `~/.js-security-orb`), checks that it holds `bin/node` and that `include/node/node_version.h` names the version asked for (without a prerelease suffix), moves it to `lib/node`, and writes `bin/js-security-node`, a launcher that runs that node. `bin` goes on the `PATH` and holds nothing else, so the job's own `node`, `npm` and `npx` stay first. It writes `.js-security-orb`, the install record (`{tool, version, arch, asset, sha512, verify_checksums}`), smoke-tests the launcher, then swaps the installation in. `install_path` must be missing, hold no files, or be an earlier install, which the record identifies.
- **Mirror.** `js_download_base_url` reads `download_base_url`, an https mirror of `https://nodejs.org/dist`, refusing credentials, a query or a fragment.

The table covers the newest two releases of each supported line (22, 24, 26); the default is the newest. `install_hash.sh`'s `verify_upstream` checks `SHASUMS256.txt.sig` with `gpgv` against the Node.js release keys from `nodejs/release-keys` at a pinned commit (`NODE_RELEASE_KEYS_COMMIT`), accepting only the fingerprints in `NODE_RELEASE_KEYS` (a retired key only for signatures made before its retirement date), requires the signature to be at least `NODE_MIN_RELEASE_AGE_DAYS` (7) days old, and checks both archives against the list. To add a release: run `install_hash.sh -v <version>` once it is 7 days old, paste the entries into the table, newest first, and move the default in `install.yml` and `actions/install/action.yml` (and the README's pins) when it is the newest. `tests/wiring_test.sh` requires the default to be the newest table entry. When the Node.js project adds a release key, add its fingerprint to `NODE_RELEASE_KEYS` and move `NODE_RELEASE_KEYS_COMMIT`.

### GitHub Actions (`actions/`)

Every command has a composite action of the same name in `actions/<command>/action.yml`, with inputs identical to the command's parameters (names and defaults). Each step passes inputs to the orb's script as `PARAM_*` environment variables, as the command does, and runs it with `bash "${GITHUB_ACTION_PATH}/../run_script.sh" SCRIPT SCRIPT_JS_SECURITY_LIB=<lib> SCRIPT_JS_HELPER_CORE=<core> SCRIPT_JS_HELPER_<CMD>=<module>`, with `working-directory: ${{ inputs.working_dir }}`. Inputs never appear inside a `run:` script. `install` restores and saves `actions/cache` with the command's key ingredients. The checks name their artifact `js-security-reports-<report_name>-<random>` and upload `output_dir` with `actions/upload-artifact` under `if: always()` and `store_artifacts`. Every `uses:` is pinned to a commit SHA with its version in a comment.

`actions/run_script.sh` and `tests/actions_test.sh` are identical in every juburr orb that ships actions; never edit them here alone. Keep the actions in sync with the command YAML by hand or with an equivalent generator, and quote any default a YAML 1.1 reader would take for a boolean or number. The action descriptions leave out "Environment variables are expanded", since there is no CircleCI CLI on GitHub's runners, and say "secret" where the commands say "context". `tests/actions_test.sh` checks all of this.

### Tests

- `tests/helper_test.sh`: every module under 120,000 bytes and parsing, then `node --test tests/helper/*.test.mjs`, the helper's unit tests, offline: the parsers on real lockfiles of every format (`tests/fixtures/lockfiles`), the registry client against `tests/fake_registry.mjs`, registry signatures and Sigstore bundles from recorded registry data (`tests/fixtures/signatures`, `tests/fixtures/attestations`, so real signatures verify against the pinned keys and root, and tampered copies don't), the advisory matcher, the SPDX parser, and each command through `runCommand`.
- `tests/fake_registry.mjs DIR [LOG]`: a stand-in npm registry on 127.0.0.1 serving packuments (with ETags), attestations, keys and the bulk advisory endpoint from DIR, logging every request; `_overrides.json` sets any response. Tests can import `startFakeRegistry`.
- `tests/commands_test.sh`: each command through `tests/run_command.sh` against the stand-in registry (real semver 7.5.1 data and an unsigned minimist 1.2.0): exit codes and reports, parameter expansion with and without the CircleCI CLI, the Node.js `js_node` picks, `NODE_OPTIONS` and `NODE_PATH` kept from the helper, missing modules, the work directory's removal, and a token reaching only the registry. It passes with bash 4.0, 4.3 and 5 first on the `PATH`.
- `tests/install_test.sh`: the shared install contract, with stand-in Node.js archives, then the mirror, the tree, the launcher and the install record.
- `tests/wiring_test.sh`: every parameter passed and read by the helper, the modules wired and imported alike, reports stored, run steps named, install's default the newest table entry, the schema naming every check, the README documenting every command and action.
- `tests/validate_reports.sh` (and `.py`, from openapi-orb): SARIF against the OASIS schema pinned by SHA-256, JUnit counts, run records against the schema.
- `tests/projects/clean` and `tests/projects/vulnerable`: one dependency set locked by npm, pnpm and Yarn 1 alike, which CI checks against registry.npmjs.org. `vulnerable` has lodash 4.17.15 and minimist 1.2.0 (advisories, and lodash has no provenance), core-js 3.45.1 (an install script) and caniuse-lite (CC-BY-4.0).

### CI Pipeline

- `.circleci/config.yml` - Setup workflow: `test-install`, `test-env-subst` (env subst and shell conventions), `test-commands` (`cimg/node`: the helper, command and wiring tests), `test-actions`, orb-tools lint, pack and review (`orb_name: js-security`), shellcheck.
- `.circleci/test-deploy.yml` - `install-test` (cimg/base, which has no Node.js: the table's binary, only the launcher on the `PATH`, the cache, Node.js 22), `checksum-test` (the unlisted 26.13.0 refused before downloading, `known_versions` installing it, a local HTTPS mirror serving the real release, then a changed one), `arm64-test`, `checks-test` (every check passes on the clean project's three lockfiles with the orb's Node.js, the checkout unchanged), `findings-test` (the vulnerable project with the image's Node.js: what `report_only` reports, each check failing by default through `tests/run_command.sh`, the provenance policies, a usage error). Both check jobs end with `tests/validate_reports.sh`. Publishing runs on `v*` tags.
- `.github/workflows/actions.yml` - The same with the actions on GitHub's runners: `offline-tests` (with the orb's Node.js as `node`), `install` (amd64 and arm64), `install-from-cache` (nodejs.org blocked), `install-hash`, `checks` (both architectures), `findings`.

## Linting

YAML linting uses `.yamllint` config (extends "relaxed", 200-char line limit). Shell scripts are linted with shellcheck via the CI pipeline.

Scripts pass parameter values to `circleci env subst` on stdin, as `js_subst` does. Passed as an argument, a value starting with `-` is parsed as a CLI flag. `tests/env_subst_test.sh` enforces this.

## Shell conventions

Every script in `src/scripts/` except the shared install code follows the conventions all juburr orbs share. `tests/shell_conventions_test.sh` checks the mechanical ones; it is identical in every orb, so never edit it.

- Line 1 is `#!/bin/bash` and the first command is `set -euo pipefail` (the library in `lib/` has no `set` line). No `set +o history`, never xtrace.
- Under `-u`, use `${VAR:-}` for variables that may be unset. `PARAM_*` values the command YAML always sets are read directly, so tests that run a script directly must set every one of them (`tests/run_command.sh` sets them from the YAML).
- Expand an array that can be empty as `${arr[@]+"${arr[@]}"}`, not `"${arr[@]}"`: under `-u`, bash before 4.4 treats an empty array as unset and aborts with "unbound variable", and the orb supports bash 4.0+. Bash 4.0 also treats an empty `"$@"` as unbound, so copy `"$@"` into an array only when `$#` is non-zero.
- `ERROR: ` and `WARN: ` messages go to stderr (`>&2` on every line of the message); everything else goes to stdout. Every non-zero exit prints an `ERROR:` line first, unless the failing tool already explained itself. The helper follows the same rules.
- `$BASH_ENV` exports use `printf 'export %s=%q\n'`; `eval` only runs orb code (`"${SCRIPT_JS_SECURITY_LIB}"`). Secrets never go on a command line: the registry token reaches curl in a 0600 config file, and never reaches a log or a report.
- Temporary files and directories come from `mktemp` and are removed by one EXIT trap per script.

## Naming

Command names say what they check (`lock_verify`, `signatures`, `audit`, `licenses`). Parameters that map onto a package manager's setting take its name in snake_case (`registry`, `scopes`, `include_dev`, `fail_on` for `--audit-level`, `ignore`); policies say what they allow or require (`allowed_registries`, `allow_git`, `allow_remote`, `allow_local`, `allow_scripts`, `allowed_licenses`, `require_signatures`, `require_provenance`, `provenance_sources`, `no_downgrade`, `min_release_age_days`, `clarify`). Plumbing matches the other juburr orbs: `working_dir`, `lockfiles`, `output_dir`, `report_name`, `junit`, `run_record`, `report_only`, `allow_empty`, `store_artifacts`; `token` names a variable; lists take commas, spaces or newlines.

## Verification

Before committing changes, verify work locally if tools are available on the system:
- Run `shellcheck src/scripts/*.sh src/scripts/lib/*.sh actions/*.sh tests/*.sh` and `yamllint .`
- Run every `tests/*_test.sh`, `tests/commands_test.sh` also with bash 4.0 and 4.3 first on the `PATH`
- Run `circleci orb pack src/ > orb.yml && circleci orb validate orb.yml`, and validate `.circleci/test-deploy.yml` with the packed orb spliced in under `orbs.js-security-orb`
- Run `actionlint .github/workflows/actions.yml`
- For changes to a check, run it with `tests/run_command.sh` on `tests/projects/clean` and `tests/projects/vulnerable` against registry.npmjs.org, as `test-deploy.yml` does
