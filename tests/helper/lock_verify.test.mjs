// Unit tests of src/helper/lock_verify.mjs, offline: the lockfile-only
// checks on the shared lockfile fixtures (tests/fixtures/lockfiles) and on
// projects of its own (tests/fixtures/lock_verify/projects), and the registry
// checks against two tests/fake_registry.mjs instances on 127.0.0.1, serving
// tests/fixtures/lock_verify/registry (with chosen publish times; ages are
// measured from NOW) and tests/fixtures/lock_verify/corp-registry (@corp).
// The projects' lockfiles name the registries http://127.0.0.1:4873/ and
// http://127.0.0.1:4874/, which project() replaces with the real ones.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as core from '../../src/helper/core.mjs';
import { lockVerify, label, readOptions, RULES } from '../../src/helper/lock_verify.mjs';
import { startFakeRegistry } from '../fake_registry.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const FIXTURES = path.join(HERE, '..', 'fixtures', 'lock_verify');
const LOCKS = path.join(HERE, '..', 'fixtures', 'lockfiles');
const MODULE = path.join(ROOT, 'src', 'helper', 'lock_verify.mjs');
const NPMJS = 'https://registry.npmjs.org/';
const NOW = Date.parse('2026-11-02T12:00:00.000Z');
const PLACEHOLDER_A = 'http://127.0.0.1:4873/';
const PLACEHOLDER_B = 'http://127.0.0.1:4874/';
const TOKEN = 'npm_LockVerifyTestToken0123456789';

const tmpdir = (prefix) => fs.mkdtempSync(path.join(os.tmpdir(), prefix));

let regA;
let regB;
let dirA;
let dirB;
let logA;
let logB;

before(async () => {
  const work = tmpdir('lv-registries-');
  dirA = path.join(work, 'a');
  dirB = path.join(work, 'b');
  fs.cpSync(path.join(FIXTURES, 'registry'), dirA, { recursive: true });
  fs.cpSync(path.join(FIXTURES, 'corp-registry'), dirB, { recursive: true });
  logA = path.join(work, 'a.log');
  logB = path.join(work, 'b.log');
  regA = await startFakeRegistry({ dir: dirA, log: logA });
  regB = await startFakeRegistry({ dir: dirB, log: logB });
});

after(async () => {
  await regA.close();
  await regB.close();
});

const requests = (log) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);

// Sets a registry's _overrides.json for the length of FN.
async function withOverrides(dir, overrides, fn) {
  const file = path.join(dir, '_overrides.json');
  fs.writeFileSync(file, JSON.stringify(overrides));
  try { return await fn(); } finally { fs.rmSync(file, { force: true }); }
}

// A fresh copy of the fixture projects outside any git checkout, with the
// placeholder registries replaced by the fake ones; returns project NAME.
function project(name) {
  const root = tmpdir('lv-projects-');
  fs.cpSync(path.join(FIXTURES, 'projects'), root, { recursive: true });
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else fs.writeFileSync(p, fs.readFileSync(p, 'utf8').replaceAll(PLACEHOLDER_A, regA.url).replaceAll(PLACEHOLDER_B, regB.url));
    }
  };
  walk(root);
  return path.join(root, name);
}

// Runs lock_verify in CWD with PARAMS (registry defaults to the fake one).
async function run(cwd, params = {}, { now = NOW, env = {} } = {}) {
  const out = [];
  const err = [];
  const outputDir = params.output_dir ?? tmpdir('lv-out-');
  const all = { registry: regA.url, output_dir: outputDir, ...params };
  const fullEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    XDG_CACHE_HOME: tmpdir('lv-cache-'),
    // No user npmrc unless a test gives one.
    NPM_CONFIG_USERCONFIG: path.join(tmpdir('lv-home-'), 'none', '.npmrc'),
    ...Object.fromEntries(Object.entries(all).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, String(v)])),
    ...env,
  };
  const code = await core.runCommand('lock_verify', (ctx) => lockVerify(ctx, { now }), {
    env: fullEnv, cwd, stdout: (s) => out.push(s), stderr: (s) => err.push(s),
  });
  const name = all.report_name ?? 'lock_verify';
  const read = (f) => (fs.existsSync(path.join(outputDir, f)) ? fs.readFileSync(path.join(outputDir, f), 'utf8') : null);
  const json = read(`${name}.json`);
  const sarif = read(`${name}.sarif`);
  return {
    code,
    out: out.join(''),
    err: err.join(''),
    json: json && JSON.parse(json),
    sarif: sarif && JSON.parse(sarif),
    junit: read(`junit/${name}.xml`),
    record: read(`${name}.run-record.json`) && JSON.parse(read(`${name}.run-record.json`)),
    outputDir,
  };
}

// The findings of a report as sorted "kind name" pairs, per level.
function found(json, level = 'error') {
  return json.findings.filter((f) => f.level === level).map((f) => `${f.kind} ${f.package.name}`).sort();
}
const byKind = (json, kind, name) => json.findings.find((f) => f.kind === kind && f.package.name === name);

// The 1-based line of the first line of FILE that contains NEEDLE.
function lineOfText(file, needle) {
  const i = fs.readFileSync(file, 'utf8').split('\n').findIndex((l) => l.includes(needle));
  assert.ok(i >= 0, `${needle} not in ${file}`);
  return i + 1;
}

// ---------------------------------------------------------------------------
// What the lockfiles say (offline)
// ---------------------------------------------------------------------------

describe('lockfile checks', () => {
  const HYGIENE = [
    'git git-pinned', 'git git-unpinned', 'git-unpinned git-unpinned', 'install-script git-pinned', 'install-script git-unpinned', 'install-script inside-lib', 'local outside-lib',
    'no-integrity no-integrity-pkg', 'no-integrity remote-noint', 'registry evil-pkg', 'remote remote-noint', 'remote remote-pkg',
    'weak-integrity dev-only', 'weak-integrity sha1-pkg',
  ];

  test('every lockfile-only finding, offline, without a request', async () => {
    const dir = project('hygiene');
    const before = requests(logA).length + requests(logB).length;
    const r = await run(dir, { offline: 'true', registry: NPMJS });
    assert.equal(r.code, 1);
    assert.deepEqual(found(r.json), HYGIENE);
    assert.deepEqual(found(r.json, 'warning'), ['deprecated deprecated-locked']);
    assert.equal(requests(logA).length + requests(logB).length, before, 'offline asks no registry');
    const lock = path.join(dir, 'package-lock.json');
    const f = (kind, name) => byKind(r.json, kind, name);
    assert.equal(f('registry', 'evil-pkg').message, 'evil-pkg@1.0.0 in package-lock.json comes from https://evil.example.com/npm/, which is not registry or a scopes registry, and allowed_registries is empty.');
    assert.equal(f('registry', 'evil-pkg').line, lineOfText(lock, '"node_modules/evil-pkg"'));
    assert.equal(f('no-integrity', 'no-integrity-pkg').message, 'no-integrity-pkg@1.0.0 in package-lock.json has no integrity hash, so nothing checks what is downloaded.');
    assert.match(f('weak-integrity', 'sha1-pkg').message, /^sha1-pkg@1\.0\.0 in package-lock\.json has only a SHA-1 integrity hash/);
    assert.match(f('git-unpinned', 'git-unpinned').message, /^git-unpinned@1\.0\.0 in package-lock\.json comes from git \(github:example\/git-unpinned\) without a full commit hash/);
    assert.match(f('git', 'git-pinned').message, /comes from git \(git\+ssh:\/\/git@github\.com\/example\/git-pinned\.git#0123456789abcdef0123456789abcdef01234567\), which allow_git doesn't allow\.$/);
    assert.equal(f('remote', 'remote-pkg').message, 'remote-pkg@1.0.0 in package-lock.json is a tarball from https://cdn.example.com/files/remote-pkg.tgz, which allow_remote doesn\'t allow.');
    assert.equal(f('local', 'outside-lib').message, 'outside-lib@0.1.0 in package-lock.json is a local package at ../outside-lib, outside the checkout, which allow_local doesn\'t allow.');
    assert.equal(f('install-script', 'inside-lib').message, 'inside-lib@0.1.0 in package-lock.json runs install scripts (the lockfile records hasInstallScript), which allow_scripts doesn\'t allow.');
    // A git package has no registry to describe its install scripts, so unknown is a finding.
    assert.equal(f('install-script', 'git-pinned').message, 'git-pinned@1.0.0 in package-lock.json may run install scripts: the lockfile doesn\'t say whether it runs install scripts, and no registry describes it (it comes from git+ssh://git@github.com/example/git-pinned.git#0123456789abcdef0123456789abcdef01234567), which allow_scripts doesn\'t allow.');
    assert.equal(f('deprecated', 'deprecated-locked').message, 'deprecated-locked@1.0.0 in package-lock.json is deprecated: "No longer maintained."');
    assert.equal(f('deprecated', 'deprecated-locked').details.from, 'lockfile');
    assert.match(r.out, /package-lock\.json:\d+: lock-verify\/deprecated: .*\(warning, does not fail the step\)/);
    assert.equal(r.json.summary.packages, 14, 'bundled-dep counts; the workspace does not');
    assert.deepEqual(r.json.summary.by_kind, { registry: 7, git: 2, remote: 2, local: 3 });
    assert.equal(r.json.summary.registry_checked, 0);
    assert.equal(r.json.summary.install_scripts_unknown, 2, 'the git packages');
    assert.match(r.json.summary.notes.join('\n'), /^offline is true, so no registry was asked about 6 registry packages/m);
    assert.match(r.out, /^Note: offline is true/m);
    assert.ok(!r.json.findings.some((f2) => f2.package.name === 'bundled-dep' || f2.package.name === 'clean-pkg'), 'a bundled dependency has no integrity of its own');
  });

  test('allow_git, allow_remote, allow_local, allow_scripts and allowed_registries', async () => {
    const dir = project('hygiene');
    const base = { offline: 'true', registry: NPMJS };
    const all = await run(dir, {
      ...base, allow_git: '*', allow_remote: 'remote-*', allow_local: 'outside-lib', allow_scripts: 'inside-lib@0.1.0 git-*',
      allowed_registries: 'https://registry.npmjs.org\nhttps://evil.example.com/npm',
    });
    assert.equal(all.code, 1);
    assert.deepEqual(found(all.json), ['git-unpinned git-unpinned', 'no-integrity no-integrity-pkg', 'no-integrity remote-noint', 'weak-integrity dev-only', 'weak-integrity sha1-pkg']);
    assert.deepEqual(all.json.summary.allowed_registries, [NPMJS, 'https://evil.example.com/npm/']);

    const some = await run(dir, { ...base, allow_git: 'git-pinned', allow_scripts: 'inside-lib@0.2.0', allowed_registries: 'https://evil.example.com/np, https://registry.npmjs.org' });
    assert.ok(found(some.json).includes('git git-unpinned') && !found(some.json).includes('git git-pinned'));
    assert.ok(found(some.json).includes('install-script inside-lib'), 'name@version allows only that version');
    assert.ok(found(some.json).includes('registry evil-pkg'), 'a prefix matches whole path segments');
    assert.match(byKind(some.json, 'registry', 'evil-pkg').message, /which allowed_registries doesn't allow\.$/);

    const origin = await run(dir, { ...base, allowed_registries: 'https://EVIL.example.com https://registry.yarnpkg.com/' });
    assert.ok(!found(origin.json).some((p) => p.startsWith('registry ')), 'an origin allows the whole host; yarnpkg is npmjs');
  });

  test('include_dev false leaves out development packages', async () => {
    const r = await run(project('hygiene'), { offline: 'true', registry: NPMJS, include_dev: 'false' });
    assert.ok(!found(r.json).includes('weak-integrity dev-only'));
    assert.ok(found(r.json).includes('weak-integrity sha1-pkg'));
    assert.equal(r.json.summary.packages, 13);
  });

  test('a path inside the checkout that links outside it is outside', async () => {
    const dir = project('hygiene');
    fs.symlinkSync('../outside-lib', path.join(dir, 'sneaky-lib'));
    const r = await run(dir, { offline: 'true', registry: NPMJS });
    assert.ok(found(r.json).includes('local sneaky-lib'));
    assert.equal(byKind(r.json, 'local', 'sneaky-lib').details.path, 'sneaky-lib');
    const allowed = await run(dir, { offline: 'true', registry: NPMJS, allow_local: 'outside-lib sneaky-*' });
    assert.ok(!found(allowed.json).some((p) => p.startsWith('local ')));
  });

  test('pnpm: a workspace outside the checkout, and integrityTarget tar', async () => {
    const dir = project('pnpm-tar');
    const r = await run(dir, { offline: 'true', registry: NPMJS });
    assert.equal(r.code, 1);
    assert.deepEqual(found(r.json), ['local shared-ws']);
    assert.equal(byKind(r.json, 'local', 'shared-ws').message, 'shared-ws@1.0.0 in pnpm-lock.yaml is a workspace at ../shared, outside the checkout, which allow_local doesn\'t allow.');
    assert.match(r.json.summary.notes[0], /^pnpm-lock\.yaml: pnpm's integrityTarget: tar hashes the unpacked tarball/);
    const allowed = await run(dir, { offline: 'true', registry: NPMJS, allow_local: 'shared-ws' });
    assert.equal(allowed.code, 0);
    assert.match(allowed.out, /^Passed: lock_verify found nothing\./m);
  });

  // The shared lockfiles of every format, in the orb's checkout, where their
  // file: and link: packages are inside it.
  const SHARED = [
    ['npm/v3', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is', 'install-script esbuild', 'install-script local-lib'], ['deprecated uuid']],
    ['npm/v1', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is'], []],
    ['pnpm/v9.0', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is'], ['deprecated uuid']],
    ['pnpm/v6.0', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is'], ['deprecated uuid']],
    ['yarn1', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is', 'weak-integrity ms'], []],
    ['berry/v10', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is'], []],
    ['bun/text', {}, ['git @sindresorhus/is', 'install-script @sindresorhus/is'], []],
    ['edge/sha1-only/npm', { allowed_registries: 'http://127.0.0.1:47616' }, ['weak-integrity kind-of'], []],
    ['edge/sha1-only/pnpm', {}, ['weak-integrity kind-of'], []],
    ['edge/sha1-only/bun', { allowed_registries: 'http://127.0.0.1:47616' }, ['weak-integrity kind-of'], []],
    ['edge/sha1-only/yarn1', {}, ['registry kind-of', 'weak-integrity kind-of'], []],
    ['edge/sha1-only/berry', {}, [], []],
    ['edge/tarball/pnpm', {}, ['install-script ms', 'remote ms'], []],
    ['edge/tarball/yarn1', { allowed_registries: 'https://registry.npmjs.org/ http://127.0.0.1:47614/' }, ['weak-integrity ms'], []],
  ];
  for (const [dir, params, errors, warnings] of SHARED) {
    test(`shared fixture ${dir}`, async () => {
      const r = await run(path.join(LOCKS, dir), { offline: 'true', registry: NPMJS, ...params });
      assert.deepEqual(found(r.json), errors);
      assert.deepEqual(found(r.json, 'warning'), warnings);
      assert.equal(r.code, errors.length ? 1 : 0);
    });
  }

  test('Yarn Berry: no checksum is a finding, except for packages with platform conditions', async () => {
    const r = await run(path.join(LOCKS, 'berry', 'v10'), { offline: 'true', registry: NPMJS });
    assert.equal(r.json.summary.conditional_without_checksum, 25);
    assert.match(r.json.summary.notes.join('\n'), /yarn\.lock: Yarn Berry records checksums of Yarn's own archives/);
    assert.match(r.json.summary.notes.join('\n'), /yarn\.lock: 25 packages with platform conditions \(@esbuild\/aix-ppc64, .* and 20 more\) have no checksum/);
    const dir = tmpdir('lv-berry-');
    const text = fs.readFileSync(path.join(LOCKS, 'berry', 'v10', 'yarn.lock'), 'utf8');
    const stripped = text.replace(/("lodash@npm:4\.17\.21":\n(?: {2}.*\n)*?) {2}checksum: .*\n/, '$1');
    assert.notEqual(stripped, text);
    fs.writeFileSync(path.join(dir, 'yarn.lock'), stripped);
    const s = await run(dir, { offline: 'true', registry: NPMJS, allow_git: '*', allow_scripts: '@sindresorhus/is' });
    assert.deepEqual(found(s.json), ['no-integrity lodash']);
  });
});

// ---------------------------------------------------------------------------
// What the registries say
// ---------------------------------------------------------------------------

describe('registry checks', () => {
  const REGISTRY_NPM = [
    'install-script gyp-pkg', 'install-script locked-script-pkg', 'install-script scripts-pkg',
    'no-publish-time badtime-pkg', 'no-publish-time notime-pkg',
    'too-new fresh-pkg', 'too-new future-pkg', 'too-new hours-pkg',
    'unpublished gone-pkg', 'unpublished removed-pkg', 'unpublished unpub-pkg',
  ];

  test('npm: every registry finding, each package asked of its own registry', async () => {
    const dir = project('registry-npm');
    const [a0, b0] = [requests(logA).length, requests(logB).length];
    // .npmrc routes @corp, and the scopes parameter allows the registry it names.
    const r = await run(dir, { run_record: 'true', scopes: `@corp=${regB.url}` });
    assert.equal(r.code, 1);
    assert.deepEqual(found(r.json), REGISTRY_NPM);
    assert.deepEqual(found(r.json, 'warning'), ['deprecated deprecated-pkg'], 'one finding for two install paths; undeprecated-pkg is no longer deprecated');
    const asked = requests(logA).slice(a0).map((q) => q.path).sort();
    assert.deepEqual(asked, ['/badtime-pkg', '/deprecated-pkg', '/fresh-pkg', '/future-pkg', '/gone-pkg', '/gyp-pkg', '/hours-pkg', '/locked-script-pkg',
      '/notime-pkg', '/old-pkg', '/removed-pkg', '/scripts-pkg', '/undeprecated-pkg', '/unpub-pkg']);
    assert.deepEqual(requests(logB).slice(b0).map((q) => q.path), ['/@corp%2Fprivate']);
    for (const q of [...requests(logA).slice(a0), ...requests(logB).slice(b0)]) {
      assert.equal(q.headers.accept, 'application/json');
      assert.equal(q.headers.authorization, undefined, 'no token was given');
    }

    const msg = (kind, name) => byKind(r.json, kind, name).message;
    assert.equal(msg('too-new', 'fresh-pkg'), 'fresh-pkg@2.0.0 in package-lock.json was published 3 days ago (2026-10-30T06:00:00.000Z); min_release_age_days is 7.');
    assert.equal(msg('too-new', 'hours-pkg'), 'hours-pkg@1.0.0 in package-lock.json was published 5 hours ago (2026-11-02T07:00:00.000Z); min_release_age_days is 7.');
    assert.equal(msg('too-new', 'future-pkg'), `future-pkg@1.0.0 in package-lock.json has a publish time in the future (2026-12-01T00:00:00.000Z) on ${regA.url}.`);
    assert.equal(msg('no-publish-time', 'notime-pkg'), `notime-pkg@1.0.0 in package-lock.json has no publish time on ${regA.url}, so its age can't be checked against min_release_age_days (7).`);
    assert.match(msg('no-publish-time', 'badtime-pkg'), /has an unreadable publish time "last Tuesday" on /);
    assert.equal(msg('unpublished', 'gone-pkg'), `gone-pkg@1.0.0 in package-lock.json is not on ${regA.url} (HTTP 404): it was unpublished, or never published there (a private registry also answers 404 without credentials).`);
    assert.equal(msg('unpublished', 'unpub-pkg'), `unpub-pkg@1.0.1 in package-lock.json is not on ${regA.url}: the version, published 2026-09-30T00:00:00.000Z, was unpublished.`);
    assert.equal(msg('unpublished', 'removed-pkg'), `removed-pkg@1.0.0 in package-lock.json is not on ${regA.url}: the package was unpublished (2026-10-01T00:00:00.000Z).`);
    assert.equal(msg('install-script', 'scripts-pkg'), 'scripts-pkg@1.0.0 in package-lock.json runs install scripts (postinstall), which allow_scripts doesn\'t allow.');
    assert.equal(msg('install-script', 'gyp-pkg'), 'gyp-pkg@1.0.0 in package-lock.json runs install scripts (install), which allow_scripts doesn\'t allow.');
    assert.equal(msg('install-script', 'locked-script-pkg'), 'locked-script-pkg@1.0.0 in package-lock.json runs install scripts (the lockfile records hasInstallScript), which allow_scripts doesn\'t allow.');
    assert.equal(msg('deprecated', 'deprecated-pkg'), 'deprecated-pkg@1.0.0 in package-lock.json is deprecated: "Use new-pkg instead."');
    const fresh = byKind(r.json, 'too-new', 'fresh-pkg');
    assert.deepEqual(fresh.details, { registry: regA.url, published: '2026-10-30T06:00:00.000Z', age_hours: 78, min_release_age_days: 7 });
    assert.deepEqual(byKind(r.json, 'install-script', 'scripts-pkg').details, { scripts: { postinstall: 'node setup.js' }, lockfile_has_install_script: false, registry: regA.url });
    assert.equal(byKind(r.json, 'deprecated', 'deprecated-pkg').details.from, 'registry');

    // The JSON report
    assert.equal(r.json.schema, 'js-security-orb/lock_verify/v1');
    assert.equal(r.json.outcome, 'findings');
    assert.deepEqual([r.json.summary.packages, r.json.summary.registry_packages, r.json.summary.registry_checked, r.json.summary.skipped], [16, 15, 15, 0]);
    assert.deepEqual(r.json.skipped, []);
    assert.deepEqual(r.json.errors, []);
    assert.equal(r.json.summary.min_release_age_days, 7);
    assert.deepEqual(r.json.summary.allowed_registries, [regA.url, regB.url]);
    const lock = path.join(dir, 'package-lock.json');
    assert.equal(fresh.line, lineOfText(lock, '"node_modules/fresh-pkg"'));
    assert.equal(fresh.lockfile, 'package-lock.json');
    assert.deepEqual(fresh.package, { name: 'fresh-pkg', version: '2.0.0' });

    // SARIF: rules with descriptions, results at the entries' lines
    const run0 = r.sarif.runs[0];
    assert.equal(run0.tool.driver.name, 'js-security-orb lock_verify');
    const rules = Object.fromEntries(run0.tool.driver.rules.map((x) => [x.id, x.shortDescription.text]));
    for (const id of ['lock-verify/too-new', 'lock-verify/no-publish-time', 'lock-verify/unpublished', 'lock-verify/install-script', 'lock-verify/deprecated']) {
      assert.equal(rules[id], RULES[id].description, id);
    }
    assert.equal(run0.results.length, 12);
    const res = run0.results.find((x) => x.ruleId === 'lock-verify/too-new' && x.message.text.startsWith('fresh-pkg'));
    assert.deepEqual(res.locations[0].physicalLocation, { artifactLocation: { uri: 'package-lock.json' }, region: { startLine: fresh.line } });
    assert.equal(res.level, 'error');
    assert.equal(run0.results.find((x) => x.ruleId === 'lock-verify/deprecated').level, 'warning');
    assert.ok(run0.results.every((x) => x.partialFingerprints.primaryLocationLineHash));

    // JUnit: a failure per failing finding, the warning skipped
    assert.match(r.junit, /tests="12" failures="11" errors="0" skipped="1"/);
    assert.match(r.junit, /<failure message="fresh-pkg@2\.0\.0 in package-lock\.json was published 3 days ago/);

    // The run record
    assert.equal(r.record.command, 'lock_verify');
    assert.equal(r.record.exit_code, 1);
    assert.equal(r.record.counts.registry_checked, 15);
    assert.equal(r.record.parameters.min_release_age_days, '7', 'not set, so the default');
    assert.deepEqual(r.record.inputs.map((i) => i.role), ['lockfile', 'npmrc']);
  });

  test('min_release_age_days 0, release_age_exclude and include_dev', async () => {
    const dir = project('registry-npm');
    const off = await run(dir, { min_release_age_days: '0' });
    assert.ok(!found(off.json).some((p) => /^(?:too-new|no-publish-time) /.test(p)));
    assert.ok(found(off.json).includes('unpublished gone-pkg'));

    const ex = await run(dir, { release_age_exclude: 'fresh-pkg, hours-*\nfuture-pkg@1.0.0 notime-pkg@9.9.9' });
    assert.deepEqual(found(ex.json).filter((p) => /^(?:too-new|no-publish-time) /.test(p)), ['no-publish-time badtime-pkg', 'no-publish-time notime-pkg']);

    const prod = await run(dir, { include_dev: 'false' });
    assert.ok(!found(prod.json).includes('too-new fresh-pkg'), 'fresh-pkg is a development package');
    assert.equal(prod.json.summary.registry_packages, 14);
  });

  test('allow_scripts, fail_on_deprecated and report_only', async () => {
    const dir = project('registry-npm');
    const scripts = await run(dir, { allow_scripts: 'gyp-pkg locked-script-pkg@1.0.0 scripts-*' });
    assert.ok(!found(scripts.json).some((p) => p.startsWith('install-script ')));
    const star = await run(dir, { allow_scripts: '*' });
    assert.ok(!found(star.json).some((p) => p.startsWith('install-script ')));

    const dep = await run(dir, { fail_on_deprecated: 'true' });
    assert.ok(found(dep.json).includes('deprecated deprecated-pkg'));
    assert.deepEqual(found(dep.json, 'warning'), []);

    const ro = await run(dir, { report_only: 'true', scopes: `@corp=${regB.url}` });
    assert.equal(ro.code, 0);
    assert.equal(ro.json.outcome, 'findings-reported');
    assert.match(ro.err, /^WARN: 11 findings of lock_verify fail the gate\.$/m);
    assert.match(ro.err, /^WARN: report_only is true, so this step passes\./m);
  });

  test('the token goes only to registry\'s origin, and never into a report', async () => {
    const dir = project('registry-npm');
    const [a0, b0] = [requests(logA).length, requests(logB).length];
    const r = await run(dir, { token: 'LV_TEST_TOKEN', run_record: 'true' }, { env: { LV_TEST_TOKEN: TOKEN } });
    assert.equal(r.code, 1);
    const a = requests(logA).slice(a0);
    const b = requests(logB).slice(b0);
    assert.ok(a.length > 0 && b.length > 0);
    for (const q of a) assert.equal(q.headers.authorization, `Bearer ${TOKEN}`, q.path);
    for (const q of b) assert.equal(q.headers.authorization, undefined, q.path);
    assert.ok(!byKind(r.json, 'unpublished', 'gone-pkg').message.includes('private registry'), 'the registry got the token');
    const everything = r.out + r.err + JSON.stringify(r.json) + JSON.stringify(r.sarif) + r.junit + JSON.stringify(r.record);
    assert.ok(!everything.includes(TOKEN));
    assert.equal(r.record.registry.token_variable, 'LV_TEST_TOKEN');
  });

  test('pnpm: sources from the scopes mapping; offline, the lockfile\'s deprecations', async () => {
    const dir = project('registry-pnpm');
    const [a0, b0] = [requests(logA).length, requests(logB).length];
    const r = await run(dir, {});
    assert.equal(r.code, 1);
    assert.deepEqual(found(r.json), ['install-script scripts-pkg', 'too-new fresh-pkg']);
    assert.deepEqual(found(r.json, 'warning'), ['deprecated deprecated-pkg']);
    assert.deepEqual(requests(logA).slice(a0).map((q) => q.path).sort(), ['/deprecated-pkg', '/fresh-pkg', '/old-pkg', '/scripts-pkg']);
    assert.deepEqual(requests(logB).slice(b0).map((q) => q.path), ['/@corp%2Fprivate']);
    assert.equal(r.json.summary.install_scripts_unknown, 0);

    const off = await run(dir, { offline: 'true' });
    assert.equal(off.code, 0);
    assert.deepEqual(found(off.json, 'warning'), ['deprecated deprecated-pkg']);
    assert.equal(byKind(off.json, 'deprecated', 'deprecated-pkg').details.from, 'lockfile');
    assert.equal(off.json.summary.install_scripts_unknown, 5);

    const prod = await run(dir, { include_dev: 'false' });
    assert.match(prod.err, /^WARN: pnpm-lock\.yaml: pnpm lockfiles don't record which packages are only for development, so include_dev: false keeps all 5 packages\.$/m);
  });

  test('packages recorded on registry.npmjs.org are asked of registry; other registries are skipped', async () => {
    const dir = project('mirror');
    const [a0, b0] = [requests(logA).length, requests(logB).length];
    const r = await run(dir, { allowed_registries: 'https://registry.npmjs.org https://npm.elsewhere.example' });
    assert.equal(r.code, 0);
    assert.deepEqual(r.json.findings, []);
    assert.deepEqual(requests(logA).slice(a0).map((q) => q.path), ['/old-pkg']);
    assert.deepEqual(requests(logB).slice(b0).map((q) => q.path), ['/@corp%2Fprivate'], 'the scope\'s registry');
    const reason = 'the lockfile records https://npm.elsewhere.example/, which is neither registry nor a scope\'s registry (scopes, .npmrc or .yarnrc.yml)';
    assert.deepEqual(r.json.skipped, [{
      name: 'elsewhere-pkg', version: '1.0.0', kind: 'registry', lockfile: 'package-lock.json',
      line: lineOfText(path.join(dir, 'package-lock.json'), '"node_modules/elsewhere-pkg"'), source: 'https://npm.elsewhere.example/', reason,
    }]);
    assert.ok(r.err.includes(`WARN: 1 package was not checked against a registry, since ${reason}: elsewhere-pkg@1.0.0. It is listed under skipped in the report.\n`), r.err);
    assert.deepEqual([r.json.summary.registry_checked, r.json.summary.skipped], [2, 1]);

    // By default, registry.npmjs.org is allowed where npm installs from registry (or a
    // scope's registry the job names) in its place, so only the other registry is a finding.
    const strict = await run(dir, { scopes: `@corp=${regB.url}` });
    assert.deepEqual(found(strict.json), ['registry elsewhere-pkg']);
    // A scope registry only the checkout's .npmrc names routes lookups but allows nothing.
    const npmrcOnly = await run(dir, {});
    assert.deepEqual(found(npmrcOnly.json), ['registry @corp/private', 'registry elsewhere-pkg']);
    // An explicit allowed_registries is the whole list: registry.npmjs.org stands for nothing.
    const only = await run(dir, { allowed_registries: regA.url, scopes: `@corp=${regB.url}` });
    assert.deepEqual(found(only.json), ['registry @corp/private', 'registry elsewhere-pkg', 'registry old-pkg']);
  });

  test('a scopes registry that wants credentials is skipped; nothing checked is an error unless allow_empty', async () => {
    const dir = project('corp-only');
    const overrides = { 'GET /@corp%2Fprivate': { status: 401, body: { error: 'unauthorized' } }, 'GET /@corp%2Ffresh': { status: 403, body: { error: 'forbidden' } } };
    await withOverrides(dirB, overrides, async () => {
      const r = await run(dir, { scopes: `@corp=${regB.url}` });
      assert.equal(r.code, 1);
      assert.equal(r.json.outcome, 'error');
      assert.equal(r.json.skipped.length, 2);
      assert.match(r.err, /^WARN: 1 package was not checked against a registry, since http:\/\/127\.0\.0\.1:\d+\/ answered HTTP 401, and the token goes only to registry's origin: @corp\/private@1\.0\.0\. It is listed under skipped in the report\.$/m);
      assert.deepEqual(r.json.skipped.map((s) => [s.name, s.reason.replace(/\d+\//, 'PORT/')]).sort(), [
        ['@corp/fresh', 'http://127.0.0.1:PORT/ answered HTTP 403, and the token goes only to registry\'s origin'],
        ['@corp/private', 'http://127.0.0.1:PORT/ answered HTTP 401, and the token goes only to registry\'s origin'],
      ]);
      assert.match(r.err, /^ERROR: None of the 2 registry packages could be checked against a registry \(see the warnings\)\./m);
      const empty = await run(dir, { allow_empty: 'true', scopes: `@corp=${regB.url}` });
      assert.equal(empty.code, 0);
      assert.equal(empty.json.summary.registry_checked, 0);
    });
    const ok = await run(dir, { scopes: `@corp=${regB.url}` });
    assert.deepEqual(found(ok.json), ['too-new @corp/fresh']);
  });

  test('a registry that fails is no verdict, whatever report_only says', async () => {
    const dir = project('flaky');
    // Without retries, so the 5xx doesn't wait for curl's backoff (1, 2 and 4 seconds).
    await withOverrides(dirA, { 'GET /flaky-pkg': { status: 500, body: 'down' } }, async () => {
      const r = await run(dir, { report_only: 'true' }, { env: { JS_SECURITY_TEST_RETRIES: '0' } });
      assert.equal(r.code, 1);
      assert.equal(r.json.outcome, 'error');
      assert.equal(r.json.errors[0].message, `Could not read the packument of 1 package from ${regA.url} (HTTP 500): flaky-pkg.`);
      assert.match(r.err, /^ERROR: There is no verdict, so this step fails whatever report_only says\./m);
      assert.match(r.junit, /<error message="Could not read the packument of 1 package/);
      assert.match(r.out, /^Checked .* against a registry\. The check is incomplete \(see the errors\), so it has no verdict\.$/m);
    });
    await withOverrides(dirA, { 'GET /flaky-pkg': { status: 200, body: '"not a packument"' } }, async () => {
      const r = await run(dir, {});
      assert.equal(r.code, 1);
      assert.match(r.err, /^ERROR: Could not read the packument of 1 package from .* \(the answer is not a JSON object\): flaky-pkg\.$/m);
    });
    await withOverrides(dirA, { 'GET /flaky-pkg': { status: 401, body: 'no' } }, async () => {
      const r = await run(dir, {});
      assert.match(r.err, /\(HTTP 401\): flaky-pkg\. If the registry needs a login, set token to the name of a variable holding a token for it\.$/m);
      const t = await run(dir, { token: 'LV_TEST_TOKEN' }, { env: { LV_TEST_TOKEN: TOKEN } });
      assert.match(t.err, /\(HTTP 401\): flaky-pkg\. Check the token in LV_TEST_TOKEN\.$/m);
    });
    const ok = await run(dir, {});
    assert.equal(ok.code, 0);
  });
});

// ---------------------------------------------------------------------------
// Parameters, empty checks and the program
// ---------------------------------------------------------------------------

describe('parameters and exit codes', () => {
  test('a bad parameter exits 2 before any request', async () => {
    const dir = project('registry-npm');
    const bad = [
      [{ min_release_age_days: '-1' }, /^ERROR: min_release_age_days must be a whole number from 0 to 36500, not "-1"\.$/m],
      [{ min_release_age_days: 'seven' }, /min_release_age_days must be a whole number/],
      [{ allowed_registries: 'ftp://npm.example.com/' }, /^ERROR: allowed_registries must be an https URL/m],
      [{ allowed_registries: 'http://npm.example.com/' }, /allowed_registries must be an https URL \(http only to localhost/],
      [{ allowed_registries: 'https://user:secret@npm.example.com/' }, /allowed_registries must not hold credentials/],
      [{ allowed_registries: 'https://npm.example.com/?x=1' }, /allowed_registries must not have a query or a fragment/],
      [{ allow_git: 'true' }, /^ERROR: allow_git takes package names or patterns, such as @scope\/\* or \* for every package, not "true"\.$/m],
      [{ allow_remote: 'FALSE' }, /allow_remote takes package names or patterns/],
      [{ allow_local: 'some-lib@1.0.0' }, /allow_local takes package names, without versions/],
      [{ allow_scripts: 'not a name!' }, /allow_scripts: "not" is not a package name|allow_scripts: "name!" is not a package name/],
      [{ release_age_exclude: 'pkg@' }, /release_age_exclude: a malformed version/],
      [{ fail_on_deprecated: 'maybe' }, /^ERROR: fail_on_deprecated must be true or false/m],
      [{ offline: 'yes' }, /^ERROR: offline must be true or false/m],
    ];
    const before = requests(logA).length + requests(logB).length;
    for (const [params, re] of bad) {
      const r = await run(dir, params);
      assert.equal(r.code, 2, JSON.stringify(params));
      assert.match(r.err, re, JSON.stringify(params));
      assert.equal(r.json, null, 'no report');
    }
    assert.equal(requests(logA).length + requests(logB).length, before, 'no request reached a registry');
  });

  test('defaults: allowed_registries is registry and the scopes registries', () => {
    const env = { NPM_CONFIG_USERCONFIG: '/nonexistent/.npmrc', PARAM_OUTPUT_DIR: tmpdir('lv-out-'), PARAM_SCOPES: '@corp=https://npm.corp.example/npm/' };
    const ctx = core.createContext('lock_verify', { env, cwd: tmpdir('lv-empty-') });
    const o = readOptions(ctx);
    assert.deepEqual(o.allowedRegistries, [NPMJS, 'https://npm.corp.example/npm/']);
    assert.equal(o.allowedExplicit, false);
    assert.deepEqual([o.minReleaseAgeDays, o.failOnDeprecated, o.offline, o.allowScripts.length], [7, false, false, 0]);
  });

  test('a check of nothing fails unless allow_empty', async () => {
    const ws = project('workspaces-only');
    const r = await run(ws, {});
    assert.equal(r.code, 1);
    assert.match(r.err, /checked nothing/);
    assert.equal((await run(ws, { allow_empty: 'true' })).code, 0);
    const none = await run(tmpdir('lv-nolock-'), {});
    assert.equal(none.code, 1);
    assert.match(none.err, /^ERROR: No lockfile in /m);
    assert.equal((await run(tmpdir('lv-nolock-'), { allow_empty: 'true' })).code, 0);
  });

  test('label', () => {
    assert.equal(label({ name: 'lodash', version: '4.17.20', alias: 'lodash-old' }), 'lodash@4.17.20 (as lodash-old)');
    assert.equal(label({ name: '@sindresorhus/is', version: null, alias: null }), '@sindresorhus/is');
  });

  // Runs the module as the step does: node lock_verify.mjs, beside core.mjs.
  const program = (cwd, params) => new Promise((resolve) => {
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, NPM_CONFIG_USERCONFIG: '/nonexistent/.npmrc', XDG_CACHE_HOME: tmpdir('lv-cache-'), PARAM_OUTPUT_DIR: tmpdir('lv-out-') };
    for (const [k, v] of Object.entries(params)) env[`PARAM_${k.toUpperCase()}`] = v;
    const child = spawn(process.execPath, [MODULE], { cwd, env, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => resolve({ code, out, err }));
  });

  test('the module runs as a program, with the helper\'s exit codes', async () => {
    const dir = project('hygiene');
    const r = await program(dir, { offline: 'true', registry: NPMJS });
    assert.equal(r.code, 1);
    assert.match(r.out, /^ {2}package-lock\.json:\d+: lock-verify\/registry: evil-pkg@1\.0\.0 in package-lock\.json comes from/m);
    assert.match(r.err, /^ERROR: 14 findings of lock_verify fail the gate\.$/m);
    const usage = await program(dir, { offline: 'true', min_release_age_days: 'x' });
    assert.equal(usage.code, 2);
    const pass = await program(project('workspaces-only'), { offline: 'true', allow_empty: 'true' });
    assert.equal(pass.code, 0);
    assert.match(pass.out, /^Passed: lock_verify found nothing\./m);
  });
});

// ---------------------------------------------------------------------------
// Regressions from review
// ---------------------------------------------------------------------------

describe('what the checkout can\'t allow, and what can\'t hide', () => {
  test('a scope registry only the checkout\'s .npmrc names allows nothing; the user\'s npmrc is the job\'s', async () => {
    const dir = project('mirror');
    const r = await run(dir, {});
    assert.equal(byKind(r.json, 'registry', '@corp/private').message,
      `@corp/private@1.0.0 in package-lock.json comes from ${NPMJS}, which is not registry or a scopes registry, and allowed_registries is empty.`);
    assert.deepEqual(r.json.summary.allowed_registries, [regA.url]);
    // Recorded from the .npmrc's own registry: the message names the file.
    const corp = await run(project('corp-only'), { offline: 'true' });
    assert.equal(byKind(corp.json, 'registry', '@corp/private').message,
      `@corp/private@1.0.0 in package-lock.json comes from ${regB.url}, which only .npmrc line 1 (for @corp) names: the change under test can edit that file, so a registry it names is not allowed unless scopes or allowed_registries lists it.`);
    // The same line in the user's npmrc, which the job sets, allows it.
    const user = path.join(tmpdir('lv-user-'), 'npmrc');
    fs.writeFileSync(user, `@corp:registry=${regB.url}\n`);
    const trusted = await run(project('corp-only'), { offline: 'true' }, { env: { NPM_CONFIG_USERCONFIG: user } });
    assert.ok(!found(trusted.json).some((p) => p.startsWith('registry ')), JSON.stringify(found(trusted.json)));
    assert.deepEqual(trusted.json.summary.allowed_registries, [regA.url, regB.url]);
  });

  test('a lockfile source that is another scope\'s registry is a registry finding', async () => {
    const dir = tmpdir('lv-t5-');
    fs.writeFileSync(path.join(dir, '.npmrc'), '@unrelated:registry=https://attacker.example/\n');
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: { '': { name: 't5' }, 'node_modules/lodash': { version: '4.17.21', resolved: 'https://attacker.example/lodash/-/lodash-4.17.21.tgz', integrity: `sha512-${Buffer.alloc(64, 9).toString('base64')}` } },
    }));
    const r = await run(dir, { offline: 'true', registry: NPMJS });
    assert.equal(r.code, 1);
    assert.deepEqual(found(r.json), ['registry lodash']);
    assert.match(byKind(r.json, 'registry', 'lodash').message, /comes from https:\/\/attacker\.example\/, which only \.npmrc line 1 \(for @unrelated\) names/);
  });

  test('a top-level inBundle is an ordinary entry: its integrity is checked', async () => {
    const dir = tmpdir('lv-t4-');
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 't4', bundleDependencies: ['lodash'] },
        'node_modules/lodash': { version: '4.17.21', resolved: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz', inBundle: true },
      },
    }));
    const r = await run(dir, { offline: 'true', registry: NPMJS });
    assert.deepEqual(found(r.json), ['no-integrity lodash']);
  });

  test('install scripts nothing describes: a git or tarball package must be allowed; registry packages are listed', async () => {
    const dir = project('registry-pnpm');
    const off = await run(dir, { offline: 'true' });
    assert.equal(off.code, 0);
    assert.match(off.err, /^WARN: The install scripts of 5 registry packages are unknown: the lockfile doesn't record them, and offline is true, so no registry was asked\. allow_scripts can't be applied to them: @corp\/private@1\.0\.0, deprecated-pkg@1\.0\.0, fresh-pkg@2\.0\.0, old-pkg@1\.0\.0, scripts-pkg@1\.0\.0\.$/m);
    const tarball = await run(path.join(LOCKS, 'edge', 'tarball', 'pnpm'), { offline: 'true', registry: NPMJS, allow_remote: 'ms' });
    assert.deepEqual(found(tarball.json), ['install-script ms']);
    assert.match(byKind(tarball.json, 'install-script', 'ms').message, /^ms@2\.1\.3 in \S*pnpm-lock\.yaml may run install scripts: the lockfile doesn't say whether it runs install scripts, and no registry describes it \(it comes from http:\/\/127\.0\.0\.1:47614\/ms\/-\/ms-2\.1\.3\.tgz\), which allow_scripts doesn't allow\.$/);
    const allowed = await run(path.join(LOCKS, 'edge', 'tarball', 'pnpm'), { offline: 'true', registry: NPMJS, allow_remote: 'ms', allow_scripts: 'ms' });
    assert.deepEqual(found(allowed.json), []);
  });
});
