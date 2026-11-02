// Unit tests of src/helper/core.mjs, offline: the lockfile parsers on real
// lockfiles (tests/fixtures/lockfiles), malformed input, the registry
// configuration, patterns, reports, the command wrapper, and registry access
// through curl against tests/fake_registry.mjs.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as core from '../../src/helper/core.mjs';
import { startFakeRegistry, satisfies } from '../fake_registry.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const LOCKS = path.join(HERE, '..', 'fixtures', 'lockfiles');
const REGISTRY_FIXTURES = path.join(HERE, '..', 'fixtures', 'registry');
const NPMJS = 'https://registry.npmjs.org/';
const ESBUILD_PLATFORMS = 25;

const tmpdir = (prefix = 'core-test-') => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const fixture = (...p) => path.join(LOCKS, ...p);
const read = (dir, opts = {}) => core.readLockfiles({ cwd: fixture(dir), ...opts });
const relOf = (abs) => core.relPath(core.findCheckoutTop(path.dirname(abs)), fs.realpathSync(abs));
const relDir = (dir) => core.relPath(core.findCheckoutTop(fixture(dir)), fs.realpathSync(fixture(dir)));

// The 1-based line of the first line of FILE that contains NEEDLE.
function lineOfText(file, needle) {
  const i = fs.readFileSync(file, 'utf8').split('\n').findIndex((l) => l.includes(needle));
  assert.ok(i >= 0, `${needle} not in ${file}`);
  return i + 1;
}

function find(entries, pred) {
  const hits = entries.filter(typeof pred === 'function' ? pred : (e) => e.name === pred.name && (pred.version === undefined || e.version === pred.version) && (pred.kind === undefined || e.kind === pred.kind));
  assert.equal(hits.length, 1, `expected one entry for ${JSON.stringify(pred)}, got ${hits.length}`);
  return hits[0];
}

function kinds(entries) {
  const out = {};
  for (const e of entries) out[e.kind] = (out[e.kind] ?? 0) + 1;
  return out;
}

const ENTRY_DEFAULTS = {
  alias: null, sourceRecorded: true, integrity: null, integrityAlgos: [], integrityKind: null, dev: null, optional: null,
  hasInstallScript: null, license: null, deprecated: null, commit: null, bundled: false,
};

// Integrity values of the fixture packages.
const SRI = {
  lodash20: 'sha512-PlhdFcillOINfeV7Ni6oF1TAEayyZBoZ8bcshTHqOYJYlrqzRK5hagpagky5o4HfCzzd1TRkXPMFq6cKk9rGmA==',
  lodash21: 'sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==',
  ms: 'sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA==',
  kindOfSha1: 'sha1-B8BQNKbDSfoG4k+jWqdttFgM5N0=',
};
const NPM_GIT = 'git+ssh://git@github.com/sindresorhus/is.git#65ea91297ede74046b19a65c434411a39c16dacd';
const PNPM_GIT = 'https://github.com/sindresorhus/is.git#65ea91297ede74046b19a65c434411a39c16dacd';

// ---------------------------------------------------------------------------
// npm
// ---------------------------------------------------------------------------

describe('npm lockfiles', () => {
  test('v3: every kind, aliases, flags and lines', () => {
    const r = read('npm/v3');
    const file = fixture('npm/v3/package-lock.json');
    const rel = relOf(file);
    assert.deepEqual(r.lockfiles.map((l) => [l.rel, l.format, l.formatVersion, l.entries]), [[rel, 'npm', '3', 46]]);
    assert.match(r.lockfiles[0].sha256, /^[0-9a-f]{64}$/);
    assert.deepEqual(kinds(r.entries), { workspace: 3, local: 1, registry: 16 + ESBUILD_PLATFORMS, git: 1 });
    assert.deepEqual(find(r.entries, { name: 'lodash', version: '4.17.20' }), {
      ...ENTRY_DEFAULTS, lockfile: rel, line: lineOfText(file, '"node_modules/lodash-old": {'), name: 'lodash', version: '4.17.20',
      alias: 'lodash-old', kind: 'registry', source: NPMJS, integrity: SRI.lodash20, integrityAlgos: ['sha512'], integrityKind: 'sri',
      dev: false, optional: false, hasInstallScript: false, license: 'MIT',
    });
    assert.deepEqual(find(r.entries, { name: '@sindresorhus/is' }), {
      ...ENTRY_DEFAULTS, lockfile: rel, line: lineOfText(file, '"node_modules/@sindresorhus/is": {'), name: '@sindresorhus/is', version: '4.6.0',
      kind: 'git', source: NPM_GIT, commit: '65ea91297ede74046b19a65c434411a39c16dacd', dev: false, optional: false, license: 'MIT',
    });
    assert.deepEqual(find(r.entries, { name: 'local-lib' }), {
      ...ENTRY_DEFAULTS, lockfile: rel, line: lineOfText(file, '"local-lib": {'), name: 'local-lib', version: '0.1.0', kind: 'local',
      source: `${relDir('npm/v3')}/local-lib`, dev: false, optional: false, hasInstallScript: true, license: 'ISC',
    });
    assert.equal(find(r.entries, { name: 'esbuild' }).hasInstallScript, true);
    assert.equal(find(r.entries, { name: 'semver' }).dev, true);
    assert.equal(find(r.entries, { name: 'is-odd' }).optional, true);
    assert.match(find(r.entries, { name: 'uuid' }).deprecated, /^uuid@10 and below is no longer supported/);
    assert.equal(find(r.entries, { name: 'is-number', version: '7.0.0' }).line, lineOfText(file, '"packages/a/node_modules/is-number": {'));
    const ms = find(r.entries, { name: 'ms' });
    assert.equal(ms.kind, 'registry'); // a tarball URL on the registry looks like a registry package in npm v2/v3
    assert.equal(ms.source, NPMJS);
    const ws = r.entries.filter((e) => e.kind === 'workspace').map((e) => [e.name, e.source, e.line]);
    assert.deepEqual(ws, [
      ['fixture-root', relDir('npm/v3'), lineOfText(file, '"": {')],
      ['@fixture/a', `${relDir('npm/v3')}/packages/a`, lineOfText(file, '"packages/a": {')],
      ['@fixture/b', `${relDir('npm/v3')}/packages/b`, lineOfText(file, '"packages/b": {')],
    ]);
    assert.equal(r.entries.filter((e) => e.kind === 'link').length, 0, 'links to entries in the lockfile are not entries');
  });

  test('v2 and npm-shrinkwrap.json read like v3', () => {
    const strip = (es) => es.map(({ lockfile, line, ...e }) => ({ ...e, source: e.source.replace(/npm\/(v2|shrinkwrap)/, 'npm/v3') }));
    const v3 = strip(read('npm/v3').entries);
    assert.deepEqual(strip(read('npm/v2').entries), v3);
    const sw = read('npm/shrinkwrap');
    assert.equal(path.basename(sw.lockfiles[0].rel), 'npm-shrinkwrap.json');
    assert.deepEqual(strip(sw.entries), v3);
  });

  test('v1 (npm 6): nested tree, specs in version, no install-script data', () => {
    const r = read('npm/v1');
    const file = fixture('npm/v1/package-lock.json');
    assert.equal(r.lockfiles[0].formatVersion, '1');
    const old = find(r.entries, { name: 'lodash', version: '4.17.20' });
    assert.equal(old.alias, 'lodash-old');
    assert.equal(old.line, lineOfText(file, '"lodash-old": {'));
    assert.equal(old.hasInstallScript, null);
    const ms = find(r.entries, { name: 'ms' });
    assert.deepEqual([ms.kind, ms.version, ms.source], ['registry', '2.1.3', NPMJS]);
    const git = find(r.entries, { name: '@sindresorhus/is' });
    assert.deepEqual([git.kind, git.version, git.commit], ['git', null, '65ea91297ede74046b19a65c434411a39c16dacd']);
    assert.equal(git.source, 'git+https://github.com/sindresorhus/is.git#65ea91297ede74046b19a65c434411a39c16dacd');
    assert.equal(find(r.entries, { name: 'local-lib' }).kind, 'local');
    assert.equal(find(r.entries, { name: 'semver' }).dev, true);
    assert.equal(find(r.entries, { name: '@esbuild/linux-x64' }).optional, true);
  });

  test('v1 with workspaces: file: paths matching package.json workspaces are workspaces', () => {
    const r = read('npm/v1-workspaces');
    const file = fixture('npm/v1-workspaces/package-lock.json');
    assert.equal(find(r.entries, { name: '@fixture/a' }).kind, 'workspace');
    assert.equal(find(r.entries, { name: 'local-lib' }).kind, 'local');
    const nested = find(r.entries, { name: 'is-number', version: '7.0.0' });
    assert.equal(nested.line, lineOfText(file, '"is-number": {'));
  });

  test('sha1-only integrity, a loopback registry, devOptional', () => {
    const sha1 = find(read('edge/sha1-only/npm').entries, { name: 'kind-of' });
    assert.deepEqual([sha1.integrity, sha1.integrityAlgos, sha1.source, sha1.sourceRecorded], [SRI.kindOfSha1, ['sha1'], 'http://127.0.0.1:47616/', true]);
    const r = read('edge/dev-optional/npm');
    const isNumber = find(r.entries, { name: 'is-number' });
    assert.deepEqual([isNumber.dev, isNumber.optional], [false, true]);
  });

  test('license: a string, a legacy {type}, or an array OR-ed, as licenses reads the registry\'s', () => {
    const lic = {
      a: 'MIT', b: { type: 'ISC' }, c: ['MIT', 'Apache-2.0'], d: [{ type: 'MIT' }, 'ISC AND BSD-2-Clause'], e: ['MIT'],
      f: [], g: [42], h: [['MIT']], i: 42, j: ['MIT', ''],
    };
    const packages = { '': { name: 'x', version: '1.0.0' } };
    for (const [n, l] of Object.entries(lic)) packages[`node_modules/${n}`] = { version: '1.0.0', integrity: SRI.ms, license: l };
    const text = JSON.stringify({ name: 'x', version: '1.0.0', lockfileVersion: 3, requires: true, packages }, null, 2);
    const r = core.parseLockfileText(text, { file: path.join(tmpdir(), 'package-lock.json'), rel: 'package-lock.json' });
    assert.deepEqual(Object.fromEntries(r.entries.filter((e) => e.kind === 'registry').map((e) => [e.name, e.license])), {
      a: 'MIT', b: 'ISC', c: 'MIT OR Apache-2.0', d: 'MIT OR (ISC AND BSD-2-Clause)', e: 'MIT', f: null, g: null, h: null, i: null, j: null,
    });
  });
});

// ---------------------------------------------------------------------------
// pnpm
// ---------------------------------------------------------------------------

describe('pnpm lockfiles', () => {
  for (const [dir, ver] of [['pnpm/v5.4', '5.4'], ['pnpm/v6.0', '6.0'], ['pnpm/v9.0', '9.0'], ['pnpm/two-documents', '9.0']]) {
    test(`${dir}: aliases, kinds, flags and lines`, () => {
      const r = read(dir);
      const file = fixture(dir, 'pnpm-lock.yaml');
      assert.deepEqual([r.lockfiles[0].format, r.lockfiles[0].formatVersion], ['pnpm', ver]);
      const key = { '5.4': '/lodash/4.17.20:', '6.0': '/lodash@4.17.20:', '9.0': '  lodash@4.17.20:' }[ver];
      const text = fs.readFileSync(file, 'utf8').split('\n');
      const line = text.findIndex((l, i) => l.startsWith('  ') && l.trimStart() === key.trim() && (dir !== 'pnpm/two-documents' || i > 190)) + 1;
      assert.deepEqual(find(r.entries, { name: 'lodash', version: '4.17.20' }), {
        ...ENTRY_DEFAULTS, lockfile: relOf(file), line, name: 'lodash', version: '4.17.20', alias: 'lodash-old', kind: 'registry',
        source: NPMJS, sourceRecorded: false, integrity: SRI.lodash20, integrityAlgos: ['sha512'], integrityKind: 'sri',
        dev: ver === '9.0' ? null : false, optional: false,
      });
      assert.equal(find(r.entries, { name: 'semver' }).dev, ver === '9.0' ? null : true);
      assert.equal(find(r.entries, { name: 'is-odd' }).optional, true);
      assert.match(find(r.entries, { name: 'uuid' }).deprecated, /^uuid@10 and below/);
      const git = find(r.entries, { name: '@sindresorhus/is' });
      assert.equal(git.kind, 'git');
      assert.match(git.commit, /^[0-9a-f]{40}$/);
      if (ver === '9.0') assert.equal(git.source, PNPM_GIT);
      assert.equal(find(r.entries, { name: 'local-lib' }).kind, 'local');
      const link = find(r.entries, { name: 'linked-lib' });
      assert.deepEqual([link.kind, link.source], ['link', `${relDir(dir)}/linked-lib`]);
      assert.deepEqual(r.entries.filter((e) => e.kind === 'workspace').map((e) => e.source),
        ['', '/packages/a', '/packages/b'].map((s) => relDir(dir) + s));
      assert.equal(find(r.entries, { name: 'ms' }).kind, 'registry');
    });
  }

  test('two documents: the package manager\'s own packages are read too', () => {
    const r = read('pnpm/two-documents');
    const exe = find(r.entries, { name: '@pnpm/exe' });
    assert.deepEqual([exe.version, exe.line], ['11.28.10', lineOfText(fixture('pnpm/two-documents/pnpm-lock.yaml'), "'@pnpm/exe@11.28.10':")]);
    assert.equal(r.entries.filter((e) => e.kind === 'workspace').length, 3);
  });

  test('a tarball URL on another host is remote; sha1-only; block scalars', () => {
    const t = read('edge/tarball/pnpm');
    const ms = find(t.entries, { name: 'ms' });
    assert.deepEqual([ms.kind, ms.source, ms.version, ms.integrity], ['remote', 'http://127.0.0.1:47614/ms/-/ms-2.1.3.tgz', '2.1.3', SRI.ms]);
    assert.equal(find(read('edge/sha1-only/pnpm').entries, { name: 'kind-of' }).integrity, SRI.kindOfSha1);
    const deprecated = find(read('edge/block-scalar/pnpm').entries, { name: 'is-number' }).deprecated;
    assert.equal(deprecated, 'line one: has colon\n  # indented hash line\n"quoted" and \'single\' {braces}, [brackets]');
    assert.equal(read('edge/time-based/pnpm').entries.length, 4);
  });

  test('include_dev false drops dev packages where pnpm records them, and warns where it doesn\'t', () => {
    const old = read('pnpm/v6.0', { includeDev: false });
    assert.equal(old.entries.some((e) => e.name === 'semver'), false);
    const v9 = read('pnpm/v9.0', { includeDev: false });
    assert.equal(v9.entries.some((e) => e.name === 'semver'), true);
    assert.match(v9.warnings.join('\n'), /don't record which packages are only for development/);
  });

  test('unrecorded sources come from the scope mapping', () => {
    const registries = core.registryConfig({ registry: 'https://mirror.example/npm', scopes: ['@tootallnate=https://npm.corp.example/'], npmrc: false });
    const r = read('pnpm/v9.0', { registries });
    assert.equal(find(r.entries, { name: '@tootallnate/once' }).source, 'https://npm.corp.example/');
    assert.equal(find(r.entries, { name: 'lodash', version: '4.17.21' }).source, 'https://mirror.example/npm/');
  });
});

// ---------------------------------------------------------------------------
// yarn v1, Berry and bun
// ---------------------------------------------------------------------------

describe('yarn v1', () => {
  test('aliases, git, link, file and a tarball URL without integrity', () => {
    const r = read('yarn1');
    const file = fixture('yarn1/yarn.lock');
    assert.deepEqual([r.lockfiles[0].format, r.lockfiles[0].formatVersion], ['yarn1', '1']);
    assert.deepEqual(find(r.entries, { name: 'lodash', version: '4.17.20' }), {
      ...ENTRY_DEFAULTS, lockfile: relOf(file), line: lineOfText(file, '"lodash-old@npm:lodash@4.17.20":'), name: 'lodash', version: '4.17.20',
      alias: 'lodash-old', kind: 'registry', source: NPMJS, integrity: SRI.lodash20, integrityAlgos: ['sha512'], integrityKind: 'sri',
    });
    const git = find(r.entries, { name: '@sindresorhus/is' });
    assert.deepEqual([git.kind, git.commit, git.source], ['git', 'c7f9665b9603cfb49114e01271aeed90cadb1ae7', 'git://127.0.0.1/gitdep.git#c7f9665b9603cfb49114e01271aeed90cadb1ae7']);
    assert.equal(find(r.entries, { name: 'linked-lib' }).kind, 'link');
    assert.equal(find(r.entries, { name: 'local-lib' }).kind, 'local');
    const ms = find(r.entries, { name: 'ms' });
    // No integrity line: the sha1 in resolved's fragment stands in.
    const sha1 = 'sha1-' + Buffer.from('574c8138ce1d2b5861f0b44579dbadd60c6615b2', 'hex').toString('base64');
    assert.deepEqual([ms.kind, ms.integrity, ms.integrityAlgos], ['registry', sha1, ['sha1']]);
    assert.equal(find(r.entries, { name: 'is-number', version: '6.0.0' }).line, lineOfText(file, 'is-number@^6.0.0:'));
    assert.equal(find(r.entries, { name: 'esbuild' }).dev, null);
  });

  test('an npm: spec of the same package is not an alias', () => {
    const text = '# yarn lockfile v1\n\nlodash@npm:lodash@^4.17.0:\n  version "4.17.21"\n  resolved "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz#679591c564c3bffaae8454cf0b3df370c3d6911c"\n';
    const [e] = core.parseLockfileText(text, { file: path.join(os.tmpdir(), 'yarn.lock'), rel: 'yarn.lock' }).entries;
    assert.deepEqual([e.name, e.alias, e.source], ['lodash', null, NPMJS]);
  });

  test('entries with several specifiers are one entry; sha1 only', () => {
    const r = read('edge/tarball/yarn1');
    assert.equal(r.entries.filter((e) => e.name === 'is-number').length, 1);
    assert.equal(find(read('edge/sha1-only/yarn1').entries, { name: 'kind-of' }).integrityAlgos.join(), 'sha1');
  });
});

describe('yarn Berry', () => {
  for (const [dir, ver] of [['berry/v6', '6'], ['berry/v10', '10']]) {
    test(`${dir}: resolutions, aliases and checksums`, () => {
      const r = read(dir);
      const file = fixture(dir, 'yarn.lock');
      assert.deepEqual([r.lockfiles[0].format, r.lockfiles[0].formatVersion], ['berry', ver]);
      const old = find(r.entries, { name: 'lodash', version: '4.17.20' });
      assert.equal(old.line, lineOfText(file, '"lodash-old@npm:lodash@4.17.20":'));
      assert.deepEqual([old.alias, old.kind, old.source, old.sourceRecorded, old.integrityKind, old.integrityAlgos],
        ['lodash-old', 'registry', NPMJS, false, 'berry', ['sha512']]);
      assert.match(old.integrity, /^(?:[0-9a-z]+\/)?[0-9a-f]{128}$/);
      const git = find(r.entries, { name: '@sindresorhus/is' });
      assert.deepEqual([git.kind, git.commit], ['git', '841a0009e83c03f1dbe2ab4c89bd564374f01c7c']);
      assert.deepEqual([find(r.entries, { name: 'linked-lib' }).kind, find(r.entries, { name: 'local-lib' }).kind], ['link', 'local']);
      assert.equal(find(r.entries, { name: 'local-lib' }).source, `${relDir(dir)}/local-lib`);
      assert.deepEqual(r.entries.filter((e) => e.kind === 'workspace').map((e) => e.name).sort(), ['@fixture/a', '@fixture/b', 'fixture-root']);
      const ms = find(r.entries, { name: 'ms' });
      assert.deepEqual([ms.kind, ms.source, ms.sourceRecorded], ['registry', NPMJS, true]);
    });
  }

  test('a builtin patch: is left out when the unpatched package has its entry', () => {
    const r = read('edge/patch/berry');
    assert.deepEqual(r.entries.map((e) => [e.name, e.kind]), [['bigapp', 'workspace'], ['typescript', 'registry']]);
  });
});

describe('bun.lock', () => {
  test('JSONC with trailing commas: kinds, aliases and lines', () => {
    const r = read('bun/text');
    const file = fixture('bun/text/bun.lock');
    assert.deepEqual([r.lockfiles[0].format, r.lockfiles[0].formatVersion], ['bun', '2']);
    assert.deepEqual(find(r.entries, { name: 'lodash', version: '4.17.20' }), {
      ...ENTRY_DEFAULTS, lockfile: relOf(file), line: lineOfText(file, '"lodash-old": ['), name: 'lodash', version: '4.17.20',
      alias: 'lodash-old', kind: 'registry', source: NPMJS, integrity: SRI.lodash20, integrityAlgos: ['sha512'], integrityKind: 'sri',
    });
    assert.equal(find(r.entries, { name: 'is-number', version: '6.0.0' }).alias, null);
    assert.equal(find(r.entries, { name: '@sindresorhus/is' }).commit, 'c7f9665b9603cfb49114e01271aeed90cadb1ae7');
    assert.equal(find(r.entries, { name: 'local-lib' }).kind, 'local');
    assert.deepEqual(r.entries.filter((e) => e.kind === 'workspace').map((e) => [e.name, e.line]), [
      ['fixture-root', lineOfText(file, '"": {')], ['@fixture/a', lineOfText(file, '"packages/a": {')], ['@fixture/b', lineOfText(file, '"packages/b": {')],
    ]);
  });

  test('comments, tarball URLs and recorded registries', () => {
    assert.equal(read('edge/comments/bun').entries.length, 2);
    const t = read('edge/tarball/bun');
    assert.deepEqual([find(t.entries, { name: 'ms' }).source, find(t.entries, { name: 'ms' }).version], ['http://127.0.0.1:47614/', '2.1.3']);
    const sha1 = find(read('edge/sha1-only/bun').entries, { name: 'kind-of' });
    assert.deepEqual([sha1.source, sha1.integrity], ['http://127.0.0.1:47616/', SRI.kindOfSha1]);
  });

  test('bun.lockb is refused with the conversion hint', () => {
    assert.throws(() => read('bun/lockb'), /bun install --save-text-lockfile --frozen-lockfile --lockfile-only/);
    assert.throws(() => read('bun/lockb', { lockfilePatterns: ['bun.lockb'] }), /binary lockfile/);
  });
});

// ---------------------------------------------------------------------------
// Malformed input
// ---------------------------------------------------------------------------

describe('malformed lockfiles are refused with file:line', () => {
  const parse = (name, text) => core.parseLockfileText(text, { file: path.join(os.tmpdir(), 'x', name), rel: name });
  const refused = (name, text, re) => assert.throws(() => parse(name, text), (e) => {
    assert.ok(e instanceof core.LockfileError, `expected a LockfileError, got ${e}`);
    assert.match(e.message, re);
    return true;
  });
  const npm = (packages) => JSON.stringify({ lockfileVersion: 3, packages: { '': { name: 'x' }, ...packages } }, null, 2);

  test('npm', () => {
    refused('package-lock.json', '{\n  "lockfileVersion": 3,\n  "packages": {},\n  "packages": {}\n}\n', /^package-lock\.json:4: duplicate key "packages"/);
    refused('package-lock.json', '{"lockfileVersion": 4, "packages": {}}', /:1: an unsupported lockfileVersion 4/);
    refused('package-lock.json', '{"lockfileVersion": 3, "packages": {},}', /expected a string key/);
    refused('package-lock.json', npm({ 'node_modules/a': { version: '1.0.0', resolved: 'ftp://x/a.tgz' } }), /:7: an unrecognised source/);
    refused('package-lock.json', npm({ 'node_modules/a': { version: '1.0.0', integrity: 'md5-abc' } }), /a malformed integrity/);
    refused('package-lock.json', npm({ 'node_modules/../a': { version: '1.0.0' } }), /a malformed install path/);
    refused('package-lock.json', npm({ 'node_modules/a': { resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz' } }), /has no version/);
  });

  test('pnpm', () => {
    const head = "lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n\npackages:\n\n";
    refused('pnpm-lock.yaml', head + "  a@1.0.0:\n\t  resolution: {integrity: sha512-AAAA}\n", /:10: a tab in the indentation/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0: &anchor\n    resolution: {integrity: sha512-AAAA}\n', /:9: an unsupported plain scalar/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    resolution: {integrity: sha512-AAAA} # comment\n', /:10: text after a flow collection/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    deprecated: yes # comment\n    resolution: {integrity: sha512-AAAA}\n', /:10: comments after a value/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n  a@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n', /:11: duplicate key "a@1\.0\.0"/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    resolution: {integrity: sha512-AAAA,\n      tarball: x}\n', /:10: a malformed flow collection/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    deprecated: >\n      folded\n    resolution: {integrity: sha512-AAAA}\n', /:10: an unsupported block scalar header/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    resolution: {type: magic}\n', /:9: an unsupported resolution type "magic"/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    engines: {node: 1}\n', /:9: "a@1\.0\.0" has no resolution/);
    refused('pnpm-lock.yaml', "lockfileVersion: '7.0'\n", /:1: an unsupported lockfileVersion "7\.0"/);
    refused('pnpm-lock.yaml', head + '  a@1.0.0:\n    resolution: {integrity: sha512-AAAA}\n   bad: indent\n', /:11: unexpected indentation/);
  });

  test('yarn v1', () => {
    refused('yarn.lock', 'a@^1:\n  version "1.0.0"\n', /missing the "# yarn lockfile v1" header/);
    const head = '# yarn lockfile v1\n\n';
    refused('yarn.lock', head + 'a@^1:\n<<<<<<< HEAD\n  version "1.0.0"\n', /:4: a merge conflict marker/);
    refused('yarn.lock', head + 'a@^1:\n   version "1.0.0"\n', /:4: odd indentation/);
    refused('yarn.lock', head + 'version "1.0.0"\n', /:3: a value outside an entry/);
    refused('yarn.lock', head + 'a@^1:\n  version "1.0.0"\n  resolved "ftp://x/a.tgz"\n', /:3: a@\^1: an unrecognised source/);
    refused('yarn.lock', head + 'a@^1:\n  version "1.0.0" extra\n', /:4: expected "key value"/);
  });

  test('yarn Berry', () => {
    const head = '__metadata:\n  version: 10\n  cacheKey: 10c0\n\n';
    refused('yarn.lock', '__metadata:\n  version: 3\n', /:2: an unsupported __metadata\.version "3"/);
    refused('yarn.lock', head + '"a@exec:./x.js":\n  version: 1.0.0\n  resolution: "a@exec:./x.js"\n', /:5: an unsupported resolution/);
    refused('yarn.lock', head + '"a@npm:1.0.0":\n  version: 1.0.0\n  resolution: "a@npm:1.0.0"\n  checksum: abc\n', /:5: a malformed checksum/);
    refused('yarn.lock', head + '"a@npm:1.0.0":\n  version: 1.0.1\n  resolution: "a@npm:1.0.0"\n', /doesn't match version/);
  });

  test('bun.lock', () => {
    refused('bun.lock', '{"lockfileVersion": 2, "packages": {}} x', /unexpected text after the JSON value/);
    refused('bun.lock', '{"lockfileVersion": 9}', /an unsupported lockfileVersion 9/);
    refused('bun.lock', '{\n "lockfileVersion": 2,\n "packages": {\n  "a": ["a@1.0.0", "", {}],\n }\n}', /:4: "a": a registry package must be/);
    refused('bun.lock', '{\n "lockfileVersion": 2,\n "packages": {\n  "a": "a@1.0.0",\n }\n}', /:4: "a" must be an array/);
    refused('bun.lock', '{"lockfileVersion": 2, /* never closed', /a comment is never closed/);
  });

  test('unknown formats and bun.lockb', () => {
    refused('lock.txt', 'hello', /not a lockfile format this orb reads/);
    refused('bun.lockb', '#!/usr/bin/env bun\nbun-lockfile-format-v0\n', /bun install --save-text-lockfile/);
  });

  test('a lockfile key cannot change an object\'s prototype', () => {
    const v = core.parseJsonWithLines('{"__proto__": {"polluted": true}}', 'x.json');
    assert.equal(Object.getPrototypeOf(v), Object.prototype);
    assert.equal({}.polluted, undefined);
    assert.deepEqual(Object.keys(v), ['__proto__']);
    const [doc] = core.parseYamlSubset('__proto__:\n  polluted: x\n', 'x.yaml');
    assert.equal(Object.getPrototypeOf(doc), Object.prototype);
  });
});

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

describe('discovery', () => {
  test('auto-detection, globs, patterns that match nothing, allow_empty', () => {
    const dir = tmpdir();
    assert.throws(() => core.readLockfiles({ cwd: dir }), /No lockfile in .*package-lock\.json, npm-shrinkwrap\.json, pnpm-lock\.yaml, yarn\.lock, bun\.lock/);
    const empty = core.readLockfiles({ cwd: dir, allowEmpty: true });
    assert.deepEqual([empty.lockfiles.length, empty.entries.length], [0, 0]);
    assert.match(empty.warnings[0], /No lockfile/);
    const all = core.readLockfiles({ cwd: LOCKS, lockfilePatterns: ['**/yarn.lock'] });
    assert.deepEqual(all.lockfiles.map((l) => l.format).sort(), ['berry', 'berry', 'berry', 'berry', 'berry', 'yarn1', 'yarn1', 'yarn1']);
    assert.throws(() => core.readLockfiles({ cwd: LOCKS, lockfilePatterns: ['npm/*/nothing.json'] }), /matches no file/);
    const two = core.readLockfiles({ cwd: LOCKS, lockfilePatterns: ['npm/v3/package-lock.json', 'npm/v?/package-lock.json'] });
    assert.deepEqual(two.lockfiles.map((l) => path.basename(path.dirname(l.path))), ['v3', 'v1', 'v2']);
  });

  test('npm-shrinkwrap.json hides package-lock.json', () => {
    const dir = tmpdir();
    fs.copyFileSync(fixture('npm/v3/package-lock.json'), path.join(dir, 'package-lock.json'));
    fs.copyFileSync(fixture('npm/shrinkwrap/npm-shrinkwrap.json'), path.join(dir, 'npm-shrinkwrap.json'));
    const r = core.readLockfiles({ cwd: dir });
    assert.deepEqual(r.lockfiles.map((l) => path.basename(l.path)), ['npm-shrinkwrap.json']);
    assert.match(r.warnings.join(), /npm installs from npm-shrinkwrap\.json/);
    assert.equal(r.lockfiles[0].rel, 'npm-shrinkwrap.json');
  });
});

// ---------------------------------------------------------------------------
// The registry configuration and patterns
// ---------------------------------------------------------------------------

describe('registry configuration', () => {
  test('.npmrc scope lines, merged with the scopes parameter', () => {
    const dir = tmpdir();
    fs.writeFileSync(path.join(dir, '.npmrc'), [
      'registry=https://ignored.example/',
      '@corp:registry=https://npm.corp.example/api/npm/',
      '//npm.corp.example/:_authToken=${NPM_TOKEN}',
      '@env:registry=${PRIVATE_REGISTRY}',
      '@other:registry = "https://other.example"',
      '; a comment',
    ].join('\n'));
    const c = core.registryConfig({ cwd: dir, scopes: ['@other=https://override.example/x', '# comment lines are dropped by splitLines'].filter((l) => !l.startsWith('#')) });
    assert.equal(c.registry, NPMJS);
    assert.deepEqual(Object.fromEntries(c.scopes), { '@corp': 'https://npm.corp.example/api/npm/', '@other': 'https://override.example/x/' });
    assert.match(c.warnings[0], /\.npmrc line 4: the registry of @env uses an environment variable/);
    assert.equal(c.registryFor('@corp/x'), 'https://npm.corp.example/api/npm/');
    assert.equal(c.registryFor('lodash'), NPMJS);
    assert.equal(c.npmrc, path.join(dir, '.npmrc'));
  });

  test('registry URLs are checked', () => {
    assert.equal(core.normalizeRegistryUrl('https://Registry.Example.com/npm'), 'https://registry.example.com/npm/');
    assert.equal(core.normalizeRegistryUrl('http://127.0.0.1:4873'), 'http://127.0.0.1:4873/');
    assert.equal(core.normalizeRegistryUrl('http://[::1]:4873/'), 'http://[::1]:4873/');
    for (const bad of ['http://registry.example/', 'https://u:p@registry.example/', 'https://r.example/?x=1', 'https://r.example/#f', 'ftp://r.example/', 'not a url']) {
      assert.throws(() => core.normalizeRegistryUrl(bad, 'registry'), core.UsageError, bad);
    }
    assert.throws(() => core.registryConfig({ scopes: ['corp=https://x.example/'], npmrc: false }), /scopes takes lines @scope=URL/);
    const dir = tmpdir();
    fs.writeFileSync(path.join(dir, '.npmrc'), '@corp:registry=http://insecure.example/\n');
    assert.throws(() => core.registryConfig({ cwd: dir }), /the registry of @corp \(\.npmrc line 1\) must be an https URL/);
    assert.equal(core.registryConfig({ cwd: dir, scopes: ['@corp=https://secure.example/'] }).scopes.get('@corp'), 'https://secure.example/');
  });

  test('credentials never reach sources or messages', () => {
    assert.equal(core.publicUrl('https://user:tok@host.example/a?x=1#f'), 'https://host.example/a');
    assert.equal(core.stripCredentials('git+ssh://git@github.com/o/r.git'), 'git+ssh://git@github.com/o/r.git');
    assert.equal(core.stripCredentials('git+https://ghp_secret@github.com/o/r.git'), 'git+https://github.com/o/r.git');
    const text = '# yarn lockfile v1\n\nr@git+https://tok@github.com/o/r.git:\n  version "1.0.0"\n  resolved "git+https://tok@github.com/o/r.git#0123456789abcdef0123456789abcdef01234567"\n';
    const r = core.parseLockfileText(text, { file: path.join(os.tmpdir(), 'yarn.lock'), rel: 'yarn.lock' });
    assert.equal(r.entries[0].source, 'git+https://github.com/o/r.git#0123456789abcdef0123456789abcdef01234567');
  });
});

describe('which registry a package\'s metadata comes from', () => {
  const MIRROR = 'https://mirror.example/npm/';
  const CORP = 'https://npm.corp.example/';
  const regs = core.registryConfig({ registry: MIRROR, scopes: [`@corp=${CORP}`], npmrc: false });
  const entry = (name, source, sourceRecorded = true, kind = 'registry') => ({ kind, name, version: '1.0.0', source, sourceRecorded });
  const at = (e, r = regs) => core.metadataRegistry(e, r).registry;

  test('metadataRegistry: the mapping, npmjs in its place, a configured registry, never another', () => {
    // No recorded source (pnpm, Berry): the mapping.
    assert.equal(at(entry('lodash', MIRROR, false)), MIRROR);
    assert.equal(at(entry('@corp/x', CORP, false)), CORP);
    // Recorded on registry.npmjs.org: where npm installs it from instead (replace-registry-host).
    assert.equal(at(entry('lodash', NPMJS)), MIRROR);
    assert.equal(at(entry('@corp/x', NPMJS)), CORP);
    assert.equal(at(entry('lodash', NPMJS), core.registryConfig({ npmrc: false })), NPMJS);
    // Recorded on registry or a scope's registry: there, even when it isn't the name's mapping.
    assert.equal(at(entry('lodash', MIRROR)), MIRROR);
    assert.equal(at(entry('lodash', CORP)), CORP);
    assert.equal(at(entry('@corp/x', MIRROR)), MIRROR);
    // Anything else is never contacted.
    assert.deepEqual(core.metadataRegistry(entry('lodash', 'https://evil.example/'), regs), {
      registry: null, reason: 'the lockfile records https://evil.example/, which is neither registry nor a scope\'s registry (scopes, or .npmrc)',
    });
    assert.equal(at(entry('x', 'git+https://github.com/o/x.git', true, 'git')), null);
    // yarn's registry.yarnpkg.com is recorded as registry.npmjs.org.
    const yarn = '# yarn lockfile v1\n\nleft-pad@^1.3.0:\n  version "1.3.0"\n  resolved "https://registry.yarnpkg.com/left-pad/-/left-pad-1.3.0.tgz#5b8a3a7765dfe001261dde915589e782f8c94d1e"\n'
      + '  integrity sha512-XI5MPzVNApjAyhQzphX8BkmKsKUxD4LdyK24iZeQ9lFUqNlqrhrTNuxHrJF2jvOJr4Ywnst2VWRZgCByfsmeyA==\n';
    const [e] = core.parseLockfileText(yarn, { file: path.join(os.tmpdir(), 'yarn.lock'), rel: 'yarn.lock', registries: regs }).entries;
    assert.deepEqual([e.source, at(e)], [NPMJS, MIRROR]);
  });

  test('unauthorizedSkip: a 401 or 403 from another origin skips; from registry\'s it is no verdict', () => {
    assert.equal(core.unauthorizedSkip(CORP, 401, regs), `${CORP} answered HTTP 401, and the token goes only to registry's origin`);
    assert.equal(core.unauthorizedSkip(CORP, 403, regs), `${CORP} answered HTTP 403, and the token goes only to registry's origin`);
    assert.equal(core.unauthorizedSkip('https://mirror.example/other/', 401, regs), null, 'registry\'s origin gets the token');
    for (const status of [0, 404, 500]) assert.equal(core.unauthorizedSkip(CORP, status, regs), null, String(status));
    assert.equal(core.authHint('NPM_TOKEN'), 'Check the token in NPM_TOKEN.');
    assert.equal(core.authHint(''), 'If the registry needs a login, set token to the name of a variable holding a token for it.');
  });

  test('skipWarning: one wording for packages a command didn\'t check', () => {
    assert.equal(core.skipWarning(['a@1.0.0', 'a@1.0.0'], 'checked', 'the moon is full'),
      '1 package was not checked, since the moon is full: a@1.0.0. It is listed under skipped in the report.');
    const many = Array.from({ length: 12 }, (_, i) => `p${i}@1.0.0`);
    assert.equal(core.skipWarning(many, 'audited', 'reasons', 'Do this.'),
      `12 packages were not audited, since reasons: ${many.slice(0, 10).join(', ')} and 2 more. They are listed under skipped in the report. Do this.`);
  });
});

describe('matchesAny', () => {
  const pats = ['@corp/*', 'eslint-*', 'left-pad', 'semver@7.6.3'].map((p) => core.compilePattern(p, { versions: true }));
  test('globs and versions', () => {
    assert.equal(core.matchesAny('@corp/x', pats).text, '@corp/*');
    assert.equal(core.matchesAny('@corpx/y', pats), null);
    assert.equal(core.matchesAny('eslint-plugin-x', pats).text, 'eslint-*');
    assert.equal(core.matchesAny('@x/eslint-plugin', pats), null);
    assert.equal(core.matchesAny('left-pad', pats).text, 'left-pad');
    assert.equal(core.matchesAny('left-pads', pats), null);
    assert.equal(core.matchesAny('semver', pats, '7.6.3').text, 'semver@7.6.3');
    assert.equal(core.matchesAny('semver', pats, '7.6.4'), null);
    assert.equal(core.matchesAny('semver', pats), null);
    assert.equal(core.matchesAny('semver', pats, '7.7.0', { versionMatch: (v, spec) => spec === '7.6.3' && v.startsWith('7.') }).text, 'semver@7.6.3');
    assert.ok(core.matchesAny('@any/thing', ['*']));
    assert.ok(core.matchesAny('a.b', ['a.b']) && !core.matchesAny('aXb', ['a.b']), 'dots are literal');
  });
  test('bad patterns are usage errors', () => {
    assert.throws(() => core.compilePattern('semver@7', { param: 'allow_scripts' }), /allow_scripts takes package names, without versions/);
    for (const bad of ['a b', '@/x', 'x/y', '../x', '']) assert.throws(() => core.compilePattern(bad, { versions: true }), core.UsageError, bad);
  });
});

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

describe('parameters', () => {
  test('booleans, numbers, lists and lines', () => {
    const p = core.createParams({ PARAM_A: 'true', PARAM_B: '0', PARAM_C: 'yes', PARAM_N: '12', PARAM_L: 'a, b\nc  d,,e', PARAM_S: '@a=x\n\n# c\n  @b=y  ', PARAM_T: 'MY_TOKEN', PARAM_U: 'bad-name' });
    assert.equal(p.bool('a', false), true);
    assert.equal(p.bool('b', true), false);
    assert.equal(p.bool('unset', true), true);
    assert.throws(() => p.bool('c', false), /c must be true or false \(or 1 or 0\), not "yes"/);
    assert.equal(p.int('n', 1, { min: 1, max: 16 }), 12);
    assert.throws(() => p.int('n', 1, { min: 1, max: 10 }), /n must be a whole number from 1 to 10/);
    assert.deepEqual(p.list('l'), ['a', 'b', 'c', 'd', 'e']);
    assert.deepEqual(p.lines('s'), ['@a=x', '@b=y']);
    assert.equal(p.envVarName('t'), 'MY_TOKEN');
    assert.throws(() => p.envVarName('u'), /u must be the name of an environment variable/);
    assert.throws(() => p.choice('a', ['low', 'high'], 'low'), /a must be one of low, high/);
    assert.equal(p.used.a, 'true');
    assert.equal(p.used.unset, 'true');
  });
  test('output_dir and report_name', () => {
    assert.throws(() => core.checkOutputDir('reports'), /output_dir must be an absolute path/);
    assert.equal(core.checkOutputDir('/tmp/r/'), '/tmp/r');
    for (const bad of ['../x', 'a/b', '.hidden', '', 'a b']) assert.throws(() => core.checkReportName(bad), /report_name must be a plain file name/, bad);
    assert.equal(core.checkReportName('lock_verify-1.x'), 'lock_verify-1.x');
  });
});

// ---------------------------------------------------------------------------
// Reports and the command wrapper
// ---------------------------------------------------------------------------

describe('reports', () => {
  const finding = (msg, extra = {}) => ({
    kind: 'x', rule: 'lock-verify/x', level: 'error', message: msg, package: { name: '@a/b', version: '1.0.0' }, lockfile: 'dir with space/package-lock.json', line: 7, details: {}, ...extra,
  });

  test('SARIF: rules, locations, fingerprints, security-severity as a string', () => {
    const s = core.buildSarif('audit', [
      finding('one', { rule: 'audit/GHSA-xxxx-xxxx-xxxx', securitySeverity: 7.5 }),
      finding('no lockfile', { lockfile: null }),
    ], { rules: { 'audit/GHSA-xxxx-xxxx-xxxx': { description: 'Command injection', helpUri: 'https://github.com/advisories/GHSA-xxxx-xxxx-xxxx' } } });
    assert.equal(s.version, '2.1.0');
    const run = s.runs[0];
    assert.equal(run.tool.driver.name, 'js-security-orb audit');
    assert.deepEqual(run.tool.driver.rules[0].properties['security-severity'], '7.5');
    assert.equal(run.tool.driver.rules[0].shortDescription.text, 'Command injection');
    assert.equal(run.results.length, 1);
    assert.deepEqual(run.results[0].locations[0].physicalLocation, { artifactLocation: { uri: 'dir%20with%20space/package-lock.json' }, region: { startLine: 7 } });
    assert.equal(run.results[0].partialFingerprints.primaryLocationLineHash, 'audit/GHSA-xxxx-xxxx-xxxx:@a/b@1.0.0');
  });

  test('JUnit: everything escaped, below-gate findings skipped, a passing case when empty', () => {
    const xml = core.buildJunit('lock_verify', [
      finding('<script>&"\'\u0001\ud800'),
      finding('low', { level: 'warning' }),
    ], [{ message: 'no <verdict>' }]);
    assert.ok(!/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(xml), 'no control characters');
    assert.ok(xml.includes('&lt;script&gt;&amp;&quot;&apos;��'));
    assert.match(xml, /tests="3" failures="1" errors="1" skipped="1"/);
    assert.ok(!/<(?!\/?(?:testsuites|testsuite|testcase|failure|skipped|error)\b|\?xml)/.test(xml), 'only the JUnit elements are tags');
    assert.match(core.buildJunit('audit', []), /tests="1" failures="0" errors="0" skipped="0">\n    <testcase classname="audit" name="no findings"><\/testcase>/);
  });
});

describe('isMain', () => {
  test('true for the program, after symbolic links, and false for a module it imports', () => {
    const dir = tmpdir('core-main-');
    const coreUrl = new URL('../../src/helper/core.mjs', import.meta.url).href;
    fs.writeFileSync(path.join(dir, 'lib.mjs'), `import { isMain } from '${coreUrl}';\nconsole.log('lib', isMain(import.meta.url));\n`);
    fs.writeFileSync(path.join(dir, 'prog.mjs'), `import { isMain } from '${coreUrl}';\nimport './lib.mjs';\nconsole.log('prog', isMain(import.meta.url));\n`);
    fs.symlinkSync(path.join(dir, 'prog.mjs'), path.join(dir, 'link.mjs'));
    for (const file of ['prog.mjs', 'link.mjs']) {
      const r = spawnSync(process.execPath, [path.join(dir, file)], { encoding: 'utf8' });
      assert.equal(r.stdout, 'lib false\nprog true\n', file);
    }
    assert.equal(core.isMain(coreUrl), false);
    assert.equal(core.isMain('not a URL'), false);
  });
});

describe('runCommand', () => {
  const run = async (fn, params = {}, extra = {}) => {
    const out = [];
    const err = [];
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, ...Object.fromEntries(Object.entries(params).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, v])), ...extra };
    const code = await core.runCommand('lock_verify', fn, { env, cwd: extra.cwd ?? fixture('npm/v3'), stdout: (s) => out.push(s), stderr: (s) => err.push(s) });
    return { code, out: out.join(''), err: err.join('') };
  };
  const seed = (dir, name) => {
    fs.mkdirSync(path.join(dir, 'junit'), { recursive: true });
    for (const f of [`${name}.json`, `${name}.sarif`, `${name}.run-record.json`, `junit/${name}.xml`]) fs.writeFileSync(path.join(dir, f), 'old');
  };
  const exists = (dir, name) => [`${name}.json`, `${name}.sarif`, `${name}.run-record.json`, `junit/${name}.xml`].map((f) => fs.existsSync(path.join(dir, f)));

  test('a usage error clears the old reports and exits 2', async () => {
    const dir = tmpdir();
    seed(dir, 'lock_verify');
    const r = await run((ctx) => { ctx.bool('allow_git', false); }, { output_dir: dir, allow_git: 'maybe' });
    assert.equal(r.code, 2);
    assert.match(r.err, /^ERROR: allow_git must be true or false/m);
    assert.deepEqual(exists(dir, 'lock_verify'), [false, false, false, false]);
  });

  test('bad output_dir, report_name or registry are usage errors', async () => {
    assert.equal((await run(() => ({}), { output_dir: 'relative' })).code, 2);
    assert.equal((await run(() => ({}), { output_dir: tmpdir(), report_name: '../x' })).code, 2);
    assert.equal((await run(() => ({}), { output_dir: tmpdir(), registry: 'http://example.com/' })).code, 2);
    const r = await run(() => ({}), { output_dir: tmpdir(), token: 'UNSET_TOKEN_VAR' });
    assert.equal(r.code, 2);
    assert.match(r.err, /token names UNSET_TOKEN_VAR, which is not set or empty/);
  });

  test('findings fail the gate, report_only passes, reports are written atomically', async () => {
    const dir = tmpdir();
    seed(dir, 'lv');
    const fn = (ctx) => {
      const { entries } = ctx.readLockfiles();
      const git = entries.filter((e) => e.kind === 'git');
      return { findings: git.map((e) => ctx.finding(e, { kind: 'git', message: `${e.name} comes from git` })), checked: entries.length, summary: { entries: entries.length } };
    };
    const r = await run(fn, { output_dir: dir, report_name: 'lv', run_record: 'true' });
    assert.equal(r.code, 1);
    assert.match(r.out, /package-lock\.json:\d+: lock-verify\/git: @sindresorhus\/is comes from git/);
    assert.match(r.err, /^ERROR: 1 finding of lock_verify fails the gate\./m);
    assert.deepEqual(exists(dir, 'lv'), [true, true, true, true]);
    assert.deepEqual(fs.readdirSync(dir).filter((f) => f.includes('.tmp')), []);
    const json = JSON.parse(fs.readFileSync(path.join(dir, 'lv.json'), 'utf8'));
    assert.equal(json.schema, 'js-security-orb/lock_verify/v1');
    assert.equal(json.outcome, 'findings');
    assert.equal(json.findings[0].rule, 'lock-verify/git');
    assert.equal(json.lockfiles[0].format, 'npm');
    const record = JSON.parse(fs.readFileSync(path.join(dir, 'lv.run-record.json'), 'utf8'));
    checkRunRecord(record);
    assert.equal(record.outcome, 'findings');
    assert.equal(record.exit_code, 1);
    assert.equal(record.inputs[0].role, 'lockfile');
    assert.equal(record.parameters.report_name, 'lv');
    assert.deepEqual(record.reports.map((x) => path.basename(x.path)), ['lv.json', 'lv.sarif', 'lv.xml']);
    const sarif = JSON.parse(fs.readFileSync(path.join(dir, 'lv.sarif'), 'utf8'));
    assert.equal(sarif.runs[0].results[0].ruleId, 'lock-verify/git');

    const ro = await run(fn, { output_dir: dir, report_name: 'lv', report_only: '1', junit: 'false' });
    assert.equal(ro.code, 0);
    assert.match(ro.err, /^WARN: report_only is true, so this step passes/m);
    assert.deepEqual(exists(dir, 'lv'), [true, true, false, false]);
  });

  test('errors and checking nothing are no verdict, whatever report_only says', async () => {
    const dir = tmpdir();
    const e1 = await run(() => ({ errors: ['the canary is missing'] }), { output_dir: dir, report_only: 'true' });
    assert.equal(e1.code, 1);
    assert.match(e1.err, /^ERROR: the canary is missing$/m);
    const json = JSON.parse(fs.readFileSync(path.join(dir, 'lock_verify.json'), 'utf8'));
    assert.deepEqual([json.outcome, json.errors[0].message], ['error', 'the canary is missing']);
    const nothing = await run(() => ({ checked: 0 }), { output_dir: dir });
    assert.equal(nothing.code, 1);
    assert.match(nothing.err, /checked nothing/);
    assert.equal((await run(() => ({ checked: 0 }), { output_dir: dir, allow_empty: 'true' })).code, 0);
    const thrown = await run(() => { throw new Error('curl failed'); }, { output_dir: dir });
    assert.equal(thrown.code, 1);
    assert.match(thrown.err, /^ERROR: curl failed$/m);
    assert.match(fs.readFileSync(path.join(dir, 'junit', 'lock_verify.xml'), 'utf8'), /<error message="curl failed">/);
    const noLock = await run((ctx) => ctx.readLockfiles(), { output_dir: dir }, { cwd: tmpdir() });
    assert.equal(noLock.code, 1);
    assert.match(noLock.err, /^ERROR: No lockfile in /m);
  });

  test('below-gate findings pass', async () => {
    const r = await run((ctx) => ({ findings: [ctx.finding(null, { kind: 'deprecated', level: 'warning', message: 'old' })] }), { output_dir: tmpdir() });
    assert.equal(r.code, 0);
    assert.match(r.out, /lock-verify\/deprecated: old \(warning, does not fail the step\)/);
  });
});

// A check of the run record against schemas/run-record.v1.json: required
// properties, consts, enums and patterns, without a JSON Schema library.
function checkRunRecord(record) {
  const schema = JSON.parse(fs.readFileSync(path.join(HERE, '..', '..', 'schemas', 'run-record.v1.json'), 'utf8'));
  const check = (value, s, where) => {
    if (s.$ref) s = s.$ref.split('/').slice(1).reduce((o, k) => o[k], schema);
    if (s.oneOf) {
      const ok = s.oneOf.filter((alt) => { try { check(value, alt, where); return true; } catch { return false; } });
      assert.equal(ok.length, 1, `${where}: matches ${ok.length} of oneOf`);
      return;
    }
    if (s.const !== undefined) assert.equal(value, s.const, where);
    if (s.enum) assert.ok(s.enum.includes(value), `${where}: ${value} not in enum`);
    const types = s.type ? [].concat(s.type) : [];
    if (types.length) {
      const t = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) ? 'integer' : typeof value;
      assert.ok(types.includes(t) || (t === 'integer' && types.includes('number')), `${where}: ${t} is not ${types}`);
    }
    if (s.pattern) assert.match(value, new RegExp(s.pattern), where);
    if (s.required) for (const k of s.required) assert.ok(k in value, `${where}: missing ${k}`);
    if (s.properties && value && typeof value === 'object') for (const [k, sub] of Object.entries(s.properties)) if (k in value) check(value[k], sub, `${where}.${k}`);
    if (s.items && Array.isArray(value)) value.forEach((v, i) => check(v, s.items, `${where}[${i}]`));
  };
  check(record, schema, 'record');
}

// ---------------------------------------------------------------------------
// Registry access through curl
// ---------------------------------------------------------------------------

describe('registry access', () => {
  const TOKEN = 'npm_TestToken0123456789';
  let regA;
  let regB;
  let logA;
  let logB;
  let fixtures;
  let bin;
  let argvLog;
  const work = tmpdir('core-work-');

  before(async () => {
    fixtures = tmpdir('core-registry-');
    fs.cpSync(REGISTRY_FIXTURES, fixtures, { recursive: true });
    fs.writeFileSync(path.join(fixtures, '_overrides.json'), JSON.stringify({ 'GET /broken': { status: 500, body: 'down' } }));
    logA = path.join(work, 'a.log');
    logB = path.join(work, 'b.log');
    regA = await startFakeRegistry({ dir: fixtures, log: logA });
    regB = await startFakeRegistry({ dir: fixtures, log: logB });
    // A curl on the PATH that records its arguments, then runs the real one.
    const real = core.findCurl().path;
    bin = tmpdir('core-bin-');
    argvLog = path.join(bin, 'argv.log');
    fs.writeFileSync(path.join(bin, 'curl'), `#!/bin/sh\nprintf '%s\\n' "$@" >> '${argvLog}'\nexec '${real}' "$@"\n`, { mode: 0o755 });
  });
  after(async () => {
    await regA.close();
    await regB.close();
  });

  const requests = (log) => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
  const makeClient = (cacheDir, opts = {}) => core.createRegistryClient({
    registries: core.registryConfig({ registry: regA.url, scopes: [`@tootallnate=${regB.url}`], npmrc: false }),
    token: TOKEN, workDir: work, cacheDir, retryDelay: 1, env: { ...process.env, PATH: `${bin}:${process.env.PATH}` }, ...opts,
  });

  test('packuments: 200 then 304 keeps the cache; 404; the token only for the registry\'s origin', async () => {
    const cache = tmpdir('core-cache-');
    const client = makeClient(cache);
    const first = await client.getPackuments(['lodash', '@tootallnate/once', 'missing-package'], { pick: (doc) => Object.keys(doc.versions) });
    assert.deepEqual(first.get('lodash'), { status: 200, url: `${regA.url}lodash`, fromCache: false, packument: ['4.17.20', '4.17.21'] });
    assert.equal(first.get('@tootallnate/once').url, `${regB.url}@tootallnate%2Fonce`);
    assert.equal(first.get('@tootallnate/once').status, 200);
    assert.deepEqual(first.get('missing-package'), { status: 404, url: `${regA.url}missing-package` });

    const cached = path.join(cache, 'packuments', `127.0.0.1_${regA.port}`, 'lodash.json');
    const before = fs.readFileSync(cached);
    assert.match(fs.readFileSync(cached.replace(/\.json$/, '.etag'), 'utf8'), /^W\/"[0-9a-f]{16}"\n$/);

    const second = await client.getPackuments(['lodash']);
    assert.equal(second.get('lodash').fromCache, true);
    assert.equal(second.get('lodash').packument.name, 'lodash');
    assert.deepEqual(fs.readFileSync(cached), before, 'a 304 leaves the cached copy as it was');
    const lodash = requests(logA).filter((q) => q.path === '/lodash');
    assert.equal(lodash.length, 2);
    assert.equal(lodash[0].headers['if-none-match'], undefined);
    assert.match(lodash[1].headers['if-none-match'], /^W\//);
    assert.equal(lodash[1].headers.accept, 'application/json');

    for (const q of requests(logA)) assert.equal(q.headers.authorization, `Bearer ${TOKEN}`, q.path);
    assert.ok(requests(logB).length > 0);
    for (const q of requests(logB)) assert.equal(q.headers.authorization, undefined, q.path);

    const argv = fs.readFileSync(argvLog, 'utf8');
    assert.ok(argv.includes('-K') && argv.includes('--parallel'), 'curl ran through the wrapper');
    assert.ok(!argv.includes(TOKEN), 'the token is never on curl\'s command line');
    const leftovers = [];
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { if (e.isDirectory()) walk(path.join(d, e.name)); else if (e.name === 'config') leftovers.push(e.name); } };
    walk(work);
    assert.deepEqual(leftovers, [], 'the curl config holding the token is removed');
  });

  test('a corrupt cached copy is fetched again', async () => {
    const cache = tmpdir('core-cache-');
    const client = makeClient(cache);
    await client.getPackuments(['lodash']);
    fs.writeFileSync(path.join(cache, 'packuments', `127.0.0.1_${regA.port}`, 'lodash.json'), '{"truncated');
    const again = await client.getPackuments(['lodash']);
    assert.deepEqual([again.get('lodash').status, again.get('lodash').fromCache], [200, false]);
  });

  test('JS_SECURITY_TEST_RETRIES sets the context client\'s retries, for tests only', async () => {
    const env = { ...process.env, PARAM_OUTPUT_DIR: tmpdir('core-out-'), PARAM_REGISTRY: regA.url, XDG_CACHE_HOME: tmpdir('core-cache-') };
    for (const [value, sent] of [['0', 1], ['1', 2]]) {
      const ctx = core.createContext('audit', { env: { ...env, JS_SECURITY_TEST_RETRIES: value }, cwd: tmpdir('core-empty-') });
      const before = requests(logA).filter((q) => q.path === '/broken').length;
      const [r] = await ctx.client.fetchMany([{ url: `${regA.url}broken` }]);
      assert.equal(r.status, 500);
      assert.equal(requests(logA).filter((q) => q.path === '/broken').length - before, sent, value);
    }
  });

  test('a 500 after retries, and a transfer that fails, are errors for that request', async () => {
    const before = requests(logA).filter((q) => q.path === '/broken').length;
    const [r] = await makeClient(tmpdir(), { retries: 2 }).fetchMany([{ url: `${regA.url}broken` }]);
    assert.deepEqual([r.status, r.error], [500, 'HTTP 500']);
    assert.equal(requests(logA).filter((q) => q.path === '/broken').length - before, 3, 'one request and two retries');
    const [down] = await makeClient(tmpdir(), { retries: 0 }).fetchMany([{ url: 'http://127.0.0.1:1/x' }]);
    assert.equal(down.status, 0);
    assert.match(down.error, /^the transfer failed/);
  });

  test('attestations: fetched once, then from the cache; 404 when there are none', async () => {
    const client = makeClient(tmpdir('core-cache-'));
    const items = [{ name: 'semver', version: '7.8.5' }, { name: 'lodash', version: '4.17.21' }];
    const first = await client.getAttestations(items);
    assert.deepEqual([first.get('semver@7.8.5').status, first.get('semver@7.8.5').attestations.length], [200, 2]);
    assert.equal(first.get('lodash@4.17.21').status, 404);
    const count = requests(logA).filter((q) => q.path.startsWith('/-/npm/v1/attestations/semver')).length;
    const second = await client.getAttestations(items);
    assert.equal(second.get('semver@7.8.5').fromCache, true);
    assert.equal(requests(logA).filter((q) => q.path.startsWith('/-/npm/v1/attestations/semver')).length, count);
    assert.equal(client.attestationUrl('@sigstore/bundle', '5.0.0', 'https://registry.npmjs.org/'), 'https://registry.npmjs.org/-/npm/v1/attestations/@sigstore%2Fbundle@5.0.0');
  });

  test('POST: a gzipped bulk advisory request', async () => {
    const body = path.join(work, 'bulk.json.gz');
    fs.writeFileSync(body, zlib.gzipSync(JSON.stringify({ minimist: ['0.0.8'], lodash: ['4.17.21'] })));
    const [r] = await makeClient(tmpdir()).fetchMany([{ url: `${regA.url}-/npm/v1/security/advisories/bulk`, bodyFile: body, headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' } }]);
    assert.equal(r.status, 200);
    const answer = JSON.parse(fs.readFileSync(r.file, 'utf8'));
    assert.deepEqual(answer.minimist.map((a) => a.url.split('/').pop()).sort(), ['GHSA-vh95-rmgr-6w4m', 'GHSA-xvch-5gv4-984h']);
    assert.ok(answer.lodash.every((a) => a.vulnerable_versions.includes('4.17.2')), 'only advisories affecting 4.17.21');
    const posted = requests(logA).filter((q) => q.method === 'POST').pop();
    assert.equal(JSON.parse(posted.body).minimist[0], '0.0.8');
  });

  test('URLs are checked before curl runs', async () => {
    const client = makeClient(tmpdir());
    await assert.rejects(client.fetchMany([{ url: 'http://example.com/x' }]), /only https, or http to localhost/);
    await assert.rejects(client.fetchMany([{ url: 'https://u:p@example.com/x' }]), /holds credentials/);
  });

  test('curl must be on the PATH and recent enough', () => {
    const old = tmpdir('core-oldcurl-');
    fs.writeFileSync(path.join(old, 'curl'), '#!/bin/sh\necho "curl 7.68.0 (x86_64-pc-linux-gnu) libcurl/7.68.0"\n', { mode: 0o755 });
    assert.throws(() => core.findCurl({ PATH: old }), /curl 7\.68\.0, which is too old: this orb needs curl 7\.71\.0/);
    assert.throws(() => core.findCurl({ PATH: tmpdir() }), /curl is not on the PATH/);
  });

  test('the fake registry filters advisories as the real endpoint does', () => {
    assert.equal(satisfies('0.0.8', '<0.2.4'), true);
    assert.equal(satisfies('1.2.6', '>=1.0.0 <1.2.6'), false);
    assert.equal(satisfies('1.2.6-rc.1', '>=1.0.0 <1.2.6'), false, 'a prerelease matches only comparators of its own tuple');
    assert.equal(satisfies('1.1.9', '<=1.1'), true);
    assert.equal(satisfies('1.2.0', '<=1.1'), false);
  });
});
