// Unit tests of src/helper/signatures.mjs, offline. Each test serves a registry from
// tests/fake_registry.mjs: packuments built from the real registry data recorded in
// tests/fixtures/signatures/ (so real signatures verify) with the attestation responses of
// tests/fixtures/attestations/ (so real bundles verify), plus the packages in
// tests/fixtures/signatures_cmd/extra-packuments.json. Tampered, unsupported and downgrade cases
// are made from them per test. The projects are the lockfiles in tests/fixtures/signatures_cmd/,
// copied to a temporary directory, and the command runs through core's runCommand, with curl.

import { test, describe, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as core from '../../src/helper/core.mjs';
import * as sig from '../../src/helper/signatures.mjs';
import { verifyAttestations } from '../../src/helper/sigstore.mjs';
import { startFakeRegistry } from '../fake_registry.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const MODULE = path.join(HERE, '..', '..', 'src', 'helper', 'signatures.mjs');
const FIXTURES = path.join(HERE, '..', 'fixtures');
const OWN = path.join(FIXTURES, 'signatures_cmd');
const SLICES = ['semver@7.5.1', 'semver@7.8.6', 'axios@1.9.0', 'vite@8.3.5', '@babel__core@8.1.0', '@tanstack__react-query@5.51.1', 'lodash@4.17.21', 'jest@0.0.7'];
const ATTESTED = ['semver@7.5.1', 'semver@7.8.6', 'axios@1.9.0', 'vite@8.3.5', '@babel__core@8.1.0', '@tanstack__react-query@5.51.1'];
const UNKNOWN_KEY = `SHA256:${Buffer.alloc(32, 7).toString('base64').replace(/=+$/, '')}`;

const readJson = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const slice = (slug) => readJson(path.join(FIXTURES, 'signatures', `${slug}.json`));
const made = [];
const tmpdir = (prefix = 'sig-test-') => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  made.push(dir);
  return dir;
};
const flipBase64 = (s, i = 12) => {
  const b = Buffer.from(s, 'base64');
  b[i % b.length] ^= 1;
  return b.toString('base64');
};

// The packuments and attestation responses a registry serves: {docs: {name: packument},
// attestations: {"name@version": response}}.
function registryData() {
  const docs = {};
  for (const slug of SLICES) {
    const s = slice(slug);
    const d = (docs[s.name] ??= { _id: s.name, name: s.name, 'dist-tags': {}, versions: {}, time: { created: '2011-01-01T00:00:00.000Z' } });
    d.versions[s.version] = { name: s.name, version: s.version, dist: structuredClone(s.dist) };
    d.time[s.version] = s.time;
  }
  const extra = readJson(path.join(OWN, 'extra-packuments.json')).registry;
  for (const [name, p] of Object.entries(extra)) addPackument(docs, name, p);
  const attestations = {};
  for (const slug of ATTESTED) {
    const s = slice(slug);
    attestations[`${s.name}@${s.version}`] = readJson(path.join(FIXTURES, 'attestations', `${slug}.json`));
  }
  return { docs, attestations };
}

function addPackument(docs, name, p) {
  const d = (docs[name] ??= { _id: name, name, 'dist-tags': {}, versions: {}, time: {} });
  for (const [v, m] of Object.entries(p.versions)) d.versions[v] = { name, version: v, ...structuredClone(m) };
  Object.assign(d.time, p.time ?? {});
}

function writeRegistry(dir, { docs, attestations }, overrides) {
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  for (const [name, doc] of Object.entries(docs)) {
    const file = path.join(dir, 'packuments', `${name}.json`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(doc));
  }
  for (const [spec, body] of Object.entries(attestations)) {
    const file = path.join(dir, 'attestations', `${spec}.json`);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, JSON.stringify(body));
  }
  if (overrides) fs.writeFileSync(path.join(dir, '_overrides.json'), JSON.stringify(overrides));
}

const servers = [];
after(async () => {
  for (const s of servers) await s.close();
  for (const dir of made) fs.rmSync(dir, { recursive: true, force: true });
});

// Starts a fake registry serving DATA (after MUTATE(data)), with a request log.
async function serve(mutate, { overrides, data = registryData() } = {}) {
  if (mutate) mutate(data);
  const dir = tmpdir('sig-registry-');
  writeRegistry(dir, data, overrides);
  const log = path.join(dir, 'requests.log');
  const server = await startFakeRegistry({ dir, log });
  servers.push(server);
  const requests = () => (fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
  return { ...server, dir, requests };
}

// A private registry: the extra packuments' "private" packages, without signatures.
async function servePrivate() {
  const docs = {};
  for (const [name, p] of Object.entries(readJson(path.join(OWN, 'extra-packuments.json')).private)) addPackument(docs, name, p);
  return serve(null, { data: { docs, attestations: {} } });
}

// A copy of a fixture project, after EDIT(lockfile text) when given.
function project(name, edit) {
  const dir = tmpdir('sig-project-');
  fs.cpSync(path.join(OWN, name), dir, { recursive: true });
  if (edit) {
    const file = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'].map((f) => path.join(dir, f)).find((f) => fs.existsSync(f));
    fs.writeFileSync(file, edit(fs.readFileSync(file, 'utf8')));
  }
  return dir;
}
// The 1-based line of the first line of DIR/FILE that holds NEEDLE.
const lineIn = (dir, file, needle) => fs.readFileSync(path.join(dir, file), 'utf8').split('\n').findIndex((l) => l.includes(needle)) + 1;
const editLock = (fn) => (text) => {
  const lock = JSON.parse(text);
  fn(lock.packages);
  return JSON.stringify(lock, null, 2);
};

// Runs the command in PROJECT against REGISTRY with PARAMS (and EXTRAENV); reads the reports back.
async function run(projectDir, registry, params = {}, extraEnv = {}) {
  const out = [];
  const err = [];
  const outputDir = tmpdir('sig-out-');
  const env = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    XDG_CACHE_HOME: tmpdir('sig-cache-'),
    // No user npmrc unless a test gives one.
    NPM_CONFIG_USERCONFIG: path.join(tmpdir('sig-home-'), 'none', '.npmrc'),
    PARAM_REGISTRY: registry.url,
    PARAM_OUTPUT_DIR: outputDir,
    ...Object.fromEntries(Object.entries(params).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, String(v)])),
    ...extraEnv,
  };
  const code = await core.runCommand('signatures', sig.run, { env, cwd: projectDir, stdout: (s) => out.push(s), stderr: (s) => err.push(s) });
  const name = params.report_name ?? 'signatures';
  const maybe = (f) => (fs.existsSync(path.join(outputDir, f)) ? fs.readFileSync(path.join(outputDir, f), 'utf8') : null);
  const json = maybe(`${name}.json`);
  const sarif = maybe(`${name}.sarif`);
  const record = maybe(`${name}.run-record.json`);
  return {
    code, out: out.join(''), err: err.join(''), outputDir,
    json: json && JSON.parse(json), sarif: sarif && JSON.parse(sarif), junit: maybe(`junit/${name}.xml`), record: record && JSON.parse(record),
  };
}

const kinds = (r) => r.json.findings.map((f) => `${f.kind} ${f.package.name}@${f.package.version}`).sort();
const result = (r, name, version) => {
  const hits = r.json.results.filter((x) => x.name === name && x.version === version);
  assert.equal(hits.length, 1, `one result for ${name}@${version}`);
  return hits[0];
};
const finding = (r, kind, name) => {
  const hits = r.json.findings.filter((f) => f.kind === kind && f.package.name === name);
  assert.equal(hits.length, 1, `one ${kind} finding for ${name}: ${JSON.stringify(r.json.findings.map((f) => f.message))}`);
  return hits[0];
};
const attestationRequests = (reg) => reg.requests().filter((q) => q.path.startsWith('/-/npm/v1/attestations/')).map((q) => decodeURIComponent(q.path.slice(23))).sort();

// ---------------------------------------------------------------------------
describe('the module', () => {
  test('is under 120,000 bytes and imports only node: built-ins and its sibling modules', () => {
    assert.ok(fs.statSync(MODULE).size < 120000, `${fs.statSync(MODULE).size} bytes`);
    const source = fs.readFileSync(MODULE, 'utf8');
    const imports = [...source.matchAll(/^\s*import\b[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]).sort();
    assert.deepEqual(imports, ['./core.mjs', './sigstore.mjs']);
    assert.doesNotMatch(source, /\brequire\s*\(|\bimport\s*\(/);
  });

  test('run as a script, it reads PARAM_ variables and a bad one exits 2', () => {
    const out = tmpdir('sig-out-');
    const r = spawnSync(process.execPath, [MODULE], {
      cwd: project('npm'), encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NPM_CONFIG_USERCONFIG: '/nonexistent/.npmrc', PARAM_OUTPUT_DIR: out, PARAM_NO_DOWNGRADE: 'maybe' },
    });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /^ERROR: no_downgrade must be true or false/m);
  });
});

// ---------------------------------------------------------------------------
describe('helpers', () => {
  test('provenance_sources: lines pattern=REPOSITORY, merged by pattern', () => {
    const g = sig.parseProvenanceSources(['react=https://github.com/facebook/react', '@corp/* = id:00123,https://gitlab.com/corp/mono.git', 'react=id:10270250']);
    assert.deepEqual(g.map((x) => [x.pattern.text, x.repos.map((r) => r.text)]), [
      ['react', ['https://github.com/facebook/react', 'id:10270250']],
      ['@corp/*', ['id:00123', 'https://gitlab.com/corp/mono.git']],
    ]);
    assert.deepEqual(g[1].repos.map((r) => r.id ?? r.url), ['123', 'https://gitlab.com/corp/mono']);
    for (const bad of ['react', 'react=', 'react=http://github.com/facebook/react', 'react=https://github.com/facebook', 'react=id:abc',
      'react=https://u:p@github.com/a/b', 'react=https://github.com/a/b?x=1', 'react@18=https://github.com/a/b', 'bad name!=id:1']) {
      assert.throws(() => sig.parseProvenanceSources([bad]), core.UsageError, bad);
    }
  });

  test('repositories match by URL (case-insensitively, without .git or /) or by ID from GitHub Actions', () => {
    const id = { issuer: sig.GITHUB_ISSUER, sourceRepositoryUri: 'https://github.com/TanStack/query', sourceRepositoryId: '207645083' };
    const [g] = sig.parseProvenanceSources(['x=https://github.com/tanstack/QUERY.git/,id:0207645083,id:1']);
    assert.deepEqual(g.repos.map((r) => sig.repositoryMatches(id, r)), [true, true, false]);
    assert.equal(sig.repositoryMatches({ ...id, issuer: 'https://gitlab.com' }, g.repos[1]), false, 'id: is GitHub Actions only');
    assert.equal(sig.repositoryMatches(null, g.repos[0]), false);
  });

  test('trust evidence, as pnpm 11.4 and later rank it', () => {
    const prov = { dist: { attestations: { provenance: { predicateType: 'https://slsa.dev/provenance/v1' } } } };
    assert.equal(sig.trustEvidence({ dist: {} }), 'none');
    assert.equal(sig.trustEvidence(prov), 'provenance');
    assert.equal(sig.trustEvidence({ ...prov, _npmUser: { trustedPublisher: { id: 'github' } } }), 'trusted-publisher');
    assert.equal(sig.trustEvidence({ dist: {}, _npmUser: { trustedPublisher: { id: 'github' } } }), 'none', 'a trusted publisher needs provenance');
    assert.equal(sig.trustEvidence({ dist: {}, _npmUser: { approver: { name: 'x' } } }), 'staged-publish');
    assert.equal(sig.trustEvidence(null), 'none');
  });

  test('prereleases, as node-semver (loose) tells them', () => {
    for (const v of ['1.0.0-beta.1', '1.0.0-0', 'v2.0.0-rc.1+build', '1.2.3beta']) assert.equal(sig.isPrerelease(v), true, v);
    for (const v of ['1.0.0', '1.0.0+build.5', 'v1.0.0', 'not-semver', '1.0']) assert.equal(sig.isPrerelease(v), false, v);
  });

  test('findDowngrade: earlier by time only, stable versions ignore prereleases', () => {
    const t = (d) => Date.parse(d);
    const history = [
      ['1.0.0', t('2020-01-01'), 'provenance'],
      ['2.0.0-beta.1', t('2021-01-01'), 'trusted-publisher'],
      ['3.0.0', t('2023-01-01'), 'trusted-publisher'],
      ['0.9.9', t('2022-01-01'), 'none'],
    ];
    assert.equal(sig.findDowngrade(history, '1.0.1', t('2021-06-01'), 'none').version, '1.0.0');
    assert.equal(sig.findDowngrade(history, '1.0.1', t('2021-06-01'), 'provenance'), null);
    assert.equal(sig.findDowngrade(history, '2.0.0-beta.2', t('2021-06-01'), 'provenance').version, '2.0.0-beta.1', 'a prerelease compares with all');
    assert.equal(sig.findDowngrade(history, '0.9.9', t('2022-01-01'), 'none').version, '1.0.0', 'by time, not semver');
    assert.equal(sig.findDowngrade(history, '1.0.0', t('2020-01-01'), 'none'), null, 'nothing earlier');
    assert.equal(sig.findDowngrade(history, '3.0.1', t('2024-01-01'), 'provenance').version, '3.0.0');
  });

  test('bindIntegrity: sha512 binds; sha1 must match the registry; unbound uses the registry\'s', () => {
    const P = slice('lodash@4.17.21').dist;
    const dist = { integrity: P.integrity, shasum: P.shasum };
    assert.deepEqual(sig.bindIntegrity(P.integrity, null, dist), { status: 'lockfile', integrity: P.integrity });
    const both = `${P.integrity} sha1-${Buffer.from(P.shasum, 'hex').toString('base64')}`;
    assert.deepEqual(sig.bindIntegrity(both, null, dist), { status: 'lockfile', integrity: P.integrity }, 'the string the registry signed');
    assert.deepEqual(sig.bindIntegrity(slice('axios@1.9.0').dist.integrity, null, dist), { status: 'mismatch' });
    assert.deepEqual(sig.bindIntegrity(P.integrity, null, { integrity: null, shasum: P.shasum }), { status: 'mismatch' });
    const sha1 = `sha1-${Buffer.from(P.shasum, 'hex').toString('base64')}`;
    assert.deepEqual(sig.bindIntegrity(sha1, 'weak', dist), { status: 'registry', integrity: P.integrity });
    assert.deepEqual(sig.bindIntegrity(`sha1-${Buffer.alloc(20, 1).toString('base64')}`, 'weak', dist), { status: 'mismatch' });
    assert.deepEqual(sig.bindIntegrity('10c0/abc', 'berry', dist), { status: 'registry', integrity: P.integrity });
    assert.equal(sig.unboundReason({ integrity: sha1, integrityAlgos: ['sha1'], integrityKind: 'sri' }), 'weak');
    assert.equal(sig.unboundReason({ integrity: null, integrityAlgos: [], integrityKind: null }), 'none');
    assert.equal(sig.unboundReason({ integrity: null, integrityAlgos: [], integrityKind: null }, 'berry'), 'berry');
    assert.equal(sig.unboundReason({ integrity: P.integrity, integrityAlgos: ['sha512'], integrityKind: 'tar' }), 'tar');
    assert.equal(sig.unboundReason({ integrity: P.integrity, integrityAlgos: ['sha512'], integrityKind: 'sri' }), null);
  });

  test('every rule has a description', () => {
    assert.deepEqual(Object.keys(sig.RULES).sort(), [
      'integrity-mismatch', 'invalid', 'invalid-attestation', 'missing-provenance', 'not-in-registry', 'provenance-downgrade',
      'provenance-source', 'unsigned', 'unsupported-attestation',
    ].map((k) => `signatures/${k}`));
    for (const r of Object.values(sig.RULES)) assert.ok(r.description.length > 40);
  });
});

// ---------------------------------------------------------------------------
describe('registry signatures', () => {
  test('real signatures and attestations verify, and the reports say so', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, { run_record: 'true' });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.findings, []);
    assert.deepEqual(r.json.errors, []);
    assert.equal(r.json.schema, 'js-security-orb/signatures/v1');
    assert.equal(r.json.results.length, 7);
    for (const x of r.json.results) {
      assert.equal(x.signature, 'valid', x.name);
      assert.equal(x.integrity, 'lockfile', x.name);
    }
    assert.deepEqual(result(r, 'lodash', '4.17.21').attestations, { status: 'none' });
    assert.equal(result(r, 'lodash', '4.17.21').provenance, null);
    const semver = result(r, 'semver', '7.8.6');
    assert.deepEqual([semver.attestations.status, semver.attestations.publish, semver.attestations.provenance], ['valid', 'valid', 'valid']);
    assert.deepEqual([semver.provenance.repository, semver.provenance.repository_id, semver.provenance.issuer], ['https://github.com/npm/node-semver', '1357199', sig.GITHUB_ISSUER]);
    assert.equal(semver.trust, 'provenance');
    const babel = result(r, '@babel/core', '8.1.0');
    assert.deepEqual([babel.attestations.publish, babel.attestations.provenance], [null, 'valid'], 'provenance only: no publish attestation');
    assert.equal(result(r, 'semver', '7.5.1').provenance.repository, 'https://github.com/npm/node-semver');
    assert.deepEqual(r.json.summary.signatures.valid, 7);
    assert.deepEqual([r.json.summary.attestations.verified, r.json.summary.attestations.with_provenance], [6, 6]);
    assert.deepEqual(r.json.skipped.map((s) => [s.name, s.reason]), [['signatures-fixture', 'not-from-a-registry']]);
    assert.match(r.out, /Checked 7 package versions from 1 lockfile: 7 registry signatures verified, 6 packages with verified attestations \(6 with provenance\)/);
    // Packuments are full ones; attestations only where the packument advertises them.
    const docs = reg.requests().filter((q) => !q.path.startsWith('/-/'));
    assert.ok(docs.length >= 6 && docs.every((q) => q.headers.accept === 'application/json'));
    assert.deepEqual(attestationRequests(reg), ['@babel/core@8.1.0', '@tanstack/react-query@5.51.1', 'axios@1.9.0', 'semver@7.5.1', 'semver@7.8.6', 'vite@8.3.5']);
    assert.equal(r.sarif.runs[0].results.length, 0);
    assert.match(r.junit, /<testcase classname="signatures" name="no findings">/);
    assert.equal(r.record.outcome, 'passed');
    assert.equal(r.record.counts.signatures_valid, 7);
    assert.equal(r.record.results.length, 7);
  });

  test('include_dev false leaves a dev-only package out', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, { include_dev: 'false' });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.json.results.some((x) => x.name === '@tanstack/react-query'), false);
  });

  test('an integrity the registry did not publish is integrity-mismatch, and its attestations are not fetched', async () => {
    const reg = await serve();
    const other = slice('axios@1.9.0').dist.integrity;
    const dir = project('npm', editLock((p) => { p['node_modules/semver'].integrity = other; }));
    const line = lineIn(dir, 'package-lock.json', '"node_modules/semver": {');
    assert.ok(line > 1);
    const r = await run(dir, reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['integrity-mismatch semver@7.8.6']);
    const f = finding(r, 'integrity-mismatch', 'semver');
    assert.match(f.message, /^semver@7\.8\.6 in package-lock\.json: the lockfile's integrity \(sha512-re4CqKTJaURpzbLHtIi6…\) is not the registry's \(sha512-9lpSSU4Mly3mrtruwLs1…\)/);
    assert.equal(f.lockfile, 'package-lock.json');
    assert.equal(f.line, line);
    assert.equal(f.details.lockfile_integrity, other);
    assert.ok(!attestationRequests(reg).includes('semver@7.8.6'));
    assert.equal(result(r, 'semver', '7.8.6').integrity, 'mismatch');
    assert.equal(result(r, 'semver', '7.5.1').signature, 'valid', 'the nested semver is another unit');
    const rule = r.sarif.runs[0].tool.driver.rules.find((x) => x.id === 'signatures/integrity-mismatch');
    assert.equal(rule.shortDescription.text, sig.RULES['signatures/integrity-mismatch'].description);
    assert.equal(r.sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, line);
    assert.match(r.junit, /failures="1"/);
    assert.match(r.err, /^ERROR: 1 finding of signatures fails the gate\./m);
  });

  test('findings are one per lockfile: the same package in two lockfiles is reported in each', async () => {
    const reg = await serve();
    const other = slice('axios@1.9.0').dist.integrity;
    const edit = editLock((p) => { p['node_modules/semver'].integrity = other; });
    const dir = project('npm', edit);
    fs.mkdirSync(path.join(dir, 'sub'));
    fs.writeFileSync(path.join(dir, 'sub', 'package-lock.json'), edit(fs.readFileSync(path.join(OWN, 'npm', 'package-lock.json'), 'utf8')));
    const r = await run(dir, reg, { lockfiles: 'package-lock.json, sub/package-lock.json' });
    assert.equal(r.code, 1);
    assert.deepEqual(r.json.findings.map((f) => [f.kind, f.lockfile]).sort(), [['integrity-mismatch', 'package-lock.json'], ['integrity-mismatch', 'sub/package-lock.json']]);
    assert.deepEqual(result(r, 'semver', '7.8.6').lockfiles, ['package-lock.json', 'sub/package-lock.json'], 'one result per package version and integrity');
    assert.match(r.json.findings.find((f) => f.lockfile.startsWith('sub/')).message, /^semver@7\.8\.6 in sub\/package-lock\.json: /);
  });

  test('a tampered signature is invalid', async () => {
    const reg = await serve((d) => {
      const s = d.docs.axios.versions['1.9.0'].dist.signatures[0];
      s.sig = flipBase64(s.sig, 20);
    });
    const r = await run(project('npm'), reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['invalid axios@1.9.0']);
    assert.match(finding(r, 'invalid', 'axios').message, /^axios@1\.9\.0 in package-lock\.json: its registry signature is invalid: the signature by key SHA256:DhQ8wR5A\S+ does not verify/);
  });

  test('a package the registry publishes without a signature is unsigned, since the registry signs others', async () => {
    const reg = await serve();
    const lock = editLock((p) => { p['node_modules/unsigned-pkg'] = { version: '1.0.0', integrity: registryData().docs['unsigned-pkg'].versions['1.0.0'].dist.integrity }; });
    const r = await run(project('npm', lock), reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['unsigned unsigned-pkg@1.0.0']);
    assert.match(finding(r, 'unsigned', 'unsigned-pkg').message, /it has no registry signature, but http:\/\/127\.0\.0\.1:\d+\/ signs other packages\./);
    assert.deepEqual(r.json.summary.registries, [{ url: reg.url, signs: true, packages: 8 }]);
  });

  test('a signature by a key the orb does not know is no verdict, whatever report_only says', async () => {
    const reg = await serve((d) => { d.docs.semver.versions['7.8.6'].dist.signatures[1].keyid = UNKNOWN_KEY; });
    const r = await run(project('npm'), reg, { report_only: 'true' });
    assert.equal(r.code, 1);
    assert.deepEqual(r.json.findings, []);
    assert.equal(r.json.outcome, 'error');
    assert.match(r.err, new RegExp(`^ERROR: 1 package is signed with a registry key this orb doesn't know \\(${UNKNOWN_KEY.replace(/[+/]/g, '\\$&')}\\): .* so it has no verdict: semver@7\\.8\\.6 \\(package-lock\\.json\\)\\.$`, 'm'));
    assert.equal(result(r, 'semver', '7.8.6').signature, 'unknown-key');
  });

  test('a version or package the registry does not have is not-in-registry', async () => {
    const reg = await serve();
    const lock = editLock((p) => {
      p['node_modules/ghost-pkg'] = { version: '1.0.0', integrity: slice('lodash@4.17.21').dist.integrity };
      p['node_modules/vite'].version = '8.3.4';
    });
    const r = await run(project('npm', lock), reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['not-in-registry ghost-pkg@1.0.0', 'not-in-registry vite@8.3.4']);
    assert.match(finding(r, 'not-in-registry', 'ghost-pkg').message, /has no package ghost-pkg \(HTTP 404\)/);
    assert.match(finding(r, 'not-in-registry', 'vite').message, /lists no version 8\.3\.4 of vite/);
  });

  test('a packument that can\'t be fetched is no verdict', async () => {
    const reg = await serve(null, { overrides: { 'GET /axios': { status: 403, body: { error: 'forbidden' } } } });
    const r = await run(project('npm'), reg, { report_only: 'true' });
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: Could not read 1 packument from http:\/\/127\.0\.0\.1:\d+\/, so that package has no verdict: axios \(HTTP 403\)\. If the registry needs a login, set token to the name of a variable holding a token for it\.$/m);
    assert.equal(result(r, 'axios', '1.9.0').signature, 'error');
    assert.match(r.out, /^Checked 7 package versions from 1 lockfile: 6 registry signatures verified, .*\. The check is incomplete \(see the errors\), so it has no verdict\.$/m);
    assert.equal(result(r, 'lodash', '4.17.21').signature, 'valid', 'the others are still checked');
  });
});

// ---------------------------------------------------------------------------
describe('registries without signatures, and entries no registry signs', () => {
  test('a private registry\'s unsigned packages are skipped with a warning, never passed', async () => {
    const reg = await serve();
    const priv = await servePrivate();
    const r = await run(project('private'), reg, { scopes: `@corp=${priv.url}` });
    assert.equal(r.code, 0, r.err);
    assert.ok(r.err.includes(`WARN: 1 package was not checked, since ${priv.url} has no registry signatures on any packument this check read: @corp/private-lib@1.0.0. It is listed under skipped in the report. Set require_signatures to true to make that a finding.\n`), r.err);
    assert.deepEqual(r.json.skipped.filter((s) => s.reason === 'unsigned-registry').map((s) => s.name), ['@corp/private-lib']);
    assert.equal(result(r, '@corp/private-lib', '1.0.0').signature, 'skipped');
    assert.equal(result(r, 'lodash', '4.17.21').signature, 'valid');
    assert.deepEqual(r.json.summary.registries.map((x) => [x.url, x.signs]).sort(), [[reg.url, true], [priv.url, false]].sort());
    assert.ok(priv.requests().some((q) => q.path === '/@corp%2Fprivate-lib'));
  });

  test('a provenance policy still applies to a registry that signs nothing', async () => {
    const reg = await serve();
    const priv = await servePrivate();
    const r = await run(project('private'), reg, { scopes: `@corp=${priv.url}`, require_provenance: '@corp/*' });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['missing-provenance @corp/private-lib@1.0.0']);
  });

  test('require_signatures makes them unsigned findings', async () => {
    const reg = await serve();
    const priv = await servePrivate();
    const r = await run(project('private'), reg, { scopes: `@corp=${priv.url}`, require_signatures: 'true' });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['unsigned @corp/private-lib@1.0.0']);
    assert.match(finding(r, 'unsigned', '@corp/private-lib').message, /but require_signatures is true\.$/);
  });

  test('when every package is skipped, the check checked nothing, unless allow_empty', async () => {
    const priv = await servePrivate();
    const r = await run(project('only-private'), priv);
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: No registry signature was checked: every package from a registry was skipped/m);
    const ok = await run(project('only-private'), priv, { allow_empty: 'true' });
    assert.equal(ok.code, 0, ok.err);
  });

  test('git, local, bundled and other registries\' entries are listed as skipped, and never fetched', async () => {
    const reg = await serve();
    const r = await run(project('mixed'), reg);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.skipped.map((s) => [s.name, s.reason]).sort(), [
      ['inside', 'bundled'], ['is-git', 'not-from-a-registry'], ['local-lib', 'not-from-a-registry'],
      ['other', 'other-registry'], ['signatures-mixed', 'not-from-a-registry'],
    ]);
    assert.ok(r.err.includes('WARN: 1 package was not checked, since the lockfile records https://registry.example.com/, which is neither registry nor a scope\'s registry (scopes, .npmrc or .yarnrc.yml): other@1.0.0. It is listed under skipped in the report.\n'), r.err);
    assert.ok(r.err.includes('WARN: 1 package was not checked, since no registry signs packages from git or a tarball URL: is-git@1.0.0. It is listed under skipped in the report.\n'), r.err);
    assert.equal(r.json.skipped.find((x) => x.name === 'other').source, 'https://registry.example.com/');
    assert.match(r.out, /Not checked: 3 not from a registry, 1 bundled, 1 from another registry\./);
    assert.deepEqual(reg.requests().map((q) => q.path), ['/lodash']);
  });

  test('packages recorded on registry.npmjs.org are checked against registry, a mirror, as npm installs them', async () => {
    const reg = await serve();
    const npmjs = editLock((p) => {
      for (const [key, v] of Object.entries(p)) {
        if (!key) continue;
        const name = key.slice(key.lastIndexOf('node_modules/') + 13);
        v.resolved = `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${v.version}.tgz`;
      }
    });
    const r = await run(project('npm', npmjs), reg);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.skipped.map((x) => [x.name, x.reason]), [['signatures-fixture', 'not-from-a-registry']]);
    assert.equal(r.json.results.length, 7);
    assert.ok(r.json.results.every((x) => x.signature === 'valid' && x.registry === reg.url));
    assert.ok(reg.requests().some((q) => q.path === '/@babel%2Fcore'));
  });

  test('a 401 or 403 from a scope\'s registry on another origin skips its packages; on registry\'s origin it is no verdict', async () => {
    const reg = await serve();
    const priv = await servePrivate();
    fs.writeFileSync(path.join(priv.dir, '_overrides.json'), JSON.stringify({ 'GET /@corp%2Fprivate-lib': { status: 401, body: { error: 'unauthorized' } } }));
    const r = await run(project('private'), reg, { scopes: `@corp=${priv.url}`, token: 'SIG_TEST_TOKEN' }, { SIG_TEST_TOKEN: 'npm_SigTestToken' });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.skipped.filter((x) => x.reason === 'unauthorized').map((x) => [x.name, x.detail]),
      [['@corp/private-lib', `${priv.url} answered HTTP 401, and the token goes only to registry's origin`]]);
    assert.ok(r.err.includes(`WARN: 1 package was not checked, since ${priv.url} answered HTTP 401, and the token goes only to registry's origin: @corp/private-lib@1.0.0.`), r.err);
    assert.equal(r.json.summary.skipped.unauthorized, 1);
    assert.equal(result(r, 'lodash', '4.17.21').signature, 'valid');
    assert.ok(priv.requests().every((q) => q.headers.authorization === undefined), 'no token for another origin');

    const own = await run(project('private'), priv, { token: 'SIG_TEST_TOKEN', allow_empty: 'true' }, { SIG_TEST_TOKEN: 'npm_SigTestToken' });
    assert.equal(own.code, 1);
    assert.match(own.err, /^ERROR: Could not read 1 packument from .*: @corp\/private-lib \(HTTP 401\)\. Check the token in SIG_TEST_TOKEN\.$/m);
  });
});

// ---------------------------------------------------------------------------
describe('integrity that can\'t be bound', () => {
  test('a Yarn Berry lockfile has no verdict without allow_unbound, and nothing is fetched', async () => {
    const reg = await serve();
    const r = await run(project('berry'), reg);
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: yarn\.lock: 2 packages from a registry have no integrity this check can bind the registry's signature to \(Yarn Berry's checksums are of its own zip archives\), so this lockfile has no verdict: lodash@4\.17\.21, semver@7\.8\.6\.$/m);
    assert.match(r.err, /^ERROR: Set allow_unbound to true/m);
    assert.deepEqual(reg.requests(), []);
    assert.deepEqual(r.json.skipped.filter((s) => s.reason === 'unbound').map((s) => s.name), ['lodash', 'semver']);
  });

  test('with allow_unbound, a Yarn Berry lockfile is verified against the registry\'s integrity, with a warning', async () => {
    const reg = await serve();
    const r = await run(project('berry'), reg, { allow_unbound: 'true', require_provenance: 'semver' });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^WARN: yarn\.lock: 2 packages were verified against the registry's own integrity, since the lockfile's can't be bound/m);
    assert.deepEqual([result(r, 'semver', '7.8.6').integrity, result(r, 'semver', '7.8.6').signature, result(r, 'semver', '7.8.6').attestations.status], ['registry', 'valid', 'valid']);
    assert.equal(r.json.summary.signatures.unbound_verified, 2);
  });

  test('pnpm\'s integrityTarget: tar is unbound too', async () => {
    const reg = await serve();
    const r = await run(project('pnpm-tar'), reg);
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: pnpm-lock\.yaml: 1 package from a registry has no integrity .*\(pnpm's integrityTarget: tar hashes the unpacked tarball\)/m);
    const ok = await run(project('pnpm-tar'), reg, { allow_unbound: 'true' });
    assert.equal(ok.code, 0, ok.err);
    assert.equal(result(ok, 'lodash', '4.17.21').signature, 'valid');
  });

  test('a sha1-only integrity: no verdict, or with allow_unbound the registry\'s view (jest@0.0.7 is unsigned)', async () => {
    const reg = await serve();
    const r = await run(project('sha1'), reg);
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: package-lock\.json: 1 package from a registry has no integrity .*only a sha1/m);
    const ok = await run(project('sha1'), reg, { allow_unbound: 'true' });
    assert.equal(ok.code, 1);
    assert.deepEqual(kinds(ok), ['unsigned jest@0.0.7'], 'lodash shows that the registry signs');
    assert.match(finding(ok, 'unsigned', 'jest').message, /it has no registry signature, but http:\S+ signs other packages\.$/);
    assert.equal(result(ok, 'lodash', '4.17.21').signature, 'valid');
    assert.equal(result(ok, 'jest', '0.0.7').integrity, 'registry');
    // A sha1 that is not the registry's shasum is a mismatch, allow_unbound or not.
    const bad = await run(project('sha1', (t) => t.replace('j8xYpPFrjvL6H3Jh7mA4a00xiIc=', Buffer.alloc(20, 3).toString('base64'))), reg, { allow_unbound: 'true' });
    assert.deepEqual(kinds(bad), ['integrity-mismatch jest@0.0.7']);
  });
});

// ---------------------------------------------------------------------------
describe('attestations', () => {
  const tamperProvenance = (spec, fn) => (d) => {
    const a = d.attestations[spec].attestations.find((x) => x.predicateType !== 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1');
    fn(a.bundle);
  };

  test('an attestation that does not verify is invalid-attestation', async () => {
    const reg = await serve(tamperProvenance('axios@1.9.0', (b) => { b.dsseEnvelope.signatures[0].sig = flipBase64(b.dsseEnvelope.signatures[0].sig); }));
    const r = await run(project('npm'), reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['invalid-attestation axios@1.9.0']);
    assert.match(finding(r, 'invalid-attestation', 'axios').message, /^axios@1\.9\.0 in package-lock\.json: an attestation http:\S+ serves for it does not verify: "https:\/\/slsa\.dev\/provenance\/v1": /);
    assert.equal(result(r, 'axios', '1.9.0').provenance, null);
  });

  test('an unsupported format is a warning, or a finding when policy requires provenance', async () => {
    const reg = await serve(tamperProvenance('semver@7.8.6', (b) => { b.mediaType = 'application/vnd.dev.sigstore.bundle.v0.4+json'; }));
    const r = await run(project('npm'), reg);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^WARN: The attestations of 1 package use a format this orb can't verify yet, so they were not verified \(an orb update may support them\):\nWARN: semver@7\.8\.6 \(package-lock\.json\): "https:\/\/slsa\.dev\/provenance\/v1" \(.*media type/m);
    assert.equal(result(r, 'semver', '7.8.6').attestations.status, 'unsupported');
    const req = await run(project('npm'), reg, { require_provenance: 'semver' });
    assert.equal(req.code, 1);
    assert.deepEqual(kinds(req), ['unsupported-attestation semver@7.8.6']);
    assert.match(finding(req, 'unsupported-attestation', 'semver').message, /require_provenance \(semver\) requires provenance, but its provenance is in a format this orb can't verify yet: .*media type/);
  });

  test('attestations advertised but not served: a mirror\'s are a warning and count as no provenance', async () => {
    const reg = await serve((d) => { delete d.attestations['vite@8.3.5']; });
    const r = await run(project('npm'), reg);
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^WARN: The packuments of 1 package advertise attestations that http:\S+ does not serve \(a mirror may not serve \/-\/npm\/v1\/attestations\)/m);
    assert.equal(result(r, 'vite', '8.3.5').attestations.status, 'missing');
    const req = await run(project('npm'), reg, { require_provenance: 'vite' });
    assert.deepEqual(kinds(req), ['missing-provenance vite@8.3.5']);
    assert.match(finding(req, 'missing-provenance', 'vite').message, /the packument advertises attestations that the registry does not serve/);
  });

  test('attestations that can\'t be fetched are no verdict', async () => {
    const reg = await serve(null, { overrides: { 'GET /-/npm/v1/attestations/vite@8.3.5': { status: 403, body: {} } } });
    const r = await run(project('npm'), reg);
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: Could not read the attestations of 1 package from http:\S+, so it has no verdict: vite@8\.3\.5 \(HTTP 403\)\.$/m);
  });
});

// ---------------------------------------------------------------------------
describe('provenance policies', () => {
  test('require_provenance: a match without provenance is missing-provenance, after asking the registry', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, { require_provenance: 'lodash, @tanstack/*' });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['missing-provenance lodash@4.17.21']);
    assert.match(finding(r, 'missing-provenance', 'lodash').message, /^lodash@4\.17\.21 in package-lock\.json: it has no provenance, which require_provenance \(lodash\) requires\.$/);
    assert.ok(attestationRequests(reg).includes('lodash@4.17.21'), 'the endpoint is asked even when the packument advertises nothing');
    const all = await run(project('npm'), reg, { require_provenance: '*' });
    assert.deepEqual(kinds(all), ['missing-provenance lodash@4.17.21']);
  });

  test('provenance_sources by URL: a mismatch shows the expected and actual repository', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, {
      provenance_sources: 'semver=https://github.com/npm/node-semver\naxios=https://github.com/evil/axios\n@tanstack/*=https://github.com/tanstack/QUERY.git\n# a comment\n',
    });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['provenance-source axios@1.9.0']);
    const f = finding(r, 'provenance-source', 'axios');
    assert.equal(f.message, 'axios@1.9.0 in package-lock.json: its provenance was built from https://github.com/axios/axios (repository ID 23088740, certificate issued by https://token.actions.githubusercontent.com), but provenance_sources (axios) expects https://github.com/evil/axios.');
    assert.deepEqual([f.details.expected, f.details.repository, f.details.repository_id], [['https://github.com/evil/axios'], 'https://github.com/axios/axios', '23088740']);
  });

  test('provenance_sources by repository ID, several repositories per pattern, and the first pattern decides', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, {
      provenance_sources: [
        'vite=id:257485422',
        '@babel/core=id:1',
        'axios=https://github.com/evil/axios,id:23088740',
        'semver=https://github.com/npm/node-semver',
        'sem*=id:2',
      ].join('\n'),
    });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['provenance-source @babel/core@8.1.0']);
    assert.match(finding(r, 'provenance-source', '@babel/core').message, /built from https:\/\/github\.com\/babel\/babel \(repository ID 24560307, certificate issued by https:\/\/token\.actions\.githubusercontent\.com\), but provenance_sources \(@babel\/core\) expects id:1\.$/);
  });

  test('a package a source rule names needs provenance', async () => {
    const reg = await serve();
    const r = await run(project('npm'), reg, { provenance_sources: 'lodash=https://github.com/lodash/lodash' });
    assert.deepEqual(kinds(r), ['missing-provenance lodash@4.17.21']);
    assert.match(finding(r, 'missing-provenance', 'lodash').message, /which provenance_sources \(lodash\) requires\.$/);
  });

  test('a bad parameter exits 2 before any request', async () => {
    const reg = await serve();
    for (const [param, value, pattern] of [
      ['provenance_sources', 'semver', /provenance_sources takes lines pattern=REPOSITORY/],
      ['provenance_sources', 'semver=http://github.com/npm/node-semver', /is not a repository/],
      ['provenance_sources', 'semver=id:x', /is not a repository/],
      ['require_provenance', 'semver@7.8.6', /require_provenance takes package names, without versions/],
      ['downgrade_exclude', 'bad name!', /downgrade_exclude: .* is not a package name/],
      ['no_downgrade', 'maybe', /no_downgrade must be true or false/],
      ['require_signatures', 'yes', /require_signatures must be true or false/],
      ['allow_unbound', '2', /allow_unbound must be true or false/],
    ]) {
      const r = await run(project('npm'), reg, { [param]: value });
      assert.equal(r.code, 2, `${param}=${value}: ${r.err}`);
      assert.match(r.err, pattern);
      assert.match(r.err, /^ERROR: /);
    }
    assert.deepEqual(reg.requests(), []);
  });
});

// ---------------------------------------------------------------------------
describe('no_downgrade', () => {
  const PROVENANCE = { url: 'https://registry.npmjs.org/-/npm/v1/attestations/x', provenance: { predicateType: 'https://slsa.dev/provenance/v1' } };
  // Adds an earlier lodash version with MANIFEST's fields.
  const lodashBefore = (version, time, fields) => (d) => {
    d.docs.lodash.versions[version] = { name: 'lodash', version, dist: { integrity: 'sha512-AAAA', shasum: '00' }, ...fields };
    d.docs.lodash.time[version] = time;
  };
  const trusted = { _npmUser: { name: 'GitHub Actions', trustedPublisher: { id: 'github', oidcConfigId: 'oidc:1' } } };

  test('a version with weaker evidence than an earlier one is provenance-downgrade', async () => {
    const reg = await serve(lodashBefore('4.17.20', '2020-08-13T16:53:54.152Z', { ...trusted, dist: { integrity: 'sha512-AAAA', attestations: PROVENANCE } }));
    const r = await run(project('npm'), reg, { no_downgrade: 'true' });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['provenance-downgrade lodash@4.17.21']);
    const f = finding(r, 'provenance-downgrade', 'lodash');
    assert.equal(f.message, 'lodash@4.17.21 in package-lock.json: it was published 2021-02-20T15:42:16.891Z with no trust evidence, but 4.17.20, published earlier (2020-08-13T16:53:54.152Z), had a trusted publisher, with provenance. A trust downgrade can mean the package was taken over; if this one is expected, add lodash@4.17.21 to downgrade_exclude.');
    assert.deepEqual(result(r, 'lodash', '4.17.21').downgrade, { version: '4.17.20', published: '2020-08-13T16:53:54.152Z', evidence: 'trusted-publisher' });
    assert.deepEqual((await run(project('npm'), reg)).json.findings, [], 'off by default');
    for (const exclude of ['lodash@4.17.21', 'lod*']) {
      assert.deepEqual((await run(project('npm'), reg, { no_downgrade: 'true', downgrade_exclude: exclude })).json.findings, [], exclude);
    }
    assert.deepEqual(kinds(await run(project('npm'), reg, { no_downgrade: 'true', downgrade_exclude: 'lodash@4.17.20' })), ['provenance-downgrade lodash@4.17.21']);
  });

  test('later versions, earlier prereleases and a trusted publisher without provenance don\'t count', async () => {
    const reg = await serve((d) => {
      lodashBefore('4.17.22', '2022-01-01T00:00:00.000Z', { ...trusted, dist: { attestations: PROVENANCE } })(d);
      lodashBefore('4.17.21-beta.1', '2020-01-01T00:00:00.000Z', { dist: { attestations: PROVENANCE } })(d);
      lodashBefore('4.17.19', '2020-07-08T00:00:00.000Z', trusted)(d);
    });
    const r = await run(project('npm'), reg, { no_downgrade: 'true' });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.findings, []);
  });

  test('a staged publish outranks provenance', async () => {
    const reg = await serve((d) => {
      d.docs.semver.versions['7.8.5'] = { name: 'semver', version: '7.8.5', _npmUser: { name: 'a', approver: { name: 'b' } }, dist: { integrity: 'sha512-AAAA' } };
      d.docs.semver.time['7.8.5'] = '2026-01-01T00:00:00.000Z';
    });
    const r = await run(project('npm'), reg, { no_downgrade: 'true' });
    assert.deepEqual(kinds(r), ['provenance-downgrade semver@7.8.6']);
    assert.match(finding(r, 'provenance-downgrade', 'semver').message, /with provenance, but 7\.8\.5, published earlier \(2026-01-01T00:00:00\.000Z\), had a staged publish/);
  });

  test('a locked version without a publish time is no verdict', async () => {
    const reg = await serve((d) => { delete d.docs.lodash.time['4.17.21']; });
    const r = await run(project('npm'), reg, { no_downgrade: 'true' });
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: The registry gives no publish time for 1 locked version, so no_downgrade can't compare it with earlier versions, and it has no verdict: lodash@4\.17\.21 \(package-lock\.json\)\./m);
    assert.equal(result(r, 'lodash', '4.17.21').signature, 'valid', 'npm\'s 2015 cutoff for the expired key');
  });
});

// ---------------------------------------------------------------------------
describe('reports and exit codes', () => {
  test('report_only reports findings and passes; reports name every finding', async () => {
    const reg = await serve((d) => {
      const s = d.docs.axios.versions['1.9.0'].dist.signatures[0];
      s.sig = flipBase64(s.sig, 30);
    });
    const r = await run(project('npm'), reg, { report_only: 'true', run_record: 'true', require_provenance: 'lodash', report_name: 'sigs' });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^WARN: 2 findings of signatures fail the gate\./m);
    assert.match(r.err, /^WARN: report_only is true, so this step passes\./m);
    assert.deepEqual(kinds(r), ['invalid axios@1.9.0', 'missing-provenance lodash@4.17.21']);
    assert.equal(r.json.outcome, 'findings-reported');
    assert.deepEqual(r.sarif.runs[0].results.map((x) => x.ruleId).sort(), ['signatures/invalid', 'signatures/missing-provenance']);
    for (const rule of r.sarif.runs[0].tool.driver.rules) assert.equal(rule.shortDescription.text, sig.RULES[rule.id].description);
    assert.equal(r.sarif.runs[0].tool.driver.name, 'js-security-orb signatures');
    assert.match(r.junit, /tests="2" failures="2"/);
    assert.equal(r.record.outcome, 'findings-reported');
    assert.equal(r.record.exit_code, 0);
    assert.equal(r.record.parameters.require_provenance, 'lodash');
    assert.equal(r.record.counts.by_rule['signatures/invalid'], 1);
    assert.match(r.out, /package-lock\.json:\d+: signatures\/invalid: axios@1\.9\.0 in package-lock\.json: its registry signature is invalid/);
  });

  test('a lockfile the helper refuses, or none at all, fails; allow_empty passes an empty project', async () => {
    const reg = await serve();
    const empty = tmpdir('sig-empty-');
    const none = await run(empty, reg);
    assert.equal(none.code, 1);
    assert.match(none.err, /^ERROR: No lockfile in /m);
    assert.equal((await run(empty, reg, { allow_empty: 'true' })).code, 0);
    const broken = await run(project('npm', () => '{"lockfileVersion": 9}'), reg);
    assert.equal(broken.code, 1);
    assert.match(broken.err, /an unsupported lockfileVersion 9/);
  });
});

// ---------------------------------------------------------------------------
// Regressions from review: what a skipped entry, a bundle or a project's .npmrc can no longer
// get past the policies.
describe('skipped entries, bundles and routing', () => {
  const EVIL = `sha512-${Buffer.alloc(64, 9).toString('base64')}`;
  const npmjsTarball = (name, version) => `https://registry.npmjs.org/${name}/-/${name.split('/').pop()}-${version}.tgz`;

  test('a package a provenance policy names fails when it is skipped: a tarball, another registry, git, local, bundled', async () => {
    const reg = await serve();
    const remote = await run(project('npm', editLock((p) => { p['node_modules/lodash'].resolved = 'https://evil.example/lodash-4.17.21.tgz'; })), reg, { require_provenance: 'lodash' });
    assert.equal(remote.code, 1);
    assert.deepEqual(kinds(remote), ['missing-provenance lodash@4.17.21']);
    assert.equal(finding(remote, 'missing-provenance', 'lodash').message, 'lodash@4.17.21 in package-lock.json: require_provenance (lodash) requires provenance, which can\'t be checked: '
      + 'it is a tarball URL (https://evil.example/lodash-4.17.21.tgz), which no registry serves provenance for.');

    const other = await run(project('npm', editLock((p) => { p['node_modules/lodash'].resolved = 'https://evil.example/lodash/-/lodash-4.17.21.tgz'; })), reg, { provenance_sources: 'lodash=https://github.com/lodash/lodash' });
    assert.equal(other.code, 1);
    assert.deepEqual(kinds(other), ['missing-provenance lodash@4.17.21']);
    assert.match(finding(other, 'missing-provenance', 'lodash').message, /provenance_sources \(lodash\) requires provenance, which can't be checked: its registry was not asked: the lockfile records https:\/\/evil\.example\/, which is neither registry nor a scope's registry/);

    const mixed = await run(project('mixed'), reg, { require_provenance: 'is-git, local-lib, inside, signatures-mixed' });
    assert.deepEqual(kinds(mixed), ['missing-provenance inside@1.0.0', 'missing-provenance is-git@1.0.0', 'missing-provenance local-lib@1.0.0'], 'never the workspace: it is the project itself');
    assert.match(finding(mixed, 'missing-provenance', 'inside').message, /it comes bundled in its parent's tarball/);
    assert.match(finding(mixed, 'missing-provenance', 'is-git').message, /it is a git dependency \(git\+ssh:\/\/git@github\.com\/example\/is-git\.git#65ea9129/);
  });

  test('require_signatures: a registry package whose registry was not asked, or answered 401, is unsigned', async () => {
    const reg = await serve();
    const other = await run(project('mixed'), reg, { require_signatures: 'true' });
    assert.equal(other.code, 1);
    assert.deepEqual(kinds(other), ['unsigned other@1.0.0'], 'git, local and bundled entries are lock_verify\'s');
    assert.match(finding(other, 'unsigned', 'other').message, /it has no registry signature this check could verify, since its registry was not asked: the lockfile records https:\/\/registry\.example\.com\/, .*, and require_signatures is true\.$/);

    const a401 = await serve(null, { data: { docs: {}, attestations: {} }, overrides: { 'GET /@babel%2Fcore': { status: 401, body: { error: 'nope' } } } });
    const dir = project('npm');
    fs.writeFileSync(path.join(dir, '.npmrc'), `@babel:registry=${a401.url}\n`);
    const r = await run(dir, reg, { require_signatures: 'true', require_provenance: '@babel/core' });
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['missing-provenance @babel/core@8.1.0', 'unsigned @babel/core@8.1.0']);
    assert.match(finding(r, 'unsigned', '@babel/core').message, /answered HTTP 401, and the token goes only to registry's origin, and require_signatures is true\.$/);
    assert.deepEqual(a401.requests().map((q) => q.path), ['/@babel%2Fcore']);
  });

  test('a package recorded from registry.npmjs.org whose registry serves no signature is unsigned', async () => {
    // A project .npmrc sends @babel to a registry that serves a substitute without signatures.
    const reg = await serve();
    const evil = registryData();
    evil.docs['@babel/core'].versions['8.1.0'].dist = { integrity: EVIL };
    const attacker = await serve(null, { data: { docs: { '@babel/core': evil.docs['@babel/core'] }, attestations: {} } });
    const dir = project('npm', editLock((p) => Object.assign(p['node_modules/@babel/core'], { integrity: EVIL, resolved: npmjsTarball('@babel/core', '8.1.0') })));
    fs.writeFileSync(path.join(dir, '.npmrc'), `@babel:registry=${attacker.url}\n`);
    const r = await run(dir, reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['unsigned @babel/core@8.1.0']);
    assert.match(finding(r, 'unsigned', '@babel/core').message, /the lockfile records it from https:\/\/registry\.npmjs\.org\/, which signs every package it publishes, and http:\S+, which serves it in its place, can't be told from a substitute without npm's signature\.$/);

    // A mirror, as registry, that strips npm's signatures: every entry recorded from npmjs is unsigned.
    const stripped = await serve((d) => { for (const doc of Object.values(d.docs)) for (const v of Object.values(doc.versions)) delete v.dist.signatures; });
    const all = editLock((p) => {
      for (const [key, v] of Object.entries(p)) if (key) v.resolved = npmjsTarball(key.slice(key.lastIndexOf('node_modules/') + 13), v.version);
    });
    const m = await run(project('npm', all), stripped);
    assert.equal(m.code, 1);
    assert.equal(kinds(m).length, 7);
    assert.ok(kinds(m).every((k) => k.startsWith('unsigned ')));
    // Without a recorded registry, such a mirror is a registry that signs nothing: not checked, so nothing was.
    const unrecorded = await run(project('npm'), stripped);
    assert.equal(unrecorded.code, 1);
    assert.match(unrecorded.err, /^ERROR: No registry signature was checked/m);
  });

  test('a registry only the checkout names that signs nothing is unsigned, routed or recorded (review t2)', async () => {
    // A change adds @babel:registry=<attacker> to .npmrc; the lockfile records no registry.
    const reg = await serve();
    const evil = registryData();
    evil.docs['@babel/core'].versions['8.1.0'].dist = { integrity: EVIL };
    const attacker = await serve(null, { data: { docs: { '@babel/core': evil.docs['@babel/core'] }, attestations: {} } });
    const dir = project('npm', editLock((p) => { p['node_modules/@babel/core'].integrity = EVIL; }));
    fs.writeFileSync(path.join(dir, '.npmrc'), `@babel:registry=${attacker.url}\n`);
    const r = await run(dir, reg);
    assert.equal(r.code, 1);
    assert.deepEqual(kinds(r), ['unsigned @babel/core@8.1.0']);
    assert.equal(finding(r, 'unsigned', '@babel/core').message, `@babel/core@8.1.0 in package-lock.json: it has no registry signature, but ${attacker.url}, which serves it and signs nothing, is named only by .npmrc line 1 (for @babel), which the change under test can edit. List it in scopes to trust it.`);
    // Recorded on that registry, likewise.
    const rec = project('npm', editLock((p) => Object.assign(p['node_modules/@babel/core'], { integrity: EVIL, resolved: `${attacker.url}@babel/core/-/core-8.1.0.tgz` })));
    fs.writeFileSync(path.join(rec, '.npmrc'), `@babel:registry=${attacker.url}\n`);
    assert.deepEqual(kinds(await run(rec, reg)), ['unsigned @babel/core@8.1.0']);
    // Listed in scopes, it is trusted: a registry that signs nothing is not checked, with a warning.
    const trusted = await run(dir, reg, { scopes: `@babel=${attacker.url}` });
    assert.equal(trusted.code, 0, trusted.err);
    assert.deepEqual(trusted.json.skipped.filter((x) => x.reason === 'unsigned-registry').map((x) => x.name), ['@babel/core']);
  });

  test('inBundle counts only inside an installed package, and only without a source or integrity of its own', async () => {
    const reg = await serve();
    const top = await run(project('npm', editLock((p) => Object.assign(p['node_modules/lodash'], { integrity: EVIL, inBundle: true }))), reg, { require_signatures: 'true' });
    assert.equal(top.code, 1);
    assert.deepEqual(kinds(top), ['integrity-mismatch lodash@4.17.21'], 'the root\'s own bundleDependencies are ordinary entries');
    const nested = await run(project('mixed', editLock((p) => { p['node_modules/lodash/node_modules/inside'].integrity = EVIL; })), reg);
    assert.equal(nested.code, 1);
    assert.deepEqual(kinds(nested), ['not-in-registry inside@1.0.0'], 'a bundled entry that records an integrity is checked like any other');
    assert.ok(!nested.json.skipped.some((x) => x.reason === 'bundled'));
  });

  test('a lockfile source that is another scope\'s registry is skipped, not asked', async () => {
    const reg = await serve();
    const attacker = await serve();
    const dir = project('npm', editLock((p) => { p['node_modules/lodash'].resolved = `${attacker.url}lodash/-/lodash-4.17.21.tgz`; }));
    fs.writeFileSync(path.join(dir, '.npmrc'), `@unrelated:registry=${attacker.url}\n`);
    const r = await run(dir, reg);
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(r.json.skipped.filter((x) => x.reason === 'other-registry').map((x) => [x.name, x.detail]),
      [['lodash', `the lockfile records ${attacker.url}, which is the registry of @unrelated, not registry, where lodash comes from`]]);
    assert.deepEqual(attacker.requests(), []);
  });

  test('provenance_sources: a URL matches only a certificate its forge issued', () => {
    const s = slice('axios@1.9.0');
    const { summary } = verifyAttestations(readJson(path.join(FIXTURES, 'attestations', 'axios@1.9.0.json')), { name: s.name, version: s.version, integrity: s.dist.integrity });
    const id = summary.identity;
    const [github] = sig.parseProvenanceSources(['axios=https://github.com/axios/axios'])[0].repos;
    assert.equal(sig.repositoryMatches(id, github), true);
    assert.equal(sig.repositoryMatches({ ...id, issuer: 'https://gitlab.com' }, github), false, 'another issuer claiming a GitHub repository');
    const gitlabUri = { ...id, sourceRepositoryUri: 'https://gitlab.com/axios/axios' };
    const [gitlab] = sig.parseProvenanceSources(['axios=https://gitlab.com/axios/axios'])[0].repos;
    assert.equal(sig.repositoryMatches(gitlabUri, gitlab), false, 'GitHub Actions claiming a GitLab repository');
    assert.equal(sig.repositoryMatches({ ...gitlabUri, issuer: 'https://gitlab.com' }, gitlab), true);
    assert.equal(sig.repositoryMatches({ ...gitlabUri, issuer: 'https://gitlab.example.com' }, gitlab), false);
  });
});
