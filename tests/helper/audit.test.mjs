// Unit tests of src/helper/audit.mjs, offline: the version parser and range
// matcher (with a fixed sample of node-semver's answers), the prerelease
// probes, GHSA IDs, batching, and the audit command end to end through core's
// runCommand, with curl, against tests/fake_registry.mjs serving the recorded
// advisories in tests/fixtures/audit/registry. The fake registry answers the
// bulk endpoint as npm's does: with every advisory matching any version sent,
// matched with node-semver's default satisfies().

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as core from '../../src/helper/core.mjs';
import * as A from '../../src/helper/audit.mjs';
import { startFakeRegistry, satisfies as serverSatisfies } from '../fake_registry.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FIX = path.join(HERE, '..', 'fixtures', 'audit');
const LOCKS = path.join(HERE, '..', 'fixtures', 'lockfiles');
const MODULE = path.join(HERE, '..', '..', 'src', 'helper', 'audit.mjs');
const BULK = '/-/npm/v1/security/advisories/bulk';
const MAX = '9007199254740991';

const ADVISORIES = JSON.parse(fs.readFileSync(path.join(FIX, 'registry', 'advisories.json'), 'utf8'));
// The two entries the canary minimist@0.0.8 must come back with.
const CANARY_ADVISORIES = ADVISORIES.minimist.filter((a) => ['<0.2.4', '<0.2.1'].includes(a.vulnerable_versions));
const LODASH_35JH = ADVISORIES.lodash.find((a) => a.url.endsWith('GHSA-35jh-r3h4-6jhm'));

const tmpdir = (prefix = 'audit-test-') => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const id = (f) => `${f.package.name}@${f.package.version} ${f.details.ghsa}`;
const ids = (findings) => findings.map(id).sort();
const bodies = (r) => r.posts.map((p) => p.body);

/**
 * Runs the audit command against a fresh fake registry (with OVERRIDES in its
 * _overrides.json), with params as PARAM_ variables. options are audit()'s, or
 * a function of the context that returns them.
 */
async function runAudit({ cwd, params = {}, overrides = null, options = {}, env = {}, registry = null }) {
  const dir = tmpdir('audit-registry-');
  fs.cpSync(path.join(FIX, 'registry'), dir, { recursive: true });
  if (overrides) fs.writeFileSync(path.join(dir, '_overrides.json'), JSON.stringify(overrides));
  const log = path.join(dir, 'requests.log');
  const reg = await startFakeRegistry({ dir, log });
  const out = tmpdir('audit-out-');
  const fullEnv = {
    PATH: process.env.PATH, HOME: process.env.HOME, XDG_CACHE_HOME: tmpdir('audit-cache-'),
    // No user npmrc unless a test gives one.
    NPM_CONFIG_USERCONFIG: path.join(tmpdir('audit-home-'), 'none', '.npmrc'),
    PARAM_REGISTRY: registry ?? reg.url, PARAM_OUTPUT_DIR: out, ...env,
    ...Object.fromEntries(Object.entries(params).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, v])),
  };
  const stdout = [];
  const stderr = [];
  let code;
  try {
    code = await core.runCommand('audit', (ctx) => A.audit(ctx, typeof options === 'function' ? options(ctx) : options),
      { env: fullEnv, cwd, stdout: (s) => stdout.push(s), stderr: (s) => stderr.push(s) });
  } finally {
    await reg.close();
  }
  const requests = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : [];
  const file = (f) => path.join(out, f);
  const json = (f) => (fs.existsSync(file(f)) ? JSON.parse(fs.readFileSync(file(f), 'utf8')) : null);
  const report = json(`${params.report_name ?? 'audit'}.json`);
  return {
    code, out: stdout.join(''), err: stderr.join(''), requests, posts: requests.filter((q) => q.method === 'POST'),
    url: reg.url, outDir: out, report, findings: report?.findings ?? [],
    sarif: json(`${params.report_name ?? 'audit'}.sarif`), record: json(`${params.report_name ?? 'audit'}.run-record.json`),
    junit: fs.existsSync(file(`junit/${params.report_name ?? 'audit'}.xml`)) ? fs.readFileSync(file(`junit/${params.report_name ?? 'audit'}.xml`), 'utf8') : null,
  };
}

// fetchMany without retries, so a 5xx answer doesn't wait for curl's backoff.
const noRetries = (ctx) => ({ fetchMany: (requests) => core.fetchMany(requests, { workDir: ctx.workDir, retries: 0, timeout: 10 }) });

// ---------------------------------------------------------------------------
// Versions, ranges and probes
// ---------------------------------------------------------------------------

describe('versions and ranges', () => {
  test('parseVersion reads strict semver only', () => {
    assert.deepEqual(A.parseVersion('1.2.3'), { nums: [1, 2, 3], pre: [] });
    assert.deepEqual(A.parseVersion('1.2.3-rc.1+build.5'), { nums: [1, 2, 3], pre: ['rc', '1'] });
    assert.deepEqual(A.parseVersion(`0.${MAX}.0`), { nums: [0, +MAX, 0], pre: [] });
    for (const bad of ['v1.2.3', '=1.2.3', '1.2', '1', '01.2.3', '1.02.3', '1.2.3-01', '1.2.3.4', '1.2.3-', '1.2.3+',
      '9007199254740992.0.0', ' 1.2.3', '1.2.3 ', `1.2.3-${'a'.repeat(260)}`, '', null, 123]) {
      assert.equal(A.parseVersion(bad), null, `refuses ${JSON.stringify(bad)}`);
    }
  });

  test('the matcher agrees with node-semver on a fixed sample of the advisories\' ranges', () => {
    // tests/fixtures/audit/matcher_cases.json: [version, range, expected], with
    // expected from node-semver satisfies(version, range, {includePrerelease:
    // true, loose: true}), over the range kinds the bulk endpoint uses (every
    // partial-version and > range in the research corpus, = ranges, ranges with
    // prereleases), at and around each bound. The research checked the same
    // matcher on 5,726,053 (version, range) pairs.
    const doc = JSON.parse(fs.readFileSync(path.join(FIX, 'matcher_cases.json'), 'utf8'));
    assert.ok(doc.cases.length > 600, 'the whole sample is there');
    const wrong = doc.cases.filter(([v, r, expected]) => A.satisfies(v, r) !== expected);
    assert.deepEqual(wrong, []);
    assert.ok(doc.cases.some(([, r]) => /^>0 /.test(r)) && doc.cases.some(([, r]) => r === '<=1.1') && doc.cases.some(([, r]) => r === '>=0'));
  });

  test('partial versions are desugared as node-semver does with includePrerelease', () => {
    const cases = [
      ['1.1.9', '<=1.1', true], ['1.2.0-0', '<=1.1', false], ['1.2.0-alpha', '<1.2', false], ['1.1.99', '<1.2', true],
      ['0.0.0-0', '>=0', true], ['0.9.0', '>0', false], ['1.0.0-0', '>0', true], ['1.2.0-0', '>=1.2', true],
      ['1.2.5', '=1.2', true], ['1.3.0-0', '=1.2', false], ['1.2.9', '1.2', true], ['2.0.0', '<2', false],
      ['3.0.0-rc1', '>=1.12.3 <3.0.0', true], ['3.0.0', '>=1.12.3 <3.0.0', false], ['1.2.3+b', '=1.2.3', true],
    ];
    for (const [v, r, expected] of cases) assert.equal(A.satisfies(v, r), expected, `${v} in ${r}`);
  });

  test('a range outside the grammar is refused, never matched', () => {
    for (const r of ['^1.2.3', '~1.2.3', '1.x', '1.2.x', '*', 'x', '1.2.3 - 2.0.0', '<1.0.0 || >=2.0.0', '< 1.2.3', '>=v1.2.3',
      '<1.2.3+build', '', '   ', '>=1.2.3-01', 'latest', '>=1.2.3,<2', '<=>1.2.3', '1.2.3.4', `<${MAX}`, '<1.2.3-']) {
      assert.throws(() => A.parseRange(r), A.RangeGrammarError, `refuses ${JSON.stringify(r)}`);
      assert.throws(() => A.satisfies('1.2.3', r), A.RangeGrammarError);
    }
    assert.throws(() => A.parseRange(null), A.RangeGrammarError);
    assert.throws(() => A.satisfies('v1.2.3', '<2.0.0'), /is not a version/);
  });

  test('prerelease probes: X.Y.Z and the largest release below it', () => {
    assert.deepEqual(A.prereleaseProbes('7.5.2-rc.0'), ['7.5.2', '7.5.1']);
    assert.deepEqual(A.prereleaseProbes('3.1.0-beta.1'), ['3.1.0', `3.0.${MAX}`]);
    assert.deepEqual(A.prereleaseProbes('3.0.0-rc1'), ['3.0.0', `2.${MAX}.${MAX}`]);
    assert.deepEqual(A.prereleaseProbes('0.0.0-x.1+build'), ['0.0.0']);
    assert.deepEqual(A.prereleaseProbes('1.2.3'), []);
    assert.deepEqual(A.prereleaseProbes('not-a-version'), []);
    for (const v of ['3.0.0-rc1', '3.1.0-beta.1']) for (const p of A.prereleaseProbes(v)) assert.ok(A.parseVersion(p), p);
  });

  test('the probes recover every advisory a prerelease is in, under the server\'s default semantics', () => {
    // The server matches with node-semver's default satisfies(), which drops a
    // prerelease from every range without a prerelease on the same X.Y.Z.
    const doc = JSON.parse(fs.readFileSync(path.join(FIX, 'matcher_cases.json'), 'utf8'));
    const pre = doc.cases.filter(([v, , expected]) => expected && A.parseVersion(v).pre.length);
    assert.ok(pre.length > 100);
    assert.ok(pre.some(([v, r]) => !serverSatisfies(v, r)), 'the server alone misses some');
    assert.deepEqual(pre.filter(([v, r]) => ![v, ...A.prereleaseProbes(v)].some((q) => serverSatisfies(q, r))), []);
  });

  test('GHSA IDs and advisory URLs', () => {
    assert.equal(A.normalizeGhsa('GHSA-35jh-r3h4-6jhm'), 'GHSA-35jh-r3h4-6jhm');
    assert.equal(A.normalizeGhsa(' ghsa-35JH-R3H4-6JHM '), 'GHSA-35jh-r3h4-6jhm');
    for (const bad of ['GHSA-35jh-r3h4', 'GHSA-aaaa-bbbb-cccc', 'CVE-2020-8203', 'GHSA-35jh-r3h4-6jhm-xxxx', '1106913', '']) assert.equal(A.normalizeGhsa(bad), null, bad);
    assert.equal(A.ghsaOfUrl('https://github.com/advisories/GHSA-35jh-r3h4-6jhm'), 'GHSA-35jh-r3h4-6jhm');
    for (const bad of ['http://github.com/advisories/GHSA-35jh-r3h4-6jhm', 'https://github.com/advisories/GHSA-35jh-r3h4-6jhm/x',
      'https://example.com/advisories/GHSA-35jh-r3h4-6jhm', 'https://npmjs.com/advisories/1106913', null]) assert.equal(A.ghsaOfUrl(bad), null, bad);
  });

  test('batches: under the limit, the canary in each, every version once', () => {
    const query = new Map([['lodash', ['4.17.20', '4.17.21']], ['minimist', ['0.0.8', '1.2.0']], ['@scope/pkg', ['1.0.0']], ['ms', ['2.1.3']]]);
    const one = A.makeBatches(query);
    assert.equal(one.length, 1);
    assert.deepEqual(JSON.parse(one[0].body), { minimist: ['0.0.8', '1.2.0'], lodash: ['4.17.20', '4.17.21'], '@scope/pkg': ['1.0.0'], ms: ['2.1.3'] });
    const many = A.makeBatches(query, 45);
    assert.ok(many.length > 2);
    const seen = [];
    for (const b of many) {
      assert.ok(Buffer.byteLength(b.body) <= 45 && Buffer.byteLength(b.body) === b.size, b.body);
      const doc = JSON.parse(b.body);
      assert.ok(doc.minimist.includes('0.0.8'), 'every batch carries the canary');
      assert.deepEqual([...b.names].sort(), Object.keys(doc).sort());
      for (const [n, vs] of Object.entries(doc)) for (const v of vs) if (!(n === 'minimist' && v === '0.0.8')) seen.push(`${n}@${v}`);
    }
    assert.deepEqual(seen.sort(), ['@scope/pkg@1.0.0', 'lodash@4.17.20', 'lodash@4.17.21', 'minimist@1.2.0', 'ms@2.1.3']);
    assert.throws(() => A.makeBatches(new Map([['a-package-with-a-long-name', ['1.0.0']]]), 45), /doesn't fit in 45 bytes/);
  });

  test('checkAdvisory: the shape of one advisory', () => {
    assert.equal(A.checkAdvisory(LODASH_35JH, 'lodash').advisory.ghsa, 'GHSA-35jh-r3h4-6jhm');
    const bad = (patch) => A.checkAdvisory({ ...LODASH_35JH, ...patch }, 'lodash').error;
    assert.match(bad({ id: '1106913' }), /no numeric id/);
    assert.match(bad({ url: 'https://example.com/x' }), /not a GitHub advisory/);
    assert.match(bad({ title: null }), /no title/);
    assert.match(bad({ severity: 'urgent' }), /severity "urgent"/);
    assert.match(bad({ vulnerable_versions: 5 }), /no vulnerable_versions/);
    assert.match(bad({ cwe: 'CWE-77' }), /cwe/);
    assert.match(bad({ cvss: { score: 11 } }), /malformed cvss/);
    assert.match(A.checkAdvisory('x', 'lodash').error, /not an object/);
    const range = A.checkAdvisory({ ...LODASH_35JH, vulnerable_versions: '^4.0.0' }, 'lodash').advisory;
    assert.equal(range.bounds, null);
    assert.match(range.rangeError, /outside the range grammar/);
  });
});

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

// What every lockfile fixture in tests/fixtures/lockfiles locks, against the
// recorded advisories.
const SHARED_EXPECTED = [
  '@tootallnate/once@2.0.0 GHSA-vpq2-c234-7xj6',
  'lodash@4.17.20 GHSA-29mw-wpgm-hmr9', 'lodash@4.17.20 GHSA-35jh-r3h4-6jhm', 'lodash@4.17.20 GHSA-f23m-r3pf-42rh',
  'lodash@4.17.20 GHSA-r5fr-rjxr-66jc', 'lodash@4.17.20 GHSA-xxjr-mmjv-4gpg',
  'lodash@4.17.21 GHSA-f23m-r3pf-42rh', 'lodash@4.17.21 GHSA-r5fr-rjxr-66jc', 'lodash@4.17.21 GHSA-xxjr-mmjv-4gpg',
  'uuid@3.4.0 GHSA-w5hq-g745-h8pq',
];

describe('the audit command', () => {
  for (const fixture of ['npm/v3', 'npm/v2', 'pnpm/v9.0', 'pnpm/v6.0', 'yarn1', 'berry/v10', 'bun/text']) {
    test(`findings in the ${fixture} lockfile, at each package's entry`, async () => {
      const cwd = path.join(LOCKS, fixture);
      const r = await runAudit({ cwd });
      assert.equal(r.code, 1, r.err);
      assert.deepEqual(ids(r.findings), SHARED_EXPECTED);
      const { entries } = core.readLockfiles({ cwd, registries: core.registryConfig({ npmrc: false }) });
      for (const f of r.findings) {
        const at = entries.filter((e) => e.kind === 'registry' && e.name === f.package.name && e.version === f.package.version)
          .map((e) => [e.lockfile, e.line]).sort((a, b) => a[1] - b[1]);
        assert.deepEqual([f.lockfile, f.line], at[0], id(f));
        assert.deepEqual(f.details.locations.map((l) => [l.lockfile, l.line]), at, id(f));
      }
      assert.equal(r.posts.length, 1);
      assert.equal(r.requests.length, 1, 'only the bulk request, no packument');
      assert.equal(r.report.summary.vulnerabilities.high, 3);
      assert.equal(r.report.summary.vulnerabilities.moderate, 6);
      assert.equal(r.report.summary.vulnerabilities.low, 1);
    });
  }

  test('the request: gzipped JSON of the real names (aliases resolved) and versions, plus the canary', async () => {
    const r = await runAudit({ cwd: path.join(LOCKS, 'npm/v3') });
    const [post] = r.posts;
    assert.equal(post.path, BULK);
    assert.equal(post.headers['content-type'], 'application/json');
    assert.equal(post.headers['content-encoding'], 'gzip');
    const body = JSON.parse(post.body);
    assert.deepEqual(body.lodash, ['4.17.20', '4.17.21']);
    assert.deepEqual(body.minimist, ['0.0.8']);
    assert.equal(body['lodash-old'], undefined);
    for (const name of ['@sindresorhus/is', 'local-lib', 'fixture-root', '@fixture/a', '@fixture/b']) assert.equal(body[name], undefined, name);
    assert.match(r.findings.find((f) => id(f) === 'lodash@4.17.20 GHSA-35jh-r3h4-6jhm').message, /lodash@4\.17\.20 \(installed as lodash-old\) has GHSA-35jh-r3h4-6jhm \(high\): Command Injection in lodash\. Vulnerable versions: <4\.17\.21\./);
    assert.match(r.out, /Auditing 41 packages \(41 lockfile entries\) against http:\/\/127\.0\.0\.1:\d+\/-\/npm\/v1\/security\/advisories\/bulk\./);
    assert.match(r.out, /Not audited: 3 workspace packages, 1 local package, 1 from git/);
    assert.match(r.err, /^WARN: 1 package was not audited, since advisories name registry packages, not git or tarball URLs: @sindresorhus\/is@4\.6\.0\. It is listed under skipped in the report\.$/m);
    assert.equal(r.report.summary.audited_entries, 41);
    assert.equal(r.report.summary.requests, 1);
  });

  test('a version locked in several lockfiles is one finding, with every location', async () => {
    const r = await runAudit({ cwd: LOCKS, params: { lockfiles: 'npm/v3/package-lock.json pnpm/v9.0/pnpm-lock.yaml\nyarn1/yarn.lock' } });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), SHARED_EXPECTED);
    for (const f of r.findings) {
      assert.deepEqual(f.details.locations.map((l) => l.lockfile.split('/').slice(-2).join('/')), ['npm/v3/package-lock.json', 'pnpm/v9.0/pnpm-lock.yaml', 'yarn1/yarn.lock'].map((p) => p.split('/').slice(-2).join('/')), id(f));
      assert.equal(f.lockfile, f.details.locations[0].lockfile);
      assert.match(f.message, /Also locked at .*pnpm-lock\.yaml:\d+, .*yarn\.lock:\d+\.$/);
    }
    assert.equal(r.sarif.runs[0].results.length, 10);
  });

  test('severities, CVSS, and every report', async () => {
    const r = await runAudit({ cwd: path.join(FIX, 'npm'), params: { run_record: 'true' } });
    assert.equal(r.code, 1);
    assert.deepEqual(r.findings.map((f) => [id(f), f.level, f.details.severity]), [
      ['minimist@1.2.0 GHSA-xvch-5gv4-984h', 'error', 'critical'],
      ['react@0.13.0 GHSA-hg79-j56m-fxgv', 'error', 'high'],
      ['minimist@1.2.0 GHSA-vh95-rmgr-6w4m', 'error', 'moderate'],
      ['debug@4.1.1 GHSA-gxpj-cx7g-858c', 'error', 'low'],
    ]);
    const xvch = r.findings[0];
    assert.equal(xvch.rule, 'audit/GHSA-xvch-5gv4-984h');
    assert.equal(xvch.kind, 'vulnerability');
    assert.deepEqual(xvch.details.locations.map((l) => l.line), [66, 72], 'the nested copy is the same package and version');
    assert.deepEqual(xvch.details.npm_advisory_ids, [1097678]);
    assert.equal(xvch.details.vulnerable_versions, '>=1.0.0 <1.2.6');
    assert.equal(xvch.details.url, 'https://github.com/advisories/GHSA-xvch-5gv4-984h');
    assert.deepEqual(xvch.details.cvss, { score: 9.8, vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' });
    assert.deepEqual(r.report.summary.vulnerabilities, { critical: 1, high: 1, moderate: 1, low: 1, info: 0 });
    assert.equal(r.report.schema, 'js-security-orb/audit/v1');
    assert.equal(r.report.outcome, 'findings');

    // SARIF: security-severity is a string, from CVSS, else from the severity.
    const rules = Object.fromEntries(r.sarif.runs[0].tool.driver.rules.map((x) => [x.id, x]));
    assert.equal(rules['audit/GHSA-xvch-5gv4-984h'].properties['security-severity'], '9.8');
    assert.equal(rules['audit/GHSA-hg79-j56m-fxgv'].properties['security-severity'], '8.0', 'cvss score 0: from the severity');
    assert.equal(rules['audit/GHSA-gxpj-cx7g-858c'].properties['security-severity'], '3.7');
    assert.equal(rules['audit/GHSA-xvch-5gv4-984h'].helpUri, 'https://github.com/advisories/GHSA-xvch-5gv4-984h');
    assert.match(rules['audit/GHSA-xvch-5gv4-984h'].shortDescription.text, /^GHSA-xvch-5gv4-984h: Prototype Pollution in minimist$/);
    assert.ok(rules['audit/GHSA-xvch-5gv4-984h'].properties.tags.includes('external/cwe/cwe-1321'));
    for (const res of r.sarif.runs[0].results) {
      assert.match(res.locations[0].physicalLocation.artifactLocation.uri, /tests\/fixtures\/audit\/npm\/package-lock\.json$/);
      assert.ok(res.partialFingerprints.primaryLocationLineHash);
    }

    assert.match(r.junit, /tests="4" failures="4" errors="0" skipped="0"/);
    assert.equal(r.record.command, 'audit');
    assert.equal(r.record.outcome, 'findings');
    assert.equal(r.record.counts.critical, 1);
    assert.equal(r.record.counts.audited_entries, 7);
    assert.equal(r.record.counts.audited_packages, 6);
    assert.equal(r.record.results.find((x) => x.name === 'minimist').vulnerabilities.length, 2);
    assert.equal(r.record.parameters.fail_on, 'low');
  });

  test('private names are never sent: other registries, git, tarballs, file: and workspaces are skipped', async () => {
    const r = await runAudit({ cwd: path.join(FIX, 'npm'), params: { token: 'AUDIT_TEST_TOKEN' }, env: { AUDIT_TEST_TOKEN: 'npm_AuditTestToken42' } });
    assert.equal(r.posts.length, 1);
    assert.equal(r.requests.length, 1);
    const sent = Object.keys(JSON.parse(r.posts[0].body)).sort();
    assert.deepEqual(sent, ['debug', 'is-number', 'legacy-cli', 'minimist', 'ms', 'react']);
    for (const secret of ['corp', 'secret', 'private-fork', 'internal', 'audit-fixture']) assert.ok(!r.posts[0].body.includes(secret), secret);
    assert.equal(r.posts[0].headers.authorization, 'Bearer npm_AuditTestToken42', 'the token goes to the registry\'s own endpoint');
    assert.ok(!r.out.includes('npm_AuditTestToken42') && !r.err.includes('npm_AuditTestToken42'));
    const skipped = Object.fromEntries(r.report.skipped.map((s) => [s.name, [s.kind, s.source]]));
    assert.deepEqual(skipped, {
      'audit-fixture': ['workspace', 'tests/fixtures/audit/npm'],
      'internal-local': ['local', 'tests/fixtures/audit/npm/internal-local'],
      '@corp/secret-lib': ['registry', 'https://npm.corp.example/'],
      'internal-tool': ['remote', 'https://files.corp.example/internal-tool-1.0.0.tgz'],
      'private-fork': ['git', 'git+ssh://git.corp.example/team/private-fork.git'],
      '@corp/internal-workspace': ['workspace', 'tests/fixtures/audit/npm/packages/internal-workspace'],
    });
    assert.deepEqual(r.report.summary.skipped, { workspace: 2, local: 1, registry: 1, remote: 1, git: 1 });
    assert.ok(r.err.includes(`WARN: 1 package was not audited, since the lockfile records https://npm.corp.example/, which is neither registry nor a scope's registry (scopes, .npmrc or .yarnrc.yml): @corp/secret-lib@2.0.0. It is listed under skipped in the report. The names of packages from other registries are never sent to ${r.url}, where the advisories come from. To audit them, set registry to the registry they come from, if it serves npm's advisories.\n`), r.err);
    assert.match(r.err, /^WARN: 2 packages were not audited, since advisories name registry packages, not git or tarball URLs: internal-tool@1\.0\.0, private-fork@1\.0\.0\. They are listed under skipped in the report\.$/m);
  });

  test('a scope mapped to another registry is skipped, for lockfiles that don\'t record one (pnpm)', async () => {
    const r = await runAudit({ cwd: path.join(LOCKS, 'pnpm/v9.0'), params: { scopes: '@tootallnate=https://npm.corp.example/' } });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), SHARED_EXPECTED.filter((x) => !x.startsWith('@tootallnate')));
    assert.ok(!r.posts[0].body.includes('tootallnate'));
    assert.deepEqual(r.report.skipped.filter((s) => s.kind === 'registry').map((s) => [s.name, s.source]), [['@tootallnate/once', 'https://npm.corp.example/']]);
  });

  test('a package recorded on registry.npmjs.org whose scope is mapped to another registry is skipped, as npm installs it from there', async () => {
    const r = await runAudit({ cwd: path.join(LOCKS, 'npm/v3'), params: { scopes: '@tootallnate=https://npm.corp.example/' } });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), SHARED_EXPECTED.filter((x) => !x.startsWith('@tootallnate')));
    assert.ok(!r.posts[0].body.includes('tootallnate'));
    const s = r.report.skipped.filter((x) => x.kind === 'registry');
    assert.deepEqual(s.map((x) => [x.name, x.source, x.reason]), [['@tootallnate/once', 'https://registry.npmjs.org/',
      'packages from https://npm.corp.example/, a scope\'s registry, are not sent to registry\'s advisory endpoint']]);
    assert.match(r.err, /^WARN: 1 package was not audited, since packages from https:\/\/npm\.corp\.example\/, a scope's registry, are not sent to registry's advisory endpoint: @tootallnate\/once@2\.0\.0\./m);
  });

  test('fail_on: findings below it are warnings that pass', async () => {
    const cwd = path.join(FIX, 'npm');
    const failing = {};
    for (const level of ['low', 'moderate', 'high', 'critical']) {
      const r = await runAudit({ cwd, params: { fail_on: level } });
      assert.equal(r.code, 1, level);
      assert.equal(r.findings.length, 4);
      failing[level] = r.findings.filter((f) => f.level === 'error').map((f) => f.details.severity);
      assert.ok(r.findings.filter((f) => f.level !== 'error').every((f) => f.level === 'warning'));
    }
    assert.deepEqual(failing, {
      low: ['critical', 'high', 'moderate', 'low'], moderate: ['critical', 'high', 'moderate'], high: ['critical', 'high'], critical: ['critical'],
    });
    const below = await runAudit({ cwd: path.join(LOCKS, 'npm/v3'), params: { fail_on: 'critical' } });
    assert.equal(below.code, 0, below.err);
    assert.equal(below.findings.length, 10);
    assert.ok(below.findings.every((f) => f.level === 'warning'));
    assert.match(below.out, /does not fail the step/);
    assert.match(below.junit, /failures="0" errors="0" skipped="10"/);
    assert.equal(below.sarif.runs[0].results[0].level, 'warning');
    const ro = await runAudit({ cwd, params: { report_only: 'true' } });
    assert.equal(ro.code, 0);
    assert.equal(ro.report.outcome, 'findings-reported');
    assert.match(ro.err, /^WARN: report_only is true, so this step passes/m);
  });

  test('ignore: ignored advisories are reported as ignored, unused entries are a warning', async () => {
    const r = await runAudit({ cwd: path.join(LOCKS, 'npm/v3'), params: { ignore: 'ghsa-35JH-R3H4-6JHM,\nGHSA-9vvw-cc9w-f27h  GHSA-w5hq-g745-h8pq', run_record: '1' } });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), SHARED_EXPECTED.filter((x) => !x.includes('GHSA-35jh') && !x.includes('GHSA-w5hq')));
    assert.deepEqual(r.report.summary.ignored.map((i) => `${i.name}@${i.version} ${i.ghsa} ${i.severity}`),
      ['lodash@4.17.20 GHSA-35jh-r3h4-6jhm high', 'uuid@3.4.0 GHSA-w5hq-g745-h8pq moderate']);
    assert.ok(r.report.summary.ignored[0].locations[0].line > 0);
    assert.deepEqual(r.report.summary.unused_ignores, ['GHSA-9vvw-cc9w-f27h']);
    assert.match(r.err, /^WARN: ignore lists 1 advisory that matched no audited package: GHSA-9vvw-cc9w-f27h\.$/m);
    assert.match(r.out, /^Ignored: GHSA-35jh-r3h4-6jhm in lodash@4\.17\.20 \(high\), GHSA-w5hq-g745-h8pq in uuid@3\.4\.0 \(moderate\)\.$/m);
    assert.ok(!r.sarif.runs[0].results.some((x) => x.ruleId === 'audit/GHSA-35jh-r3h4-6jhm'));
    const lodash = r.record.results.find((x) => x.name === 'lodash' && x.version === '4.17.20');
    assert.deepEqual(lodash.vulnerabilities.find((v) => v.ghsa === 'GHSA-35jh-r3h4-6jhm'), { ghsa: 'GHSA-35jh-r3h4-6jhm', severity: 'high', ignored: true });
    assert.equal(r.record.counts.ignored, 2);
    assert.equal(r.record.counts.unused_ignores, 1);
  });

  test('prereleases: the probes recover the advisories the server drops for them', async () => {
    const r = await runAudit({ cwd: path.join(FIX, 'prerelease') });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), [
      'debug@3.1.0-beta.1 GHSA-9vvw-cc9w-f27h', 'debug@3.1.0-beta.1 GHSA-gxpj-cx7g-858c',
      'jquery@3.0.0-rc1 GHSA-6c3j-c64m-qhgq', 'jquery@3.0.0-rc1 GHSA-gxr4-xjj5-5px2', 'jquery@3.0.0-rc1 GHSA-jpcq-cgw6-v4j6', 'jquery@3.0.0-rc1 GHSA-rmxg-73gg-4p98',
      'semver@7.5.2-rc.0 GHSA-c2qf-rxjj-qqgw',
    ]);
    const body = JSON.parse(r.posts[0].body);
    assert.deepEqual(body.jquery, [`2.${MAX}.${MAX}`, '3.0.0', '3.0.0-rc1']);
    assert.deepEqual(body.debug, [`3.0.${MAX}`, '3.1.0', '3.1.0-beta.1']);
    assert.deepEqual(body.semver, ['7.5.1', '7.5.2', '7.5.2-rc.0']);
    // The probes are only asked about: no finding is for a probe's version.
    assert.ok(r.findings.every((f) => f.package.version.includes('-')));
    assert.equal(r.report.summary.audited_packages, 3);

    // Without the probes, the server returns nothing for these prereleases.
    const dir = tmpdir('audit-registry-');
    fs.cpSync(path.join(FIX, 'registry'), dir, { recursive: true });
    const reg = await startFakeRegistry({ dir });
    try {
      const body2 = path.join(dir, 'body.json');
      fs.writeFileSync(body2, JSON.stringify({ minimist: ['0.0.8'], jquery: ['3.0.0-rc1'], debug: ['3.1.0-beta.1'], semver: ['7.5.2-rc.0'] }));
      const [res] = await core.fetchMany([{ url: reg.url + BULK.slice(1), bodyFile: body2, headers: { 'Content-Type': 'application/json' } }], { workDir: dir, retries: 0 });
      assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(res.file, 'utf8'))), ['minimist']);
    } finally {
      await reg.close();
    }
  });

  test('batching: each request under the limit, with the canary, and the same findings', async () => {
    const r = await runAudit({ cwd: path.join(LOCKS, 'npm/v3'), options: { batchBytes: 300 } });
    assert.equal(r.code, 1);
    assert.deepEqual(ids(r.findings), SHARED_EXPECTED);
    assert.ok(r.posts.length >= 4, `${r.posts.length} requests`);
    assert.equal(r.report.summary.requests, r.posts.length);
    const names = new Set();
    for (const body of bodies(r)) {
      assert.ok(Buffer.byteLength(body) <= 300, body);
      const doc = JSON.parse(body);
      assert.ok(doc.minimist.includes('0.0.8'));
      for (const n of Object.keys(doc)) names.add(n);
    }
    assert.equal(names.size, 1 + 39, 'the canary and the 39 package names');
  });

  test('the canary missing is no verdict: a mirror answering {} can\'t pass', async () => {
    const cwd = path.join(LOCKS, 'npm/v3');
    const empty = await runAudit({ cwd, params: { report_only: 'true' }, overrides: { [`POST ${BULK}`]: { status: 200, body: {} } } });
    assert.equal(empty.code, 1);
    assert.match(empty.err, /^ERROR: The advisory endpoint .* did not return GHSA-vh95-rmgr-6w4m and GHSA-xvch-5gv4-984h for minimist@0\.0\.8/m);
    assert.match(empty.err, /^ERROR: There is no verdict/m);
    assert.equal(empty.report.outcome, 'error');
    assert.deepEqual(empty.findings, []);

    // A mirror that serves some advisories, but not the canary's.
    const partial = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status: 200, body: { lodash: [LODASH_35JH] } } } });
    assert.equal(partial.code, 1);
    assert.match(partial.err, /did not return GHSA-vh95-rmgr-6w4m and GHSA-xvch-5gv4-984h/);
    assert.deepEqual(ids(partial.findings), ['lodash@4.17.20 GHSA-35jh-r3h4-6jhm'], 'what came back is still reported');

    const one = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status: 200, body: { minimist: CANARY_ADVISORIES.filter((a) => a.vulnerable_versions === '<0.2.4') } } } });
    assert.equal(one.code, 1);
    assert.match(one.err, /did not return GHSA-vh95-rmgr-6w4m for minimist@0\.0\.8/);

    // The canary's entries must match 0.0.8 locally.
    const shifted = CANARY_ADVISORIES.map((a) => ({ ...a, vulnerable_versions: '>=0.1.0 <0.2.4' }));
    const wrong = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status: 200, body: { minimist: shifted } } } });
    assert.equal(wrong.code, 1);
    assert.match(wrong.err, /did not return GHSA-vh95-rmgr-6w4m and GHSA-xvch-5gv4-984h/);

    const ok = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status: 200, body: { minimist: CANARY_ADVISORIES } } } });
    assert.equal(ok.code, 0, ok.err);
    assert.deepEqual(ok.findings, [], 'the canary is never a finding');
  });

  test('HTTP errors and failed transfers are no verdict', async () => {
    const cwd = path.join(FIX, 'prerelease');
    for (const status of [400, 403, 404, 405, 413]) {
      const r = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status, body: { statusCode: status, error: 'Nope' } } } });
      assert.equal(r.code, 1, String(status));
      assert.match(r.err, new RegExp(`^ERROR: The advisory endpoint http://127\\.0\\.0\\.1:\\d+/-/npm/v1/security/advisories/bulk answered HTTP ${status}: \\{"statusCode":${status},"error":"Nope"\\}\\.$`, 'm'));
      assert.equal(r.report.outcome, 'error');
      assert.equal(r.posts.length, 1, '4xx is not retried');
      if (status === 403) assert.match(r.err, /^ERROR: If the registry needs a login, set token to the name of a variable holding a token for it\.$/m);
      if (status === 404 || status === 405) assert.match(r.err, /^ERROR: The registry may not serve npm's bulk advisory endpoint/m);
    }
    const auth = await runAudit({ cwd, params: { token: 'AUDIT_TEST_TOKEN' }, env: { AUDIT_TEST_TOKEN: 'npm_Expired' }, overrides: { [`POST ${BULK}`]: { status: 401, body: '' } } });
    assert.equal(auth.code, 1);
    assert.match(auth.err, /^ERROR: .* answered HTTP 401\.\nERROR: Check the token in AUDIT_TEST_TOKEN\.$/m);
    assert.ok(!auth.err.includes('npm_Expired'));
    for (const status of [500, 502, 503]) {
      const r = await runAudit({ cwd, options: noRetries, overrides: { [`POST ${BULK}`]: { status, body: 'down' } } });
      assert.equal(r.code, 1, String(status));
      assert.match(r.err, new RegExp(`answered HTTP ${status}: down\\.`));
    }
    const down = await runAudit({ cwd, options: noRetries, registry: 'http://127.0.0.1:1/' });
    assert.equal(down.code, 1);
    assert.match(down.err, /^ERROR: Could not reach the advisory endpoint http:\/\/127\.0\.0\.1:1\/-\/npm\/v1\/security\/advisories\/bulk: the transfer failed/m);
    // What came back (nothing) is not a verdict, and the summary line doesn't read as one.
    assert.match(down.out, /^Found 0 vulnerabilities in 0 packages in the answers received, but the audit is incomplete \(see the errors\), so it has no verdict\.$/m);
    assert.doesNotMatch(down.out, /fail_on is/);
    const ok = await runAudit({ cwd });
    assert.match(ok.out, /^Found \d+ vulnerabilit(?:y|ies) .*; fail_on is low\.$/m);
  });

  test('a malformed answer is no verdict', async () => {
    const cwd = path.join(LOCKS, 'npm/v3');
    const withCanary = (extra) => ({ minimist: CANARY_ADVISORIES, ...extra });
    const cases = [
      ['oops, not JSON', /answered with something that is not JSON: oops, not JSON\./],
      [[], /answered with \[\], not an object of advisories by package name/],
      ['null', /answered with null, not an object/],
      [withCanary({ lodash: 'none' }), /answered with "none" for lodash, not a list of advisories/],
      [withCanary({ 'left-pad': [] }), /answered for "left-pad", which it was not asked about/],
      [withCanary({ lodash: [{ ...LODASH_35JH, url: undefined }] }), /malformed advisory: .* of lodash has no url/],
      [withCanary({ lodash: [{ ...LODASH_35JH, severity: 'urgent' }] }), /of lodash has the severity "urgent"/],
      [withCanary({ lodash: [{ ...LODASH_35JH, url: 'https://www.npmjs.com/advisories/1106913' }] }), /not a GitHub advisory/],
      [withCanary({ lodash: [{ ...LODASH_35JH, cvss: { score: 'high' } }] }), /malformed cvss/],
      [withCanary({ lodash: [7] }), /advisory 7 of lodash is not an object/],
    ];
    for (const [body, pattern] of cases) {
      const r = await runAudit({ cwd, overrides: { [`POST ${BULK}`]: { status: 200, body: typeof body === 'string' ? body : JSON.stringify(body) } } });
      assert.equal(r.code, 1, JSON.stringify(body));
      assert.match(r.err, pattern);
      assert.match(r.err, /^ERROR: There is no verdict/m);
    }
  });

  test('a range outside the grammar is an error, not a skip', async () => {
    const cwd = path.join(LOCKS, 'npm/v3');
    for (const range of ['^4.17.0', '<4.17.0 || >=4.17.20', '4.17.x']) {
      const body = { minimist: CANARY_ADVISORIES, lodash: [{ ...LODASH_35JH, vulnerable_versions: range }] };
      const r = await runAudit({ cwd, params: { report_only: 'true' }, overrides: { [`POST ${BULK}`]: { status: 200, body } } });
      assert.equal(r.code, 1, range);
      assert.match(r.err, new RegExp(`^ERROR: The advisory GHSA-35jh-r3h4-6jhm of lodash: ${JSON.stringify(range).replace(/[|^.*]/g, '\\$&')} is outside the range grammar`, 'm'));
      assert.match(r.err, /^ERROR: Whether it affects lodash@4\.17\.2[01] can't be told, so the audit has no verdict\.$/m);
      assert.equal(r.report.outcome, 'error');
    }
  });

  test('bad parameters exit 2 before any request', async () => {
    const cwd = path.join(LOCKS, 'npm/v3');
    for (const [params, pattern] of [
      [{ fail_on: 'urgent' }, /^ERROR: fail_on must be one of low, moderate, high, critical, not "urgent"\.$/m],
      [{ fail_on: '' }, /fail_on must be one of/],
      [{ ignore: 'CVE-2020-8203' }, /^ERROR: ignore takes GitHub advisory IDs such as GHSA-35jh-r3h4-6jhm, not "CVE-2020-8203"/m],
      [{ ignore: 'GHSA-35jh-r3h4-6jhm GHSA-35jh-r3h4' }, /not "GHSA-35jh-r3h4"/],
      [{ token: 'UNSET_AUDIT_TOKEN' }, /token names UNSET_AUDIT_TOKEN, which is not set or empty/],
    ]) {
      const r = await runAudit({ cwd, params });
      assert.equal(r.code, 2, JSON.stringify(params));
      assert.match(r.err, pattern);
      assert.deepEqual(r.requests, [], 'nothing was sent');
    }
  });

  test('a locked version the matcher can\'t read is an error, before any request', async () => {
    const r = await runAudit({ cwd: path.join(FIX, 'badversion') });
    assert.equal(r.code, 1);
    assert.match(r.err, /^ERROR: tests\/fixtures\/audit\/badversion\/package-lock\.json:15: left-pad is locked at "1\.3", which is not a semver version/m);
    assert.deepEqual(r.requests, []);
  });

  test('nothing to audit: no request, and no verdict unless allow_empty', async () => {
    const cwd = path.join(FIX, 'private-only');
    const r = await runAudit({ cwd });
    assert.equal(r.code, 1);
    assert.match(r.err, /checked nothing/);
    assert.match(r.err, /@corp\/secret-lib/);
    assert.deepEqual(r.requests, []);
    const empty = await runAudit({ cwd, params: { allow_empty: 'true' } });
    assert.equal(empty.code, 0, empty.err);
    assert.deepEqual(empty.requests, []);
    assert.equal(empty.report.summary.audited_entries, 0);
  });

  test('the module runs the command when it is the program, and only then', () => {
    const out = tmpdir('audit-out-');
    const r = spawnSync(process.execPath, [MODULE], {
      cwd: path.join(FIX, 'npm'), encoding: 'utf8',
      env: { PATH: process.env.PATH, HOME: process.env.HOME, NPM_CONFIG_USERCONFIG: '/nonexistent/.npmrc', PARAM_OUTPUT_DIR: out, PARAM_FAIL_ON: 'nope' },
    });
    assert.equal(r.status, 2, r.stderr);
    assert.match(r.stderr, /^ERROR: fail_on must be one of/m);
    assert.equal(typeof A.audit, 'function', 'importing it ran nothing');
  });
});

// ---------------------------------------------------------------------------
// Regressions from review: the project's configuration says where a package comes from, so its
// name never reaches another registry.
describe('names a project\'s configuration routes elsewhere', () => {
  const PNPM = (dep) => `lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      '${dep}':\n        specifier: 1.0.0\n        version: 1.0.0\n      minimist:\n        specifier: 1.2.0\n        version: 1.2.0\n\npackages:\n\n  '${dep}@1.0.0':\n    resolution: {integrity: sha512-kZrcVFFp3hGvROhHafpNZ9U1tB3jLr4ptfq7hZiJ1g18VSy817gWxfm8FQhNUC1jXcCBoMsrg3os434eYU2M4g==}\n\n  minimist@1.2.0:\n    resolution: {integrity: sha512-kZrcVFFp3hGvROhHafpNZ9U1tB3jLr4ptfq7hZiJ1g18VSy817gWxfm8FQhNUC1jXcCBoMsrg3os434eYU2M4g==}\n\nsnapshots:\n\n  '${dep}@1.0.0': {}\n\n  minimist@1.2.0: {}\n`;
  const project = (dep, files) => {
    const dir = tmpdir('audit-config-');
    fs.writeFileSync(path.join(dir, 'pnpm-lock.yaml'), PNPM(dep));
    for (const [name, text] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), text);
    return dir;
  };

  test('an .npmrc registry= that is not registry stops the check before any request', async () => {
    const r = await runAudit({ cwd: project('corp-internal-billing', { '.npmrc': 'registry=https://npm.corp.example/\n//npm.corp.example/:_authToken=${CORP_TOKEN}\n' }) });
    assert.equal(r.code, 2);
    assert.match(r.err, /^ERROR: \.npmrc line 1 sets registry=https:\/\/npm\.corp\.example\/, but registry is http:\/\/127\.0\.0\.1:\d+\/: packages the lockfiles record no registry for would be looked up on .*, sending their names there\. Set registry to https:\/\/npm\.corp\.example\/ \(and token, if it needs one\)\.$/m);
    assert.deepEqual(r.requests, []);
    // A .yarnrc.yml's npmRegistryServer, likewise.
    const y = await runAudit({ cwd: project('corp-internal-billing', { '.yarnrc.yml': 'npmRegistryServer: "https://npm.corp.example"\n' }) });
    assert.equal(y.code, 2);
    assert.deepEqual(y.requests, []);
  });

  test('a scope whose registry can\'t be resolved is never sent anywhere', async () => {
    const r = await runAudit({ cwd: project('@corp/billing', { '.npmrc': '@corp:registry=${CORP_REGISTRY_URL}\n' }) });
    assert.equal(r.code, 1, 'minimist\'s advisories');
    assert.ok(r.posts.length > 0 && r.posts.every((q) => !q.body.includes('corp')), JSON.stringify(bodies(r)));
    assert.match(r.err, /^WARN: \.npmrc line 1: the registry of @corp is "\$\{CORP_REGISTRY_URL\}", which can't be resolved \(\$\{CORP_REGISTRY_URL\} is not set\)/m);
    assert.deepEqual(r.report.skipped.filter((x) => x.kind === 'registry').map((x) => [x.name, x.reason]), [['@corp/billing', 'the registry of @corp (.npmrc line 1) can\'t be resolved']]);
    // Resolved from the environment, it is that scope's registry's, which audit never asks.
    const set = await runAudit({ cwd: project('@corp/billing', { '.npmrc': '@corp:registry=${CORP_REGISTRY_URL}\n' }), env: { CORP_REGISTRY_URL: 'https://npm.corp.example/' } });
    assert.ok(set.posts.every((q) => !q.body.includes('corp')));
    assert.match(set.report.skipped.find((x) => x.name === '@corp/billing').reason, /a scope's registry, are not sent/);
    // A .yarnrc.yml scope (Yarn writes it without the @) routes the same way.
    const yarn = await runAudit({ cwd: project('@corp/billing', { '.yarnrc.yml': 'npmScopes:\n  corp:\n    npmRegistryServer: "https://npm.corp.example"\n' }) });
    assert.ok(yarn.posts.every((q) => !q.body.includes('corp')));
    assert.ok(yarn.report.skipped.some((x) => x.name === '@corp/billing'));
  });
});
