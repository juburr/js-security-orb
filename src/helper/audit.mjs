// audit.mjs: the audit command of js-security-orb's Node.js helper (Node >= 22,
// standard library only). It audits the packages the lockfiles lock against the
// GitHub advisories npm's registry serves, and matches every locked version
// itself:
//
//   1. Reads the lockfiles (core), then sorts the entries into those to audit
//      and those it skips. Each registry package's registry is core's
//      metadataRegistry, the rule every command follows (a package recorded on
//      registry.npmjs.org comes from the registry configured for its name). It
//      is audited when that is the registry parameter, or the public registry
//      (https://registry.npmjs.org/, through a scope mapped to it), whose names
//      are public anyway, so asking a mirror about them leaks nothing. Unlike
//      the other commands, which ask each package's own registry, audit skips
//      packages from a scope's registry too: the advisories come from
//      registry's endpoint only, and a private package's name must never reach
//      another origin. Everything skipped is listed, and its name never sent:
//      packages from other registries, git, tarball URLs, file:/link: packages
//      and workspaces. Asking about a git fork or a workspace by name would
//      report the registry package of that name, which npm 10 and yarn 1 get
//      wrong.
//   2. Checks every version it will send with a strict semver parser (what
//      node-semver accepts without loose, minus a leading v or =, at most 256
//      characters, safe integers): one it can't read is an error naming the
//      package, before any request.
//   3. POSTs <registry>-/npm/v1/security/advisories/bulk on the registry
//      parameter's origin, with the token if one is set (core sends it to that
//      origin only): {name: [versions]}, gzipped, in batches of at most 5 MiB of
//      JSON (the endpoint refuses more than 10,485,760 bytes once decompressed).
//      Every batch also carries:
//        - prerelease probes: the server matches with node-semver's default
//          satisfies(), which drops almost every advisory for a prerelease. For
//          X.Y.Z-pre it is also sent X.Y.Z and the largest release below it
//          (X.Y.(Z-1), X.(Y-1).MAX or (X-1).MAX.MAX, MAX = 2^53-1), which
//          recovered every advisory on the research corpus. The probes only
//          widen the answer: the local match against the locked version decides.
//        - the canary minimist@0.0.8, which must come back with its two
//          advisories (GHSA-vh95-rmgr-6w4m and GHSA-xvch-5gv4-984h), matching
//          0.0.8 locally. Otherwise there is no verdict: a mirror or proxy that
//          answers {} can't be told from a clean audit any other way. The canary
//          is never a finding; a locked minimist is matched like any package.
//   4. Checks each answer strictly: HTTP 200, a JSON object whose keys are names
//      that batch asked about, each an array of advisories with an integer id,
//      a https://github.com/advisories/GHSA-... url, a title, a severity (info,
//      low, moderate, high, critical) and vulnerable_versions; cwe and cvss are
//      checked when present. Anything else, a transfer error, or any other HTTP
//      status is no verdict.
//   5. The server answers with every advisory matching any version it was sent,
//      so each locked version is matched locally against vulnerable_versions,
//      with node-semver's includePrerelease semantics (validated against
//      node-semver on 5.7M checks; tests/fixtures/audit/matcher_cases.json holds
//      a sample). The grammar is the one the endpoint uses: space-separated
//      comparators (<, <=, >, >=, = or none) on full versions, or on partial
//      ones such as <1.2 or >=0, which node-semver desugars. ||, hyphen ranges,
//      ^, ~, x, *, build metadata, a leading v or a space after an operator is
//      outside it: an error, never a skip, since the advisory might apply.
//
// Findings: one per (package, version, GHSA), the GHSA read from the advisory's
// url, whichever lockfiles and lines lock that version (details.locations lists
// them; the finding, and its SARIF result, is at the first). npm splits one
// GHSA into an entry per range, and when several match, the most severe one
// (then the highest CVSS score) describes the finding. The rule is
// audit/<GHSA>, level 'error' at or above fail_on, else 'warning'; SARIF's
// security-severity is the CVSS score when there is one (npm sends score 0 for
// none), else 9.5, 8.0, 5.5, 2.0 or 0.0 by severity. ignore takes GHSA IDs,
// checked before anything else (a bad one exits 2): an ignored match is not a
// finding but is listed in the report's summary (ignored) and the log, and an
// entry that matched nothing is a warning. The JSON report's results list every
// audited package with what matched; summary has counts by severity.
//
// checked, which core turns into "checked nothing" when 0, is the number of
// lockfile entries audited, not counting the canary and the probes; with none,
// no request is made. A registry that forwards the bulk request upstream
// (Verdaccio forwards it to registry.npmjs.org) forwards the names of the
// packages it served too: they are audited, since they come from the registry
// the user chose.

import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import {
  main, isMain, metadataRegistry, authHint, skipWarning, UsageError, DEFAULT_REGISTRY, PACKAGE_NAME_RE, plural, publicUrl, show,
} from './core.mjs';

/** The bulk advisory endpoint, relative to the registry. */
export const BULK_PATH = '-/npm/v1/security/advisories/bulk';
/** The most decompressed JSON the endpoint accepts in one request. */
export const MAX_REQUEST_BYTES = 10485760;
/** The batch size the command uses: well under the endpoint's limit. */
export const BATCH_BYTES = 5 * 1024 * 1024;
/** The canary every request carries, and the advisories it must come back with. */
export const CANARY = Object.freeze({ name: 'minimist', version: '0.0.8', ghsas: Object.freeze(['GHSA-vh95-rmgr-6w4m', 'GHSA-xvch-5gv4-984h']) });
/** The severities the endpoint uses, lowest first. */
export const SEVERITIES = Object.freeze(['info', 'low', 'moderate', 'high', 'critical']);
/** The values fail_on takes. */
export const FAIL_ON = Object.freeze(['low', 'moderate', 'high', 'critical']);
/** SARIF security-severity by severity, for an advisory without a CVSS score. */
export const SEVERITY_SCORES = Object.freeze({ critical: '9.5', high: '8.0', moderate: '5.5', low: '2.0', info: '0.0' });

const MAX = Number.MAX_SAFE_INTEGER;
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const rank = (severity) => SEVERITIES.indexOf(severity);

// ---------------------------------------------------------------------------
// Versions and ranges
// ---------------------------------------------------------------------------

const NUM = '0|[1-9]\\d*';
const PRE_ID = '0|[1-9]\\d*|\\d*[A-Za-z-][0-9A-Za-z-]*';
const PRE = `(?:${PRE_ID})(?:\\.(?:${PRE_ID}))*`;
const BUILD = '[0-9A-Za-z-]+(?:\\.[0-9A-Za-z-]+)*';
const VERSION_RE = new RegExp(`^(${NUM})\\.(${NUM})\\.(${NUM})(?:-(${PRE}))?(?:\\+${BUILD})?$`);
const BOUND_RE = new RegExp(`^(${NUM})\\.(${NUM})\\.(${NUM})(?:-(${PRE}))?$`);
const PARTIAL_RE = new RegExp(`^(${NUM})(?:\\.(${NUM}))?$`);

/** A vulnerable_versions range outside the grammar the matcher reads. */
export class RangeGrammarError extends Error {
  constructor(message) { super(message); this.name = 'RangeGrammarError'; }
}

function fromMatch(m) {
  const nums = [m[1], m[2], m[3]].map(Number);
  if (!nums.every(Number.isSafeInteger)) return null;
  return { nums, pre: m[4] === undefined ? [] : m[4].split('.') };
}

/**
 * Parses a version strictly: MAJOR.MINOR.PATCH, an optional prerelease and
 * build metadata, as node-semver reads a version without loose (no leading v
 * or =), at most 256 characters, with numbers up to 2^53-1.
 * @param {string} version
 * @returns {{nums: number[], pre: string[]}|null} null when it isn't one
 */
export function parseVersion(version) {
  if (typeof version !== 'string' || version.length > 256) return null;
  const m = VERSION_RE.exec(version);
  return m ? fromMatch(m) : null;
}

function compareIds(a, b) {
  const an = /^\d+$/.test(a);
  const bn = /^\d+$/.test(b);
  if (an && bn) {
    const x = BigInt(a);
    const y = BigInt(b);
    return x < y ? -1 : x > y ? 1 : 0;
  }
  if (an) return -1;
  if (bn) return 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Compares two parsed versions as semver orders them (build metadata ignored).
 * @returns {number} -1, 0 or 1
 */
export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) if (a.nums[i] !== b.nums[i]) return a.nums[i] < b.nums[i] ? -1 : 1;
  if (!a.pre.length || !b.pre.length) return (b.pre.length ? 1 : 0) - (a.pre.length ? 1 : 0);
  for (let i = 0; ; i++) {
    if (i >= a.pre.length || i >= b.pre.length) return (a.pre.length > i ? 1 : 0) - (b.pre.length > i ? 1 : 0);
    const c = compareIds(a.pre[i], b.pre[i]);
    if (c) return c;
  }
}

/**
 * Parses a vulnerable_versions range into the bounds every version in it
 * meets, with node-semver's includePrerelease desugaring of partial versions:
 * <1.2 is <1.2.0-0, <=1.2 is <1.3.0-0, >1.2 is >=1.3.0-0, >=1.2 is >=1.2.0-0,
 * =1.2 (or 1.2) is both, and >=0 or >=0.0 is any version.
 * @param {string} range
 * @returns {Array<[string, object]>} [operator, parsed version] pairs
 * @throws {RangeGrammarError} for anything outside the grammar
 */
export function parseRange(range) {
  if (typeof range !== 'string') throw new RangeGrammarError(`vulnerable_versions is ${show(range)}, not a string`);
  const text = range.trim();
  if (!text || text.length > 1024) throw new RangeGrammarError(`${show(range)} is not a range`);
  const bounds = [];
  for (const token of text.split(/\s+/)) {
    const m = /^(<=|>=|<|>|=)?([\s\S]*)$/.exec(token);
    const op = m[1] ?? '=';
    const full = BOUND_RE.exec(m[2]);
    const parsed = full && fromMatch(full);
    if (parsed) {
      bounds.push([op, parsed]);
      continue;
    }
    const p = PARTIAL_RE.exec(m[2]);
    const major = p ? Number(p[1]) : NaN;
    const minor = p && p[2] !== undefined ? Number(p[2]) : null;
    if (!p || !(major < MAX) || !(minor === null || minor < MAX)) {
      throw new RangeGrammarError(`${show(range)} is outside the range grammar this orb reads (comparators such as <1.2.3, >=1.2 or =1.2.3, separated by spaces): ${show(token)}`);
    }
    const lo = { nums: [major, minor ?? 0, 0], pre: ['0'] };
    const hi = { nums: minor === null ? [major + 1, 0, 0] : [major, minor + 1, 0], pre: ['0'] };
    if (op === '<') bounds.push(['<', lo]);
    else if (op === '<=') bounds.push(['<', hi]);
    else if (op === '>') bounds.push(['>=', hi]);
    else if (op === '>=') { if (major !== 0 || (minor ?? 0) !== 0) bounds.push(['>=', lo]); }
    else bounds.push(['>=', lo], ['<', hi]);
  }
  return bounds;
}

/**
 * Whether VERSION is in RANGE, with node-semver's includePrerelease
 * semantics: satisfies(version, range, {includePrerelease: true}).
 * @param {string|object} version a version, or parseVersion()'s result
 * @param {string|Array} range a range, or parseRange()'s result
 * @throws {RangeGrammarError} for a range outside the grammar; Error for a version that isn't one
 */
export function satisfies(version, range) {
  const v = typeof version === 'string' ? parseVersion(version) : version;
  if (!v) throw new Error(`${show(version)} is not a version`);
  const bounds = typeof range === 'string' ? parseRange(range) : range;
  return bounds.every(([op, b]) => {
    const c = compareVersions(v, b);
    return op === '<' ? c < 0 : op === '<=' ? c <= 0 : op === '>' ? c > 0 : op === '>=' ? c >= 0 : c === 0;
  });
}

/**
 * The probes sent with a prerelease X.Y.Z-pre, so the server, which matches
 * prereleases with node-semver's default semantics, returns every advisory
 * the prerelease may be in: X.Y.Z and the largest release below it. None for
 * a release.
 * @param {string} version
 * @returns {string[]}
 */
export function prereleaseProbes(version) {
  const v = parseVersion(version);
  if (!v || !v.pre.length) return [];
  const [x, y, z] = v.nums;
  const probes = [`${x}.${y}.${z}`];
  if (z > 0) probes.push(`${x}.${y}.${z - 1}`);
  else if (y > 0) probes.push(`${x}.${y - 1}.${MAX}`);
  else if (x > 0) probes.push(`${x - 1}.${MAX}.${MAX}`);
  return probes;
}

// ---------------------------------------------------------------------------
// Advisory identity
// ---------------------------------------------------------------------------

const GHSA_PART = '[23456789cfghjmpqrvwx]{4}';
const GHSA_RE = new RegExp(`^GHSA-(${GHSA_PART})-(${GHSA_PART})-(${GHSA_PART})$`, 'i');
const ADVISORY_URL_RE = /^https:\/\/github\.com\/advisories\/(GHSA-[A-Za-z0-9-]+)$/;

/**
 * A GHSA ID as GHSA-xxxx-xxxx-xxxx (lower-case body), or null when it isn't one.
 * @param {string} id
 */
export function normalizeGhsa(id) {
  const m = GHSA_RE.exec(String(id ?? '').trim());
  return m ? `GHSA-${m[1].toLowerCase()}-${m[2].toLowerCase()}-${m[3].toLowerCase()}` : null;
}

/** The GHSA of an advisory url (https://github.com/advisories/GHSA-...), or null. */
export function ghsaOfUrl(url) {
  const m = ADVISORY_URL_RE.exec(String(url ?? ''));
  return m ? normalizeGhsa(m[1]) : null;
}

// ---------------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------------

const jsonLength = (s) => Buffer.byteLength(JSON.stringify(s));

/**
 * Splits the query into batches of at most LIMIT bytes of JSON, each starting
 * with the canary. A package's versions may be split between batches.
 * @param {Map<string, string[]>} query name -> versions
 * @param {number} limit
 * @returns {Array<{body: string, names: Set<string>, size: number}>}
 */
export function makeBatches(query, limit = BATCH_BYTES) {
  const fresh = () => ({ map: new Map([[CANARY.name, [CANARY.version]]]), size: 2 + jsonLength(CANARY.name) + 3 + jsonLength(CANARY.version) });
  const batches = [];
  let cur = fresh();
  for (const [name, versions] of query) {
    for (const version of versions) {
      if (name === CANARY.name && version === CANARY.version) continue;
      const delta = (b) => (b.map.has(name) ? 1 + jsonLength(version) : 1 + jsonLength(name) + 3 + jsonLength(version));
      if (cur.size + delta(cur) > limit) {
        if (cur.map.size === 1 && cur.map.get(CANARY.name).length === 1) throw new Error(`The advisory request for ${show(name)} doesn't fit in ${limit} bytes.`);
        batches.push(cur);
        cur = fresh();
        if (cur.size + delta(cur) > limit) throw new Error(`The advisory request for ${show(name)} doesn't fit in ${limit} bytes.`);
      }
      cur.size += delta(cur);
      if (cur.map.has(name)) cur.map.get(name).push(version);
      else cur.map.set(name, [version]);
    }
  }
  batches.push(cur);
  return batches.map((b) => {
    const body = `{${[...b.map].map(([n, vs]) => `${JSON.stringify(n)}:[${vs.map((v) => JSON.stringify(v)).join(',')}]`).join(',')}}`;
    if (Buffer.byteLength(body) !== b.size || b.size > limit) throw new Error(`Internal error: an advisory request of ${Buffer.byteLength(body)} bytes, not ${b.size}.`);
    return { body, names: new Set(b.map.keys()), size: b.size };
  });
}

/**
 * Checks one advisory of the endpoint's answer.
 * @returns {{advisory?: object, error?: string}} advisory has ghsa, and bounds
 *   (null with rangeError when its range is outside the grammar)
 */
export function checkAdvisory(a, name) {
  const bad = (what) => ({ error: `the advisory ${show(a)} of ${name} ${what}` });
  if (!isObj(a)) return bad('is not an object');
  if (!Number.isSafeInteger(a.id) || a.id < 0) return bad('has no numeric id');
  if (typeof a.url !== 'string') return bad('has no url');
  const ghsa = ghsaOfUrl(a.url);
  if (!ghsa) return bad('has a url that is not a GitHub advisory (https://github.com/advisories/GHSA-...)');
  if (typeof a.title !== 'string') return bad('has no title');
  if (!SEVERITIES.includes(a.severity)) return bad(`has the severity ${show(a.severity)}, not one of ${SEVERITIES.join(', ')}`);
  if (typeof a.vulnerable_versions !== 'string') return bad('has no vulnerable_versions');
  if (own(a, 'cwe') && !(Array.isArray(a.cwe) && a.cwe.every((c) => typeof c === 'string'))) return bad('has a cwe that is not a list of strings');
  let cvss = null;
  if (own(a, 'cvss') && a.cvss !== null) {
    if (!isObj(a.cvss) || typeof a.cvss.score !== 'number' || !(a.cvss.score >= 0 && a.cvss.score <= 10)
      || !(a.cvss.vectorString === null || a.cvss.vectorString === undefined || typeof a.cvss.vectorString === 'string')) {
      return bad('has a malformed cvss');
    }
    cvss = { score: a.cvss.score, vectorString: a.cvss.vectorString ?? null };
  }
  let bounds = null;
  let rangeError = null;
  try { bounds = parseRange(a.vulnerable_versions); } catch (e) {
    if (!(e instanceof RangeGrammarError)) throw e;
    rangeError = e.message;
  }
  return {
    advisory: {
      id: a.id, ghsa, url: `https://github.com/advisories/${ghsa}`, title: a.title, severity: a.severity,
      range: a.vulnerable_versions, bounds, rangeError, cwe: a.cwe ?? [], cvss,
    },
  };
}

/**
 * Reads one batch's answer: the advisories by name, and errors (no verdict)
 * for an HTTP error, a malformed answer or a missing canary.
 * @param {{status, file, error}} res fetchMany's result
 * @param {{names: Set<string>}} batch
 * @param {string} where the endpoint, for messages
 * @param {{auth?: string}} [hints] what to say about a 401 or 403
 * @returns {{advisories: Map<string, object[]>, errors: string[]}}
 */
export function readAnswer(res, batch, where, { auth = authHint(null) } = {}) {
  const advisories = new Map();
  const errors = [];
  let text = '';
  try { text = fs.readFileSync(res.file, 'utf8'); } catch { /* no body */ }
  // eslint-disable-next-line no-control-regex
  const flat = text.trim().replace(/\s+/g, ' ').replace(/[\0-\x1f\x7f]/g, '?');
  const snippet = () => (flat ? `: ${flat.slice(0, 200)}${flat.length > 200 ? '...' : ''}` : '');
  if (res.status === 0) return { advisories, errors: [`Could not reach the advisory endpoint ${where}: ${res.error}.`] };
  if (res.status !== 200) {
    const hint = res.status === 401 || res.status === 403 ? `\n${auth}`
      : res.status === 404 || res.status === 405 || res.status === 501 ? '\nThe registry may not serve npm\'s bulk advisory endpoint: set registry to one that does, such as https://registry.npmjs.org.' : '';
    return { advisories, errors: [`The advisory endpoint ${where} answered HTTP ${res.status}${snippet()}.${hint}`] };
  }
  let doc;
  try { doc = JSON.parse(text); } catch {
    return { advisories, errors: [`The advisory endpoint ${where} answered with something that is not JSON${snippet()}.`] };
  }
  if (!isObj(doc)) return { advisories, errors: [`The advisory endpoint ${where} answered with ${show(doc)}, not an object of advisories by package name.`] };
  for (const name of Object.keys(doc)) {
    if (!batch.names.has(name)) {
      errors.push(`The advisory endpoint ${where} answered for ${show(name)}, which it was not asked about.`);
      continue;
    }
    if (!Array.isArray(doc[name])) {
      errors.push(`The advisory endpoint ${where} answered with ${show(doc[name])} for ${name}, not a list of advisories.`);
      continue;
    }
    const list = [];
    for (const a of doc[name]) {
      const r = checkAdvisory(a, name);
      if (r.error) errors.push(`The advisory endpoint ${where} answered with a malformed advisory: ${r.error}.`);
      else list.push(r.advisory);
    }
    advisories.set(name, list);
  }
  const canary = parseVersion(CANARY.version);
  const found = new Set((advisories.get(CANARY.name) ?? []).filter((a) => a.bounds && satisfies(canary, a.bounds)).map((a) => a.ghsa));
  const missing = CANARY.ghsas.filter((g) => !found.has(g));
  if (missing.length && !errors.length) {
    errors.push(`The advisory endpoint ${where} did not return ${missing.join(' and ')} for ${CANARY.name}@${CANARY.version}, a known vulnerable version every request asks about,\n`
      + 'so its answers can\'t be told from a clean audit. A registry, mirror or proxy that doesn\'t serve npm\'s advisories\n'
      + '(or answers {}) does this: set registry to one that does, such as https://registry.npmjs.org.');
  }
  return { advisories, errors };
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const SKIP_LABELS = {
  registry: ['from another registry', 'from other registries'], git: ['from git', 'from git'],
  remote: ['from a tarball URL', 'from tarball URLs'], local: ['local package', 'local packages'],
  link: ['linked package', 'linked packages'], workspace: ['workspace package', 'workspace packages'],
};

const SKIP_REASONS = {
  git: 'from git, not a registry: advisories name registry packages',
  remote: 'from a tarball URL, not a registry: advisories name registry packages',
  local: 'a local package (file:)',
  link: 'a linked local package (link:)',
  workspace: 'a package of the project\'s workspace',
};

const where = (l) => `${l.lockfile}:${l.line ?? 1}`;
const byLocation = (a, b) => (a.lockfile < b.lockfile ? -1 : a.lockfile > b.lockfile ? 1 : (a.line ?? 0) - (b.line ?? 0));

/**
 * Runs the audit command on a context (see core's createContext).
 * @param {object} ctx
 * @param {{batchBytes?: number, fetchMany?: Function}} [options] for tests:
 *   the batch size, and a stand-in for ctx.client.fetchMany
 * @returns {Promise<object>} the result for core's runCommand
 */
export async function audit(ctx, { batchBytes = BATCH_BYTES, fetchMany } = {}) {
  const { io } = ctx;
  // Every parameter first: a bad one exits 2 before any request.
  const failOn = ctx.choice('fail_on', [...FAIL_ON], 'low');
  const ignore = new Map();
  for (const text of ctx.list('ignore', '')) {
    const id = normalizeGhsa(text);
    if (!id) throw new UsageError(`ignore takes GitHub advisory IDs such as GHSA-35jh-r3h4-6jhm, not ${show(text)}: the advisories npm serves are identified by their GHSA.`);
    ignore.set(id, false);
  }
  if (!Number.isSafeInteger(batchBytes) || batchBytes < 64 || batchBytes > MAX_REQUEST_BYTES) throw new Error(`Internal error: a batch size of ${batchBytes} bytes.`);

  const { entries } = ctx.readLockfiles();
  const registry = ctx.registries.registry;
  const endpoint = registry + BULK_PATH;
  const shownEndpoint = publicUrl(endpoint);

  // Sort the entries into packages to audit and entries to skip.
  const packages = new Map(); // name@version -> {name, version, parsed, entries}
  const skipped = [];
  const errors = [];
  let checked = 0;
  for (const e of entries) {
    const target = e.kind === 'registry' ? metadataRegistry(e, ctx.registries) : null;
    if (!target || (target.registry !== registry && target.registry !== DEFAULT_REGISTRY)) {
      skipped.push({
        name: e.name ?? null, version: e.version ?? null, kind: e.kind, lockfile: e.lockfile, line: e.line ?? null,
        source: e.source == null ? null : ['registry', 'git', 'remote'].includes(e.kind) ? publicUrl(e.source) : e.source,
        reason: !target ? SKIP_REASONS[e.kind] ?? `a ${e.kind} entry`
          : target.reason ?? `packages from ${target.registry}, a scope's registry, are not sent to registry's advisory endpoint`,
      });
      continue;
    }
    const parsed = parseVersion(e.version);
    if (typeof e.name !== 'string' || !PACKAGE_NAME_RE.test(e.name)) {
      errors.push(`${where(e)}: ${show(e.name)} is not a package name the advisory endpoint can be asked about.`);
      continue;
    }
    if (!parsed) {
      errors.push(`${where(e)}: ${e.name} is locked at ${show(e.version)}, which is not a semver version the advisory endpoint can match, so it can't be audited.`);
      continue;
    }
    checked++;
    const key = `${e.name}@${e.version}`;
    if (!packages.has(key)) packages.set(key, { name: e.name, version: e.version, parsed, entries: [] });
    packages.get(key).entries.push(e);
  }

  const skipCounts = {};
  for (const s of skipped) skipCounts[s.kind] = (skipCounts[s.kind] ?? 0) + 1;
  const warnings = [];
  const label = (s) => (s.version ? `${s.name}@${s.version}` : s.name ?? s.source);
  const foreign = new Map(); // reason -> labels
  for (const s of skipped.filter((x) => x.kind === 'registry')) foreign.set(s.reason, [...(foreign.get(s.reason) ?? []), label(s)]);
  for (const [reason, names] of foreign) {
    warnings.push(skipWarning(names, 'audited', reason, `The names of packages from other registries are never sent to ${publicUrl(registry)}, where the advisories come from. `
      + 'To audit them, set registry to the registry they come from, if it serves npm\'s advisories.'));
  }
  const unregistered = skipped.filter((s) => s.kind === 'git' || s.kind === 'remote');
  if (unregistered.length) warnings.push(skipWarning(unregistered.map(label), 'audited', 'advisories name registry packages, not git or tarball URLs'));
  if (skipped.length) {
    io.log(`Not audited: ${Object.entries(skipCounts).map(([k, n]) => `${n} ${(SKIP_LABELS[k] ?? [k, k])[n === 1 ? 0 : 1]}`).join(', ')} (listed in the report's skipped).`);
  }

  const summary = {
    registry: publicUrl(registry), endpoint: shownEndpoint, fail_on: failOn, requests: 0,
    audited_entries: checked, audited_packages: packages.size, skipped: skipCounts,
    vulnerabilities: Object.fromEntries([...SEVERITIES].reverse().map((s) => [s, 0])), findings: 0, failing: 0,
    ignored: [], unused_ignores: [],
  };
  const base = { warnings, skipped, summary, checked };
  if (errors.length) return { ...base, errors };
  if (!packages.size) return { ...base, errors: [] };

  // The query: every audited version, with the prerelease probes.
  const query = new Map();
  for (const p of [...packages.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))) {
    if (!query.has(p.name)) query.set(p.name, new Set());
    for (const v of [p.version, ...prereleaseProbes(p.version)]) query.get(p.name).add(v);
  }
  const batches = makeBatches(new Map([...query].map(([n, vs]) => [n, [...vs].sort()])), batchBytes);
  summary.requests = batches.length;
  io.log(`Auditing ${plural(packages.size, 'package')} (${plural(checked, 'lockfile entry', 'lockfile entries')}) against ${shownEndpoint}${batches.length > 1 ? ` in ${batches.length} requests` : ''}.`);

  const dir = fs.mkdtempSync(path.join(ctx.workDir, 'audit-'));
  const requests = batches.map((b, i) => {
    const file = path.join(dir, `bulk-${i}.json.gz`);
    fs.writeFileSync(file, zlib.gzipSync(b.body), { mode: 0o600 });
    return { url: endpoint, bodyFile: file, headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip', Accept: 'application/json' } };
  });
  const answers = await (fetchMany ?? ((r) => ctx.client.fetchMany(r)))(requests);

  // Merge the answers: advisories by name, each entry once.
  const byName = new Map();
  const errorSet = new Set();
  answers.forEach((res, i) => {
    const r = readAnswer(res, batches[i], shownEndpoint, {
      auth: authHint(ctx.tokenVar),
    });
    for (const e of r.errors) errorSet.add(e);
    for (const [name, list] of r.advisories) {
      if (!byName.has(name)) byName.set(name, new Map());
      for (const a of list) byName.get(name).set(`${a.id}\n${a.ghsa}\n${a.range}`, a);
    }
  });

  // Match every audited version locally.
  const findings = [];
  const ignored = [];
  const results = [];
  const rules = {};
  const rangeErrors = new Map();
  for (const p of [...packages.values()].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : compareVersions(a.parsed, b.parsed)))) {
    const hits = new Map(); // ghsa -> {best, ids, ranges}
    for (const a of (byName.get(p.name) ?? new Map()).values()) {
      if (!a.bounds) {
        rangeErrors.set(`${p.name}\n${a.range}`, `The advisory ${a.ghsa} of ${p.name}: ${a.rangeError}.\nWhether it affects ${p.name}@${p.version} can't be told, so the audit has no verdict.`);
        continue;
      }
      if (!satisfies(p.parsed, a.bounds)) continue;
      const h = hits.get(a.ghsa) ?? { best: a, ids: new Set(), ranges: new Set() };
      const score = (x) => x.cvss?.score ?? 0;
      if (rank(a.severity) > rank(h.best.severity) || (rank(a.severity) === rank(h.best.severity) && (score(a) > score(h.best) || (score(a) === score(h.best) && a.id < h.best.id)))) h.best = a;
      h.ids.add(a.id);
      h.ranges.add(a.range);
      hits.set(a.ghsa, h);
    }
    const located = [...p.entries].sort(byLocation);
    const locations = located.map((e) => ({ lockfile: e.lockfile, line: e.line ?? null, alias: e.alias ?? null }));
    const aliases = [...new Set(locations.map((l) => l.alias).filter(Boolean))];
    const vulnerabilities = [];
    for (const [ghsa, h] of [...hits].sort((x, y) => rank(y[1].best.severity) - rank(x[1].best.severity) || (x[0] < y[0] ? -1 : 1))) {
      const a = h.best;
      const isIgnored = ignore.has(ghsa);
      vulnerabilities.push({ ghsa, severity: a.severity, ignored: isIgnored });
      const details = {
        ghsa, severity: a.severity, title: a.title, url: a.url, vulnerable_versions: [...h.ranges].join(' || '),
        npm_advisory_ids: [...h.ids].sort((x, y) => x - y), cvss: a.cvss, cwe: a.cwe, fail_on: failOn, locations,
      };
      if (isIgnored) {
        ignore.set(ghsa, true);
        ignored.push({ name: p.name, version: p.version, ...details });
        continue;
      }
      const score = a.cvss && a.cvss.score > 0 ? a.cvss.score.toFixed(1) : SEVERITY_SCORES[a.severity];
      const others = locations.slice(1);
      const as = aliases.length ? ` (installed as ${aliases.join(', ')})` : '';
      const also = others.length ? ` Also locked at ${others.slice(0, 3).map(where).join(', ')}${others.length > 3 ? `, and ${others.length - 3} more` : ''}.` : '';
      const rule = `audit/${ghsa}`;
      rules[rule] = {
        description: `${ghsa}: ${a.title}`, helpUri: a.url, securitySeverity: score,
        tags: ['vulnerability', ...a.cwe.filter((c) => /^CWE-\d+$/.test(c)).map((c) => `external/cwe/${c.toLowerCase()}`)],
      };
      findings.push(ctx.finding(located[0], {
        kind: 'vulnerability',
        rule,
        level: rank(a.severity) >= rank(failOn) ? 'error' : 'warning',
        message: `${p.name}@${p.version}${as} has ${ghsa} (${a.severity}): ${a.title}. Vulnerable versions: ${details.vulnerable_versions}. ${a.url}${also}`,
        lockfile: locations[0].lockfile,
        line: locations[0].line,
        securitySeverity: score,
        ruleDescription: `${ghsa}: ${a.title}`,
        details,
      }));
    }
    results.push({ name: p.name, version: p.version, locations, vulnerabilities });
  }
  for (const e of rangeErrors.values()) errorSet.add(e);

  findings.sort((x, y) => rank(y.details.severity) - rank(x.details.severity));
  for (const f of findings) summary.vulnerabilities[f.details.severity]++;
  summary.findings = findings.length;
  summary.failing = findings.filter((f) => f.level === 'error').length;
  summary.ignored = ignored.map((i) => ({ ghsa: i.ghsa, name: i.name, version: i.version, severity: i.severity, title: i.title, url: i.url, locations: i.locations }));
  summary.unused_ignores = [...ignore].filter(([, used]) => !used).map(([id]) => id);
  if (summary.unused_ignores.length) {
    warnings.push(`ignore lists ${plural(summary.unused_ignores.length, 'advisory', 'advisories')} that matched no audited package: ${summary.unused_ignores.join(', ')}.\n`
      + 'Remove an entry once the package it was for is upgraded.');
  }
  if (ignored.length) {
    io.log(`Ignored: ${ignored.map((i) => `${i.ghsa} in ${i.name}@${i.version} (${i.severity})`).join(', ')}.`);
  }
  const counts = SEVERITIES.slice().reverse().filter((s) => summary.vulnerabilities[s]).map((s) => `${summary.vulnerabilities[s]} ${s}`);
  const found = `${plural(findings.length, 'vulnerability', 'vulnerabilities')}${counts.length ? ` (${counts.join(', ')})` : ''} in ${plural(new Set(findings.map((f) => `${f.package.name}@${f.package.version}`)).size, 'package')}`
    + `${ignored.length ? `, and ignored ${ignored.length}` : ''}`;
  // With errors, what came back is not a verdict: say so, rather than "Found 0".
  io.log(errorSet.size ? `Found ${found} in the answers received, but the audit is incomplete (see the errors), so it has no verdict.`
    : `Found ${found}; fail_on is ${failOn}.`);

  return {
    ...base,
    findings,
    errors: [...errorSet],
    results,
    rules,
    counts: {
      audited_entries: checked, audited_packages: packages.size, requests: batches.length, skipped: skipped.length,
      ...summary.vulnerabilities, ignored: ignored.length, unused_ignores: summary.unused_ignores.length,
    },
  };
}

// Runs the command when this module is the program, not when a test imports it.
if (isMain(import.meta.url)) await main('audit', (ctx) => audit(ctx));
