// core.mjs: the core of js-security-orb's Node.js helper (Node >= 22,
// standard library only), imported by the command modules as './core.mjs':
// lockfile discovery and strict parsers (npm v1-v3, pnpm 5.4/6.0/9.0, yarn v1,
// yarn Berry 4-10, bun.lock) into one Entry per package; the registry
// configuration (registry, scopes, .npmrc); registry access through curl, with
// packument and attestation caches; package patterns; the reports (JSON, SARIF,
// JUnit, run record); and the CLI glue (PARAM_*, exit codes, ERROR:/WARN:).
//
// A command module:
//
//   import { main, isMain, metadataRegistry } from './core.mjs';
//
//   export async function run(ctx) {
//     // Read every parameter first: a bad one is a usage error (exit 2),
//     // which must come before any network access.
//     const allowGit = ctx.bool('allow_git', false);
//     const { entries } = ctx.readLockfiles(); // lockfiles, include_dev, allow_empty
//     for (const e of entries.filter((x) => x.kind === 'registry')) {
//       // The registry to ask (null, with a reason: skip it, never contacted).
//       const { registry, reason } = metadataRegistry(e, ctx.registries);
//       if (registry) await ctx.client.getPackuments([e.name],
//         { pick: (doc) => ({ time: doc.time }), registryFor: () => registry });
//     }
//     const findings = entries.filter((e) => e.kind === 'git' && !allowGit)
//       .map((e) => ctx.finding(e, { kind: 'git', message: `${e.name} comes from git: ${e.source}` }));
//     // main() prints the findings, writes the reports and applies the gate:
//     // level 'error' findings fail it unless report_only; errors are no verdict.
//     return { findings, checked: entries.length, summary: { packages: entries.length } };
//   }
//
//   // Only as the program (node lock_verify.mjs), so tests can import it.
//   if (isMain(import.meta.url)) await main('lock_verify', run);
//
// Exit codes: 0 passed (or findings with report_only), 1 findings or no
// verdict, 2 a usage error. Every non-zero exit prints an ERROR: line.

import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import crypto from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/** The URL every run record names as its schema. */
export const RUN_RECORD_SCHEMA = 'https://github.com/juburr/js-security-orb/blob/main/schemas/run-record.v1.json';
/** The orb's home page, used in SARIF. */
export const INFORMATION_URI = 'https://github.com/juburr/js-security-orb';
/** The registry used when the registry parameter is not set. */
export const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';
/** The oldest curl the helper accepts: 7.71.0 added --retry-all-errors (7.66.0 --parallel). */
export const MIN_CURL_VERSION = '7.71.0';
/** The lockfiles auto-detection looks for in the project directory, in this order. */
export const LOCKFILE_NAMES = ['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lock'];
/** How to replace a binary bun.lockb, which the helper can't read. */
export const BUN_LOCKB_HINT = 'bun.lockb is a binary lockfile, which this orb can\'t read. Convert it to bun.lock with\n'
  + '  bun install --save-text-lockfile --frozen-lockfile --lockfile-only\n'
  + 'and commit bun.lock (bun 1.2 and later read it).';

// ---------------------------------------------------------------------------
// Errors and output
// ---------------------------------------------------------------------------

/** A bad parameter or configuration, found before any network access: exit 2. */
export class UsageError extends Error {
  constructor(message) { super(message); this.name = 'UsageError'; }
}

/** A lockfile the helper refuses to read: the message starts with "file:line: ". Exit 1. */
export class LockfileError extends Error {
  constructor(file, line, message) {
    super(`${file}:${line ?? 1}: ${message}`);
    this.name = 'LockfileError';
    this.file = file;
    this.line = line ?? 1;
  }
}

/**
 * Prefixes every line of a message, as the orb's ERROR:/WARN: convention wants.
 * @param {string} prefix such as 'ERROR: '
 * @param {string} message one or more lines
 * @returns {string} the prefixed lines, ending in a newline
 */
export function prefixLines(prefix, message) {
  return String(message).split('\n').map((line) => prefix + line).join('\n') + '\n';
}

/**
 * Makes the output functions: log() to stdout; warn() and error() to stderr,
 * every line prefixed WARN: or ERROR:. The sinks are for tests.
 * @param {{stdout?: Function, stderr?: Function}} [sinks]
 */
export function createIO({ stdout, stderr } = {}) {
  const out = stdout ?? ((s) => process.stdout.write(s));
  const err = stderr ?? ((s) => process.stderr.write(s));
  return {
    log: (message) => out(String(message) + '\n'),
    warn: (message) => err(prefixLines('WARN: ', message)),
    error: (message) => err(prefixLines('ERROR: ', message)),
  };
}

/** Shows a value in a message: JSON-quoted, at most 120 characters. */
export function show(value) {
  const s = JSON.stringify(value === undefined ? null : value) ?? String(value);
  return s.length > 120 ? s.slice(0, 117) + '...' : s;
}

/**
 * Says COUNT and the noun that goes with it: plural(1, 'file') is '1 file'.
 * @param {number} count
 * @param {string} singular
 * @param {string} [plural] defaults to singular + 's'
 */
export function plural(count, singular, plural = singular + 's') {
  return `${count} ${count === 1 ? singular : plural}`;
}

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const readJson = (file) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; } };
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

// Sets a property even when its name is __proto__, so a lockfile key can never
// change an object's prototype.
function setOwn(obj, key, value) {
  Object.defineProperty(obj, key, { value, enumerable: true, writable: true, configurable: true });
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/**
 * Splits a list parameter on commas, spaces and newlines.
 * @param {string} value
 * @returns {string[]} the non-empty items
 */
export function splitList(value) {
  return String(value ?? '').split(/[\s,]+/).filter(Boolean);
}

/**
 * Splits a lines parameter (such as scopes) on newlines; blank lines and
 * lines starting with # are left out, and each line is trimmed.
 * @param {string} value
 * @returns {string[]}
 */
export function splitLines(value) {
  return String(value ?? '').split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

/**
 * Makes the reader of PARAM_* variables. Each reader takes the YAML name
 * (PARAM_<NAME> is read), returns the default when it is unset, throws a
 * UsageError naming the parameter for a bad value, and records the value in
 * `used`, for the run record.
 * @param {object} [env] default process.env
 */
export function createParams(env = process.env) {
  const used = {};
  const get = (name, def) => {
    const v = env['PARAM_' + name.toUpperCase()];
    used[name] = v ?? (def === undefined ? null : String(def));
    return v;
  };
  const bad = (name, what, v) => new UsageError(`${name} must be ${what}, not ${show(v)}.`);
  return {
    used,
    str: (name, def = '') => get(name, def) ?? def,
    bool(name, def = false) {
      const v = get(name, def);
      if (v === undefined) return def;
      if (v === 'true' || v === '1') return true;
      if (v === 'false' || v === '0') return false;
      throw bad(name, 'true or false (or 1 or 0)', v);
    },
    int(name, def, { min = 0, max = 2147483647 } = {}) {
      const v = get(name, def);
      if (v === undefined) return def;
      if (!/^[0-9]{1,10}$/.test(v.trim()) || +v < min || +v > max) throw bad(name, `a whole number from ${min} to ${max}`, v);
      return +v;
    },
    list: (name, def = '') => splitList(get(name, def) ?? def),
    lines: (name, def = '') => splitLines(get(name, def) ?? def),
    choice(name, choices, def) {
      const v = get(name, def) ?? def;
      if (!choices.includes(v)) throw bad(name, `one of ${choices.join(', ')}`, v);
      return v;
    },
    envVarName(name, def = '') {
      const v = (get(name, def) ?? def).trim();
      if (v && !/^[A-Za-z_][A-Za-z0-9_]*$/.test(v)) throw bad(name, 'the name of an environment variable', v);
      return v;
    },
  };
}

/**
 * Checks output_dir: an absolute path. It is not expanded, since the YAML's
 * store steps read it as given.
 * @param {string} value
 * @returns {string} the directory, without trailing slashes
 */
export function checkOutputDir(value) {
  if (typeof value !== 'string' || !path.isAbsolute(value) || /[\0\r\n]/.test(value)) {
    throw new UsageError(`output_dir must be an absolute path, not ${show(value)}.`);
  }
  return value.length > 1 ? value.replace(/\/+$/, '') || '/' : value;
}

/**
 * Checks report_name: a plain file name of letters, digits, '.', '_' and '-'.
 * @param {string} value
 * @returns {string}
 */
export function checkReportName(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/.test(value)) {
    throw new UsageError(`report_name must be a plain file name of letters, digits, '.', '_' and '-', not ${show(value)}.`);
  }
  return value;
}

// ---------------------------------------------------------------------------
// URLs and the registry configuration
// ---------------------------------------------------------------------------

/** Whether a host name is localhost, 127.x.x.x or ::1. */
export function isLoopbackHost(host) {
  const h = String(host).replace(/^\[|\]$/g, '').toLowerCase();
  return h === 'localhost' || h === '::1' || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
}

/**
 * A URL without credentials, query and fragment, safe for messages and reports.
 * @param {string} url
 * @returns {string}
 */
export function publicUrl(url) {
  const s = String(url);
  const m = /^([a-z][a-z0-9+.-]*:\/\/)(?:[^/?#@]*@)?([^?#]*)/i.exec(s);
  if (m) return m[1] + m[2];
  return s.replace(/[?#][\s\S]*$/, '');
}

/**
 * Removes the credentials from a URL, keeping an ssh login name (git@) that
 * carries no password. Query and fragment are removed too.
 * @param {string} url
 * @returns {string}
 */
export function stripCredentials(url) {
  const s = String(url);
  const m = /^([a-z][a-z0-9+.-]*:\/\/)([^/?#@]*@)?([^?#]*)/i.exec(s);
  if (!m) return s.replace(/[?#][\s\S]*$/, '');
  const [, scheme, user = '', rest] = m;
  if (/^(?:git\+)?ssh:/i.test(scheme) && user && !user.includes(':')) return scheme + user + rest;
  return scheme + rest;
}

/**
 * Checks a registry URL (https, or http to localhost, 127.x or [::1]; no
 * credentials, query or fragment) and adds a trailing /. UsageError if bad.
 * @param {string} value
 * @param {string} [what] the parameter, for the message
 * @returns {string}
 */
export function normalizeRegistryUrl(value, what = 'registry') {
  const v = String(value ?? '').trim();
  let u;
  try { u = new URL(v); } catch { throw new UsageError(`${what} must be a URL, not ${show(publicUrl(v))}.`); }
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && isLoopbackHost(u.hostname))) {
    throw new UsageError(`${what} must be an https URL (http only to localhost, 127.x or [::1]), not ${show(publicUrl(v))}.`);
  }
  if (u.username || u.password) throw new UsageError(`${what} must not hold credentials (use the token parameter): ${show(publicUrl(v))}.`);
  if (v.includes('?') || v.includes('#')) throw new UsageError(`${what} must not have a query or a fragment: ${show(publicUrl(v))}.`);
  if (/["\\\s]/.test(u.pathname)) throw new UsageError(`${what} must not hold spaces, quotes or backslashes: ${show(v)}.`);
  return `${u.protocol}//${u.host}${u.pathname.endsWith('/') ? u.pathname : u.pathname + '/'}`;
}

// A registry base recorded in a lockfile, for Entry.source: lower-case scheme
// and host, no credentials, a trailing /, and registry.yarnpkg.com (yarn's
// alias of the public registry) as registry.npmjs.org.
function normalizeRecordedRegistry(base) {
  let out = stripCredentials(base);
  try {
    const u = new URL(out);
    out = `${u.protocol}//${u.host}${u.pathname}`;
  } catch { /* keep it as recorded */ }
  if (!out.endsWith('/')) out += '/';
  return out.replace(/^https:\/\/registry\.yarnpkg\.com\//, 'https://registry.npmjs.org/');
}

/**
 * The scope of a package name ('@corp' for '@corp/x'), or null.
 * @param {string} name
 */
export function scopeOf(name) {
  return typeof name === 'string' && name.startsWith('@') && name.includes('/') ? name.slice(0, name.indexOf('/')) : null;
}

/**
 * Reads the @scope:registry=URL lines of an .npmrc, ignoring every other
 * line. ${VAR} values are not expanded but left out with a warning.
 * @param {string} file
 * @returns {{scopes: {scope, url, line}[], warnings: string[]}}
 */
export function readNpmrcScopes(file) {
  const scopes = [];
  const warnings = [];
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT') return { scopes, warnings };
    throw new UsageError(`Could not read ${file}: ${e.message}`);
  }
  text.split(/\r?\n/).forEach((raw, i) => {
    const m = /^\s*(@[^\s:=]+):registry\s*=\s*(.*?)\s*$/.exec(raw);
    if (!m) return;
    let value = m[2];
    if (/^".*"$/.test(value)) {
      try { value = JSON.parse(value); } catch { /* keep the quotes: the URL check refuses it */ }
    } else if (/^'.*'$/.test(value)) value = value.slice(1, -1);
    if (value.includes('${')) {
      warnings.push(`${path.basename(file)} line ${i + 1}: the registry of ${m[1]} uses an environment variable, which this orb doesn't expand in a project .npmrc, so the line is ignored. Set it with the scopes parameter instead.`);
      return;
    }
    scopes.push({ scope: m[1], url: value, line: i + 1 });
  });
  return { scopes, warnings };
}

/**
 * The registry configuration: the registry, and the scope registries of
 * the project's .npmrc merged with the scopes parameter (@scope=URL lines),
 * which wins. UsageError for a bad URL or line.
 * @param {{registry?: string, scopes?: string[], cwd?: string, npmrc?: boolean}} [options]
 * @returns {{registry, scopes: Map, npmrc, warnings, registryFor: (name) => string}}
 */
export function registryConfig({ registry = DEFAULT_REGISTRY, scopes = [], cwd = process.cwd(), npmrc = true } = {}) {
  const reg = normalizeRegistryUrl(registry || DEFAULT_REGISTRY, 'registry');
  const raw = new Map();
  const warnings = [];
  let npmrcFile = null;
  if (npmrc) {
    const file = path.join(cwd, '.npmrc');
    const read = readNpmrcScopes(file);
    if (fs.existsSync(file)) npmrcFile = file;
    warnings.push(...read.warnings);
    for (const s of read.scopes) raw.set(s.scope, { url: s.url, where: `.npmrc line ${s.line}` });
  }
  for (const line of scopes) {
    const m = /^(@[^\s:=]+)(?::registry)?\s*=\s*(\S+)$/.exec(line.trim());
    if (!m) throw new UsageError(`scopes takes lines @scope=URL, not ${show(line)}.`);
    raw.set(m[1], { url: m[2], where: 'scopes' });
  }
  const map = new Map();
  for (const [scope, { url, where }] of raw) {
    if (!/^@[A-Za-z0-9~-][A-Za-z0-9._~-]*$/.test(scope)) throw new UsageError(`${where}: ${show(scope)} is not a package scope.`);
    map.set(scope, normalizeRegistryUrl(url, `the registry of ${scope} (${where})`));
  }
  return {
    registry: reg,
    scopes: map,
    npmrc: npmrcFile,
    warnings,
    registryFor(name) { return map.get(scopeOf(name)) ?? reg; },
  };
}

/**
 * The registry every command asks about a registry entry: where npm installs
 * it from. A source the lockfile doesn't record (pnpm, Berry): the registry
 * configured for the name (registry, or its scope's). One recorded on
 * https://registry.npmjs.org/ (yarn's registry.yarnpkg.com is the same): that
 * one too, as npm's replace-registry-host=npmjs default does, so a mirror set as
 * registry serves it. One recorded on registry or a scope's registry: itself.
 * Any other registry is never contacted: registry null, and the reason.
 * @param {object} entry an Entry
 * @param {object} registries registryConfig()'s
 * @returns {{registry: string|null, reason: string|null}}
 */
export function metadataRegistry(entry, registries) {
  if (entry.kind !== 'registry') return { registry: null, reason: `not from a registry (${entry.kind})` };
  const mapped = registries.registryFor(entry.name);
  const s = entry.source;
  if (!entry.sourceRecorded || s === mapped || s === DEFAULT_REGISTRY) return { registry: mapped, reason: null };
  if (s === registries.registry || [...registries.scopes.values()].includes(s)) return { registry: s, reason: null };
  return { registry: null, reason: `the lockfile records ${s}, which is neither registry nor a scope's registry (scopes, or .npmrc)` };
}

/**
 * Why a 401 or 403 from REGISTRY skips its packages: it is on another origin
 * than registry, so it was asked without the token, which goes only to
 * registry's origin. null for any other status, and on registry's origin,
 * where the answer is no verdict (see authHint).
 */
export function unauthorizedSkip(registry, status, registries) {
  if (status !== 401 && status !== 403) return null;
  try { if (new URL(registry).origin === new URL(registries.registry).origin) return null; } catch { /* another origin */ }
  return `${registry} answered HTTP ${status}, and the token goes only to registry's origin`;
}

/** What to add to a 401 or 403 from registry's origin, which is no verdict. */
export function authHint(tokenVar) {
  return tokenVar ? `Check the token in ${tokenVar}.` : 'If the registry needs a login, set token to the name of a variable holding a token for it.';
}

/**
 * The warning for packages a command didn't check: "N packages were not VERB,
 * since REASON: a@1, b@2 and 3 more. They are listed under skipped in the
 * report." and ADVICE.
 * @param {string[]} names name@version of each, repeats ignored
 */
export function skipWarning(names, verb, reason, advice = '') {
  const list = [...new Set(names)];
  const one = list.length === 1;
  const shown = list.length > 10 ? `${list.slice(0, 10).join(', ')} and ${list.length - 10} more` : list.join(', ');
  return `${plural(list.length, 'package')} ${one ? 'was' : 'were'} not ${verb}, since ${reason}: ${shown}. `
    + `${one ? 'It is' : 'They are'} listed under skipped in the report.${advice ? ' ' + advice : ''}`;
}

// ---------------------------------------------------------------------------
// JSON and JSONC with line numbers
// ---------------------------------------------------------------------------

const LINES = new WeakMap();

/**
 * The 1-based line of KEY in an object a lockfile parser returned, or null.
 * @param {object} obj
 * @param {string} key
 * @returns {number|null}
 */
export function lineOf(obj, key) {
  const m = obj && LINES.get(obj);
  return (m && m.get(key)) ?? null;
}

function lineMap(obj) {
  let m = LINES.get(obj);
  if (!m) { m = new Map(); LINES.set(obj, m); }
  return m;
}

const JSON_NUMBER = /-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/y;

/**
 * Parses JSON strictly, recording each object key's line (see lineOf); a
 * duplicate key is an error. jsonc allows comments and trailing commas.
 * @param {string} src
 * @param {string} file for messages
 * @param {{jsonc?: boolean}} [options]
 */
export function parseJsonWithLines(src, file, { jsonc = false } = {}) {
  let i = src.charCodeAt(0) === 0xfeff ? 1 : 0;
  let line = 1;
  let depth = 0;
  const n = src.length;
  const fail = (msg) => { throw new LockfileError(file, line, msg); };
  const ws = () => {
    for (;;) {
      const c = src.charCodeAt(i);
      if (c === 10) { line++; i++; } else if (c === 32 || c === 9 || c === 13) i++;
      else if (jsonc && c === 47) {
        if (src[i + 1] === '/') { while (i < n && src[i] !== '\n') i++; }
        else if (src[i + 1] === '*') {
          const end = src.indexOf('*/', i + 2);
          if (end < 0) fail('a comment is never closed');
          for (let k = i; k < end; k++) if (src.charCodeAt(k) === 10) line++;
          i = end + 2;
        } else fail('unexpected "/"');
      } else return;
    }
  };
  const string = () => {
    let j = i + 1;
    for (;;) {
      if (j >= n) fail('a string is never closed');
      const c = src.charCodeAt(j);
      if (c === 34) break;
      if (c < 0x20) fail('a control character or line break in a string');
      j += c === 92 ? 2 : 1;
    }
    let v;
    try { v = JSON.parse(src.slice(i, j + 1)); } catch { fail('a malformed string'); }
    i = j + 1;
    return v;
  };
  const value = () => {
    ws();
    const c = src[i];
    if (c === '{' || c === '[') {
      if (++depth > 500) fail('nested too deeply');
      const v = c === '{' ? object() : array();
      depth--;
      return v;
    }
    if (c === '"') return string();
    for (const [word, v] of [['true', true], ['false', false], ['null', null]]) {
      if (src.startsWith(word, i)) { i += word.length; return v; }
    }
    JSON_NUMBER.lastIndex = i;
    const m = JSON_NUMBER.exec(src);
    if (!m) fail(i >= n ? 'unexpected end of the file' : `unexpected ${show(src[i])}`);
    i += m[0].length;
    return Number(m[0]);
  };
  const object = () => {
    i++;
    const obj = {};
    const lines = lineMap(obj);
    ws();
    if (src[i] === '}') { i++; return obj; }
    for (;;) {
      ws();
      if (src[i] !== '"') fail('expected a string key');
      const keyLine = line;
      const key = string();
      if (lines.has(key)) fail(`duplicate key ${show(key)}`);
      ws();
      if (src[i] !== ':') fail('expected ":"');
      i++;
      setOwn(obj, key, value());
      lines.set(key, keyLine);
      ws();
      if (src[i] === ',') {
        i++;
        ws();
        if (jsonc && src[i] === '}') { i++; return obj; }
        continue;
      }
      if (src[i] === '}') { i++; return obj; }
      fail('expected "," or "}"');
    }
  };
  const array = () => {
    i++;
    const arr = [];
    ws();
    if (src[i] === ']') { i++; return arr; }
    for (;;) {
      arr.push(value());
      ws();
      if (src[i] === ',') {
        i++;
        ws();
        if (jsonc && src[i] === ']') { i++; return arr; }
        continue;
      }
      if (src[i] === ']') { i++; return arr; }
      fail('expected "," or "]"');
    }
  };
  const v = value();
  ws();
  if (i < n) fail('unexpected text after the JSON value');
  return v;
}

// ---------------------------------------------------------------------------
// The YAML subset pnpm and yarn Berry write
// ---------------------------------------------------------------------------

class YamlError extends Error {
  constructor(line, message) { super(message); this.line = line; }
}
const yfail = (line, msg) => { throw new YamlError(line, msg); };

const DQ_ESCAPES = { 0: '\0', a: '\x07', b: '\b', t: '\t', '\t': '\t', n: '\n', v: '\v', f: '\f', r: '\r', e: '\x1b', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', _: '\xa0', L: '\u2028', P: '\u2029' };

function yReadQuoted(s, i, n) {
  const q = s[i];
  let out = '';
  i++;
  while (i < s.length) {
    const c = s[i];
    if (q === "'") {
      if (c === "'") {
        if (s[i + 1] === "'") { out += "'"; i += 2; continue; }
        return [out, i + 1];
      }
      out += c; i++;
    } else {
      if (c === '"') return [out, i + 1];
      if (c === '\\') {
        const e = s[i + 1];
        if (own(DQ_ESCAPES, e)) { out += DQ_ESCAPES[e]; i += 2; continue; }
        const len = e === 'x' ? 2 : e === 'u' ? 4 : e === 'U' ? 8 : 0;
        if (!len) yfail(n, `a bad escape \\${e}`);
        const hex = s.slice(i + 2, i + 2 + len);
        if (hex.length !== len || !/^[0-9a-fA-F]+$/.test(hex)) yfail(n, 'a bad hex escape');
        out += String.fromCodePoint(parseInt(hex, 16));
        i += 2 + len;
        continue;
      }
      out += c; i++;
    }
  }
  return yfail(n, 'a quoted scalar is never closed (multi-line quoted scalars are not supported)');
}

function yCheckPlain(v, n) {
  if (v === '') yfail(n, 'an empty plain scalar');
  if (/^[&*!|>%@`#,[\]{}'"]/.test(v) || /^[-?:](?:\s|$)/.test(v)) yfail(n, `an unsupported plain scalar ${show(v.slice(0, 40))}`);
  if (/\s#/.test(v)) yfail(n, 'comments after a value are not supported');
  if (/:(?:\s|$)/.test(v)) yfail(n, `a plain scalar holding ": " ${show(v.slice(0, 40))}`);
  return v;
}

function yReadFlowScalar(s, i, n, isKey) {
  if (s[i] === "'" || s[i] === '"') return yReadQuoted(s, i, n);
  let j = i;
  while (j < s.length) {
    const c = s[j];
    if (c === ',' || c === '}' || c === ']') break;
    if (c === ':' && (s[j + 1] === ' ' || s[j + 1] === undefined || (isKey && (s[j + 1] === ',' || s[j + 1] === '}')))) break;
    if (c === '#' && s[j - 1] === ' ') yfail(n, 'comments are not supported');
    j++;
  }
  const v = s.slice(i, j).trim();
  if (v === '') yfail(n, 'an empty plain scalar in a flow collection');
  if (/^[&*!|>%@`#[{]/.test(v)) yfail(n, `an unsupported plain scalar ${show(v.slice(0, 40))}`);
  return [v, j];
}

function yReadFlow(s, i, n, depth = 0) {
  if (depth > 20) yfail(n, 'flow collections nested too deeply');
  const close = s[i] === '{' ? '}' : ']';
  const isMap = s[i] === '{';
  const out = isMap ? {} : [];
  if (isMap) lineMap(out);
  i++;
  const skip = () => { while (s[i] === ' ') i++; };
  skip();
  if (s[i] === close) return [out, i + 1];
  for (;;) {
    skip();
    if (i >= s.length) yfail(n, 'a malformed flow collection (it must fit on one line)');
    let key;
    if (isMap) {
      [key, i] = yReadFlowScalar(s, i, n, true);
      if (s[i] !== ':') yfail(n, 'expected ":" in a flow mapping');
      i++;
      skip();
    }
    let val;
    if (s[i] === '{' || s[i] === '[') [val, i] = yReadFlow(s, i, n, depth + 1);
    else [val, i] = yReadFlowScalar(s, i, n, false);
    if (isMap) {
      if (own(out, key)) yfail(n, `duplicate key ${show(key)}`);
      setOwn(out, key, val);
      lineMap(out).set(key, n);
    } else out.push(val);
    skip();
    if (s[i] === ',') { i++; continue; }
    if (s[i] === close) return [out, i + 1];
    yfail(n, 'a malformed flow collection (it must fit on one line)');
  }
}

function yInlineValue(text, n) {
  if (text[0] === '{' || text[0] === '[') {
    const [v, j] = yReadFlow(text, 0, n);
    if (text.slice(j).trim() !== '') yfail(n, 'text after a flow collection');
    return v;
  }
  if (text[0] === "'" || text[0] === '"') {
    const [v, j] = yReadQuoted(text, 0, n);
    if (text.slice(j).trim() !== '') yfail(n, 'text after a quoted scalar');
    return v;
  }
  return yCheckPlain(text.trim(), n);
}

function ySplitKey(t, n) {
  let key;
  let i;
  if (t[0] === "'" || t[0] === '"') {
    [key, i] = yReadQuoted(t, 0, n);
    if (t[i] !== ':') yfail(n, 'expected ":" after a quoted key');
  } else {
    i = 0;
    while (i < t.length && !(t[i] === ':' && (t[i + 1] === ' ' || i + 1 === t.length))) i++;
    if (i === t.length) yfail(n, 'expected "key:"');
    key = yCheckPlain(t.slice(0, i), n);
  }
  const rest = t.slice(i + 1);
  if (rest !== '' && rest[0] !== ' ') yfail(n, 'expected a space after ":"');
  return [key, rest.trim()];
}

function yParseDocument(lines) {
  let pos = 0;

  function blockScalar(header, parentIndent, n) {
    const m = header.match(/^\|(?:([1-9])([+-]?)|([+-])([1-9]?))?$/);
    if (!m) yfail(n, `an unsupported block scalar header ${show(header)} (only literal "|" is supported)`);
    const digit = +(m[1] || m[4] || 0);
    const chomp = m[2] || m[3] || '';
    let indent = digit ? parentIndent + digit : -1;
    const content = [];
    let maxLeadingBlank = 0;
    while (pos < lines.length) {
      const raw = lines[pos].raw;
      const spaces = raw.match(/^ */)[0].length;
      const isBlank = raw.trim() === '';
      if (indent < 0) {
        if (isBlank) { maxLeadingBlank = Math.max(maxLeadingBlank, spaces); content.push(null); pos++; continue; }
        if (spaces <= parentIndent) break;
        indent = spaces;
        if (maxLeadingBlank > indent) yfail(lines[pos].n, 'a leading blank line indented more than the block');
      }
      if (isBlank && spaces <= indent) { content.push(null); pos++; continue; }
      if (spaces < indent) break;
      content.push(raw.slice(indent));
      pos++;
    }
    let last = content.length - 1;
    while (last >= 0 && content[last] === null) last--;
    const body = content.slice(0, last + 1).map((x) => (x === null ? '' : x));
    const trailing = content.length - 1 - last;
    if (body.length === 0) return chomp === '+' ? '\n'.repeat(trailing) : '';
    const text = body.join('\n');
    if (chomp === '-') return text;
    if (chomp === '+') return text + '\n' + '\n'.repeat(trailing);
    return text + '\n';
  }

  function node(indent, depth) {
    if (depth > 50) yfail(lines[pos].n, 'nested too deeply');
    const first = lines[pos];
    if (first.text.startsWith('- ') || first.text === '-') {
      const arr = [];
      while (pos < lines.length && lines[pos].indent === indent && (lines[pos].text.startsWith('- ') || lines[pos].text === '-')) {
        const L = lines[pos++];
        const t = L.text.slice(1).trim();
        if (t === '') yfail(L.n, 'a nested block under "-" is not supported');
        if (/^[^'"{[].*?:( |$)/.test(t) || /^['"].*['"]:( |$)/.test(t)) yfail(L.n, 'a mapping inside a sequence item is not supported');
        arr.push(yInlineValue(t, L.n));
      }
      if (pos < lines.length && lines[pos].indent > indent) yfail(lines[pos].n, 'unexpected indentation');
      return arr;
    }
    const obj = {};
    const map = lineMap(obj);
    while (pos < lines.length && lines[pos].indent === indent) {
      const L = lines[pos++];
      if (L.text.startsWith('- ') || L.text === '-') yfail(L.n, 'a sequence item inside a mapping');
      let key;
      let rest;
      if (L.text.startsWith('? ')) {
        key = yInlineValue(L.text.slice(2).trim(), L.n);
        const C = lines[pos++];
        if (!C || C.indent !== indent || !(C.text === ':' || C.text.startsWith(': '))) yfail(L.n, 'an explicit key without a ":" line');
        rest = C.text.slice(1).trim();
        if (rest !== '' && (/^- /.test(rest) || /^(?:'(?:[^']|'')*'|"(?:[^"\\]|\\.)*"|[^'"{[|>][^]*?):(?: |$)/.test(rest))) {
          // js-yaml's compact form: the value's first line continues on the ":" line.
          pos--;
          lines[pos] = { n: C.n, raw: ' '.repeat(indent + 2) + rest, indent: indent + 2, text: rest };
          rest = '';
        }
      } else {
        [key, rest] = ySplitKey(L.text, L.n);
      }
      if (own(obj, key)) yfail(L.n, `duplicate key ${show(key)}`);
      let val;
      if (rest === '') {
        if (pos < lines.length && lines[pos].indent > indent) val = node(lines[pos].indent, depth + 1);
        else if (pos < lines.length && lines[pos].indent === indent && lines[pos].text.startsWith('- ')) val = node(indent, depth + 1);
        else val = null;
      } else if (/^[|>]/.test(rest)) {
        val = blockScalar(rest, indent, L.n);
      } else {
        val = yInlineValue(rest, L.n);
      }
      setOwn(obj, key, val);
      map.set(key, L.n);
    }
    if (pos < lines.length && lines[pos].indent > indent) yfail(lines[pos].n, 'unexpected indentation');
    return obj;
  }

  if (lines.length === 0) return null;
  const root = node(lines[0].indent, 0);
  if (pos < lines.length) yfail(lines[pos].n, 'unexpected text after the document');
  return root;
}

/**
 * Parses the YAML subset of pnpm-lock.yaml and Berry's yarn.lock into
 * documents (separated by ---) of strings, and throws a LockfileError on
 * anything else: tabs, anchors, tags, comments after values, multi-line flow
 * or quoted scalars, folded scalars.
 * @param {string} src
 * @param {string} file for messages
 * @returns {Array} the documents
 */
export function parseYamlSubset(src, file) {
  try {
    if (src.charCodeAt(0) === 0xfeff) src = src.slice(1);
    const raw = src.split(/\r?\n/);
    if (raw.length && raw[raw.length - 1] === '') raw.pop();
    const docs = [];
    let cur = [];
    raw.forEach((r, idx) => {
      const n = idx + 1;
      if (r === '---' || r === '...') { if (cur.length) docs.push(cur); cur = []; return; }
      if (/^ *\t/.test(r)) yfail(n, 'a tab in the indentation');
      const indent = r.match(/^ */)[0].length;
      cur.push({ n, raw: r, indent, text: r.slice(indent) });
    });
    if (cur.length) docs.push(cur);
    return docs.map((lines) => {
      const out = [];
      let inBlock = -1;
      for (const L of lines) {
        const blank = L.raw.trim() === '';
        if (inBlock >= 0) {
          if (blank || L.indent > inBlock) { out.push(L); continue; }
          inBlock = -1;
        }
        if (blank || /^\s*#/.test(L.raw)) continue;
        out.push(L);
        if (/:\s+[|>][1-9]?[+-]?[1-9]?$/.test(L.text) && !/^['"]/.test(L.text.split(': ').pop())) inBlock = L.indent;
      }
      return yParseDocument(out);
    });
  } catch (e) {
    if (e instanceof YamlError) throw new LockfileError(file, e.line, e.message);
    throw e;
  }
}

// ---------------------------------------------------------------------------
// yarn v1's lockfile format
// ---------------------------------------------------------------------------

function y1Tokens(s, n, fail) {
  const out = [];
  let i = 0;
  while (i < s.length) {
    if (s[i] === ' ') { i++; continue; }
    if (s[i] === '"') {
      let j = i + 1;
      while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
      if (j >= s.length) fail(n, 'a string is never closed');
      let v;
      try { v = JSON.parse(s.slice(i, j + 1)); } catch { fail(n, 'a malformed string'); }
      out.push({ v });
      i = j + 1;
    } else {
      let j = i;
      while (j < s.length && s[j] !== ' ' && !(s[j] === ',' && s[j + 1] === ' ')) j++;
      const word = s.slice(i, j);
      if (word.includes('"')) fail(n, 'a quote inside an unquoted word');
      out.push({ v: word });
      i = j;
    }
    if (s[i] === ',') { out.push({ comma: true }); i++; }
  }
  return out;
}

/**
 * Parses a yarn v1 lockfile into {"<specifier>": entry}, an entry's
 * specifiers sharing one object; lineOf gives its header line.
 * @param {string} src
 * @param {string} file for messages
 */
export function parseYarn1Text(src, file) {
  const fail = (n, msg) => { throw new LockfileError(file, n, msg); };
  if (!/^(?:#.*\r?\n)*# yarn lockfile v1\r?\n/.test(src.replace(/^\ufeff/, ''))) fail(1, 'missing the "# yarn lockfile v1" header');
  const lines = src.replace(/^\ufeff/, '').split(/\r?\n/);
  const root = {};
  lineMap(root);
  const stack = [{ indent: -2, obj: root }];
  lines.forEach((raw, idx) => {
    const n = idx + 1;
    if (/^(<<<<<<<|=======|>>>>>>>)/.test(raw)) fail(n, 'a merge conflict marker');
    if (raw.trim() === '' || /^\s*#/.test(raw)) return;
    if (raw.includes('\t')) fail(n, 'a tab');
    const indent = raw.match(/^ */)[0].length;
    if (indent % 2) fail(n, 'odd indentation');
    while (stack.length && stack[stack.length - 1].indent >= indent) stack.pop();
    const parent = stack[stack.length - 1];
    if (!parent || indent !== parent.indent + 2) fail(n, 'unexpected indentation');
    const body = raw.slice(indent).trimEnd();
    if (body.endsWith(':')) {
      const toks = y1Tokens(body.slice(0, -1), n, fail);
      const keys = [];
      toks.forEach((t, k) => {
        if (t.comma) { if (k === 0 || toks[k - 1].comma || k === toks.length - 1) fail(n, 'a misplaced comma'); } else keys.push(t.v);
      });
      if (!keys.length || keys.some((k) => k === '')) fail(n, 'an empty key');
      const obj = {};
      lineMap(obj);
      for (const k of keys) {
        if (own(parent.obj, k)) fail(n, `duplicate key ${show(k)}`);
        setOwn(parent.obj, k, obj);
        lineMap(parent.obj).set(k, n);
      }
      stack.push({ indent, obj });
      return;
    }
    if (parent.obj === root) fail(n, 'a value outside an entry');
    const toks = y1Tokens(body, n, fail);
    if (toks.length !== 2 || toks.some((t) => t.comma)) fail(n, 'expected "key value"');
    const [k, v] = toks;
    if (own(parent.obj, k.v)) fail(n, `duplicate key ${show(k.v)}`);
    setOwn(parent.obj, k.v, v.v);
    lineMap(parent.obj).set(k.v, n);
  });
  return root;
}

// ---------------------------------------------------------------------------
// The package model
// ---------------------------------------------------------------------------

/** A package name the helper can query a registry for. */
export const PACKAGE_NAME_RE = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~!'()*-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~!'()*-]*$/;
const VERSION_RE = /^[0-9A-Za-z][0-9A-Za-z.+_-]*$/;
const SEMVER_RE = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHA_RE = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;
const GIT_SPEC_RE = /^(?:git\+[a-z]+:|git:|ssh:|github:|gitlab:|bitbucket:|gist:)/i;
const SRI_ALGOS = new Set(['sha1', 'sha256', 'sha384', 'sha512']);

/**
 * Splits "name@spec" into its parts, for scoped names too ('@a/b@1' gives
 * name '@a/b' and spec '1'). Returns null when there is no spec.
 * @param {string} s
 * @returns {{name: string, spec: string}|null}
 */
export function splitNameSpec(s) {
  const m = /^(@?[^@]+)@([\s\S]*)$/.exec(String(s));
  return m ? { name: m[1], spec: m[2] } : null;
}

function sriAlgos(integrity, fail) {
  const algos = [];
  for (const token of String(integrity).trim().split(/\s+/)) {
    const m = /^([a-z0-9]+)-[A-Za-z0-9+/]+={0,2}(?:\?\S*)?$/.exec(token);
    if (!m || !SRI_ALGOS.has(m[1])) fail(`a malformed integrity ${show(String(integrity).slice(0, 60))}`);
    if (!algos.includes(m[1])) algos.push(m[1]);
  }
  return algos;
}

// The registry base of a tarball URL whose path is the registry layout
// <base><name>/-/<file>-<version>.tgz (the file part with or without the
// scope, the name with "/" or %2f), or GitHub Packages'
// <base>download/<name>/<version>/<hash>. Returns {base, version} or null.
function matchRegistryTarball(url, name, version) {
  const clean = String(url).replace(/[?#][\s\S]*$/, '');
  const unscoped = name.includes('/') ? name.slice(name.indexOf('/') + 1) : name;
  const names = [...new Set([name, name.replace('/', '%2f'), name.replace('/', '%2F')])];
  const files = [...new Set([unscoped, name, name.replace('/', '%2f'), name.replace('/', '%2F')])];
  const ver = version ? escapeRe(version) : '([0-9][^/]*?)';
  for (const nm of names) {
    for (const file of files) {
      const m = new RegExp(`^(https?://[^?#]*/)${escapeRe(nm)}/-/${escapeRe(file)}-${ver}\\.tgz$`, 'i').exec(clean);
      if (m) return { base: m[1], version: version ?? m[2] };
    }
    const g = new RegExp(`^(https?://[^?#]*/)download/${escapeRe(nm)}/${ver}/[0-9a-f]+$`, 'i').exec(clean);
    if (g) return { base: g[1], version: version ?? g[2] };
  }
  return null;
}

// The repository and commit of a git source: the commit is the #fragment
// when it is a full SHA-1/SHA-256, or a #commit=<sha> parameter (Berry).
function gitParts(spec) {
  const s = String(spec);
  const hash = s.indexOf('#');
  const base = hash < 0 ? s : s.slice(0, hash);
  const frag = hash < 0 ? '' : s.slice(hash + 1);
  let commit = null;
  if (SHA_RE.test(frag)) commit = frag;
  else {
    const m = /(?:^|&)commit=([0-9a-f]{40}(?:[0-9a-f]{24})?)(?:&|$)/.exec(frag);
    if (m) commit = m[1];
  }
  const repo = stripCredentials(base);
  return { kind: 'git', source: commit ? `${repo}#${commit}` : repo, commit, sourceRecorded: true };
}

// The Entry builder for one lockfile: paths relative to the checkout top,
// source classification, and error reporting with the lockfile's name.
function makeBuilder({ file, rel, top, registries }) {
  const lockDir = path.dirname(file);
  const entries = [];
  const warnings = [];
  const b = {
    rel,
    lockDir,
    entries,
    warnings,
    fail(line, msg) { throw new LockfileError(rel, line, msg); },
    // A path in the lockfile, relative to BASE (the lockfile's directory),
    // as a path relative to the checkout top.
    pathSource(p, base = lockDir) {
      return relPath(top, path.resolve(base, String(p).replace(/^file:/, '')));
    },
    checkName(name, line) {
      if (typeof name !== 'string' || !PACKAGE_NAME_RE.test(name)) b.fail(line, `a malformed package name ${show(name)}`);
      return name;
    },
    checkVersion(version, line, what) {
      if (typeof version !== 'string' || !VERSION_RE.test(version)) b.fail(line, `${what}: a malformed version ${show(version)}`);
      return version;
    },
    // Classifies a URL: a registry tarball, a git source, or a remote tarball.
    classifyUrl(url, name, version, line) {
      if (typeof url !== 'string' || /[\s"\\]/.test(url)) b.fail(line, `a malformed URL ${show(url)}`);
      const codeload = /^https:\/\/codeload\.github\.com\/([^/]+)\/([^/]+)\/tar\.gz\/([0-9a-f]{40})$/.exec(url.replace(/[?#][\s\S]*$/, ''));
      if (codeload) return gitParts(`https://github.com/${codeload[1]}/${codeload[2]}.git#${codeload[3]}`);
      if (/#(?:.*&)?commit=/.test(url) || /\.git(?:#|$)/.test(url)) return gitParts(url);
      const reg = name ? matchRegistryTarball(url, name, version) : null;
      if (reg) return { kind: 'registry', source: normalizeRecordedRegistry(reg.base), sourceRecorded: true, version: reg.version };
      return { kind: 'remote', source: publicUrl(url), sourceRecorded: true };
    },
    // Classifies npm's "resolved", or a yarn/bun spec: git, file:, or a URL.
    classifySpec(spec, name, version, line) {
      if (GIT_SPEC_RE.test(spec)) return gitParts(spec);
      if (spec.startsWith('file:')) return { kind: 'local', source: b.pathSource(spec.slice(5)), sourceRecorded: true };
      if (/^https?:\/\//i.test(spec)) return b.classifyUrl(spec, name, version, line);
      return b.fail(line, `an unrecognised source ${show(publicUrl(spec))}`);
    },
    // An unrecorded registry: the scope mapping or the registry parameter.
    unrecorded(name) {
      return { kind: 'registry', source: registries.registryFor(name), sourceRecorded: false };
    },
    add(o) {
      const integrity = o.integrity ?? null;
      if (integrity !== null && typeof integrity !== 'string') b.fail(o.line, 'integrity must be a string');
      const integrityKind = integrity === null ? null : (o.integrityKind ?? 'sri');
      const integrityAlgos = integrity === null ? [] : integrityKind === 'berry' ? ['sha512']
        : sriAlgos(integrity, (msg) => b.fail(o.line, msg));
      if (o.kind === 'registry') {
        b.checkName(o.name, o.line);
        b.checkVersion(o.version, o.line, o.name);
      }
      const entry = {
        lockfile: rel,
        line: o.line ?? null,
        name: o.name,
        version: o.version ?? null,
        alias: o.alias ?? null,
        kind: o.kind,
        source: o.source ?? null,
        sourceRecorded: !!o.sourceRecorded,
        integrity,
        integrityAlgos,
        integrityKind,
        dev: o.dev ?? null,
        optional: o.optional ?? null,
        hasInstallScript: o.hasInstallScript ?? null,
        license: o.license ?? null,
        deprecated: o.deprecated ?? null,
        commit: o.commit ?? null,
        bundled: !!o.bundled,
      };
      entries.push(entry);
      return entry;
    },
  };
  return b;
}

const str = (v) => (typeof v === 'string' ? v : null);

// A workspace's package.json, for its name and version, or {}.
function readPackageJson(dir) {
  const file = path.join(dir, 'package.json');
  try { if (fs.statSync(file).size > 1 << 20) return {}; } catch { return {}; }
  const doc = readJson(file);
  return isObj(doc) ? doc : {};
}

// The workspace globs of a package.json "workspaces" field (an array, or
// {packages: []}) as anchored regular expressions over relative paths.
function workspacePatterns(field) {
  const list = Array.isArray(field) ? field : isObj(field) && Array.isArray(field.packages) ? field.packages : [];
  return list.filter((p) => typeof p === 'string' && !p.startsWith('!')).map((p) => {
    const glob = p.replace(/^\.\//, '').replace(/\/+$/, '');
    const re = glob.split('/').map((seg) => (seg === '**' ? '(?:.*)' : seg.split('*').map(escapeRe).join('[^/]*'))).join('/');
    return new RegExp(`^${re.replace(/\/\(\?:\.\*\)/g, '(?:/.*)?')}$`);
  });
}

// --- npm ---

// An npm lockfile's license: a string, a legacy {type} object's type, or an
// array of either, OR-ed as the licenses command reads the registry's legacy
// array; null for anything else.
function npmLicense(v) {
  const one = (x) => (typeof x === 'string' ? x.trim() : isObj(x) && typeof x.type === 'string' ? x.type.trim() : null);
  if (!Array.isArray(v)) return typeof v === 'string' ? v : one(v);
  const parts = v.map(one);
  if (!parts.length || parts.some((p) => !p)) return null;
  return parts.length === 1 ? parts[0] : parts.map((p) => (/\s/.test(p) ? `(${p})` : p)).join(' OR ');
}

function parseNpm(text, b) {
  const data = parseJsonWithLines(text, b.rel);
  if (!isObj(data)) b.fail(1, 'a package lock must be a JSON object');
  const lv = data.lockfileVersion;
  const lvLine = lineOf(data, 'lockfileVersion') ?? 1;
  if (lv !== 1 && lv !== 2 && lv !== 3) b.fail(lvLine, `an unsupported lockfileVersion ${show(lv)} (this orb reads npm lockfiles of versions 1, 2 and 3)`);
  if (lv === 1) {
    const ws = workspacePatterns(readPackageJson(b.lockDir).workspaces);
    b.add({ kind: 'workspace', name: str(data.name) ?? '.', version: str(data.version), source: b.pathSource('.'), sourceRecorded: true, line: lineOf(data, 'name') ?? 1, dev: false, optional: false });
    if (data.dependencies !== undefined) npmV1Walk(data.dependencies, b, ws, lineOf(data, 'dependencies'));
    return { format: 'npm', formatVersion: '1' };
  }
  const pk = data.packages;
  if (!isObj(pk)) b.fail(lineOf(data, 'packages') ?? lvLine, 'packages must be an object');
  const root = pk[''];
  const ws = workspacePatterns(isObj(root) ? root.workspaces : undefined);
  const pathKeys = new Set(Object.keys(pk).filter((k) => k !== '' && !/(?:^|\/)node_modules\//.test(k)).map((k) => path.posix.normalize(k)));
  for (const key of Object.keys(pk)) {
    const v = pk[key];
    const line = lineOf(pk, key);
    if (!isObj(v)) b.fail(line, `${show(key)} must be an object`);
    if (v.integrity !== undefined && typeof v.integrity !== 'string') b.fail(line, 'integrity must be a string');
    const common = {
      line,
      dev: v.dev === true,
      optional: v.optional === true || v.devOptional === true,
      license: npmLicense(v.license),
      deprecated: str(v.deprecated),
      hasInstallScript: v.hasInstallScript === true,
      integrity: v.integrity ?? null,
    };
    if (key === '') {
      b.add({ ...common, kind: 'workspace', name: str(v.name) ?? '.', version: str(v.version), source: b.pathSource('.'), sourceRecorded: true });
      continue;
    }
    const idx = key.lastIndexOf('node_modules/');
    if (idx < 0) {
      const workspace = ws.some((re) => re.test(path.posix.normalize(key)));
      b.add({ ...common, kind: workspace ? 'workspace' : 'local', name: str(v.name) ?? path.posix.basename(key), version: str(v.version), source: b.pathSource(key), sourceRecorded: true });
      continue;
    }
    if (idx > 0 && key[idx - 1] !== '/') b.fail(line, `a malformed install path ${show(key)}`);
    const pathName = key.slice(idx + 'node_modules/'.length);
    if (!PACKAGE_NAME_RE.test(pathName)) b.fail(line, `a malformed install path ${show(key)}`);
    if (v.link === true) {
      if (typeof v.resolved !== 'string') b.fail(line, 'a link without "resolved"');
      if (pathKeys.has(path.posix.normalize(v.resolved))) continue; // its target's entry stands for it
      b.add({ ...common, kind: 'link', name: str(v.name) ?? pathName, version: str(v.version), source: b.pathSource(v.resolved), sourceRecorded: true });
      continue;
    }
    const name = v.name === undefined ? pathName : b.checkName(v.name, line);
    const alias = name !== pathName ? pathName : null;
    if (typeof v.version !== 'string') b.fail(line, `${key} has no version`);
    let src;
    if (v.resolved === undefined) src = b.unrecorded(name);
    else if (typeof v.resolved !== 'string') b.fail(line, 'resolved must be a string');
    else src = b.classifySpec(v.resolved, name, v.version, line);
    b.add({
      ...common,
      ...src,
      name,
      alias,
      version: v.version,
      hasInstallScript: src.kind === 'git' ? null : common.hasInstallScript,
      dev: v.dev === true,
      bundled: v.inBundle === true,
    });
  }
  return { format: 'npm', formatVersion: String(lv) };
}

function npmV1Walk(deps, b, ws, parentLine) {
  if (!isObj(deps)) b.fail(parentLine, 'dependencies must be an object');
  for (const key of Object.keys(deps)) {
    const v = deps[key];
    const line = lineOf(deps, key);
    if (!isObj(v)) b.fail(line, `${show(key)} must be an object`);
    if (typeof v.version !== 'string') b.fail(line, `${key} has no version`);
    let name = key;
    let alias = null;
    let spec = v.version;
    if (spec.startsWith('npm:')) {
      const p = splitNameSpec(spec.slice(4));
      if (!p) b.fail(line, `a malformed alias ${show(spec)}`);
      name = b.checkName(p.name, line);
      alias = key !== name ? key : null;
      spec = p.spec;
    }
    const common = { line, name, alias, dev: v.dev === true, optional: v.optional === true, integrity: v.integrity ?? null, bundled: v.bundled === true };
    if (GIT_SPEC_RE.test(spec)) b.add({ ...common, ...gitParts(spec), version: null });
    else if (spec.startsWith('file:')) {
      const rel = path.posix.normalize(spec.slice(5));
      const workspace = ws.some((re) => re.test(rel));
      b.add({ ...common, kind: workspace ? 'workspace' : 'local', version: null, source: b.pathSource(spec.slice(5)), sourceRecorded: true });
    } else if (/^https?:\/\//i.test(spec)) {
      const c = b.classifyUrl(spec, name, null, line);
      b.add({ ...common, ...c, version: c.kind === 'registry' ? c.version : null });
    } else {
      const src = typeof v.resolved === 'string' ? b.classifySpec(v.resolved, name, spec, line) : b.unrecorded(name);
      b.add({ ...common, ...src, version: spec });
    }
    if (v.dependencies !== undefined) npmV1Walk(v.dependencies, b, ws, line);
  }
}

// --- pnpm ---

// A pnpm dependency reference: a link, a (name, version) of the registry, or
// null for other sources (the packages key then holds the spec).
function pnpmDepRef(depName, value, ver) {
  if (typeof value !== 'string') return null;
  if (value.startsWith('link:')) return { link: value.slice(5) };
  if (ver === '9.0') {
    if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return null;
    const v = value.split('(')[0];
    const p = splitNameSpec(v);
    if (p && p.name !== depName && !p.name.includes(':')) return { name: p.name, version: p.spec };
    return SEMVER_RE.test(v) ? { name: depName, version: v } : null;
  }
  if (ver === '6.0') {
    if (value.startsWith('/')) {
      const p = splitNameSpec(value.slice(1).split('(')[0]);
      return p ? { name: p.name, version: p.spec } : null;
    }
    const v = value.split('(')[0];
    return SEMVER_RE.test(v) ? { name: depName, version: v } : null;
  }
  if (value.startsWith('/')) {
    const k = pnpmKey('/' + value.slice(1), '5.4');
    return k.registry ? { name: k.name, version: k.version } : null;
  }
  const v = value.split('_')[0];
  return SEMVER_RE.test(v) ? { name: depName, version: v } : null;
}

// A pnpm packages/snapshots key: {registry: true, name, version} for a
// registry package, else {registry: false, name, spec}.
function pnpmKey(key, ver) {
  if (ver === '5.4') {
    if (!key.startsWith('/')) return { registry: false, name: null, spec: key };
    const segs = key.slice(1).split('/');
    const scoped = segs[0].startsWith('@');
    const name = scoped ? `${segs[0]}/${segs[1]}` : segs[0];
    const rest = segs.slice(scoped ? 2 : 1).join('/');
    return { registry: true, name, version: rest.split('_')[0] };
  }
  if (ver === '6.0') {
    if (!key.startsWith('/')) return { registry: false, name: null, spec: key };
    const p = splitNameSpec(key.slice(1));
    return p ? { registry: true, name: p.name, version: p.spec.split('(')[0] } : { registry: false, name: null, spec: key };
  }
  const p = splitNameSpec(key);
  if (!p) return { registry: false, name: null, spec: key };
  const spec = p.spec.split('(')[0];
  if (SEMVER_RE.test(spec)) return { registry: true, name: p.name, version: spec };
  return { registry: false, name: p.name, spec: p.spec };
}

function parsePnpm(text, b) {
  const docs = parseYamlSubset(text, b.rel).filter((d) => d !== null);
  if (!docs.length) b.fail(1, 'an empty pnpm lockfile');
  for (const d of docs) if (!isObj(d)) b.fail(1, 'a pnpm lockfile document must be a mapping');
  const main = docs[docs.length - 1];
  const ver = main.lockfileVersion;
  const verLine = lineOf(main, 'lockfileVersion') ?? 1;
  if (!['5.4', '6.0', '9.0'].includes(ver)) b.fail(verLine, `an unsupported lockfileVersion ${show(ver)} (this orb reads pnpm lockfiles of versions 5.4, 6.0 and 9.0)`);
  for (const d of docs) if (d.lockfileVersion !== ver) b.fail(lineOf(d, 'lockfileVersion') ?? 1, 'documents of different lockfile versions');
  const tarTarget = isObj(main.settings) && main.settings.integrityTarget === 'tar';
  const aliases = new Map();
  const noteAlias = (depName, value) => {
    const r = pnpmDepRef(depName, value, ver);
    if (r && r.name && r.name !== depName && !aliases.has(`${r.name}@${r.version}`)) aliases.set(`${r.name}@${r.version}`, depName);
  };
  const depMaps = (obj, line) => {
    const out = [];
    for (const field of ['dependencies', 'devDependencies', 'optionalDependencies']) {
      if (obj[field] === undefined || obj[field] === null) continue;
      if (!isObj(obj[field])) b.fail(lineOf(obj, field) ?? line, `${field} must be a mapping`);
      out.push(obj[field]);
    }
    return out;
  };

  // Importers: the workspace projects, their links and aliases.
  const importers = main.importers !== undefined ? main.importers : ver !== '9.0' ? { '.': main } : {};
  if (!isObj(importers)) b.fail(lineOf(main, 'importers') ?? 1, 'importers must be a mapping');
  const importerDirs = new Set(Object.keys(importers).map((k) => path.resolve(b.lockDir, k)));
  const links = new Set();
  for (const ipath of Object.keys(importers)) {
    const imp = importers[ipath];
    const line = main.importers !== undefined ? lineOf(importers, ipath) : null;
    if (imp !== null && !isObj(imp)) b.fail(line, `importer ${show(ipath)} must be a mapping`);
    const dir = path.resolve(b.lockDir, ipath);
    const pj = readPackageJson(dir);
    b.add({ kind: 'workspace', name: str(pj.name) ?? ipath, version: str(pj.version), source: b.pathSource(ipath), sourceRecorded: true, line, dev: false, optional: false });
    for (const deps of imp ? depMaps(imp, line) : []) {
      for (const dn of Object.keys(deps)) {
        const dv = deps[dn];
        // 5.4 writes the version; 6.0 and 9.0 write {specifier, version}.
        const value = ver === '5.4' ? dv : isObj(dv) ? dv.version : undefined;
        if (typeof value !== 'string') b.fail(lineOf(deps, dn), `${show(dn)} has no version`);
        const r = pnpmDepRef(dn, value, ver);
        if (r && r.link !== undefined) {
          const target = path.resolve(dir, r.link);
          if (importerDirs.has(target) || links.has(target)) continue;
          links.add(target);
          b.add({ kind: 'link', name: dn, version: str(readPackageJson(target).version), source: b.pathSource(target), sourceRecorded: true, line: lineOf(deps, dn) });
        } else noteAlias(dn, value);
      }
    }
  }

  for (const doc of docs) {
    // Snapshots (9.0): optional flags and aliases of the dependency graph.
    const optional = new Map();
    if (ver === '9.0' && doc.snapshots !== undefined && doc.snapshots !== null) {
      if (!isObj(doc.snapshots)) b.fail(lineOf(doc, 'snapshots') ?? 1, 'snapshots must be a mapping');
      for (const skey of Object.keys(doc.snapshots)) {
        const sv = doc.snapshots[skey];
        const sline = lineOf(doc.snapshots, skey);
        if (sv !== null && !isObj(sv)) b.fail(sline, `snapshot ${show(skey)} must be a mapping`);
        const base = skey.split('(')[0];
        const opt = !!sv && sv.optional === 'true';
        optional.set(base, optional.has(base) ? optional.get(base) && opt : opt);
        for (const deps of sv ? depMaps(sv, sline) : []) for (const dn of Object.keys(deps)) noteAlias(dn, deps[dn]);
      }
    }
    if (doc.packages === undefined || doc.packages === null) continue;
    if (!isObj(doc.packages)) b.fail(lineOf(doc, 'packages') ?? 1, 'packages must be a mapping');
    if (ver !== '9.0') {
      for (const key of Object.keys(doc.packages)) {
        const pv = doc.packages[key];
        if (isObj(pv)) for (const deps of depMaps(pv, lineOf(doc.packages, key))) for (const dn of Object.keys(deps)) noteAlias(dn, deps[dn]);
      }
    }
    for (const key of Object.keys(doc.packages)) {
      const pv = doc.packages[key];
      const line = lineOf(doc.packages, key);
      if (!isObj(pv)) b.fail(line, `package ${show(key)} must be a mapping`);
      const k = pnpmKey(key, ver);
      const res = pv.resolution;
      if (!isObj(res)) b.fail(line, `${show(key)} has no resolution`);
      if (res.type === 'variations' || res.type === 'binary') {
        b.warnings.push(`${b.rel}:${line}: ${key} is left out: pnpm's ${res.type} resolutions (such as a Node.js runtime) are not packages.`);
        continue;
      }
      const name = k.registry ? k.name : (str(pv.name) ?? k.name);
      if (typeof name !== 'string' || !name) b.fail(line, `${show(key)} has no package name`);
      const version = k.registry ? k.version : str(pv.version);
      let src;
      if (res.type === 'git') {
        if (typeof res.repo !== 'string' || typeof res.commit !== 'string') b.fail(line, 'a git resolution needs repo and commit');
        src = gitParts(`${res.repo}#${res.commit}`);
      } else if (res.type === 'directory') {
        if (typeof res.directory !== 'string') b.fail(line, 'a directory resolution needs directory');
        src = { kind: 'local', source: b.pathSource(res.directory), sourceRecorded: true };
      } else if (res.type !== undefined) {
        b.fail(line, `an unsupported resolution type ${show(res.type)}`);
      } else if (res.tarball !== undefined) {
        if (typeof res.tarball !== 'string') b.fail(line, 'tarball must be a string');
        src = res.tarball.startsWith('file:') ? { kind: 'local', source: b.pathSource(res.tarball.slice(5)), sourceRecorded: true }
          : b.classifyUrl(res.tarball, name, version, line);
        if (src.kind === 'registry' && !k.registry) src = { kind: 'remote', source: publicUrl(res.tarball), sourceRecorded: true };
      } else if (res.integrity !== undefined) {
        if (!k.registry) b.fail(line, `${show(key)} has only an integrity, but its key is not a registry package`);
        src = b.unrecorded(name);
      } else {
        b.fail(line, 'a resolution without integrity, tarball, commit or directory');
      }
      if (src.kind === 'registry' && !k.registry) b.fail(line, `${show(key)} is not a registry package key`);
      b.add({
        ...src,
        line,
        name,
        version,
        alias: src.kind === 'registry' ? (aliases.get(`${name}@${version}`) ?? null) : null,
        integrity: res.integrity ?? null,
        integrityKind: res.integrity !== undefined && (tarTarget || res.integrityTarget === 'tar') ? 'tar' : 'sri',
        dev: ver === '9.0' ? null : pv.dev === 'true',
        optional: ver === '9.0' ? (optional.size ? optional.get(key) === true : null) : pv.optional === 'true',
        deprecated: str(pv.deprecated),
      });
    }
  }
  return { format: 'pnpm', formatVersion: ver };
}

// --- yarn v1 ---

function parseYarn1(text, b) {
  const root = parseYarn1Text(text, b.rel);
  const seen = new Set();
  for (const key of Object.keys(root)) {
    const e = root[key];
    if (seen.has(e)) continue;
    seen.add(e);
    const line = lineOf(root, key);
    const desc = splitNameSpec(key);
    if (!desc) b.fail(line, `a malformed entry key ${show(key)}`);
    let name = desc.name;
    let alias = null;
    let range = desc.spec;
    if (range.startsWith('npm:')) {
      const p = splitNameSpec(range.slice(4));
      if (!p) b.fail(line, `a malformed alias ${show(key)}`);
      alias = desc.name !== p.name ? desc.name : null;
      name = p.name;
      range = p.spec;
    }
    if (typeof e.version !== 'string') b.fail(line, `${key} has no version`);
    const resolved = e.resolved;
    if (resolved !== undefined && typeof resolved !== 'string') b.fail(line, 'resolved must be a string');
    let integrity = str(e.integrity);
    let src;
    if (range.startsWith('file:')) src = { kind: 'local', source: b.pathSource(range.slice(5)), sourceRecorded: true };
    else if (range.startsWith('link:')) src = { kind: 'link', source: b.pathSource(range.slice(5)), sourceRecorded: true };
    else if (resolved !== undefined && (GIT_SPEC_RE.test(resolved) || GIT_SPEC_RE.test(range))) src = gitParts(resolved);
    else if (resolved !== undefined && /^https?:\/\//i.test(resolved)) {
      src = b.classifyUrl(resolved, name, e.version, line);
      const sha1 = /#([0-9a-f]{40})$/.exec(resolved);
      if (integrity === null && sha1 && src.kind !== 'git') integrity = 'sha1-' + Buffer.from(sha1[1], 'hex').toString('base64');
    } else if (resolved === undefined && GIT_SPEC_RE.test(range)) src = gitParts(range);
    else b.fail(line, `${key}: an unrecognised source ${show(publicUrl(resolved ?? range))}`);
    b.add({ ...src, line, name, alias, version: e.version, integrity });
  }
  return { format: 'yarn1', formatVersion: '1' };
}

// --- yarn Berry ---

function parseBerry(text, b) {
  const docs = parseYamlSubset(text, b.rel).filter((d) => d !== null);
  if (docs.length !== 1 || !isObj(docs[0])) b.fail(1, 'a yarn lockfile must be one mapping');
  const d = docs[0];
  const meta = d.__metadata;
  if (!isObj(meta)) b.fail(1, 'missing __metadata');
  const version = meta.version;
  if (typeof version !== 'string' || !/^(?:[4-9]|10)$/.test(version)) {
    b.fail(lineOf(meta, 'version') ?? lineOf(d, '__metadata'), `an unsupported __metadata.version ${show(version)} (this orb reads yarn lockfiles of versions 4 to 10)`);
  }
  const keys = Object.keys(d).filter((k) => k !== '__metadata');
  const resolutions = new Set(keys.map((k) => (isObj(d[k]) ? d[k].resolution : null)));
  for (const key of keys) {
    const e = d[key];
    const line = lineOf(d, key);
    if (!isObj(e)) b.fail(line, `${show(key)} must be a mapping`);
    if (typeof e.resolution !== 'string') b.fail(line, `${show(key)} has no resolution`);
    const desc = splitNameSpec(key.split(/,\s*/)[0]);
    if (!desc) b.fail(line, `a malformed descriptor ${show(key)}`);
    let loc = splitNameSpec(e.resolution);
    if (!loc) b.fail(line, `a malformed resolution ${show(e.resolution)}`);
    if (loc.spec.startsWith('patch:')) {
      const inner = decodeURIComponent(loc.spec.slice(6).split('#')[0].split('::')[0]);
      if (resolutions.has(inner)) continue; // the unpatched package has its own entry
      loc = splitNameSpec(inner);
      if (!loc) b.fail(line, `a malformed patch resolution ${show(e.resolution)}`);
    }
    const ref = loc.spec;
    const name = loc.name;
    const ver = str(e.version);
    if (e.checksum !== undefined && (typeof e.checksum !== 'string' || !/^(?:[0-9a-z]+\/)?[0-9a-f]{128}$/.test(e.checksum))) b.fail(line, `a malformed checksum ${show(e.checksum)}`);
    const integrity = str(e.checksum);
    // file: and link: paths are relative to the workspace named by ::locator=.
    let base = b.lockDir;
    const locator = /::(?:.*&)?locator=([^&]+)/.exec(ref);
    if (locator) {
      const l = splitNameSpec(decodeURIComponent(locator[1]));
      if (l && l.spec.startsWith('workspace:')) base = path.resolve(b.lockDir, l.spec.slice(10));
    }
    let src;
    if (ref.startsWith('npm:')) {
      if (ref.slice(4) !== ver) b.fail(line, `the resolution ${show(e.resolution)} doesn't match version ${show(ver)}`);
      src = b.unrecorded(name);
    } else if (ref.startsWith('workspace:')) src = { kind: 'workspace', source: b.pathSource(ref.slice(10)), sourceRecorded: true };
    else if (ref.startsWith('link:') || ref.startsWith('portal:')) {
      src = { kind: 'link', source: b.pathSource(ref.slice(ref.indexOf(':') + 1).split('::')[0], base), sourceRecorded: true };
    } else if (ref.startsWith('file:')) {
      src = { kind: 'local', source: b.pathSource(ref.slice(5).split('#')[0].split('::')[0], base), sourceRecorded: true };
    } else if (/#(?:.*&)?commit=/.test(ref) || GIT_SPEC_RE.test(ref)) src = gitParts(ref);
    else if (/^https?:\/\//i.test(ref)) src = b.classifyUrl(ref.split('::')[0], name, ver, line);
    else b.fail(line, `an unsupported resolution ${show(publicUrl(e.resolution))}`);
    b.add({
      ...src,
      line,
      name,
      alias: desc.name !== name ? desc.name : null,
      version: ver,
      integrity,
      integrityKind: 'berry',
    });
  }
  return { format: 'berry', formatVersion: version };
}

// --- bun ---

function bunKeyName(key) {
  const segs = key.split('/');
  const last = segs[segs.length - 1];
  return segs.length >= 2 && segs[segs.length - 2].startsWith('@') ? `${segs[segs.length - 2]}/${last}` : last;
}

function parseBun(text, b) {
  const data = parseJsonWithLines(text, b.rel, { jsonc: true });
  if (!isObj(data)) b.fail(1, 'bun.lock must be a JSON object');
  const lv = data.lockfileVersion;
  if (lv !== 0 && lv !== 1 && lv !== 2) b.fail(lineOf(data, 'lockfileVersion') ?? 1, `an unsupported lockfileVersion ${show(lv)} (this orb reads bun.lock versions 0 to 2)`);
  const ws = data.workspaces ?? {};
  if (!isObj(ws)) b.fail(lineOf(data, 'workspaces') ?? 1, 'workspaces must be an object');
  for (const wpath of Object.keys(ws)) {
    const w = ws[wpath];
    const line = lineOf(ws, wpath);
    if (!isObj(w)) b.fail(line, `workspace ${show(wpath)} must be an object`);
    b.add({ kind: 'workspace', name: str(w.name) ?? (wpath || '.'), version: str(w.version), source: b.pathSource(wpath || '.'), sourceRecorded: true, line, dev: false, optional: false });
  }
  const pk = data.packages ?? {};
  if (!isObj(pk)) b.fail(lineOf(data, 'packages') ?? 1, 'packages must be an object');
  for (const key of Object.keys(pk)) {
    const arr = pk[key];
    const line = lineOf(pk, key);
    if (!Array.isArray(arr) || typeof arr[0] !== 'string') b.fail(line, `${show(key)} must be an array that starts with "name@version"`);
    const id = splitNameSpec(arr[0]);
    if (!id) b.fail(line, `a malformed package ${show(arr[0])}`);
    const { name, spec } = id;
    const keyName = bunKeyName(key);
    const alias = keyName !== name ? keyName : null;
    const integrity = arr.slice(1).find((x) => typeof x === 'string' && /^(?:sha1|sha256|sha384|sha512)-/.test(x)) ?? null;
    if (spec.startsWith('workspace:') || spec.startsWith('root:')) continue; // listed under workspaces
    let src;
    let version = null;
    if (spec.startsWith('file:')) src = { kind: 'local', source: b.pathSource(spec.slice(5)), sourceRecorded: true };
    else if (spec.startsWith('link:')) src = { kind: 'link', source: b.pathSource(spec.slice(5)), sourceRecorded: true };
    else if (GIT_SPEC_RE.test(spec)) src = gitParts(spec);
    else if (/^https?:\/\//i.test(spec)) {
      src = b.classifyUrl(spec, name, null, line);
      if (src.kind === 'registry') version = src.version;
    } else if (VERSION_RE.test(spec)) {
      version = spec;
      if (arr.length !== 4 || typeof arr[1] !== 'string' || !isObj(arr[2])) b.fail(line, `${show(key)}: a registry package must be [name@version, url, meta, integrity]`);
      if (arr[1] === '') src = { kind: 'registry', source: DEFAULT_REGISTRY, sourceRecorded: true };
      else {
        src = b.classifyUrl(arr[1], name, spec, line);
        if (src.kind !== 'registry') b.fail(line, `${show(key)}: the tarball URL is not ${name}@${spec} on a registry`);
      }
    } else b.fail(line, `${show(key)}: an unrecognised source ${show(publicUrl(spec))}`);
    b.add({ ...src, line, name, alias, version, integrity });
  }
  return { format: 'bun', formatVersion: String(lv) };
}

// ---------------------------------------------------------------------------
// Discovery and readLockfiles
// ---------------------------------------------------------------------------

/**
 * The top of the git checkout DIR is in (the nearest parent with .git), or
 * DIR itself outside one.
 * @param {string} dir
 * @returns {string} an absolute path
 */
export function findCheckoutTop(dir) {
  let d = path.resolve(dir);
  try { d = fs.realpathSync(d); } catch { /* keep it */ }
  for (let cur = d; ; cur = path.dirname(cur)) {
    if (fs.existsSync(path.join(cur, '.git'))) return cur;
    if (path.dirname(cur) === cur) return d;
  }
}

/**
 * A path relative to BASE, with / separators ('.' for BASE itself).
 * @param {string} base
 * @param {string} p
 */
export function relPath(base, p) {
  return path.relative(base, p).split(path.sep).join('/') || '.';
}

function globSegment(seg) {
  return new RegExp(`^${seg.split('*').map((part) => part.split('?').map(escapeRe).join('[^/]')).join('[^/]*')}$`);
}

/**
 * The files a pattern matches, relative to CWD: * and ? within a path
 * segment, and ** for any number of directories (skipping node_modules and
 * hidden directories). Sorted absolute paths.
 * @param {string} cwd
 * @param {string} pattern
 * @returns {string[]}
 */
export function globFiles(cwd, pattern) {
  const segs = pattern.split('/').filter((s) => s !== '' && s !== '.');
  let current = [path.isAbsolute(pattern) ? '/' : cwd];
  const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };
  for (const seg of segs) {
    const next = new Set();
    if (seg === '**') {
      const walk = (d, depth) => {
        next.add(d);
        if (depth > 32) return;
        let names;
        try { names = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
        for (const de of names) {
          if (de.isDirectory() && de.name !== 'node_modules' && !de.name.startsWith('.')) walk(path.join(d, de.name), depth + 1);
        }
      };
      for (const d of current) walk(d, 0);
    } else if (!/[*?]/.test(seg)) {
      for (const d of current) { const p = path.join(d, seg); if (fs.existsSync(p)) next.add(p); }
    } else {
      const re = globSegment(seg);
      for (const d of current) {
        let names;
        try { names = fs.readdirSync(d); } catch { continue; }
        for (const nm of names) if (re.test(nm) && (seg.startsWith('.') || !nm.startsWith('.'))) next.add(path.join(d, nm));
      }
    }
    current = [...next];
  }
  return current.filter((p) => { try { return fs.statSync(p).isFile(); } catch { return false; } }).sort();
}

/**
 * Finds the lockfiles in CWD: PATTERNS, or LOCKFILE_NAMES when empty
 * (npm-shrinkwrap.json hides package-lock.json). A pattern matching nothing,
 * or a bun.lockb, is an error.
 * @returns {{files: string[], warnings: string[]}}
 */
export function discoverLockfiles(cwd, patterns = []) {
  const warnings = [];
  const files = [];
  if (!patterns.length) {
    for (const name of LOCKFILE_NAMES) {
      const p = path.join(cwd, name);
      if (fs.existsSync(p) && fs.statSync(p).isFile()) files.push(p);
    }
    if (files.some((f) => path.basename(f) === 'npm-shrinkwrap.json') && files.some((f) => path.basename(f) === 'package-lock.json')) {
      warnings.push('npm-shrinkwrap.json and package-lock.json are both here: npm installs from npm-shrinkwrap.json, so package-lock.json is not checked.');
      files.splice(files.findIndex((f) => path.basename(f) === 'package-lock.json'), 1);
    }
    if (fs.existsSync(path.join(cwd, 'bun.lockb'))) {
      if (!fs.existsSync(path.join(cwd, 'bun.lock'))) throw new Error(BUN_LOCKB_HINT);
      warnings.push('bun.lockb is not checked: bun installs from bun.lock when both are present.');
    }
    return { files, warnings };
  }
  for (const pattern of patterns) {
    const matches = globFiles(cwd, pattern);
    if (!matches.length) throw new Error(`lockfiles: ${show(pattern)} matches no file in ${cwd}.`);
    for (const m of matches) {
      if (path.basename(m) === 'bun.lockb') throw new Error(`${relPath(cwd, m)}: ${BUN_LOCKB_HINT}`);
      if (!files.includes(m)) files.push(m);
    }
  }
  return { files, warnings };
}

function detectFormat(file, text) {
  const base = path.basename(file);
  if (base === 'bun.lockb' || text.startsWith('#!/usr/bin/env bun\nbun-lockfile-format')) return 'bun.lockb';
  if (base === 'package-lock.json' || base === 'npm-shrinkwrap.json') return 'npm';
  if (base === 'pnpm-lock.yaml') return 'pnpm';
  if (base === 'bun.lock') return 'bun';
  const yarn1 = /^# yarn lockfile v1\r?$/m.test(text);
  const berry = /^__metadata:\r?$/m.test(text);
  if (base === 'yarn.lock' || yarn1 || berry) {
    return berry && !yarn1 ? 'berry' : 'yarn1';
  }
  if (/^\s*\{/.test(text)) {
    if (/"packages"\s*:\s*\{\s*(?:\/\/[^\n]*\s*|\/\*[\s\S]*?\*\/\s*)*"[^"]*"\s*:\s*\[/.test(text) || /,\s*[}\]]/.test(text)) return 'bun';
    return 'npm';
  }
  if (/^(?:---\r?\n)?lockfileVersion:/m.test(text)) return 'pnpm';
  return null;
}

const PARSERS = { npm: parseNpm, pnpm: parsePnpm, yarn1: parseYarn1, berry: parseBerry, bun: parseBun };

/**
 * Parses one lockfile's text. file: its absolute path; rel: its name in
 * entries (default: relative to top, the checkout top); format: npm, pnpm,
 * yarn1, berry or bun (default: detected); registries: registryConfig().
 * @returns {{format, formatVersion, entries, warnings}}
 */
export function parseLockfileText(text, { file, rel, top, format, registries } = {}) {
  const abs = path.resolve(file);
  const t = top ?? findCheckoutTop(path.dirname(abs));
  const name = rel ?? relPath(t, abs);
  const fmt = format ?? detectFormat(abs, text);
  if (fmt === 'bun.lockb') throw new LockfileError(name, 1, BUN_LOCKB_HINT);
  if (!fmt || !PARSERS[fmt]) throw new LockfileError(name, 1, 'not a lockfile format this orb reads (package-lock.json, npm-shrinkwrap.json, pnpm-lock.yaml, yarn.lock or bun.lock)');
  const b = makeBuilder({ file: abs, rel: name, top: t, registries: registries ?? registryConfig({ npmrc: false }) });
  const { format: f, formatVersion } = PARSERS[fmt](text, b);
  return { format: f, formatVersion, entries: b.entries, warnings: b.warnings };
}

/**
 * Finds, reads and parses the lockfiles of cwd (default process.cwd()):
 * lockfilePatterns (empty: auto-detect), includeDev and allowEmpty apply, and
 * registries (registryConfig()) gives the sources a lockfile doesn't record.
 * Throws a LockfileError for a lockfile it refuses, and an Error when none is
 * found (unless allowEmpty) or a pattern matches nothing.
 * @returns {{lockfiles: {path, rel, format, formatVersion, sha256, entries}[], entries, warnings, top}}
 */
export function readLockfiles({ cwd = process.cwd(), lockfilePatterns = [], includeDev = true, allowEmpty = false, registries } = {}) {
  const dir = path.resolve(cwd);
  const top = findCheckoutTop(dir);
  const regs = registries ?? registryConfig({ cwd: dir, npmrc: false });
  const { files, warnings } = discoverLockfiles(dir, lockfilePatterns);
  const out = { lockfiles: [], entries: [], warnings, top };
  if (!files.length) {
    const msg = `No lockfile in ${dir}: looked for ${LOCKFILE_NAMES.join(', ')}.`;
    if (!allowEmpty) throw new Error(`${msg}\nSet lockfiles to the lockfiles to check, or allow_empty to true.`);
    warnings.push(msg);
    return out;
  }
  const seen = new Set();
  for (const f of files) {
    const abs = fs.realpathSync(f);
    if (seen.has(abs)) continue;
    seen.add(abs);
    const rel = relPath(top, abs);
    const buf = fs.readFileSync(abs);
    if (buf.length > 512 * 1024 * 1024) throw new LockfileError(rel, 1, 'larger than 512 MB');
    let text;
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(buf); } catch {
      if (path.basename(abs) === 'bun.lockb' || buf.subarray(0, 40).toString('latin1').includes('bun-lockfile-format')) throw new LockfileError(rel, 1, BUN_LOCKB_HINT);
      throw new LockfileError(rel, 1, 'not UTF-8 text');
    }
    const parsed = parseLockfileText(text, { file: abs, rel, top, registries: regs });
    let entries = parsed.entries;
    if (!includeDev) {
      const unknown = entries.filter((e) => e.dev === null && e.kind !== 'workspace').length;
      if (unknown) warnings.push(`${rel}: ${parsed.format} lockfiles don't record which packages are only for development, so include_dev: false keeps all ${plural(unknown, 'package')}.`);
      entries = entries.filter((e) => e.dev !== true);
    }
    warnings.push(...parsed.warnings);
    out.lockfiles.push({ path: abs, rel, format: parsed.format, formatVersion: parsed.formatVersion, sha256: sha256(buf), entries: entries.length });
    out.entries.push(...entries);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Policy patterns
// ---------------------------------------------------------------------------

/**
 * Compiles a package pattern: a name with * globs ('@corp/*', 'eslint-*',
 * '*'), with @version only when versions is true. UsageError if bad.
 * @returns {{text, name, version, re}}
 */
export function compilePattern(text, { versions = false, param = 'a pattern' } = {}) {
  const t = String(text).trim();
  let name = t;
  let version = null;
  const at = t.lastIndexOf('@');
  if (at > 0) { name = t.slice(0, at); version = t.slice(at + 1); }
  if (version !== null && !versions) throw new UsageError(`${param} takes package names, without versions: ${show(t)}.`);
  if (version === '' || (version !== null && /\s/.test(version))) throw new UsageError(`${param}: a malformed version in ${show(t)}.`);
  if (!/^(?:@[A-Za-z0-9*~-][A-Za-z0-9._~*-]*\/)?[A-Za-z0-9*~-][A-Za-z0-9._~*-]*$/.test(name)) {
    throw new UsageError(`${param}: ${show(t)} is not a package name or a pattern such as @scope/* or eslint-*.`);
  }
  return { text: t, name, version, re: new RegExp(`^${name.split('*').map(escapeRe).join('.*')}$`) };
}

/**
 * The first pattern NAME matches, or null. A pattern with a version matches
 * only VERSION: exactly, or by versionMatch(version, spec).
 * @param {string} name
 * @param {Array<string|object>} patterns compiled, or strings
 * @param {string} [version]
 * @param {{versionMatch?: Function}} [options]
 */
export function matchesAny(name, patterns, version, { versionMatch } = {}) {
  for (const p of patterns ?? []) {
    const c = typeof p === 'string' ? compilePattern(p, { versions: true }) : p;
    if (!c.re.test(name)) continue;
    if (c.version === null) return c;
    if (version === undefined || version === null) continue;
    if (versionMatch ? versionMatch(version, c.version) : version === c.version) return c;
  }
  return null;
}

// ---------------------------------------------------------------------------
// curl
// ---------------------------------------------------------------------------

let curlCache = null;

function versionAtLeast(v, min) {
  const a = v.split('.').map(Number);
  const b = min.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (a[i] !== b[i]) return a[i] > b[i];
  return true;
}

/**
 * Finds curl on the PATH and checks its version (7.71.0 or later).
 * @param {Record<string, string|undefined>} [env]
 * @returns {{path: string, version: string}}
 */
export function findCurl(env = process.env) {
  const PATH = env.PATH ?? '';
  if (curlCache && curlCache.PATH === PATH) return curlCache;
  let found = null;
  for (const dir of PATH.split(':')) {
    if (!dir) continue;
    const p = path.join(dir, 'curl');
    try {
      fs.accessSync(p, fs.constants.X_OK);
      if (fs.statSync(p).isFile()) { found = p; break; }
    } catch { /* not here */ }
  }
  if (!found) throw new Error('curl is not on the PATH. This orb reaches registries with curl: install it in an earlier step.');
  const r = spawnSync(found, ['-q', '--version'], { encoding: 'utf8', env });
  const m = /^curl (\d+\.\d+\.\d+)/.exec(r.stdout ?? '');
  if (r.status !== 0 || !m) throw new Error(`Could not read the version of ${found}.`);
  if (!versionAtLeast(m[1], MIN_CURL_VERSION)) {
    throw new Error(`${found} is curl ${m[1]}, which is too old: this orb needs curl ${MIN_CURL_VERSION} or later (for --parallel and --retry-all-errors).`);
  }
  curlCache = { PATH, path: found, version: m[1] };
  return curlCache;
}

// A value in curl's config file: double-quoted, with \ " and line breaks escaped.
function curlQuote(value) {
  const s = String(value);
  if (/[\0-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(s)) throw new Error('A control character in a curl option.');
  return `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\r/g, '\\r').replace(/\t/g, '\\t')}"`;
}

function runProcess(cmd, args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: ['ignore', 'pipe', 'pipe'] });
    const out = [];
    const err = [];
    let errLen = 0;
    child.stdout.on('data', (d) => out.push(d));
    child.stderr.on('data', (d) => { if (errLen < 1 << 20) { err.push(d); errLen += d.length; } });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ code, signal, stdout: Buffer.concat(out).toString('utf8'), stderr: Buffer.concat(err).toString('utf8') }));
  });
}

function parseHeaderFile(file) {
  let text;
  try { text = fs.readFileSync(file, 'latin1'); } catch { return {}; }
  const blocks = text.split(/\r?\n\r?\n/).filter((blk) => /^HTTP\//.test(blk.trim()));
  const last = blocks[blocks.length - 1];
  const headers = {};
  if (!last) return headers;
  for (const line of last.trim().split(/\r?\n/).slice(1)) {
    const i = line.indexOf(':');
    if (i > 0) headers[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
  }
  return headers;
}

/**
 * Runs requests with one curl --parallel, from a 0600 config file in workDir
 * (removed when curl ends; curl reads no .curlrc and follows no redirects):
 * --compressed, --max-time, --retry --retry-all-errors, --globoff, and
 * --proto =https (=http, without a proxy, for loopback hosts). Requests to
 * auth.origin get auth.header, which is never on a command line.
 * @param {Array<{url, method?, headers?, bodyFile?, output?}>} requests
 *   bodyFile is POSTed (--data-binary @file); output defaults to workDir
 * @param {{workDir, concurrency?, timeout?, retries?, retryDelay?, auth?, env?}} options
 *   retryDelay 0 is curl's backoff
 * @returns {Promise<Array<{url, status, file, headers, error}>>} status 0: the
 *   transfer failed; error is set unless 2xx or 304
 */
export async function fetchMany(requests, { workDir, concurrency = 16, timeout = 60, retries = 3, retryDelay = 0, auth = null, env = process.env } = {}) {
  if (!requests.length) return [];
  if (!workDir) throw new Error('fetchMany needs a work directory.');
  const curl = findCurl(env);
  const dir = fs.mkdtempSync(path.join(workDir, 'curl-'));
  const lines = [];
  const files = requests.map((r, i) => {
    let u;
    try { u = new URL(r.url); } catch { throw new Error(`Not a URL: ${show(publicUrl(r.url))}.`); }
    const loopback = isLoopbackHost(u.hostname);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && loopback)) throw new Error(`Refusing to fetch ${publicUrl(r.url)}: only https, or http to localhost, is allowed.`);
    if (u.username || u.password) throw new Error(`Refusing to fetch a URL that holds credentials: ${publicUrl(r.url)}.`);
    const output = r.output ?? path.join(dir, `${i}.body`);
    const headerFile = path.join(dir, `${i}.headers`);
    if (i) lines.push('next');
    lines.push(`url = ${curlQuote(r.url)}`, `output = ${curlQuote(output)}`, `dump-header = ${curlQuote(headerFile)}`,
      `write-out = ${curlQuote(`${i} %{http_code}\n`)}`, 'globoff', 'compressed', `max-time = ${timeout}`,
      `proto = ${curlQuote(u.protocol === 'https:' ? '=https' : '=http')}`, 'user-agent = "js-security-orb"');
    if (retries > 0) lines.push(`retry = ${retries}`, 'retry-all-errors');
    if (retryDelay > 0) lines.push(`retry-delay = ${retryDelay}`);
    if (loopback) lines.push('noproxy = "*"');
    for (const [k, v] of Object.entries(r.headers ?? {})) {
      if (!/^[A-Za-z0-9-]+$/.test(k) || /[\r\n]/.test(String(v))) throw new Error(`A malformed header ${show(k)}.`);
      lines.push(`header = ${curlQuote(`${k}: ${v}`)}`);
    }
    if (auth && u.origin === auth.origin) lines.push(`header = ${curlQuote(auth.header)}`);
    if (r.bodyFile) lines.push(`data-binary = ${curlQuote('@' + r.bodyFile)}`);
    if (r.method && r.method !== (r.bodyFile ? 'POST' : 'GET')) lines.push(`request = ${curlQuote(r.method)}`);
    return { output, headerFile };
  });
  const config = path.join(dir, 'config');
  fs.writeFileSync(config, lines.join('\n') + '\n', { mode: 0o600 });
  let res;
  try {
    res = await runProcess(curl.path, ['-q', '-sS', '--parallel', '--parallel-max', String(Math.max(1, concurrency)), '-K', config], env);
  } finally {
    fs.rmSync(config, { force: true });
  }
  const status = new Map();
  for (const line of res.stdout.split('\n')) {
    const m = /^(\d+) (\d{3})$/.exec(line.trim());
    if (m) status.set(+m[1], +m[2]);
  }
  const curlErrors = res.stderr.split('\n').map((l) => l.trim()).filter(Boolean).slice(0, 5).join('; ');
  return requests.map((r, i) => {
    const s = status.get(i) ?? 0;
    const ok = (s >= 200 && s < 300) || s === 304;
    return {
      url: r.url,
      status: s,
      file: files[i].output,
      headers: parseHeaderFile(files[i].headerFile),
      error: ok ? null : s === 0 ? `the transfer failed${curlErrors ? ` (curl: ${curlErrors})` : ''}` : `HTTP ${s}`,
    };
  });
}

// ---------------------------------------------------------------------------
// The registry client: packuments and attestations, cached
// ---------------------------------------------------------------------------

/**
 * The cache directory for registry metadata:
 * ${XDG_CACHE_HOME:-~/.cache}/js-security-orb-registry. (The install
 * command's own cache, ~/.cache/js-security-orb, holds Node.js releases.)
 * @param {Record<string, string|undefined>} [env]
 */
export function defaultCacheDir(env = process.env) {
  const xdg = env.XDG_CACHE_HOME && path.isAbsolute(env.XDG_CACHE_HOME) ? env.XDG_CACHE_HOME : null;
  return path.join(xdg ?? path.join(env.HOME || os.homedir(), '.cache'), 'js-security-orb-registry');
}

/**
 * A package name as a registry URL path segment: '@scope/name' is
 * '@scope%2Fname'.
 * @param {string} name
 */
export function escapePackageName(name) {
  if (!PACKAGE_NAME_RE.test(name)) throw new Error(`Not a package name: ${show(name)}.`);
  return name.startsWith('@') ? '@' + encodeURIComponent(name.slice(1)) : encodeURIComponent(name);
}

function registryDirName(registry) {
  const u = new URL(registry);
  const p = u.pathname.replace(/\/+$/, '');
  return `${u.hostname}${u.port ? '_' + u.port : ''}${p}`.replace(/[^A-Za-z0-9._-]/g, '_');
}

function writeAtomicSync(file, data, mode = 0o644) {
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  try {
    fs.writeFileSync(tmp, data, { mode });
    fs.renameSync(tmp, file);
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    throw e;
  }
}

/**
 * The registry client: fetchMany with this configuration, getPackuments
 * and getAttestations. token goes only to the registry's origin.
 * @param {{registries, token?, concurrency?, timeout?, retries?, retryDelay?, workDir, cacheDir?, io?, env?}} options
 */
export function createRegistryClient({ registries, token = null, concurrency = 16, timeout = 60, retries = 3, retryDelay = 0, workDir, cacheDir, io = createIO(), env = process.env } = {}) {
  if (!registries) throw new Error('createRegistryClient needs registries.');
  if (token !== null && /[\0\r\n]/.test(token)) throw new UsageError('The token holds a line break, which no registry token does.');
  const auth = token ? { origin: new URL(registries.registry).origin, header: `Authorization: Bearer ${token}` } : null;
  let cacheRoot = cacheDir ?? defaultCacheDir(env);
  // A cache directory that can't be made falls back to the work directory.
  const dirFor = (kind, registry) => {
    const d = () => path.join(cacheRoot, kind, registryDirName(registry));
    try { fs.mkdirSync(d(), { recursive: true, mode: 0o700 }); } catch (e) {
      io.warn(`Could not use the cache directory ${cacheRoot} (${e.code ?? e.message}), so registry metadata is not cached.`);
      cacheRoot = path.join(workDir, 'cache');
      fs.mkdirSync(d(), { recursive: true, mode: 0o700 });
    }
    return d();
  };
  const many = (requests) => fetchMany(requests, { workDir, concurrency, timeout, retries, retryDelay, auth, env });
  const client = {
    registries,
    /** The cache directory in use. */
    get cacheDir() { return cacheRoot; },
    /** fetchMany with this client's settings: token for the registry's origin only. */
    fetchMany: many,
    /** The packument URL of NAME on its registry (or REGISTRY). */
    packumentUrl(name, registry = registries.registryFor(name)) { return registry + escapePackageName(name); },
    /** The attestations URL of NAME@VERSION on its registry (or REGISTRY). */
    attestationUrl(name, version, registry = registries.registryFor(name)) {
      return `${registry}-/npm/v1/attestations/${escapePackageName(name)}@${encodeURIComponent(version)}`;
    },
    /**
     * Full packuments (Accept: application/json) from each name's registry,
     * through the ETag cache: If-None-Match, a 304 keeps the cached copy, and a
     * 200 replaces it only once it parses. pick(doc, name) keeps what is needed.
     * @returns {Promise<Map<string, {status, url, packument?, fromCache?, error?}>>}
     *   packument is set when usable (status 200, also after a 304); else
     *   status 404 (not found), or error says why (status 0: transfer failed)
     */
    async getPackuments(names, { pick = null, registryFor = registries.registryFor } = {}) {
      const results = new Map();
      let todo = [...new Set(names)].map((name) => {
        const registry = registryFor(name);
        const dir = dirFor('packuments', registry);
        const base = path.join(dir, encodeURIComponent(name));
        return { name, url: registry + escapePackageName(name), dir, cache: base + '.json', etagFile: base + '.etag' };
      });
      for (let round = 0; round < 2 && todo.length; round++) {
        const requests = todo.map((t) => {
          const headers = { Accept: 'application/json' };
          let etag = null;
          if (round === 0) {
            try {
              etag = fs.readFileSync(t.etagFile, 'utf8').trim();
              if (!fs.existsSync(t.cache) || !/^[\x21-\x7e]{1,512}$/.test(etag)) etag = null;
            } catch { etag = null; }
          }
          if (etag) headers['If-None-Match'] = etag;
          t.tmp = path.join(t.dir, `.${encodeURIComponent(t.name)}.${process.pid}.${crypto.randomBytes(4).toString('hex')}.tmp`);
          return { url: t.url, headers, output: t.tmp };
        });
        const res = await many(requests);
        const again = [];
        res.forEach((r, k) => {
          const t = todo[k];
          try {
            if (r.status === 200) {
              const doc = readJson(t.tmp);
              const error = !isObj(doc) ? 'the answer is not a JSON object' : doc.name !== undefined && doc.name !== t.name ? `the answer is the packument of ${show(doc.name)}` : null;
              if (error) { results.set(t.name, { status: 200, url: t.url, error }); return; }
              fs.rmSync(t.etagFile, { force: true });
              fs.renameSync(t.tmp, t.cache);
              const etag = r.headers.etag;
              if (etag && /^[\x21-\x7e][\x20-\x7e]{0,511}$/.test(etag)) writeAtomicSync(t.etagFile, etag + '\n');
              results.set(t.name, { status: 200, url: t.url, fromCache: false, packument: pick ? pick(doc, t.name) : doc });
            } else if (r.status === 304) {
              const doc = readJson(t.cache);
              if (!isObj(doc)) { again.push(t); return; }
              results.set(t.name, { status: 200, url: t.url, fromCache: true, packument: pick ? pick(doc, t.name) : doc });
            } else if (r.status === 404) {
              results.set(t.name, { status: 404, url: t.url });
            } else {
              results.set(t.name, { status: r.status, url: t.url, error: r.error });
            }
          } finally {
            fs.rmSync(t.tmp, { force: true });
          }
        });
        todo = again;
      }
      for (const t of todo) results.set(t.name, { status: 0, url: t.url, error: 'the cached packument is unreadable' });
      return results;
    },
    /**
     * Attestation bundles (<registry>-/npm/v1/attestations/<name>@<version>),
     * cached by name@version (a 404 is not cached).
     * @param {Array<{name, version, registry?}>} items
     * @returns {Promise<Map<string, {status, url, attestations?, fromCache?, error?}>>} keyed by name@version
     */
    async getAttestations(items) {
      const results = new Map();
      const todo = [];
      const seen = new Set();
      for (const it of items) {
        const key = `${it.name}@${it.version}`;
        if (seen.has(key)) continue;
        seen.add(key);
        if (typeof it.version !== 'string' || !VERSION_RE.test(it.version)) throw new Error(`Not a version: ${show(it.version)}.`);
        const registry = it.registry ?? registries.registryFor(it.name);
        const url = client.attestationUrl(it.name, it.version, registry);
        const cache = path.join(dirFor('attestations', registry), `${encodeURIComponent(it.name)}@${encodeURIComponent(it.version)}.json`);
        const doc = readJson(cache);
        if (isObj(doc) && Array.isArray(doc.attestations)) results.set(key, { status: 200, url, fromCache: true, attestations: doc.attestations });
        else todo.push({ key, url, cache });
      }
      const res = await many(todo.map((t) => ({ url: t.url, headers: { Accept: 'application/json' } })));
      res.forEach((r, k) => {
        const t = todo[k];
        if (r.status === 200) {
          const doc = readJson(r.file);
          if (!isObj(doc) || !Array.isArray(doc.attestations)) { results.set(t.key, { status: 200, url: t.url, error: 'the answer has no attestations array' }); return; }
          try { writeAtomicSync(t.cache, JSON.stringify(doc)); } catch { /* not cached */ }
          results.set(t.key, { status: 200, url: t.url, fromCache: false, attestations: doc.attestations });
        } else if (r.status === 404) results.set(t.key, { status: 404, url: t.url });
        else results.set(t.key, { status: r.status, url: t.url, error: r.error });
        fs.rmSync(r.file, { force: true });
      });
      return results;
    },
  };
  return client;
}

// ---------------------------------------------------------------------------
// Reports
// ---------------------------------------------------------------------------

/**
 * The SHA-256 of a buffer or string, in hex.
 * @param {Buffer|string} data
 */
export function sha256(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/** The SHA-256 of a file, in hex, or null when it can't be read. */
export function sha256File(file) {
  try { return sha256(fs.readFileSync(file)); } catch { return null; }
}

/**
 * Writes a file atomically: a temporary file in the same directory, then a
 * rename, so a reader never sees half a report.
 * @param {string} file
 * @param {string|Buffer} data
 */
export function writeFileAtomic(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  writeAtomicSync(file, data);
}

/**
 * The report files of a run: <name>.json, .sarif, .run-record.json and
 * junit/<name>.xml in DIR.
 * @param {string} outputDir
 * @param {string} reportName
 */
export function reportPaths(outputDir, reportName) {
  return {
    json: path.join(outputDir, `${reportName}.json`),
    sarif: path.join(outputDir, `${reportName}.sarif`),
    junit: path.join(outputDir, 'junit', `${reportName}.xml`),
    record: path.join(outputDir, `${reportName}.run-record.json`),
  };
}

/**
 * Removes the reports an earlier run with the same report_name left, so none
 * is ever stored as this run's.
 * @param {string} outputDir
 * @param {string} reportName
 */
export function clearReports(outputDir, reportName) {
  for (const p of Object.values(reportPaths(outputDir, reportName))) {
    try { fs.unlinkSync(p); } catch (e) {
      if (e.code !== 'ENOENT') throw new Error(`Could not remove the earlier report ${p}: ${e.code ?? e.message}.`);
    }
  }
}

/**
 * Escapes text for XML: & < > " ', and characters XML can't hold become U+FFFD.
 * @param {*} value
 */
export function xmlEscape(value) {
  return String(value ?? '')
    // eslint-disable-next-line no-control-regex
    .replace(/[\0-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '\ufffd')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&apos;');
}

/**
 * The SARIF 2.1.0 log: a rule per finding rule (description from RULES or a
 * finding's ruleDescription; security-severity, a string, from its
 * securitySeverity) and a result per finding with a lockfile, at its line.
 */
export function buildSarif(command, findings, { rules = {} } = {}) {
  const located = findings.filter((f) => f.lockfile);
  const ruleIds = [...new Set(located.map((f) => f.rule))];
  const sarifRules = ruleIds.map((id) => {
    const r = rules[id] ?? {};
    const sample = located.find((f) => f.rule === id);
    const severity = sample.securitySeverity ?? r.securitySeverity;
    const rule = {
      id,
      name: id,
      shortDescription: { text: r.description ?? sample.ruleDescription ?? id },
      properties: { tags: ['security', 'supply-chain', ...(r.tags ?? [])] },
    };
    if (r.helpUri) rule.helpUri = r.helpUri;
    if (severity !== undefined && severity !== null) rule.properties['security-severity'] = String(severity);
    return rule;
  });
  const uri = (rel) => rel.split('/').map((seg) => (seg === '..' || seg === '.' ? seg : encodeURIComponent(seg))).join('/');
  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: { driver: { name: `js-security-orb ${command}`, informationUri: INFORMATION_URI, rules: sarifRules } },
      results: located.map((f) => ({
        ruleId: f.rule,
        level: f.level,
        message: { text: f.message },
        locations: [{ physicalLocation: { artifactLocation: { uri: uri(f.lockfile) }, region: { startLine: f.line ?? 1 } } }],
        partialFingerprints: {
          primaryLocationLineHash: f.package ? `${f.rule}:${f.package.name}@${f.package.version ?? ''}` : `${f.rule}:${f.message}`,
        },
      })),
    }],
  };
}

/**
 * The JUnit XML: a failure per level 'error' finding, a skipped case per
 * finding below the gate, an error case per error, else one passing case.
 */
export function buildJunit(command, findings, errors = []) {
  const cases = [];
  const where = (f) => `${f.lockfile ?? command}${f.line ? ':' + f.line : ''}`;
  for (const f of findings) {
    const pkg = f.package ? ` ${f.package.name}${f.package.version ? '@' + f.package.version : ''}` : '';
    const name = `${where(f)}:${pkg} ${f.rule}`;
    const body = f.level === 'error'
      ? `<failure message="${xmlEscape(f.message)}" type="${xmlEscape(f.rule)}">${xmlEscape(f.message)}</failure>`
      : `<skipped message="${xmlEscape(`${f.level}: ${f.message}`)}"/>`;
    cases.push({ name, body, kind: f.level === 'error' ? 'failure' : 'skipped' });
  }
  for (const e of errors) {
    cases.push({ name: `error: ${e.message.split('\n')[0].slice(0, 200)}`, body: `<error message="${xmlEscape(e.message)}">${xmlEscape(e.message)}</error>`, kind: 'error' });
  }
  if (!cases.length) cases.push({ name: 'no findings', body: '', kind: 'passed' });
  const count = (k) => cases.filter((c) => c.kind === k).length;
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<testsuites>',
    `  <testsuite name="${xmlEscape(`js-security-orb ${command}`)}" tests="${cases.length}" failures="${count('failure')}" errors="${count('error')}" skipped="${count('skipped')}">`,
    ...cases.map((c) => `    <testcase classname="${xmlEscape(command)}" name="${xmlEscape(c.name)}">${c.body}</testcase>`),
    '  </testsuite>',
    '</testsuites>',
    '',
  ].join('\n');
}

/**
 * Describes the CI job this runs in, for run records: a CircleCI job or a
 * GitHub Actions run, or null.
 * @param {Record<string, string|undefined>} [env]
 */
export function ciJson(env = process.env) {
  if (env.CIRCLE_BUILD_URL) {
    return {
      provider: 'circleci', build_url: env.CIRCLE_BUILD_URL, sha1: env.CIRCLE_SHA1 ?? '', job: env.CIRCLE_JOB ?? '',
      repository: [env.CIRCLE_PROJECT_USERNAME, env.CIRCLE_PROJECT_REPONAME].filter(Boolean).join('/'),
    };
  }
  if (env.GITHUB_ACTIONS === 'true') {
    return {
      provider: 'github-actions',
      build_url: `${env.GITHUB_SERVER_URL ?? 'https://github.com'}/${env.GITHUB_REPOSITORY ?? ''}/actions/runs/${env.GITHUB_RUN_ID ?? ''}/attempts/${env.GITHUB_RUN_ATTEMPT ?? '1'}`,
      sha1: env.GITHUB_SHA ?? '', job: env.GITHUB_JOB ?? '', repository: env.GITHUB_REPOSITORY ?? '',
    };
  }
  return null;
}

/**
 * A finding for ENTRY (or null). rule defaults to '<command-with-dashes>/<kind>',
 * level to 'error', which fails the gate; 'warning' and 'note' don't.
 * @param {{kind, message, rule?, level?, details?, securitySeverity?, ruleDescription?}} fields
 */
export function makeFinding(command, entry, fields) {
  const f = {
    kind: fields.kind,
    rule: fields.rule ?? `${command.replace(/_/g, '-')}/${fields.kind}`,
    level: fields.level ?? 'error',
    message: fields.message,
    package: entry ? { name: entry.name, version: entry.version ?? null } : null,
    lockfile: fields.lockfile ?? entry?.lockfile ?? null,
    line: fields.line ?? entry?.line ?? null,
    details: fields.details ?? {},
  };
  if (fields.securitySeverity !== undefined) f.securitySeverity = String(fields.securitySeverity);
  if (fields.ruleDescription !== undefined) f.ruleDescription = fields.ruleDescription;
  return f;
}

/**
 * Writes <name>.json, <name>.sarif, junit/<name>.xml (junit) and
 * <name>.run-record.json (runRecord), atomically. main() calls it.
 * @param {object} ctx the context
 * @param {object} data the run's result, with outcome and exitCode
 * @returns {string[]} the files written
 */
export function writeReports(ctx, data) {
  const paths = reportPaths(ctx.outputDir, ctx.reportName);
  const written = [];
  const lockfiles = (ctx.lockfileSet?.lockfiles ?? []).map((l) => ({ path: l.rel, format: l.format, format_version: l.formatVersion, sha256: l.sha256, entries: l.entries }));
  const json = {
    schema: `js-security-orb/${ctx.command}/v1`,
    tool: { name: 'js-security-orb', command: ctx.command, node: process.version },
    outcome: data.outcome,
    lockfiles,
    summary: data.summary ?? data.counts ?? {},
    findings: data.findings,
    errors: data.errors,
    warnings: data.warnings,
    skipped: data.skipped ?? [],
  };
  if (data.results) json.results = data.results;
  writeFileAtomic(paths.json, JSON.stringify(json, null, 2) + '\n');
  written.push(paths.json);
  writeFileAtomic(paths.sarif, JSON.stringify(buildSarif(ctx.command, data.findings, { rules: data.rules }), null, 2) + '\n');
  written.push(paths.sarif);
  if (ctx.junit) {
    writeFileAtomic(paths.junit, buildJunit(ctx.command, data.findings, data.errors));
    written.push(paths.junit);
  }
  if (ctx.runRecord) {
    const inputs = lockfiles.map((l, i) => ({ role: 'lockfile', path: l.path, sha256: l.sha256, format: l.format, format_version: l.format_version, entries: ctx.lockfileSet.lockfiles[i].entries }));
    if (ctx.registries?.npmrc) inputs.push({ role: 'npmrc', path: relPath(ctx.top, ctx.registries.npmrc), sha256: sha256File(ctx.registries.npmrc) });
    const record = {
      schema: RUN_RECORD_SCHEMA,
      command: ctx.command,
      outcome: data.outcome,
      exit_code: data.exitCode,
      started_at: ctx.startedAt.toISOString(),
      finished_at: new Date().toISOString(),
      ci: ciJson(ctx.env),
      working_directory: ctx.cwd,
      checkout_top: ctx.top,
      node: { path: process.execPath, version: process.version },
      parameters: { ...ctx.params.used },
      registry: ctx.registries ? {
        url: ctx.registries.registry,
        scopes: Object.fromEntries(ctx.registries.scopes),
        token_variable: ctx.tokenVar || null,
      } : null,
      inputs,
      counts: data.counts ?? null,
      results: data.results ?? null,
      reports: written.map((p) => ({ path: p, sha256: sha256File(p) })),
    };
    writeFileAtomic(paths.record, JSON.stringify(record, null, 2) + '\n');
    written.push(paths.record);
  }
  return written;
}

// ---------------------------------------------------------------------------
// The command context and main()
// ---------------------------------------------------------------------------

/**
 * The context of a command (main() makes it): checks output_dir and
 * report_name, removes the earlier run's reports, then reads the other common
 * parameters (UsageError if bad). It holds command, cwd, top, env, io,
 * startedAt; the readers str/bool/int/list/lines/choice/envVarName/patterns for
 * the command's own parameters; outputDir, reportName, junit, runRecord,
 * reportOnly, allowEmpty, includeDev, lockfilePatterns, concurrency, timeout,
 * registries, tokenVar, workDir; readLockfiles() (cached as lockfileSet);
 * client, the registry client; and finding(entry, fields).
 */
export function createContext(command, { env = process.env, cwd = process.cwd(), io = createIO(), startedAt = new Date() } = {}) {
  const params = createParams(env);
  const ctx = { command, env, io, startedAt, params, cwd: path.resolve(cwd), reportsReady: false };
  ctx.outputDir = checkOutputDir(params.str('output_dir', '/tmp/js-security-reports'));
  ctx.reportName = checkReportName(params.str('report_name', command));
  try { fs.mkdirSync(ctx.outputDir, { recursive: true }); } catch (e) {
    throw new UsageError(`Could not create output_dir ${ctx.outputDir}: ${e.code ?? e.message}.`);
  }
  clearReports(ctx.outputDir, ctx.reportName);
  ctx.reportsReady = true;
  ctx.top = findCheckoutTop(ctx.cwd);
  ctx.junit = params.bool('junit', true);
  ctx.runRecord = params.bool('run_record', false);
  ctx.reportOnly = params.bool('report_only', false);
  ctx.allowEmpty = params.bool('allow_empty', false);
  ctx.includeDev = params.bool('include_dev', true);
  ctx.lockfilePatterns = params.list('lockfiles', '');
  ctx.concurrency = params.int('concurrency', 16, { min: 1, max: 256 });
  ctx.timeout = params.int('timeout', 60, { min: 1, max: 3600 });
  ctx.tokenVar = params.envVarName('token', '');
  ctx.registries = registryConfig({ registry: params.str('registry', DEFAULT_REGISTRY) || DEFAULT_REGISTRY, scopes: params.lines('scopes', ''), cwd: ctx.cwd });
  let token = null;
  if (ctx.tokenVar) {
    token = env[ctx.tokenVar] ?? '';
    if (!token) throw new UsageError(`token names ${ctx.tokenVar}, which is not set or empty.`);
    if (/[\0\r\n]/.test(token)) throw new UsageError(`${ctx.tokenVar} holds a line break, which no registry token does.`);
  }
  const work = env.JS_SECURITY_WORK;
  if (work && path.isAbsolute(work) && fs.existsSync(work)) ctx.workDir = work;
  else {
    ctx.workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'js-security-'));
    ctx.ownWorkDir = true;
  }
  let client = null;
  // Only the helper's tests set JS_SECURITY_TEST_RETRIES (0 to 3), so a 5xx
  // doesn't wait for curl's backoff (1 + 2 + 4 s).
  const retries = /^[0-3]$/.test(env.JS_SECURITY_TEST_RETRIES ?? '') ? +env.JS_SECURITY_TEST_RETRIES : 3;
  Object.defineProperty(ctx, 'client', {
    enumerable: false,
    get() {
      client ??= createRegistryClient({ registries: ctx.registries, token, concurrency: ctx.concurrency, timeout: ctx.timeout, retries, workDir: ctx.workDir, io, env });
      return client;
    },
  });
  const p = params;
  Object.assign(ctx, {
    str: p.str, bool: p.bool, int: p.int, list: p.list, lines: p.lines, choice: p.choice, envVarName: p.envVarName,
    /** A list parameter of package patterns, compiled (see compilePattern). */
    patterns(name, def = '', { versions = false } = {}) {
      return p.list(name, def).map((t) => compilePattern(t, { versions, param: name }));
    },
    readLockfiles() {
      ctx.lockfileSet ??= readLockfiles({ cwd: ctx.cwd, lockfilePatterns: ctx.lockfilePatterns, includeDev: ctx.includeDev, allowEmpty: ctx.allowEmpty, registries: ctx.registries });
      return ctx.lockfileSet;
    },
    finding(entry, fields) { return makeFinding(command, entry, fields); },
  });
  return ctx;
}

function normalizeError(e) {
  if (typeof e === 'string') return { message: e };
  if (e instanceof Error) return { message: e.message };
  if (isObj(e) && typeof e.message === 'string') return e;
  return { message: String(e) };
}

function checkFindings(findings) {
  for (const f of findings) {
    if (!isObj(f) || typeof f.rule !== 'string' || typeof f.message !== 'string' || !['error', 'warning', 'note'].includes(f.level)) {
      throw new Error(`Internal error: a malformed finding ${show(f)}.`);
    }
  }
}

function finish(ctx, result) {
  const { io } = ctx;
  const findings = result.findings ?? [];
  checkFindings(findings);
  const errors = (result.errors ?? []).map(normalizeError);
  const warnings = [...(ctx.registries?.warnings ?? []), ...(ctx.lockfileSet?.warnings ?? []), ...(result.warnings ?? [])].map(String);
  if (typeof result.checked === 'number' && result.checked === 0 && !ctx.allowEmpty && !errors.length) {
    errors.push({ message: 'There was nothing to check, so the check checked nothing. Check lockfiles and include_dev, or set allow_empty to true.' });
  }
  const failing = findings.filter((f) => f.level === 'error');
  const outcome = errors.length ? 'error' : failing.length ? (ctx.reportOnly ? 'findings-reported' : 'findings') : 'passed';
  const exitCode = outcome === 'error' || outcome === 'findings' ? 1 : 0;
  const byRule = {};
  for (const f of findings) byRule[f.rule] = (byRule[f.rule] ?? 0) + 1;
  const counts = {
    lockfiles: ctx.lockfileSet?.lockfiles.length ?? 0,
    entries: ctx.lockfileSet?.entries.length ?? 0,
    findings: findings.length,
    failing: failing.length,
    errors: errors.length,
    by_rule: byRule,
    ...(result.counts ?? {}),
  };
  if (findings.length) {
    io.log('Findings:');
    for (const f of findings) {
      const loc = f.lockfile ? `${f.lockfile}:${f.line ?? 1}: ` : '';
      io.log(`  ${loc}${f.rule}: ${f.message}${f.level === 'error' ? '' : ` (${f.level}, does not fail the step)`}`);
    }
  }
  for (const w of warnings) io.warn(w);
  writeReports(ctx, { ...result, findings, errors, warnings, counts, outcome, exitCode });
  const where = `The reports are in ${ctx.outputDir}.`;
  if (errors.length) {
    for (const e of errors) io.error(e.message);
    io.error(`There is no verdict, so this step fails whatever report_only says. ${where}`);
  } else if (failing.length) {
    const msg = `${plural(failing.length, 'finding')} of ${ctx.command} ${failing.length === 1 ? 'fails' : 'fail'} the gate.`;
    if (ctx.reportOnly) {
      io.warn(msg);
      io.warn(`report_only is true, so this step passes. ${where}`);
    } else {
      io.error(msg);
      io.error(`${where} Set report_only to true to report findings without failing.`);
    }
  } else {
    io.log(`Passed: ${ctx.command} found ${findings.length ? plural(findings.length, 'finding') + ', none failing the gate' : 'nothing'}. ${where}`);
  }
  return exitCode;
}

/**
 * Runs a command and returns its exit code (main() without the exit, for
 * tests). RUN(ctx) returns {findings, errors, warnings, skipped, summary,
 * results, counts, rules, checked}: level 'error' findings fail the gate
 * unless report_only; errors (strings or {message}) mean no verdict (exit 1);
 * checked 0 is an error unless allow_empty; summary goes to the JSON report,
 * counts (merged with the core's) to the run record, rules ({id: {description,
 * helpUri, tags}}) to SARIF. A UsageError exits 2; any other exception exits
 * 1, with the reports written.
 * @returns {Promise<number>}
 */
export async function runCommand(command, run, { env = process.env, cwd = process.cwd(), stdout, stderr } = {}) {
  const io = createIO({ stdout, stderr });
  let ctx = null;
  const cleanup = () => { if (ctx?.ownWorkDir) fs.rmSync(ctx.workDir, { recursive: true, force: true }); };
  try {
    ctx = createContext(command, { env, cwd, io, startedAt: new Date() });
    const result = (await run(ctx)) ?? {};
    return finish(ctx, result);
  } catch (e) {
    if (e instanceof UsageError) {
      io.error(e.message);
      return 2;
    }
    io.error(e instanceof Error ? e.message : String(e));
    if (env.JS_SECURITY_DEBUG && e instanceof Error && e.stack) io.error(e.stack);
    if (ctx?.reportsReady) {
      try {
        writeReports(ctx, { findings: [], warnings: [], errors: [normalizeError(e)], outcome: 'error', exitCode: 1, counts: { errors: 1 } });
      } catch (e2) {
        io.warn(`Could not write the reports: ${e2.message}`);
      }
    }
    io.error('There is no verdict, so this step fails.');
    return 1;
  } finally {
    cleanup();
  }
}

/**
 * The entry point of a command module: runs the command and sets the
 * process's exit code (see runCommand).
 * @param {string} command
 * @param {(ctx: object) => Promise<object>|object} run
 */
export async function main(command, run) {
  process.exitCode = await runCommand(command, run);
}

/**
 * Whether the module whose import.meta.url is given is the program (node
 * helper/<cmd>.mjs), not one a test imported: a command runs main() only then.
 * @param {string} importMetaUrl
 */
export function isMain(importMetaUrl) {
  try { return !!process.argv[1] && fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(importMetaUrl)); } catch { return false; }
}
