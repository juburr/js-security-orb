// registries.mjs: the registry configuration of js-security-orb's Node.js helper (Node >= 22,
// standard library only). core.mjs imports it and re-exports what the commands use
// (registryConfig, metadataRegistry, unauthorizedSkip, authHint), so a command module imports
// them from './core.mjs' as before.
//
// Where a package's metadata comes from:
// - registry (the parameter) for every package whose scope maps nowhere else. Any registry
//   setting the job or the checkout makes (registry= in an npmrc, npmRegistryServer in
//   .yarnrc.yml, npm_config_registry) must be that registry: one that differs is a usage error,
//   since the packages a lockfile records no registry for would otherwise be looked up on
//   registry, sending their names there.
// - Scope registries, from the scopes parameter (which wins), working_dir/.npmrc,
//   working_dir/.yarnrc.yml (npmScopes.<scope>.npmRegistryServer) and the user's npmrc
//   (NPM_CONFIG_USERCONFIG or npm_config_userconfig, else ~/.npmrc), in that order of
//   precedence, as npm and pnpm put the project's .npmrc over the user's. Only registry
//   settings are read, never credentials. ${VAR} is expanded as npm (${VAR?}), pnpm (${VAR-x},
//   ${VAR:-x}) and Yarn (${VAR:-x}, nested) expand it. A scope whose registry can't be resolved
//   (an unset variable, a value that isn't a registry URL) maps to no registry: its packages are
//   skipped with a warning naming the file and line, and their names are never sent anywhere.
// - The scopes parameter and the user's npmrc are the job's configuration (trusted, as
//   lock_verify's default allowed_registries counts them); the project's .npmrc and
//   .yarnrc.yml are the checkout's, which the change under test can edit: they route lookups,
//   but allow nothing.
// - A file this reader can't read exactly for those settings is a usage error naming the file
//   and line, rather than a guess.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { UsageError, LockfileError, DEFAULT_REGISTRY, normalizeRegistryUrl, publicUrl, scopeOf, show, parseYamlSubset, lineOf } from './core.mjs';

const SCOPE_RE = /^@[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
// yarn's alias of the public registry is the public registry.
const canonical = (url) => url.replace(/^https:\/\/registry\.yarnpkg\.com\//, DEFAULT_REGISTRY);
// How a setting is shown: as written, without credentials, query or fragment (a ${VAR} stays
// unexpanded, so nothing a variable holds reaches a message).
const shown = (raw) => show(publicUrl(String(raw)));
// Expanded values at least this long are kept out of messages and reports (redact).
const SECRET_MIN = 8;

// ---------------------------------------------------------------------------
// ${VAR} expansion
// ---------------------------------------------------------------------------

/**
 * Expands ${VAR} in an npmrc value or key, as npm (${VAR}, ${VAR?} for empty when unset) and
 * pnpm (${VAR-default}, ${VAR:-default}) do; a backslash escapes a reference.
 * @param {string} text
 * @param {Record<string, string|undefined>} env
 * @returns {{value: string|null, missing: string|null, used: Array<[string, string]>}} value null
 *   when a reference can't be resolved (missing names it); used holds [value, reference] pairs
 */
export function expandNpmrcEnv(text, env) {
  let missing = null;
  const used = [];
  const lookup = (name) => (own(env, name) && typeof env[name] === 'string' ? env[name] : undefined);
  const value = String(text).replace(/(?<!\\)(\\*)\$\{([^${}]+)\}/g, (orig, esc, body) => {
    if (esc.length % 2) return orig.slice((esc.length + 1) / 2);
    const half = esc.slice(esc.length / 2);
    let val;
    if (body.endsWith('?')) val = lookup(body.slice(0, -1)) ?? '';
    else {
      let name = body;
      let fallback;
      let onEmpty = false;
      const d = body.indexOf('-');
      if (d > 0) {
        const colon = body[d - 1] === ':';
        const vn = body.slice(0, colon ? d - 1 : d);
        if (vn && !vn.includes(':') && body.length > d + 1) [name, fallback, onEmpty] = [vn, body.slice(d + 1), colon];
      }
      const v = lookup(name);
      val = v === undefined || (onEmpty && v === '') ? fallback : v;
    }
    if (val === undefined) {
      missing ??= orig;
      return orig;
    }
    if (val) used.push([val, orig]);
    return half + val;
  });
  return { value: missing ? null : value, missing, used };
}

/**
 * Expands ${VAR}, ${VAR:-default} and ${VAR-default} (defaults may nest references) in a
 * .yarnrc.yml value, as Yarn 4 does; \\, \$ and \} escape.
 * @returns {{value: string|null, missing: string|null, used: Array<[string, string]>}}
 */
export function expandYarnEnv(text, env) {
  const t = String(text);
  const used = [];
  const fail = (why) => ({ value: null, missing: why, used });
  const re = /\\(?<escaped>[\\$}])|\$\{(?<variable>[a-zA-Z]\w*)(?<operator>:-|-|(?=\}))|(?<unknown>\$\{)|\}/g;
  const matches = [...t.matchAll(re)];
  let out = '';
  let last = 0;
  let depth = 0;
  for (let k = 0; k < matches.length; k++) {
    const m = matches[k];
    const { escaped, variable, operator, unknown } = m.groups;
    out += t.slice(last, m.index);
    last = m.index + m[0].length;
    if (escaped) out += escaped;
    else if (variable) {
      const v = own(env, variable) && typeof env[variable] === 'string' ? env[variable] : undefined;
      depth++;
      if ((operator === '' && v !== undefined) || (operator === ':-' && v) || (operator === '-' && v !== undefined)) {
        out += v;
        if (v) used.push([v, `\${${variable}}`]);
        // Skip the default, up to the } that closes this reference.
        const base = depth;
        for (k++; k < matches.length; k++) {
          if (matches[k].groups.variable) depth++;
          else if (matches[k][0] === '}' && --depth < base) break;
        }
        last = k < matches.length ? matches[k].index + 1 : t.length;
      } else if (operator === '') return fail(`\${${variable}}`);
    } else if (m[0] === '}') {
      if (depth === 0) out += '}';
      else depth--;
    } else if (unknown) return fail(show(t));
  }
  if (depth > 0) return fail(show(t));
  return { value: out + t.slice(last), missing: null, used };
}

// ---------------------------------------------------------------------------
// npmrc files, as npm's ini parser reads them
// ---------------------------------------------------------------------------

// ini's unsafe(): a quoted value is unquoted (and JSON-parsed); otherwise an unescaped ; or #
// ends it.
function iniUnsafe(raw) {
  let val = String(raw ?? '').trim();
  if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
    if (val[0] === "'") val = val.slice(1, -1);
    try { val = JSON.parse(val); } catch { /* as written */ }
    return val;
  }
  let esc = false;
  let out = '';
  for (const c of val) {
    if (esc) {
      out += '\\;#'.includes(c) ? c : '\\' + c;
      esc = false;
    } else if (c === ';' || c === '#') break;
    else if (c === '\\') esc = true;
    else out += c;
  }
  return (esc ? out + '\\' : out).trim();
}

/**
 * Reads the registry settings of an npmrc file, as npm reads them (the ini package's decode,
 * then ${VAR} expansion): registry= and @scope:registry= outside any [section], the last
 * occurrence winning. Every other line, credentials included, is ignored.
 * @param {string} file
 * @param {string} label how messages name the file
 * @param {Record<string, string|undefined>} env
 * @returns {null|{registry: object|null, scopes: Map<string, object>}} null when the file doesn't
 *   exist; each setting is {raw, value (null when it can't be resolved), missing, used, line}
 */
export function readNpmrc(file, label, env) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return null;
    throw new UsageError(`Could not read ${label}: ${e.code ?? e.message}.`);
  }
  const out = { registry: null, scopes: new Map() };
  let inSection = false;
  text.split('\n').forEach((full, i) => {
    for (const line of full.split('\r')) {
      if (!line || /^\s*[;#]/.test(line) || /^\s*$/.test(line)) continue;
      const m = /^\[([^\]]*)\]\s*$|^([^=]+)(=(.*))?$/i.exec(line);
      if (!m) continue;
      if (m[1] !== undefined) { inSection = true; continue; }
      if (inSection) continue;
      const where = `${label} line ${i + 1}`;
      let key = iniUnsafe(m[2]);
      if (typeof key !== 'string') continue;
      const isArray = key.length > 2 && key.endsWith('[]');
      if (isArray) key = key.slice(0, -2);
      if (key.includes('${')) {
        const k = expandNpmrcEnv(key, env);
        if (k.value === null) {
          if (/registry/i.test(key)) throw new UsageError(`${where}: the setting ${shown(key)} names ${k.missing}, which is not set, so this orb can't tell which registry it sets.`);
          continue;
        }
        key = k.value;
      }
      const scoped = /^(@[^:]+):registry$/.exec(key);
      if (key !== 'registry' && !scoped) continue;
      if (isArray) throw new UsageError(`${where}: ${key}[] makes a list, which no package manager reads as a registry, so this orb can't tell which registry it sets.`);
      if (scoped && !SCOPE_RE.test(scoped[1])) throw new UsageError(`${where}: ${show(scoped[1])} is not a package scope.`);
      const raw = m[3] ? iniUnsafe(m[4]) : true;
      const setting = typeof raw === 'string' ? { raw, ...expandNpmrcEnv(raw, env), line: i + 1, where }
        : { raw: String(raw), value: null, missing: null, used: [], line: i + 1, where };
      if (scoped) out.scopes.set(scoped[1], setting);
      else out.registry = setting;
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// .yarnrc.yml
// ---------------------------------------------------------------------------

const YARN_KEYS = new Set(['npmRegistryServer', 'npmScopes']);

// A line of a block this reader parses, without a comment after its value.
function stripYamlComment(line) {
  let q = null;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (q === '"') {
      if (c === '\\') i++;
      else if (c === '"') q = null;
    } else if (q === "'") {
      if (c === "'") q = null;
    } else if ((c === '"' || c === "'") && (i === 0 || /[\s:[{,-]/.test(line[i - 1]))) q = c;
    else if (c === '#' && (i === 0 || /\s/.test(line[i - 1]))) return line.slice(0, i).trimEnd();
  }
  return line;
}

/**
 * Reads npmRegistryServer and npmScopes.<scope>.npmRegistryServer from a .yarnrc.yml. Only
 * those two top-level keys are parsed (with core's YAML subset, after comments are removed);
 * any other top-level key is skipped with its block. A top-level line that is not a plain
 * key, or one of those keys in a form the subset can't read, is a UsageError.
 * @returns {null|{registry: object|null, scopes: Map<string, object>, warnings: string[]}}
 */
export function readYarnrc(file, label, env) {
  let text;
  try { text = fs.readFileSync(file, 'utf8'); } catch (e) {
    if (e.code === 'ENOENT' || e.code === 'ENOTDIR') return null;
    throw new UsageError(`Could not read ${label}: ${e.code ?? e.message}.`);
  }
  const unreadable = (line, why) => new UsageError(`${label} line ${line}: ${why}, so this orb can't read which registries Yarn uses from it. Write npmRegistryServer and npmScopes as plain block mappings, or set registry and scopes instead.`);
  const lines = text.replace(/^﻿/, '').split(/\r?\n/);
  const blocks = new Map();
  let current = null;
  let content = false;
  lines.forEach((line, i) => {
    if (/^\s*(?:#.*)?$/.test(line)) return;
    if (/^[ \t]/.test(line)) {
      if (!current) throw unreadable(i + 1, 'an indented line comes before any key');
      if (current.ours) current.lines.push([i, line]);
      return;
    }
    if (line === '---' && !content) return;
    content = true;
    const k = /^(?:([A-Za-z_][\w.-]*)|"([\w.-]+)"|'([\w.-]+)')[ \t]*:(?:[ \t]|$)/.exec(line);
    if (!k) throw unreadable(i + 1, 'this top-level line is not a plain key');
    const key = k[1] ?? k[2] ?? k[3];
    if (YARN_KEYS.has(key)) {
      if (blocks.has(key)) throw unreadable(i + 1, `${key} is set twice`);
      current = { ours: true, lines: [[i, line]] };
      blocks.set(key, current);
    } else current = { ours: false };
  });
  const parse = (key) => {
    const b = blocks.get(key);
    if (!b) return undefined;
    // The block's lines at their own line numbers, every other line blank.
    const arr = Array.from({ length: b.lines[b.lines.length - 1][0] + 1 }, () => '');
    for (const [i, l] of b.lines) {
      arr[i] = stripYamlComment(l);
      if (/:\s*[|>]/.test(arr[i])) throw unreadable(i + 1, 'a block scalar');
    }
    const src = arr.join('\n');
    try {
      const docs = parseYamlSubset(src, label);
      return { doc: docs[docs.length - 1] };
    } catch (e) {
      if (e instanceof LockfileError) throw unreadable(e.line, e.message.slice(e.message.indexOf(': ', label.length) + 2));
      throw e;
    }
  };
  const out = { registry: null, scopes: new Map(), warnings: [] };
  const setting = (raw, line) => ({ raw, ...expandYarnEnv(raw, env), line, where: `${label} line ${line}` });
  const server = parse('npmRegistryServer');
  if (server) {
    const v = server.doc.npmRegistryServer;
    const line = lineOf(server.doc, 'npmRegistryServer');
    if (typeof v === 'string') out.registry = setting(v, line);
    else if (v !== null) throw unreadable(line, 'npmRegistryServer is not a string');
  }
  const scopes = parse('npmScopes');
  if (scopes) {
    const map = scopes.doc.npmScopes;
    const line = lineOf(scopes.doc, 'npmScopes');
    if (map !== null && !isObj(map)) throw unreadable(line, 'npmScopes is not a mapping');
    for (const name of Object.keys(map ?? {})) {
      const sline = lineOf(map, name);
      const s = map[name];
      if (s !== null && !isObj(s)) throw unreadable(sline, `npmScopes.${name} is not a mapping`);
      if (!s || !own(s, 'npmRegistryServer') || s.npmRegistryServer === null) continue;
      if (typeof s.npmRegistryServer !== 'string') throw unreadable(lineOf(s, 'npmRegistryServer'), `npmScopes.${name}.npmRegistryServer is not a string`);
      if (name.startsWith('@')) {
        out.warnings.push(`${label} line ${sline}: Yarn names npmScopes without the @, so it never uses the settings of ${show(name)}; neither does this orb.`);
        continue;
      }
      if (!SCOPE_RE.test('@' + name)) throw unreadable(sline, `${show(name)} is not a package scope`);
      out.scopes.set('@' + name, setting(s.npmRegistryServer, lineOf(s, 'npmRegistryServer')));
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The configuration
// ---------------------------------------------------------------------------

/**
 * The registry configuration (see the top of this file). UsageError for a bad parameter, a
 * registry setting that differs from registry, or a file it can't read exactly.
 * @param {{registry?: string, scopes?: string[], cwd?: string, npmrc?: boolean, env?: object}} [options]
 *   npmrc false reads no file and no environment variable (the parameters only)
 * @returns {{registry, scopes: Map, trusted: string[], routes: Map, files: {role, path}[], npmrc,
 *   warnings, registryFor: (name) => string|null, unresolvedReason: (name) => string|null,
 *   configuredBy: (url) => object[], redact: (text) => string}}
 */
export function registryConfig({ registry = DEFAULT_REGISTRY, scopes = [], cwd = process.cwd(), npmrc = true, env = process.env } = {}) {
  const reg = normalizeRegistryUrl(registry || DEFAULT_REGISTRY, 'registry');
  const warnings = [];
  const files = [];
  const routes = new Map(); // scope -> {url|null, where, raw, why, trusted, used}
  const trusted = new Set([canonical(reg)]);
  const settings = [];
  // A registry setting must be registry.
  const checkRegistry = (s, name) => {
    let url = null;
    if (s.value !== null) try { url = canonical(normalizeRegistryUrl(s.value, name)); } catch { url = null; }
    if (url === canonical(reg)) return;
    const text = publicUrl(s.raw).slice(0, 200);
    const why = s.value === null ? (s.missing ? `, which can't be resolved (${s.missing} is not set)` : ', which is not a URL') : url ? '' : ', which is not an https registry URL';
    throw new UsageError(`${s.where} sets ${name}${name === 'registry' ? '=' : ': '}${text}${why}, but registry is ${reg}: packages the lockfiles record no registry for would be looked up on ${reg}, sending their names there. `
      + `Set registry to ${text} (and token, if it needs one).`);
  };
  const route = (scope, s, isTrusted) => {
    let url = null;
    let why = null;
    if (s.value === null) why = s.missing ? `${s.missing} is not set` : 'it is not a URL';
    else {
      try { url = normalizeRegistryUrl(s.value, scope); } catch { why = 'it is not an https registry URL without credentials, a query or a fragment'; }
    }
    routes.set(scope, { url, where: s.where, raw: s.raw, why, trusted: isTrusted, used: s.used ?? [] });
    if (url && isTrusted) trusted.add(canonical(url));
  };
  if (npmrc) {
    const projectNpmrc = path.join(cwd, '.npmrc');
    const real = (p) => { try { return fs.realpathSync(p); } catch { return path.resolve(p); } };
    // Lowest precedence first: the user's npmrc, then the project's .yarnrc.yml and .npmrc.
    let users = [...new Set([env.npm_config_userconfig, env.NPM_CONFIG_USERCONFIG].filter((v) => typeof v === 'string' && v))].map((p) => path.resolve(cwd, p));
    if (!users.length) users = [path.join(env.HOME || os.homedir(), '.npmrc')];
    for (const file of users) {
      // A user npmrc that is the project's .npmrc is the checkout's, read below.
      const r = real(file) === real(projectNpmrc) ? null : readNpmrc(file, file, env);
      if (!r) continue;
      files.push({ role: 'user-npmrc', path: file });
      if (r.registry) settings.push([r.registry, 'registry']);
      for (const [scope, s] of r.scopes) route(scope, s, true);
    }
    const yarnrc = readYarnrc(path.join(cwd, '.yarnrc.yml'), '.yarnrc.yml', env);
    if (yarnrc) {
      files.push({ role: 'yarnrc', path: path.join(cwd, '.yarnrc.yml') });
      warnings.push(...yarnrc.warnings);
      if (yarnrc.registry) settings.push([yarnrc.registry, 'npmRegistryServer']);
      for (const [scope, s] of yarnrc.scopes) route(scope, s, false);
    }
    const project = readNpmrc(projectNpmrc, '.npmrc', env);
    if (project) {
      files.push({ role: 'npmrc', path: projectNpmrc });
      if (project.registry) settings.push([project.registry, 'registry']);
      for (const [scope, s] of project.scopes) route(scope, s, false);
    }
    for (const name of ['npm_config_registry', 'NPM_CONFIG_REGISTRY']) {
      // npm ignores an empty npm_config_ variable.
      if (typeof env[name] === 'string' && env[name]) settings.push([{ raw: env[name], ...expandNpmrcEnv(env[name], env), where: `The environment variable ${name}` }, 'registry']);
    }
    for (const [s, name] of settings) checkRegistry(s, name);
  }
  for (const line of scopes) {
    const m = /^(@[^\s:=]+)(?::registry)?\s*=\s*(\S+)$/.exec(line.trim());
    if (!m) throw new UsageError(`scopes takes lines @scope=URL, not ${show(line)}.`);
    if (!SCOPE_RE.test(m[1])) throw new UsageError(`scopes: ${show(m[1])} is not a package scope.`);
    const url = normalizeRegistryUrl(m[2], `the registry of ${m[1]} (scopes)`);
    routes.set(m[1], { url, where: 'scopes', raw: m[2], why: null, trusted: true, used: [] });
    trusted.add(canonical(url));
  }
  const map = new Map();
  const secrets = new Map();
  for (const [scope, r] of routes) {
    if (r.url) {
      map.set(scope, r.url);
      for (const [value, ref] of r.used) if (value.length >= SECRET_MIN && !secrets.has(value)) secrets.set(value, ref);
    } else {
      warnings.push(`${r.where}: the registry of ${scope} is ${shown(r.raw)}, which can't be resolved (${r.why}), so packages of ${scope} are looked up on no registry, and their names are never sent anywhere: they are listed as not checked.`);
    }
  }
  // The longest values first, so one that holds another is replaced whole.
  const redactions = [...secrets].sort((a, b) => b[0].length - a[0].length);
  return {
    registry: reg,
    scopes: map,
    trusted: [...trusted],
    routes,
    files,
    npmrc: files.find((f) => f.role === 'npmrc')?.path ?? null,
    warnings,
    registryFor(name) {
      const r = routes.get(scopeOf(name));
      return r ? r.url : reg;
    },
    /** Why a name's scope maps to no registry, or null. */
    unresolvedReason(name) {
      const r = routes.get(scopeOf(name));
      return r && !r.url ? `the registry of ${scopeOf(name)} (${r.where}) can't be resolved` : null;
    },
    /** The scope routes whose registry is URL. */
    configuredBy(url) { return [...routes].filter(([, r]) => r.url && canonical(r.url) === canonical(url)).map(([scope, r]) => ({ scope, ...r })); },
    /** TEXT with every value a variable gave a scope registry replaced by its ${VAR}. */
    redact(text) {
      let s = String(text);
      for (const [value, ref] of redactions) s = s.split(value).join(ref);
      return s;
    },
  };
}

/**
 * The registry every command asks about a registry entry: where npm installs it from. A
 * source the lockfile doesn't record (pnpm, Berry), or one recorded on
 * https://registry.npmjs.org/ (yarn's registry.yarnpkg.com is the same, and npm's
 * replace-registry-host replaces it, so a mirror set as registry serves it): the registry
 * configured for the name (registry, or its scope's). One recorded on registry, or on the
 * registry the name's own scope maps to: itself. Anything else, and a name whose scope's
 * registry can't be resolved, is never contacted: registry null, and the reason.
 * @param {object} entry an Entry
 * @param {object} registries registryConfig()'s
 * @returns {{registry: string|null, reason: string|null}}
 */
export function metadataRegistry(entry, registries) {
  if (entry.kind !== 'registry') return { registry: null, reason: `not from a registry (${entry.kind})` };
  const mapped = registries.registryFor(entry.name);
  const s = entry.source;
  if (!entry.sourceRecorded || s === DEFAULT_REGISTRY) {
    return mapped ? { registry: mapped, reason: null } : { registry: null, reason: registries.unresolvedReason(entry.name) };
  }
  if (s === mapped || s === registries.registry) return { registry: s, reason: null };
  const other = [...registries.scopes].find(([, url]) => url === s);
  const scope = scopeOf(entry.name);
  if (other) return { registry: null, reason: `the lockfile records ${s}, which is the registry of ${other[0]}, not ${scope ? `of ${scope}` : `registry, where ${entry.name} comes from`}` };
  return { registry: null, reason: `the lockfile records ${s}, which is neither registry nor a scope's registry (scopes, .npmrc or .yarnrc.yml)` };
}

/**
 * Why a 401 or 403 from REGISTRY skips its packages: it is on another origin than registry, so
 * it was asked without the token, which goes only to registry's origin. null for any other
 * status, and on registry's origin, where the answer is no verdict (see authHint).
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
