// lock_verify.mjs: the lock_verify command of js-security-orb's Node.js helper
// (Node >= 22, standard library only; run as `node lock_verify.mjs` beside
// core.mjs). It checks a project's lockfiles for supply-chain hygiene, then
// asks each package's registry about the locked versions.
//
// Findings (SARIF rule lock-verify/<kind>; level error fails the gate):
//
//   lockfile only
//     no-integrity     a registry or tarball-URL package without an integrity hash
//     weak-integrity   its only integrity hash is SHA-1
//     registry         a registry the lockfile records that allowed_registries doesn't allow
//     git              a git dependency allow_git doesn't allow
//     git-unpinned     a git dependency without a full commit hash (even when allowed)
//     remote           a tarball URL (not a registry) allow_remote doesn't allow
//     local            a file:/link: path, or a workspace, outside the checkout
//                      that allow_local doesn't allow
//   lockfile or registry
//     install-script   preinstall/install/postinstall or binding.gyp, unless allow_scripts
//     deprecated       level warning, or error with fail_on_deprecated
//   registry
//     too-new          published less than min_release_age_days ago
//     no-publish-time  the registry has no (readable) publish time: fails closed
//     unpublished      the version isn't in the packument, or the packument is 404
//
// Decisions:
// - Integrity. Yarn Berry's checksum (a hash of Yarn's own zip) and pnpm's
//   integrityTarget: tar (a hash of the unpacked tar) count as integrity of
//   their own kind: neither is a registry's hash, so neither can show a weak
//   upstream hash, which a note in the report says. Bundled dependencies (npm
//   inBundle) come inside their parent's tarball: they have no integrity or
//   source of their own, and are never looked up on a registry.
// - allowed_registries holds origins or URL prefixes, compared by whole path
//   segments; empty allows registry and the scopes (and .npmrc) registries.
//   It applies only to sources a lockfile records (npm, yarn v1, bun);
//   pnpm and Berry sources come from that mapping.
// - allow_git, allow_remote and allow_local take package patterns (a real
//   name, not an alias; * allows every package), not booleans: true and false
//   are refused, so a value meant as a switch can't silently allow nothing.
//   allow_scripts and release_age_exclude also take name@version, matching
//   that one version exactly, as npm's allowScripts pins versions.
// - local covers local, link and workspace entries whose path, after
//   symbolic links, is outside the checkout (the top of the git checkout
//   working_dir is in, or working_dir outside one).
// - Which registry is asked about a registry package: the one the lockfile
//   records when it is registry or a scopes registry; for packages recorded
//   from registry.npmjs.org (or registry.yarnpkg.com), the registry
//   configured for the package, as npm's replace-registry-host=npmjs default
//   does, so a mirror set as registry serves them; for lockfiles that record
//   none, the mapping. A package recorded from any other registry is not
//   looked up (no request goes to a host named only by a repository file):
//   it is listed under skipped, with a warning.
// - Credentials: core sends the token only to registry's origin. A scopes
//   registry on another origin is asked without one; when it answers 401 or
//   403 its packages are skipped, with a warning. On registry's origin, 401
//   and 403 are errors. A 404 is unpublished: for a registry that got no
//   token, the message says a private registry may also answer 404.
// - Install scripts: either source suffices. The lockfile's hasInstallScript
//   (npm v2/v3, also offline), or the registry's version document: non-empty
//   scripts.preinstall, install or postinstall, gypfile, or hasInstallScript.
//   Packages neither source covers (git, tarball and local ones outside npm
//   lockfiles, and everything offline) are counted as install_scripts_unknown.
// - Deprecation: the registry's current word for packages it was asked
//   about (a version can be deprecated after it was locked, or undeprecated);
//   the lockfile's (npm, pnpm) for the others, offline included.
// - Release age: time[version] of the full packument; a missing or
//   non-ISO-8601 time is no-publish-time; a time in the future is too-new.
// - Findings are one per lockfile, kind, package, version and source: npm's
//   duplicate install paths of one version give one finding, at the first.
// - checked is every non-workspace package of the lockfiles, so a lockfile
//   with only workspaces checks nothing. Online, when registry packages exist
//   but none could be asked about (all skipped), that is a check of nothing
//   too: an error unless allow_empty. A registry that can't be read (5xx
//   after retries, a failed transfer, an answer that isn't a packument) is no
//   verdict, whatever report_only says.

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import fsPath from 'node:path';
import { main, compilePattern, matchesAny, normalizeRegistryUrl, parseYamlSubset, lineOf, UsageError, show, plural } from './core.mjs';

/** The command's name. */
export const COMMAND = 'lock_verify';
/** The public npm registry, as core normalizes it. */
export const NPMJS = 'https://registry.npmjs.org/';

const DAY_MS = 86400000;
const HOUR_MS = 3600000;
const LIST_MAX = 5;
const SCRIPT_TEXT_MAX = 200;
const ISO_TIME_RE = /^\d{4}-\d\d-\d\dT\d\d:\d\d(?::\d\d(?:\.\d+)?)?(?:Z|[+-]\d\d:?\d\d)$/;

/** The SARIF rules of lock_verify, with their descriptions. */
export const RULES = {
  'lock-verify/no-integrity': { description: 'A package from a registry or a tarball URL has no integrity hash in the lockfile, so nothing checks what is downloaded.' },
  'lock-verify/weak-integrity': { description: 'A package\'s only integrity hash in the lockfile is SHA-1, which no longer resists collisions; registries serve SHA-512.' },
  'lock-verify/registry': { description: 'The lockfile records a registry that allowed_registries doesn\'t allow for a package.' },
  'lock-verify/git': { description: 'A package comes from a git repository, which allow_git doesn\'t allow: it has no registry integrity, and its prepare script runs at install.' },
  'lock-verify/git-unpinned': { description: 'A git dependency is not pinned to a full commit hash, so what it installs can change.' },
  'lock-verify/remote': { description: 'A package is a tarball from a URL other than a registry, which allow_remote doesn\'t allow.' },
  'lock-verify/local': { description: 'A package comes from a path outside the checkout, which allow_local doesn\'t allow.' },
  'lock-verify/install-script': { description: 'A package runs install scripts (preinstall, install, postinstall or node-gyp), which allow_scripts doesn\'t allow.' },
  'lock-verify/too-new': { description: 'A locked version was published less than min_release_age_days ago; most malicious releases are found and removed within days.' },
  'lock-verify/no-publish-time': { description: 'The registry has no publish time for a locked version, so its age can\'t be checked.' },
  'lock-verify/unpublished': { description: 'A locked version is not on its registry: it was unpublished, or never published there.' },
  'lock-verify/deprecated': { description: 'A locked version is deprecated by its maintainers.' },
};

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

/** A package as messages name it: name@version, with the alias the project uses. */
export function label(e) {
  return `${e.name}${e.version ? '@' + e.version : ''}${e.alias ? ` (as ${e.alias})` : ''}`;
}

// The key findings and packages are deduplicated by.
const keyOf = (e) => [e.lockfile, e.kind, e.name, e.version ?? '', e.source ?? ''].join('\0');

// A list of names for a message: the first few, and how many more.
function nameList(names) {
  const list = [...new Set(names)];
  const head = list.slice(0, LIST_MAX).join(', ');
  return list.length > LIST_MAX ? `${head} and ${list.length - LIST_MAX} more` : head;
}

const canonicalRegistry = (url) => url.replace(/^https:\/\/registry\.yarnpkg\.com\//i, NPMJS);
const originOf = (url) => { try { return new URL(url).origin; } catch { return null; } };

// A list of package patterns; true and false are refused (see the top).
function patternParam(ctx, name, versions = false) {
  const items = ctx.list(name, '');
  const flag = items.find((t) => /^(?:true|false)$/i.test(t));
  if (flag !== undefined) throw new UsageError(`${name} takes package names or patterns, such as @scope/* or * for every package, not ${show(flag)}.`);
  return items.map((t) => compilePattern(t, { versions, param: name }));
}

/**
 * Reads lock_verify's own parameters (the common ones are the context's).
 * Throws a UsageError for a bad value, before any network access.
 * @param {object} ctx the command context
 */
export function readOptions(ctx) {
  const regs = ctx.registries;
  const allowed = ctx.list('allowed_registries', '');
  return {
    allowedRegistries: allowed.length
      ? [...new Set(allowed.map((u) => canonicalRegistry(normalizeRegistryUrl(u, 'allowed_registries'))))]
      : [...new Set([regs.registry, ...regs.scopes.values()].map(canonicalRegistry))],
    allowedExplicit: allowed.length > 0,
    allowGit: patternParam(ctx, 'allow_git'),
    allowRemote: patternParam(ctx, 'allow_remote'),
    allowLocal: patternParam(ctx, 'allow_local'),
    allowScripts: patternParam(ctx, 'allow_scripts', true),
    minReleaseAgeDays: ctx.int('min_release_age_days', 7, { min: 0, max: 36500 }),
    releaseAgeExclude: patternParam(ctx, 'release_age_exclude', true),
    failOnDeprecated: ctx.bool('fail_on_deprecated', false),
    offline: ctx.bool('offline', false),
  };
}

// Whether a path (relative to TOP, as Entry.source holds it) is outside TOP,
// after symbolic links when it exists.
function outsideCheckout(top, source) {
  if (typeof source !== 'string') return false;
  let p = fsPath.resolve(top, source);
  try { p = fs.realpathSync(p); } catch { /* it needn't exist on this machine */ }
  const rel = fsPath.relative(top, p);
  return rel === '..' || rel.startsWith('..' + fsPath.sep) || fsPath.isAbsolute(rel);
}

// The text of a deprecation (a non-empty string, or true), or null.
function deprecation(value) {
  if (value === true) return '';
  return typeof value === 'string' && value.trim() ? value.trim() : null;
}

// The lines of a Yarn Berry lockfile's entries that have platform
// conditions (core's entries don't carry them): Yarn records no checksum for
// those, whatever the platform.
function berryConditionalLines(file, rel) {
  const lines = new Set();
  let docs;
  try { docs = parseYamlSubset(fs.readFileSync(file, 'utf8'), rel); } catch { return lines; }
  const d = docs.find((x) => isObj(x));
  if (!d) return lines;
  for (const key of Object.keys(d)) {
    if (key !== '__metadata' && isObj(d[key]) && d[key].conditions !== undefined) lines.add(lineOf(d, key));
  }
  return lines;
}

// What a version document says about install scripts: {names, scripts}.
function installScripts(m) {
  const scripts = {};
  const s = isObj(m.scripts) ? m.scripts : {};
  for (const k of ['preinstall', 'install', 'postinstall']) {
    if (own(s, k) && typeof s[k] === 'string' && s[k].trim()) scripts[k] = s[k].slice(0, SCRIPT_TEXT_MAX);
  }
  const names = Object.keys(scripts);
  if (m.gypfile === true && !names.includes('install')) names.push('node-gyp (gypfile)');
  if (m.hasInstallScript === true && !names.length) names.push('hasInstallScript');
  return { names, scripts };
}

// The pick for getPackuments: only the locked versions' publish times,
// deprecations and install scripts, so big packuments don't stay in memory.
function makePick(wanted) {
  return (doc, name) => {
    const want = wanted.get(name) ?? new Set();
    const versions = isObj(doc.versions) ? doc.versions : null;
    const time = isObj(doc.time) ? doc.time : null;
    let unpublishedAt = null;
    if (time && own(time, 'unpublished') && isObj(time.unpublished)) {
      const t = time.unpublished.time;
      unpublishedAt = typeof t === 'string' && ISO_TIME_RE.test(t) ? t : '';
    }
    const out = { hasVersions: !!versions && Object.keys(versions).length > 0, unpublishedAt, versions: new Map(), time: new Map() };
    for (const v of want) {
      if (versions && own(versions, v) && isObj(versions[v])) {
        const m = versions[v];
        out.versions.set(v, { deprecated: deprecation(m.deprecated), ...installScripts(m) });
      }
      const t = time && own(time, v) ? time[v] : null;
      out.time.set(v, typeof t === 'string' ? t.slice(0, 60) : null);
    }
    return out;
  };
}

// The age of a version for a message.
function ageText(ms) {
  if (ms < HOUR_MS) return 'less than an hour';
  if (ms < 2 * DAY_MS) return plural(Math.floor(ms / HOUR_MS), 'hour');
  return plural(Math.floor(ms / DAY_MS), 'day');
}

/**
 * The lock_verify command: returns the result main() reports (findings,
 * errors, warnings, skipped, summary, counts, rules, checked).
 * @param {object} ctx the command context (core's createContext)
 * @param {{now?: number}} [options] now: the time release ages are measured
 *   from, in ms since the epoch (for tests)
 */
export async function lockVerify(ctx, { now = Date.now() } = {}) {
  const opts = readOptions(ctx);
  const set = ctx.readLockfiles();
  const regs = ctx.registries;
  const top = set.top ?? ctx.top;
  const findings = [];
  const seen = new Set();
  const errors = [];
  const warnings = [];
  const notes = [];
  const skipped = [];

  const add = (e, kind, message, { level = 'error', details = {} } = {}) => {
    const key = `${kind}\0${keyOf(e)}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(ctx.finding(e, { kind, message, level, details }));
  };
  const allowedRegistry = (source) => opts.allowedRegistries.some((p) => source.startsWith(p));
  const checkPath = (e) => {
    if (!outsideCheckout(top, e.source) || matchesAny(e.name, opts.allowLocal)) return;
    const what = e.kind === 'workspace' ? 'a workspace' : e.kind === 'link' ? 'a link' : 'a local package';
    add(e, 'local', `${label(e)} in ${e.lockfile} is ${what} at ${e.source}, outside the checkout, which allow_local doesn't allow.`, { details: { path: e.source, kind: e.kind } });
  };

  // --- What the lockfiles say.
  const packages = [];
  const packageKeys = new Set();
  for (const e of set.entries) {
    if (e.kind === 'workspace') { checkPath(e); continue; }
    const k = keyOf(e);
    if (packageKeys.has(k)) continue;
    packageKeys.add(k);
    packages.push(e);
  }
  const byKind = {};
  for (const e of packages) byKind[e.kind] = (byKind[e.kind] ?? 0) + 1;
  const conditional = new Map(); // a Berry lockfile's rel -> lines of entries with conditions
  for (const l of set.lockfiles) if (l.format === 'berry') conditional.set(l.rel, berryConditionalLines(l.path, l.rel));
  const unchecksummed = new Map(); // a Berry lockfile's rel -> names of conditional packages without a checksum

  for (const e of packages) {
    const lf = e.lockfile;
    if (e.kind === 'local' || e.kind === 'link') checkPath(e);
    if (e.kind === 'git') {
      if (!matchesAny(e.name, opts.allowGit)) add(e, 'git', `${label(e)} in ${lf} comes from git (${e.source}), which allow_git doesn't allow.`, { details: { source: e.source } });
      if (!e.commit) add(e, 'git-unpinned', `${label(e)} in ${lf} comes from git (${e.source}) without a full commit hash, so what it installs can change.`, { details: { source: e.source } });
    }
    if (e.kind === 'remote' && !matchesAny(e.name, opts.allowRemote)) {
      add(e, 'remote', `${label(e)} in ${lf} is a tarball from ${e.source}, which allow_remote doesn't allow.`, { details: { source: e.source } });
    }
    if ((e.kind === 'registry' || e.kind === 'remote') && !e.bundled) {
      if (!e.integrity && conditional.get(lf)?.has(e.line)) {
        if (!unchecksummed.has(lf)) unchecksummed.set(lf, []);
        unchecksummed.get(lf).push(e.name);
      } else if (!e.integrity) {
        add(e, 'no-integrity', `${label(e)} in ${lf} has no integrity hash, so nothing checks what is downloaded.`, { details: { source: e.source } });
      } else if (e.integrityKind === 'sri' && e.integrityAlgos.length && e.integrityAlgos.every((a) => a === 'sha1')) {
        add(e, 'weak-integrity', `${label(e)} in ${lf} has only a SHA-1 integrity hash; regenerate the lockfile from a registry that serves SHA-512.`, { details: { integrity: e.integrity.slice(0, 100) } });
      }
    }
    if (e.kind === 'registry' && !e.bundled && e.sourceRecorded && !allowedRegistry(e.source)) {
      const why = opts.allowedExplicit ? 'which allowed_registries doesn\'t allow' : 'which is not registry or a scopes registry, and allowed_registries is empty';
      add(e, 'registry', `${label(e)} in ${lf} comes from ${e.source}, ${why}.`, { details: { source: e.source } });
    }
  }
  for (const l of set.lockfiles) {
    if (l.format === 'berry') {
      notes.push(`${l.rel}: Yarn Berry records checksums of Yarn's own archives, not the registry's integrity, so they count as integrity here but can't show whether the registry's hash is weak.`);
      const list = unchecksummed.get(l.rel) ?? [];
      if (list.length) {
        notes.push(`${l.rel}: ${plural(list.length, 'package')} with platform conditions (${nameList(list)}) ${list.length === 1 ? 'has' : 'have'} no checksum, since Yarn never records one for them: nothing verifies their downloads, but this check can't require it.`);
      }
    }
    if (set.entries.some((e) => e.lockfile === l.rel && e.integrityKind === 'tar')) {
      notes.push(`${l.rel}: pnpm's integrityTarget: tar hashes the unpacked tarball, not the registry's integrity, so it counts as integrity here but can't show whether the registry's hash is weak.`);
    }
  }

  // --- What the registries say.
  const registryPackages = packages.filter((e) => e.kind === 'registry' && !e.bundled);
  const versionDocs = new Map(); // key -> {deprecated, names, scripts, registry}
  const asked = new Set(); // keys of packages a registry answered about
  const configured = new Set([regs.registry, ...regs.scopes.values()]);
  const registryOrigin = originOf(regs.registry);
  const tokenSentTo = (target) => !!ctx.tokenVar && originOf(target) === registryOrigin;
  const skip = (e, reason) => skipped.push({ package: { name: e.name, version: e.version ?? null }, lockfile: e.lockfile, line: e.line ?? null, kind: e.kind, source: e.source, reason });

  if (opts.offline) {
    if (registryPackages.length) {
      notes.push(`offline is true, so no registry was asked about ${plural(registryPackages.length, 'registry package')}: release ages and unpublished versions were not checked, deprecated versions and install scripts only where the lockfile records them (npm; pnpm for deprecations).`);
    }
  } else if (registryPackages.length) {
    const groups = new Map(); // registry -> Map name -> Set of versions
    const targets = new Map(); // key -> registry
    for (const e of registryPackages) {
      let target = null;
      if (!e.sourceRecorded || configured.has(e.source)) target = e.source;
      else if (e.source === NPMJS) target = regs.registryFor(e.name);
      if (!target) {
        skip(e, `${e.source} is not registry or a scopes registry, so it was not asked`);
        continue;
      }
      targets.set(keyOf(e), target);
      if (!groups.has(target)) groups.set(target, new Map());
      const names = groups.get(target);
      if (!names.has(e.name)) names.set(e.name, new Set());
      names.get(e.name).add(e.version);
    }
    const answers = new Map();
    for (const [target, names] of groups) {
      answers.set(target, await ctx.client.getPackuments([...names.keys()], { pick: makePick(names), registryFor: () => target }));
    }
    const failures = new Map();
    for (const e of registryPackages) {
      const target = targets.get(keyOf(e));
      if (!target) continue;
      const lf = e.lockfile;
      const r = answers.get(target).get(e.name) ?? { status: 0, error: 'no answer' };
      if (r.packument) {
        asked.add(keyOf(e));
        const p = r.packument;
        const v = e.version;
        const doc = p.versions.get(v);
        if (!doc) {
          const published = ISO_TIME_RE.test(p.time.get(v) ?? '') ? p.time.get(v) : null;
          const why = p.unpublishedAt !== null ? `the package was unpublished${p.unpublishedAt ? ` (${p.unpublishedAt})` : ''}`
            : published ? `the version, published ${published}, was unpublished` : p.hasVersions ? 'the registry doesn\'t list the version' : 'the registry lists no versions of it';
          add(e, 'unpublished', `${label(e)} in ${lf} is not on ${target}: ${why}.`, { details: { registry: target } });
          continue;
        }
        versionDocs.set(keyOf(e), { ...doc, registry: target });
        if (opts.minReleaseAgeDays > 0 && !matchesAny(e.name, opts.releaseAgeExclude, v)) {
          const t = p.time.get(v);
          const ms = t !== null && ISO_TIME_RE.test(t) ? Date.parse(t) : NaN;
          if (Number.isNaN(ms)) {
            const what = t === null ? 'no publish time' : `an unreadable publish time ${show(t)}`;
            add(e, 'no-publish-time', `${label(e)} in ${lf} has ${what} on ${target}, so its age can't be checked against min_release_age_days (${opts.minReleaseAgeDays}).`, { details: { registry: target, time: t } });
          } else {
            const age = now - ms;
            const iso = new Date(ms).toISOString();
            if (age < 0) {
              add(e, 'too-new', `${label(e)} in ${lf} has a publish time in the future (${iso}) on ${target}.`, { details: { registry: target, published: iso, min_release_age_days: opts.minReleaseAgeDays } });
            } else if (age < opts.minReleaseAgeDays * DAY_MS) {
              add(e, 'too-new', `${label(e)} in ${lf} was published ${ageText(age)} ago (${iso}); min_release_age_days is ${opts.minReleaseAgeDays}.`, {
                details: { registry: target, published: iso, age_hours: Math.floor(age / HOUR_MS), min_release_age_days: opts.minReleaseAgeDays },
              });
            }
          }
        }
      } else if (r.status === 404) {
        asked.add(keyOf(e));
        const hint = target !== NPMJS && !tokenSentTo(target) ? ' (a private registry also answers 404 without credentials)' : '';
        add(e, 'unpublished', `${label(e)} in ${lf} is not on ${target} (HTTP 404): it was unpublished, or never published there${hint}.`, { details: { registry: target, status: 404 } });
      } else if ((r.status === 401 || r.status === 403) && originOf(target) !== registryOrigin) {
        skip(e, `${target} answered HTTP ${r.status}, and the token goes only to registry's origin`);
      } else {
        const error = r.error ?? `HTTP ${r.status}`;
        const fk = `${target}\0${error}`;
        if (!failures.has(fk)) failures.set(fk, { target, error, status: r.status, names: [] });
        failures.get(fk).names.push(e.name);
      }
    }
    for (const f of failures.values()) {
      let hint = '';
      if (f.status === 401 || f.status === 403) {
        hint = ctx.tokenVar ? ` Check the token in ${ctx.tokenVar}.` : ' Set token to the name of a variable holding a token for it.';
      }
      const count = new Set(f.names).size;
      errors.push(`Could not read the packument of ${plural(count, 'package')} from ${f.target} (${f.error}): ${nameList(f.names)}.${hint}`);
    }
    if (skipped.length) {
      const byReason = new Map();
      for (const s of skipped) {
        if (!byReason.has(s.reason)) byReason.set(s.reason, []);
        byReason.get(s.reason).push(`${s.package.name}@${s.package.version}`);
      }
      for (const [reason, list] of byReason) {
        warnings.push(`${plural(new Set(list).size, 'package')} not checked against a registry, since ${reason}: ${nameList(list)}. They are listed under skipped in the report.`);
      }
    }
    if (!asked.size && !errors.length && !ctx.allowEmpty) {
      errors.push(`None of the ${plural(registryPackages.length, 'registry package')} could be checked against a registry (see the warnings). Set registry or scopes to the registries they come from, offline to true to check only the lockfiles, or allow_empty to true.`);
    }
  }

  // --- Deprecations and install scripts, from either source.
  let scriptsUnknown = 0;
  for (const e of packages) {
    const k = keyOf(e);
    const doc = versionDocs.get(k);
    const lf = e.lockfile;
    const dep = asked.has(k) ? (doc ? doc.deprecated : null) : deprecation(e.deprecated);
    if (dep !== null) {
      add(e, 'deprecated', `${label(e)} in ${lf} is deprecated${dep ? ': ' + show(dep) : ''}.`, {
        level: opts.failOnDeprecated ? 'error' : 'warning',
        details: { message: dep.slice(0, 500), from: asked.has(k) ? 'registry' : 'lockfile' },
      });
    }
    const names = doc ? doc.names : [];
    const fromLockfile = e.hasInstallScript === true;
    if (!doc && e.hasInstallScript === null) scriptsUnknown++;
    if ((names.length || fromLockfile) && !matchesAny(e.name, opts.allowScripts, e.version ?? undefined)) {
      const what = names.length ? names.join(', ') : 'the lockfile records hasInstallScript';
      add(e, 'install-script', `${label(e)} in ${lf} runs install scripts (${what}), which allow_scripts doesn't allow.`, {
        details: { scripts: doc ? doc.scripts : {}, lockfile_has_install_script: fromLockfile, registry: doc ? doc.registry : null },
      });
    }
  }

  findings.sort((a, b) => (a.lockfile ?? '').localeCompare(b.lockfile ?? '') || (a.line ?? 0) - (b.line ?? 0) || a.rule.localeCompare(b.rule));
  for (const n of notes) ctx.io.log(`Note: ${n}`);
  const registryChecked = asked.size;
  ctx.io.log(`Checked ${plural(packages.length, 'package')} in ${plural(set.lockfiles.length, 'lockfile')}`
    + `${opts.offline ? ', offline' : `, ${registryChecked} of ${plural(registryPackages.length, 'registry package')} against a registry`}.`);
  const counts = {
    packages: packages.length,
    registry_packages: registryPackages.length,
    registry_checked: registryChecked,
    skipped: skipped.length,
    install_scripts_unknown: scriptsUnknown,
    conditional_without_checksum: [...unchecksummed.values()].reduce((a, b) => a + b.length, 0),
  };
  return {
    findings,
    errors,
    warnings,
    skipped,
    rules: RULES,
    checked: packages.length,
    counts,
    summary: {
      ...counts,
      by_kind: byKind,
      offline: opts.offline,
      min_release_age_days: opts.minReleaseAgeDays,
      allowed_registries: opts.allowedRegistries,
      notes,
    },
  };
}

function isMainModule() {
  if (!process.argv[1]) return false;
  try { return fs.realpathSync(process.argv[1]) === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
}

if (isMainModule()) await main(COMMAND, (ctx) => lockVerify(ctx));
