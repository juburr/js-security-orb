// signatures.mjs: the signatures command of js-security-orb's Node.js helper (Node >= 22,
// standard library only). For every package a lockfile pins from a registry, it verifies the
// registry's signature over the integrity the lockfile records, and the Sigstore attestations
// (npm's publish attestation and SLSA provenance) the registry serves for it, then applies the
// provenance policies: require_provenance, provenance_sources and no_downgrade. The checks are
// sigstore.mjs's, against pinned npm registry keys and a pinned Sigstore trusted root; this module
// decides what to check and what each result means.
//
// What is checked:
// - Registry entries whose registry is one the job configured: `registry`, or a scope's registry
//   (scopes, or @scope:registry lines in working_dir/.npmrc). An entry a lockfile records from any
//   other registry is skipped with a warning, never queried. git, remote, local, link and
//   workspace entries are listed as skipped (not signed by any registry); so is a bundled
//   dependency, which comes inside its parent's tarball, which the parent's signature covers.
// - The binding. The sha512 of the lockfile's integrity must equal the sha512 of the packument
//   version's dist.integrity, or the finding is integrity-mismatch: the locked tarball is not the
//   one the registry published. The signature is then verified over name@version:<integrity>,
//   with the lockfile's integrity string, or dist.integrity when the two strings differ but hold
//   the same sha512 (a lockfile may add a sha1): the registry signed dist.integrity's exact bytes.
// - Unbound integrity. A Yarn Berry lockfile's checksums are of Yarn's own zip archives, pnpm's
//   integrityTarget: tar hashes the unpacked tarball, and an entry with only a sha1 integrity, or
//   none, holds no sha512 at all: none of these can be bound to what the registry signed. Without
//   allow_unbound, they are skipped, and each lockfile holding any has no verdict (an error). With
//   it, they are verified against the registry's own dist.integrity, with a warning per lockfile:
//   that shows the registry signed what it serves, not that the lockfile pins those bytes. A sha1
//   (or sha256, sha384) the lockfile does record must still equal the registry's (dist.shasum
//   counts as its sha1), or the finding is integrity-mismatch.
// - Registry signatures (verifyRegistrySignature, with the version's publish time from `time`):
//   valid passes; invalid is a finding; unknown-key is no verdict (an orb update is needed for a
//   new npm key; another registry's own keys can't be verified). unsigned is a finding when the
//   registry signs: npmjs always does, and any registry does when a packument read from it in
//   this run carries dist.signatures on any version (a mirror of npmjs serves npm's signatures,
//   which verify). A registry whose packuments carry none at all (most private registries) has
//   its entries listed as skipped, with a warning, never as passed; require_signatures makes
//   them unsigned findings instead. A run whose registry signatures were all skipped checked
//   nothing, which fails unless allow_empty.
// - A packument the registry doesn't have (404), or one that doesn't list the locked version, is
//   the finding not-in-registry: nothing can verify it (an unpublished version, as after a
//   takeover is cleaned up, or a lockfile pointing at another registry). Any other answer, or a
//   transfer that fails, is no verdict.
// - Attestations are fetched for every version whose packument advertises dist.attestations,
//   and, for a package a policy requires provenance of, also when it doesn't (a 404 is then the
//   answer "none"). They are verified with the bound integrity (verifyAttestations), never for
//   an integrity mismatch, which is already a finding. invalid (of either attestation) is the
//   finding invalid-attestation. unsupported is a warning, but the finding
//   unsupported-attestation for a package that needs provenance and has no valid one. Attestations
//   the packument advertises but the registry doesn't serve (404, or none) are no verdict on
//   npmjs; on another registry (a mirror that doesn't serve /-/npm/v1/attestations) a warning,
//   and the package counts as having no provenance.
// - require_provenance (package patterns): a match without valid provenance is missing-provenance.
// - provenance_sources (lines pattern=REPOSITORY): the first pattern that matches a package
//   decides; a pattern may be given on several lines, or with several repositories separated by
//   commas, and provenance from any of them passes. A repository is https://HOST/OWNER/REPO,
//   compared with the certificate's Source Repository URI (case-insensitively, without a trailing
//   / or .git), or id:<numeric ID>, compared with its Source Repository Identifier, which survives
//   a transfer or rename of the repository; an id: matches only certificates GitHub Actions'
//   issuer obtained, since another forge's IDs are a different sequence. A mismatch is the
//   finding provenance-source, with the expected and actual repository. A package a source
//   policy names needs provenance: without it, the finding is missing-provenance, since a source
//   rule an attacker passes by publishing without provenance would protect nothing.
// - no_downgrade: pnpm's trustPolicy: no-downgrade, as pnpm 11.4 and later rank trust evidence,
//   from the packument alone (presence, not verification, as pnpm): a staged publish
//   (_npmUser.approver) > a trusted publisher (_npmUser.trustedPublisher, with provenance) >
//   provenance (dist.attestations.provenance) > none. A locked version is compared with every
//   version published strictly earlier by `time`, not by semver; a stable version ignores
//   earlier prereleases, a prerelease compares with all. Weaker evidence than an earlier
//   version's is the finding provenance-downgrade, naming that version. A locked version with no
//   publish time can't be compared: no verdict, as pnpm's error. downgrade_exclude takes package
//   patterns, or name@version.
//
// Findings are one per lockfile, package version and kind. The report's results list every
// package version checked, with its registry signature, attestations, provenance identity and
// trust evidence; skipped lists every entry not checked, with the reason.
//
// Exit codes are core's: 0 passed, 1 findings or no verdict, 2 a bad parameter (before any
// network access).

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import { main, UsageError, compilePattern, matchesAny, show, plural } from './core.mjs';
import { verifyRegistrySignature, verifyAttestations, integrityToHex, NPM_REGISTRY_KEYS } from './sigstore.mjs';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const own = (o, k) => isObj(o) && Object.prototype.hasOwnProperty.call(o, k);
const str = (v) => (typeof v === 'string' ? v : null);

/** The issuer of GitHub Actions' OIDC tokens, which id: repositories must come from. */
export const GITHUB_ISSUER = 'https://token.actions.githubusercontent.com';

/** Whether a registry URL is npm's public registry, which signs every version it publishes. */
export function isNpmjs(registry) {
  try { return new URL(registry).hostname === 'registry.npmjs.org'; } catch { return false; }
}

/** SARIF rule descriptions of the command's finding kinds. */
export const RULES = {
  'signatures/integrity-mismatch': {
    description: 'The integrity a lockfile records for a package is not the one its registry publishes and signs for that version, so the locked tarball is not the one the registry published.',
  },
  'signatures/invalid': {
    description: 'A registry signature on a locked package does not verify over its name, version and integrity, or was made with a registry key that had expired when the version was published.',
  },
  'signatures/unsigned': {
    description: 'A locked package has no registry signature, although its registry signs packages (or require_signatures is set).',
  },
  'signatures/not-in-registry': {
    description: 'A lockfile pins a version its registry does not list (unpublished, or from another registry), so nothing can verify it.',
  },
  'signatures/invalid-attestation': {
    description: 'A Sigstore attestation (npm publish attestation or SLSA provenance) the registry serves for a locked package does not verify against the pinned trusted root and npm keys, or does not name the locked tarball.',
  },
  'signatures/unsupported-attestation': {
    description: 'A package that policy requires provenance of has only attestations in a format this orb cannot verify yet.',
  },
  'signatures/missing-provenance': {
    description: 'A package that require_provenance or provenance_sources names has no valid SLSA provenance.',
  },
  'signatures/provenance-source': {
    description: 'The verified provenance of a package names a source repository that provenance_sources does not allow for it.',
  },
  'signatures/provenance-downgrade': {
    description: 'A locked version was published with weaker trust evidence (staged publish, trusted publisher, provenance) than an earlier version of the same package, which can mean the package was taken over.',
  },
};
for (const r of Object.values(RULES)) r.tags = ['signatures', 'provenance'];

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

/**
 * A repository URL as provenance_sources compares it: lower case, without a trailing / or .git.
 * @param {string} url
 */
export function normalizeRepositoryUrl(url) {
  return String(url).trim().replace(/\/+$/, '').replace(/\.git$/i, '').toLowerCase();
}

const stripZeros = (id) => String(id).replace(/^0+(?=\d)/, '');

function parseRepository(text) {
  const id = /^id:([0-9]{1,20})$/.exec(text);
  if (id) return { kind: 'id', id: stripZeros(id[1]), text };
  let u = null;
  try { u = new URL(text); } catch { u = null; }
  if (!u || u.protocol !== 'https:' || u.username || u.password || /[?#]/.test(text) || !/^\/[^/]+\/[^/]+/.test(u.pathname)) {
    throw new UsageError(`provenance_sources: ${show(text)} is not a repository. Write https://github.com/OWNER/REPO, or id:<the repository's numeric ID>.`);
  }
  return { kind: 'url', url: normalizeRepositoryUrl(`https://${u.host}${u.pathname}`), text };
}

/**
 * Parses provenance_sources: lines pattern=REPOSITORY[,REPOSITORY...]. Lines with the same
 * pattern are merged; the groups keep the order their patterns first appear in.
 * UsageError for a bad line.
 * @param {string[]} lines
 * @returns {{pattern: object, repos: {kind, id?, url?, text}[]}[]}
 */
export function parseProvenanceSources(lines) {
  const groups = new Map();
  for (const line of lines) {
    const m = /^([^=\s]+)\s*=\s*(\S+)$/.exec(line.trim());
    if (!m) {
      throw new UsageError(`provenance_sources takes lines pattern=REPOSITORY, such as react=https://github.com/facebook/react or @corp/*=id:123456, not ${show(line)}.`);
    }
    const pattern = compilePattern(m[1], { param: 'provenance_sources' });
    const repos = m[2].split(',').filter(Boolean).map(parseRepository);
    if (!repos.length) throw new UsageError(`provenance_sources: ${show(line)} names no repository.`);
    const g = groups.get(pattern.text) ?? { pattern, repos: [] };
    for (const r of repos) if (!g.repos.some((x) => x.text === r.text)) g.repos.push(r);
    groups.set(pattern.text, g);
  }
  return [...groups.values()];
}

/**
 * Whether a provenance identity (sigstore's summary.identity) names REPO.
 * @param {object|null} identity
 * @param {{kind: 'id'|'url', id?: string, url?: string}} repo
 */
export function repositoryMatches(identity, repo) {
  if (!identity) return false;
  if (repo.kind === 'id') {
    return identity.issuer === GITHUB_ISSUER && typeof identity.sourceRepositoryId === 'string' && stripZeros(identity.sourceRepositoryId) === repo.id;
  }
  return typeof identity.sourceRepositoryUri === 'string' && normalizeRepositoryUrl(identity.sourceRepositoryUri) === repo.url;
}

// ---------------------------------------------------------------------------
// Trust evidence (no_downgrade)
// ---------------------------------------------------------------------------

/** The ranks of trust evidence, as pnpm 11.4 and later rank them. */
export const TRUST_RANK = Object.freeze({ 'staged-publish': 3, 'trusted-publisher': 2, provenance: 1, none: 0 });
const TRUST_TEXT = {
  'staged-publish': 'a staged publish (approved with two-factor authentication)',
  'trusted-publisher': 'a trusted publisher, with provenance',
  provenance: 'provenance',
  none: 'no trust evidence',
};

/**
 * The trust evidence of a packument version, as pnpm reads it: presence only.
 * @param {object} manifest packument.versions[version]
 * @returns {'staged-publish'|'trusted-publisher'|'provenance'|'none'}
 */
export function trustEvidence(manifest) {
  const user = isObj(manifest) && isObj(manifest._npmUser) ? manifest._npmUser : null;
  const provenance = isObj(manifest) && isObj(manifest.dist) && isObj(manifest.dist.attestations) && !!manifest.dist.attestations.provenance;
  if (user && user.approver) return 'staged-publish';
  if (user && user.trustedPublisher && provenance) return 'trusted-publisher';
  return provenance ? 'provenance' : 'none';
}

/**
 * Whether a version is a prerelease, as node-semver's prerelease(version, loose) says. A
 * version that isn't semver is not one.
 * @param {string} version
 */
export function isPrerelease(version) {
  const id = '[0-9A-Za-z-]+';
  const re = new RegExp(`^[v=\\s]*\\d+\\.\\d+\\.\\d+(?:-?(${id}(?:\\.${id})*))?(?:\\+${id}(?:\\.${id})*)?\\s*$`);
  const m = re.exec(String(version));
  return !!(m && m[1]);
}

/**
 * The downgrade of a version, as pnpm's no-downgrade finds it: the version published strictly
 * earlier (prereleases ignored for a stable version) with the strongest evidence (the latest
 * of those), when that is stronger than EVIDENCE; else null.
 * @param {Array<[string, number, string]>} history [version, publish time in ms, evidence]
 * @param {string} version the locked version
 * @param {number} publishedAt its publish time, in ms
 * @param {string} evidence its trust evidence
 * @returns {{version, time, evidence}|null}
 */
export function findDowngrade(history, version, publishedAt, evidence) {
  const stableOnly = !isPrerelease(version);
  let best = null;
  for (const [v, t, ev] of history) {
    if (!(t < publishedAt) || ev === 'none' || (stableOnly && isPrerelease(v))) continue;
    if (!best || TRUST_RANK[ev] > TRUST_RANK[best.evidence] || (TRUST_RANK[ev] === TRUST_RANK[best.evidence] && t > best.time)) {
      best = { version: v, time: t, evidence: ev };
    }
  }
  return best && TRUST_RANK[best.evidence] > TRUST_RANK[evidence] ? best : null;
}

// ---------------------------------------------------------------------------
// Integrity binding
// ---------------------------------------------------------------------------

// Why lockfile integrity can't be bound: for a lockfile's message, and for one entry.
const UNBOUND_TEXT = {
  berry: "Yarn Berry's checksums are of its own zip archives",
  tar: "pnpm's integrityTarget: tar hashes the unpacked tarball",
  weak: 'some integrities have no sha512, only a sha1 (or sha256, sha384)',
  none: 'some packages have no integrity',
};
const UNBOUND_ENTRY = {
  berry: "Yarn Berry's checksum, of its own zip archive",
  tar: "pnpm's integrityTarget: tar hash, of the unpacked tarball",
  weak: 'an integrity without a sha512',
  none: 'no integrity',
};

/**
 * Why an entry's lockfile integrity can't be bound to a registry signature, or null.
 * @param {object} entry
 * @param {string} [format] its lockfile's format
 * @returns {'berry'|'tar'|'weak'|'none'|null}
 */
export function unboundReason(entry, format) {
  if (format === 'berry' || entry.integrityKind === 'berry') return 'berry';
  if (entry.integrityKind === 'tar') return 'tar';
  if (!entry.integrity) return 'none';
  if (!(entry.integrityAlgos ?? []).includes('sha512')) return 'weak';
  return null;
}

/**
 * Binds a lockfile integrity to the registry's: {status: 'lockfile', integrity} (the string to
 * verify the signature over), {status: 'registry', integrity} (unbound: the registry's own),
 * or {status: 'mismatch'}.
 * @param {string|null} lockIntegrity
 * @param {string|null} unbound unboundReason()
 * @param {{integrity: string|null, shasum: string|null}} dist the packument version's
 */
export function bindIntegrity(lockIntegrity, unbound, dist) {
  const reg = dist.integrity;
  if (!unbound) {
    const mine = integrityToHex(lockIntegrity);
    if (!mine || mine !== integrityToHex(reg)) return { status: 'mismatch' };
    return { status: 'lockfile', integrity: lockIntegrity === reg ? lockIntegrity : reg };
  }
  if (unbound === 'weak') {
    for (const algo of ['sha384', 'sha256', 'sha1']) {
      const mine = integrityToHex(lockIntegrity, algo);
      if (!mine) continue;
      let theirs = integrityToHex(reg, algo);
      if (!theirs && algo === 'sha1' && /^[0-9a-f]{40}$/i.test(dist.shasum ?? '')) theirs = dist.shasum.toLowerCase();
      if (theirs && theirs !== mine) return { status: 'mismatch' };
    }
  }
  return { status: 'registry', integrity: reg };
}

const PINNED_KEYIDS = new Set(NPM_REGISTRY_KEYS.map((k) => k.keyid));
const short = (sri) => (typeof sri === 'string' ? (sri.length > 28 ? `${sri.slice(0, 27)}…` : sri) : 'none');

// ---------------------------------------------------------------------------
// The packument slice this command needs
// ---------------------------------------------------------------------------

// What getPackuments keeps of each packument: whether any version is signed, the locked
// versions' dist, publish time and trust evidence, and (for no_downgrade) every version's
// publish time and trust evidence. Full packuments are large; nothing else is kept.
function makePick(wanted, withHistory) {
  return (doc, name) => {
    const versions = doc.versions;
    if (!isObj(versions)) return { malformed: 'it has no versions object' };
    const times = isObj(doc.time) ? doc.time : null;
    const timeOf = (v) => (own(times, v) ? times[v] : null);
    const out = { signed: false, locked: Object.create(null), history: withHistory ? [] : null };
    for (const v of Object.keys(versions)) {
      const m = versions[v];
      if (!isObj(m)) continue;
      if (!out.signed && isObj(m.dist) && Array.isArray(m.dist.signatures) && m.dist.signatures.length) out.signed = true;
      if (out.history) {
        const t = Date.parse(timeOf(v));
        if (!Number.isNaN(t)) out.history.push([v, t, trustEvidence(m)]);
      }
    }
    for (const v of wanted.get(name) ?? []) {
      if (!own(versions, v) || !isObj(versions[v])) continue;
      const m = versions[v];
      const dist = isObj(m.dist) ? m.dist : {};
      out.locked[v] = {
        integrity: str(dist.integrity),
        shasum: str(dist.shasum),
        signatures: dist.signatures,
        attestations: isObj(dist.attestations) ? { provenance: !!dist.attestations.provenance } : null,
        time: timeOf(v),
        evidence: trustEvidence(m),
      };
    }
    return out;
  };
}

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

const groupBy = (items, key) => {
  const m = new Map();
  for (const it of items) {
    const k = key(it);
    if (!m.has(k)) m.set(k, []);
    m.get(k).push(it);
  }
  return m;
};
const listSome = (items, max = 10) => (items.length > max ? `${items.slice(0, max).join(', ')}, and ${items.length - max} more` : items.join(', '));
const iso = (ms) => new Date(ms).toISOString();

/**
 * The signatures command (main() runs it): see the top of this file.
 * @param {object} ctx core's command context
 */
export async function run(ctx) {
  // Every parameter first: a bad one is a usage error before any network access.
  const requireSignatures = ctx.bool('require_signatures', false);
  const allowUnbound = ctx.bool('allow_unbound', false);
  const requireProvenance = ctx.patterns('require_provenance', '');
  const sourceRules = parseProvenanceSources(ctx.lines('provenance_sources', ''));
  const noDowngrade = ctx.bool('no_downgrade', false);
  const downgradeExclude = ctx.patterns('downgrade_exclude', '', { versions: true });

  const { entries, lockfiles } = ctx.readLockfiles();
  const io = ctx.io;
  const configured = new Set([ctx.registries.registry, ...ctx.registries.scopes.values()]);
  const formatOf = new Map(lockfiles.map((l) => [l.rel, l.format]));
  const findings = [];
  const errors = [];
  const warnings = [];
  const skipped = [];
  const seen = new Set();

  const skip = (e, reason, detail) => skipped.push({ name: e.name, version: e.version, lockfile: e.lockfile, line: e.line, kind: e.kind, reason, detail });
  // One finding per lockfile, package version and kind.
  const find = (u, kind, message, details = {}) => {
    for (const e of u.entries) {
      const k = `${e.lockfile}\0${u.name}\0${u.version}\0${kind}`;
      if (seen.has(k)) continue;
      seen.add(k);
      findings.push(ctx.finding(e, { kind, message: `${u.name}@${u.version} in ${e.lockfile}: ${message}`, details: { registry: u.registry, ...details } }));
    }
  };
  const label = (u) => `${u.name}@${u.version} (${[...new Set(u.entries.map((e) => e.lockfile))].join(', ')})`;

  // --- Which entries are checked, grouped into units: one per registry, name, version and
  // lockfile integrity.
  const units = new Map();
  const otherRegistries = new Map();
  const unboundSkipped = new Map();
  for (const e of entries) {
    if (e.kind !== 'registry') {
      skip(e, 'not-from-a-registry', `a ${e.kind} dependency, which no registry signs`);
      continue;
    }
    if (e.bundled) {
      skip(e, 'bundled', "bundled in its parent's tarball, which the parent's signature covers");
      continue;
    }
    if (!configured.has(e.source)) {
      skip(e, 'other-registry', `from ${e.source}, which is neither registry nor a scope's registry`);
      if (!otherRegistries.has(e.source)) otherRegistries.set(e.source, []);
      otherRegistries.get(e.source).push(`${e.name}@${e.version}`);
      continue;
    }
    const unbound = unboundReason(e, formatOf.get(e.lockfile));
    if (unbound && !allowUnbound) {
      skip(e, 'unbound', `the lockfile records ${UNBOUND_ENTRY[unbound]}, which can't be bound to the registry's signature`);
      if (!unboundSkipped.has(e.lockfile)) unboundSkipped.set(e.lockfile, []);
      unboundSkipped.get(e.lockfile).push({ e, unbound });
      continue;
    }
    const key = [e.source, e.name, e.version, e.integrity ?? '', unbound ?? ''].join('\0');
    if (!units.has(key)) units.set(key, { name: e.name, version: e.version, registry: e.source, lockIntegrity: e.integrity, unbound, entries: [] });
    units.get(key).entries.push(e);
  }
  for (const [registry, names] of otherRegistries) {
    warnings.push(`${plural(names.length, 'package')} come${names.length === 1 ? 's' : ''} from ${registry}, which is neither registry nor a scope's registry (scopes, or .npmrc), so ${names.length === 1 ? 'its' : 'their'} signatures and provenance were not checked: ${listSome([...new Set(names)])}.`);
  }
  for (const [lockfile, list] of unboundSkipped) {
    const why = [...new Set(list.map((x) => UNBOUND_TEXT[x.unbound]))].join('; ');
    const names = [...new Set(list.map((x) => `${x.e.name}@${x.e.version}`))];
    errors.push({
      message: `${lockfile}: ${plural(names.length, 'package')} from a registry ${names.length === 1 ? 'has' : 'have'} no integrity this check can bind the registry's signature to (${why}), so this lockfile has no verdict: ${listSome(names, 5)}.\n`
        + `Set allow_unbound to true to verify ${names.length === 1 ? 'it' : 'them'} against the registry's own integrity instead, which shows that the registry signed what it serves, but not that the lockfile pins those bytes.`,
    });
  }
  if (allowUnbound) {
    const byLockfile = groupBy([...units.values()].filter((u) => u.unbound).flatMap((u) => u.entries.map((e) => ({ e, u }))), (x) => x.e.lockfile);
    for (const [lockfile, list] of byLockfile) {
      const why = [...new Set(list.map((x) => UNBOUND_TEXT[x.u.unbound]))].join('; ');
      warnings.push(`${lockfile}: ${plural(new Set(list.map((x) => `${x.u.name}@${x.u.version}`)).size, 'package')} ${list.length === 1 ? 'was' : 'were'} verified against the registry's own integrity, since the lockfile's can't be bound to the registry's signature (${why}): that shows the registry signed what it serves, not that the lockfile pins those bytes (allow_unbound).`);
    }
  }

  // Which packages a policy requires provenance of, and why.
  const sourceRuleFor = (name) => sourceRules.find((g) => g.pattern.re.test(name)) ?? null;
  const needsProvenance = (name) => {
    const p = matchesAny(name, requireProvenance);
    if (p) return { param: 'require_provenance', pattern: p.text };
    const s = sourceRuleFor(name);
    return s ? { param: 'provenance_sources', pattern: s.pattern.text } : null;
  };

  // --- Packuments, from each unit's registry.
  const byRegistry = groupBy(units.values(), (u) => u.registry);
  const packuments = new Map();
  const registrySigns = new Map();
  for (const [registry, list] of byRegistry) {
    const wanted = new Map();
    for (const u of list) {
      if (!wanted.has(u.name)) wanted.set(u.name, new Set());
      wanted.get(u.name).add(u.version);
    }
    const res = await ctx.client.getPackuments([...wanted.keys()], { pick: makePick(wanted, noDowngrade), registryFor: () => registry });
    packuments.set(registry, res);
    registrySigns.set(registry, isNpmjs(registry) || [...res.values()].some((r) => r.packument && r.packument.signed));
  }

  // --- Registry signatures, per unit.
  const fetchErrors = new Map();
  const unknownKeys = new Map();
  const unsignedRegistries = new Map();
  const results = [];
  for (const u of units.values()) {
    const res = {
      name: u.name, version: u.version, registry: u.registry, lockfiles: [...new Set(u.entries.map((e) => e.lockfile))],
      integrity: null, signature: null, keyids: [], attestations: null, provenance: null, trust: null, downgrade: null,
    };
    u.result = res;
    results.push(res);
    const r = packuments.get(u.registry).get(u.name);
    if (!r || (r.status !== 200 && r.status !== 404) || r.error) {
      res.signature = 'error';
      if (!fetchErrors.has(u.registry)) fetchErrors.set(u.registry, []);
      fetchErrors.get(u.registry).push(`${u.name} (${r?.error ?? 'no answer'})`);
      continue;
    }
    if (r.status === 404) {
      res.signature = 'not-in-registry';
      find(u, 'not-in-registry', `${u.registry} has no package ${u.name} (HTTP 404), so nothing can verify the locked version: it may have been unpublished, or come from another registry.`);
      continue;
    }
    const doc = r.packument;
    if (doc.malformed) {
      res.signature = 'error';
      errors.push({ message: `The packument of ${u.name} from ${u.registry} can't be read: ${doc.malformed}.` });
      continue;
    }
    const v = doc.locked[u.version];
    if (!v) {
      res.signature = 'not-in-registry';
      find(u, 'not-in-registry', `${u.registry} lists no version ${u.version} of ${u.name}, so nothing can verify it: it may have been unpublished, or come from another registry.`);
      continue;
    }
    u.v = v;
    u.doc = doc;
    res.trust = v.evidence;
    res.attestations = v.attestations ? { status: 'not-checked' } : { status: 'none' };
    const bound = bindIntegrity(u.lockIntegrity, u.unbound, v);
    res.integrity = bound.status;
    u.bound = bound;
    if (bound.status === 'mismatch') {
      res.attestations = { status: 'not-checked' };
      find(u, 'integrity-mismatch', `the lockfile's integrity (${short(u.lockIntegrity)}) is not ${v.integrity ? `the registry's (${short(v.integrity)})` : 'one the registry lists (it lists none)'}, so the locked tarball is not the one ${u.registry} published for this version.`, {
        lockfile_integrity: u.lockIntegrity, registry_integrity: v.integrity,
      });
      continue;
    }
    const sig = verifyRegistrySignature({ name: u.name, version: u.version, integrity: bound.integrity, signatures: v.signatures, publishedAt: v.time ?? null });
    res.signature = sig.status;
    res.keyids = sig.keyids;
    if (sig.status === 'invalid') {
      find(u, 'invalid', `its registry signature is invalid: ${sig.reason}. The package may have been tampered with since ${u.registry} published it.`, { keyids: sig.keyids });
    } else if (sig.status === 'unsigned') {
      if (registrySigns.get(u.registry) || requireSignatures) {
        const why = isNpmjs(u.registry) ? `${u.registry} signs the packages it publishes`
          : registrySigns.get(u.registry) ? `${u.registry} signs other packages` : 'require_signatures is true';
        find(u, 'unsigned', `it has no registry signature, but ${why}.`);
      } else {
        res.signature = 'skipped';
        for (const e of u.entries) skip(e, 'unsigned-registry', `${u.registry} has no registry signatures`);
        if (!unsignedRegistries.has(u.registry)) unsignedRegistries.set(u.registry, []);
        unsignedRegistries.get(u.registry).push(`${u.name}@${u.version}`);
      }
    } else if (sig.status === 'unknown-key') {
      const keyids = sig.keyids.filter((k) => !PINNED_KEYIDS.has(k));
      const k = `${u.registry}\0${keyids.join(' ')}`;
      if (!unknownKeys.has(k)) unknownKeys.set(k, { registry: u.registry, keyids, packages: [] });
      unknownKeys.get(k).packages.push(label(u));
    }
  }
  for (const [registry, list] of fetchErrors) {
    errors.push({ message: `Could not read ${plural(list.length, 'packument')} from ${registry}, so ${list.length === 1 ? 'that package has' : 'those packages have'} no verdict: ${listSome(list)}.` });
  }
  for (const { registry, keyids, packages } of unknownKeys.values()) {
    const why = isNpmjs(registry)
      ? 'npm has started signing with a key this orb does not pin yet, and an orb update is needed'
      : `${registry} signs with keys that are not the npm registry's, which this orb can't verify`;
    errors.push({ message: `${plural(packages.length, 'package')} ${packages.length === 1 ? 'is' : 'are'} signed with a registry key this orb doesn't know (${keyids.join(', ')}): ${why}, so ${packages.length === 1 ? 'it has' : 'they have'} no verdict: ${listSome(packages)}.` });
  }
  for (const [registry, names] of unsignedRegistries) {
    warnings.push(`${registry} has no registry signatures on any packument this check read, so the signatures of ${plural(names.length, 'package')} from it were not checked, and ${names.length === 1 ? 'it is' : 'they are'} listed as skipped: ${listSome(names)}. Set require_signatures to true to make that a finding.`);
  }

  // --- Attestations: advertised by the packument, or probed for a package a policy requires
  // provenance of. Never for an integrity mismatch.
  const attUnits = [...units.values()].filter((u) => u.v && u.bound && u.bound.status !== 'mismatch' && u.bound.integrity
    && (u.v.attestations || needsProvenance(u.name)));
  const attErrors = new Map();
  const missingAdvertised = new Map();
  const unsupported = [];
  for (const [registry, list] of groupBy(attUnits, (u) => u.registry)) {
    const res = await ctx.client.getAttestations(list.map((u) => ({ name: u.name, version: u.version, registry })));
    for (const u of list) {
      const a = res.get(`${u.name}@${u.version}`);
      if (!a || (a.status !== 200 && a.status !== 404) || a.error) {
        u.result.attestations = { status: 'error' };
        if (!attErrors.has(registry)) attErrors.set(registry, []);
        attErrors.get(registry).push(`${u.name}@${u.version} (${a?.error ?? 'no answer'})`);
        continue;
      }
      if (a.status === 404 || !a.attestations.length) {
        u.result.attestations = { status: u.v.attestations ? 'missing' : 'none' };
        if (u.v.attestations) {
          if (!missingAdvertised.has(registry)) missingAdvertised.set(registry, []);
          missingAdvertised.get(registry).push(label(u));
        }
        continue;
      }
      const verified = verifyAttestations({ attestations: a.attestations }, { name: u.name, version: u.version, integrity: u.bound.integrity });
      const s = verified.summary;
      u.verified = verified;
      u.result.attestations = { status: s.status, publish: s.publish, provenance: s.provenance, reason: s.reason };
      if (s.identity) {
        const i = s.identity;
        u.result.provenance = {
          issuer: i.issuer, repository: i.sourceRepositoryUri, repository_id: i.sourceRepositoryId, owner_id: i.sourceRepositoryOwnerId,
          ref: i.sourceRef, commit: i.sourceDigest, workflow: i.buildConfigUri, signer: i.san, runner: i.runnerEnvironment,
        };
      }
    }
  }
  for (const [registry, list] of attErrors) {
    errors.push({ message: `Could not read the attestations of ${plural(list.length, 'package')} from ${registry}, so ${list.length === 1 ? 'it has' : 'they have'} no verdict: ${listSome(list)}.` });
  }
  for (const [registry, list] of missingAdvertised) {
    if (isNpmjs(registry)) {
      errors.push({ message: `The packuments of ${plural(list.length, 'package')} advertise attestations that ${registry} does not serve, so ${list.length === 1 ? 'it has' : 'they have'} no verdict: ${listSome(list)}.` });
    } else {
      warnings.push(`The packuments of ${plural(list.length, 'package')} advertise attestations that ${registry} does not serve (a mirror may not serve /-/npm/v1/attestations), so they were not verified, and the packages count as having no provenance: ${listSome(list)}.`);
    }
  }

  // --- Attestation findings and provenance policies.
  // Units whose attestations had no answer (an error, or npmjs not serving what it advertises)
  // have no verdict already, and nothing to judge.
  for (const u of units.values()) {
    if (!u.v || !u.bound || u.bound.status === 'mismatch') continue;
    const st = u.result.attestations?.status;
    if (st === 'error' || (st === 'missing' && isNpmjs(u.registry))) continue;
    const s = u.verified?.summary ?? null;
    const need = needsProvenance(u.name);
    if (s && s.status === 'invalid') {
      find(u, 'invalid-attestation', `an attestation ${u.registry} serves for it does not verify: ${s.reason}.`);
      continue;
    }
    const validProvenance = !!(s && s.provenance === 'valid' && s.identity);
    const odd = (u.verified?.attestations ?? []).filter((a) => a.status === 'unsupported');
    if (odd.length) {
      if (need && !validProvenance && odd.some((a) => a.kind !== 'publish')) {
        find(u, 'unsupported-attestation', `${need.param} (${need.pattern}) requires provenance, but its provenance is in a format this orb can't verify yet: ${odd.map((a) => a.reason).join('; ')}.`);
        continue;
      }
      unsupported.push(`${label(u)}: ${odd.map((a) => `${a.predicateType ?? 'an attestation'} (${a.reason})`).join('; ')}`);
    }
    if (need && !validProvenance) {
      const what = u.result.attestations?.status === 'missing' ? 'provenance its registry serves (the packument advertises attestations that the registry does not serve)' : 'provenance';
      find(u, 'missing-provenance', `it has no ${what}, which ${need.param} (${need.pattern}) requires.`);
      continue;
    }
    const rule = sourceRuleFor(u.name);
    if (rule && validProvenance && !rule.repos.some((r) => repositoryMatches(s.identity, r))) {
      const i = s.identity;
      find(u, 'provenance-source', `its provenance was built from ${i.sourceRepositoryUri ?? 'no named repository'} (repository ID ${i.sourceRepositoryId ?? 'unknown'}), but provenance_sources (${rule.pattern.text}) expects ${rule.repos.map((r) => r.text).join(' or ')}.`, {
        expected: rule.repos.map((r) => r.text), repository: i.sourceRepositoryUri, repository_id: i.sourceRepositoryId, issuer: i.issuer,
      });
    }
  }
  if (unsupported.length) {
    warnings.push(`The attestations of ${plural(unsupported.length, 'package')} use a format this orb can't verify yet, so they were not verified (an orb update may support them):\n${unsupported.slice(0, 10).join('\n')}${unsupported.length > 10 ? `\nand ${unsupported.length - 10} more` : ''}`);
  }

  // --- no_downgrade.
  let downgrades = 0;
  if (noDowngrade) {
    const missingTime = [];
    for (const u of units.values()) {
      if (!u.v || matchesAny(u.name, downgradeExclude, u.version)) continue;
      const t = Date.parse(u.v.time);
      if (Number.isNaN(t)) {
        missingTime.push(label(u));
        continue;
      }
      const d = findDowngrade(u.doc.history, u.version, t, u.v.evidence);
      if (!d) continue;
      downgrades += 1;
      u.result.downgrade = { version: d.version, published: iso(d.time), evidence: d.evidence };
      find(u, 'provenance-downgrade', `it was published ${iso(t)} with ${TRUST_TEXT[u.v.evidence]}, but ${d.version}, published earlier (${iso(d.time)}), had ${TRUST_TEXT[d.evidence]}. A trust downgrade can mean the package was taken over; if this one is expected, add ${u.name}@${u.version} to downgrade_exclude.`, {
        evidence: u.v.evidence, earlier_version: d.version, earlier_evidence: d.evidence, earlier_published: iso(d.time),
      });
    }
    if (missingTime.length) {
      errors.push({ message: `The registry gives no publish time for ${plural(missingTime.length, 'locked version')}, so no_downgrade can't compare ${missingTime.length === 1 ? 'it' : 'them'} with earlier versions, and ${missingTime.length === 1 ? 'it has' : 'they have'} no verdict: ${listSome(missingTime)}. Add ${missingTime.length === 1 ? 'it' : 'them'} to downgrade_exclude to skip the comparison.` });
    }
  }

  // --- Summary.
  const count = (pred) => results.filter(pred).length;
  const sigCount = (s) => count((r) => r.signature === s);
  const attCount = (s) => count((r) => r.attestations?.status === s);
  const skipCount = (reason) => skipped.filter((s) => s.reason === reason).length;
  const summary = {
    lockfiles: lockfiles.length,
    packages: units.size,
    signatures: {
      valid: sigCount('valid'), invalid: sigCount('invalid'), unsigned: sigCount('unsigned'), unknown_key: sigCount('unknown-key'),
      integrity_mismatch: count((r) => r.integrity === 'mismatch'), not_in_registry: sigCount('not-in-registry'),
      unbound_verified: count((r) => r.integrity === 'registry' && r.signature === 'valid'), errors: sigCount('error'),
    },
    attestations: {
      verified: attCount('valid'), with_provenance: count((r) => r.provenance !== null), invalid: attCount('invalid'),
      unsupported: attCount('unsupported'), missing: attCount('missing'), errors: attCount('error'),
    },
    downgrades,
    skipped: {
      not_from_a_registry: skipCount('not-from-a-registry'), bundled: skipCount('bundled'), other_registry: skipCount('other-registry'),
      unbound: skipCount('unbound'), unsigned_registry: skipCount('unsigned-registry'),
    },
    registries: [...byRegistry.entries()].map(([url, list]) => ({ url, signs: !!registrySigns.get(url), packages: list.length })),
    policies: {
      require_signatures: requireSignatures,
      allow_unbound: allowUnbound,
      require_provenance: requireProvenance.map((p) => p.text),
      provenance_sources: sourceRules.map((g) => ({ pattern: g.pattern.text, repositories: g.repos.map((r) => r.text) })),
      no_downgrade: noDowngrade,
      downgrade_exclude: downgradeExclude.map((p) => p.text),
    },
  };
  const s = summary.signatures;
  io.log(`Checked ${plural(units.size, 'package version')} from ${plural(lockfiles.length, 'lockfile')}: ${plural(s.valid, 'registry signature')} verified${s.unbound_verified ? ` (${s.unbound_verified} against the registry's own integrity)` : ''}, ${plural(summary.attestations.verified, 'package')} with verified attestations (${summary.attestations.with_provenance} with provenance).`);
  const sk = summary.skipped;
  const skippedText = [
    sk.not_from_a_registry && `${sk.not_from_a_registry} not from a registry`, sk.bundled && `${sk.bundled} bundled`,
    sk.other_registry && `${sk.other_registry} from another registry`, sk.unbound && `${sk.unbound} with an unbound integrity`,
    sk.unsigned_registry && `${sk.unsigned_registry} from a registry without signatures`,
  ].filter(Boolean);
  if (skippedText.length) io.log(`Not checked: ${skippedText.join(', ')}.`);

  // Checked: a package version that got a verdict on its registry signature (or binding).
  const checked = count((r) => ['valid', 'invalid', 'unsigned', 'unknown-key', 'not-in-registry'].includes(r.signature) || r.integrity === 'mismatch');
  if (checked === 0 && (units.size > 0 || sk.other_registry > 0) && !ctx.allowEmpty && !errors.length) {
    errors.push({ message: 'No registry signature was checked: every package from a registry was skipped (see the warnings), so this check checked nothing. Set require_signatures to true to make unsigned packages findings, or allow_empty to true to pass.' });
  }

  return {
    findings,
    errors,
    warnings,
    skipped,
    summary,
    results,
    rules: RULES,
    checked,
    counts: {
      packages: units.size,
      signatures_valid: s.valid,
      attestations_verified: summary.attestations.verified,
      provenance: summary.attestations.with_provenance,
      downgrades,
      skipped: skipped.length,
    },
  };
}

// Run as the step's entry point (node .../helper/signatures.mjs), not when a test imports it.
const entry = (() => {
  try { return fs.realpathSync(process.argv[1] ?? '') === fs.realpathSync(fileURLToPath(import.meta.url)); } catch { return false; }
})();
if (entry) await main('signatures', run);
