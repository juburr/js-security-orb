// Unit tests of src/helper/sigstore.mjs, offline. Real registry data recorded on 2026-11-02 is in
// tests/fixtures/signatures/ (packument version slices, the registry keys from both sources) and
// tests/fixtures/attestations/ (attestation responses as served); tampered and unsupported cases
// are made from them in memory. A synthetic Sigstore (a Fulcio CA, Rekor and CT log keys and an
// npm registry key generated here, with certificates built by hand) covers what real data can't
// reach without breaking a signature first.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import {
  NPM_REGISTRY_KEYS,
  TRUSTED_ROOT,
  TRUSTED_ROOT_JSON,
  TRUSTED_ROOT_SHA256,
  PUBLISH_ATTESTATION,
  SLSA_PROVENANCE_V02,
  SLSA_PROVENANCE_V1,
  verifyRegistrySignature,
  verifyAttestations,
  integrityToHex,
  packagePurl,
  npmKeyId,
  certificateIdentity,
} from '../../src/helper/sigstore.mjs';

const MODULE = new URL('../../src/helper/sigstore.mjs', import.meta.url);
const FIXTURES = new URL('../fixtures/', import.meta.url);
const readRaw = (rel) => readFileSync(new URL(rel, FIXTURES));
const readJson = (rel) => JSON.parse(readRaw(rel).toString('utf8'));
const slice = (slug) => readJson(`signatures/${slug}.json`);
const response = (slug) => readJson(`attestations/${slug}.json`);
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const clone = (v) => structuredClone(v);

const ATTESTED = ['semver@7.5.1', 'semver@7.8.6', 'axios@1.9.0', 'vite@8.3.5', '@babel__core@8.1.0', '@tanstack__react-query@5.51.1'];
const OLD_KEY = 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA';
const NEW_KEY = 'SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U';
const GITHUB = 'https://token.actions.githubusercontent.com';

function verifyFixture(slug, resp = response(slug), opts = {}) {
  const s = slice(slug);
  return verifyAttestations(resp, { name: s.name, version: s.version, integrity: s.dist.integrity, ...opts });
}
const of = (result, kind) => result.attestations.find((a) => a.kind === kind);
function editBundle(resp, kind, fn) {
  const a = resp.attestations.find((x) => (kind === 'publish' ? x.predicateType === PUBLISH_ATTESTATION : x.predicateType !== PUBLISH_ATTESTATION));
  fn(a.bundle, a);
  return resp;
}
function flipBase64(s, index = 10) {
  const buf = Buffer.from(s, 'base64');
  buf[index % buf.length] ^= 0x01;
  return buf.toString('base64');
}
function assertStatus(result, kind, status, pattern) {
  const a = of(result, kind);
  assert.ok(a, `no ${kind} attestation`);
  assert.equal(a.status, status, `${kind}: ${a.reason} (expected ${pattern})`);
  if (pattern) assert.match(a.reason, pattern);
  if (status !== 'valid') {
    assert.equal(a.identity, null);
    // Never valid in the summary either.
    assert.notEqual(result.summary.status, 'valid');
    assert.notEqual(result.summary[kind], 'valid');
    if (kind === 'provenance') assert.equal(result.summary.identity, null);
  }
}

// ---------------------------------------------------------------------------------------------
describe('the module', () => {
  test('is under 120,000 bytes, so it fits in one environment variable', () => {
    assert.ok(statSync(MODULE).size < 120000, `${statSync(MODULE).size} bytes`);
  });

  test('imports nothing but node: built-ins', () => {
    const source = readFileSync(MODULE, 'utf8');
    const imports = [...source.matchAll(/^\s*import\b[^'"]*['"]([^'"]+)['"]/gm)].map((m) => m[1]);
    assert.deepEqual(imports, ['node:crypto']);
    assert.doesNotMatch(source, /\bimport\s*\(/);
    assert.doesNotMatch(source, /\brequire\s*\(/);
  });
});

describe('pinned data', () => {
  test('NPM_REGISTRY_KEYS is the recorded /-/npm/v1/keys response', () => {
    assert.deepEqual(clone(NPM_REGISTRY_KEYS), readJson('signatures/npm-keys.json').keys);
  });

  test('NPM_REGISTRY_KEYS agrees with the Sigstore TUF target registry.npmjs.org/keys.json', () => {
    const raw = readRaw('signatures/tuf-registry.npmjs.org-keys.json');
    assert.equal(sha256(raw).toString('hex'), '160677eb6e1c7083c89b166b20f8fe4e837fb71181506aff1991b80b89184f7d');
    const tuf = JSON.parse(raw.toString('utf8')).keys;
    assert.deepEqual([...new Set(tuf.map((k) => k.keyId))].sort(), NPM_REGISTRY_KEYS.map((k) => k.keyid).sort());
    for (const t of tuf) {
      const pinned = NPM_REGISTRY_KEYS.find((k) => k.keyid === t.keyId);
      assert.equal(pinned.key, t.publicKey.rawBytes);
      assert.equal(t.publicKey.keyDetails, 'PKIX_ECDSA_P256_SHA_256');
      assert.equal(pinned.expires, t.publicKey.validFor.end ?? null);
    }
  });

  test('the recorded attestation responses are as served (index.json hashes)', () => {
    const index = readJson('attestations/index.json');
    assert.deepEqual(Object.keys(index.files).sort(), ATTESTED.map((s) => `${s}.json`).sort());
    for (const [file, meta] of Object.entries(index.files)) {
      assert.equal(sha256(readRaw(`attestations/${file}`)).toString('hex'), meta.sha256, file);
      assert.equal(slice(file.slice(0, -5)).dist.integrity, meta.integrity, file);
    }
  });

  test('every keyid is the OpenSSH SHA256 fingerprint of its key', () => {
    for (const k of NPM_REGISTRY_KEYS) assert.equal(npmKeyId(k.key), k.keyid);
    const ed = crypto.generateKeyPairSync('ed25519').publicKey;
    assert.throws(() => npmKeyId(ed), TypeError);
  });

  test('TRUSTED_ROOT is the TUF target trusted_root.json, byte for byte, and frozen', () => {
    assert.equal(sha256(TRUSTED_ROOT_JSON).toString('hex'), TRUSTED_ROOT_SHA256);
    assert.equal(TRUSTED_ROOT_SHA256, '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66');
    assert.deepEqual(TRUSTED_ROOT, JSON.parse(TRUSTED_ROOT_JSON));
    assert.ok(Object.isFrozen(TRUSTED_ROOT) && Object.isFrozen(TRUSTED_ROOT.tlogs[0].publicKey));
    assert.ok(Object.isFrozen(NPM_REGISTRY_KEYS) && Object.isFrozen(NPM_REGISTRY_KEYS[0]));
    assert.deepEqual(TRUSTED_ROOT.tlogs.map((l) => [l.baseUrl, l.publicKey.keyDetails]), [
      ['https://rekor.sigstore.dev', 'PKIX_ECDSA_P256_SHA_256'],
      ['https://log2025-1.rekor.sigstore.dev', 'PKIX_ED25519'],
    ]);
    assert.equal(TRUSTED_ROOT.certificateAuthorities.length, 2);
    assert.equal(TRUSTED_ROOT.ctlogs.length, 2);
    assert.equal(TRUSTED_ROOT.timestampAuthorities.length, 1);
  });
});

// ---------------------------------------------------------------------------------------------
describe('integrityToHex and packagePurl', () => {
  test('integrityToHex returns the sha512 digest in hex', () => {
    const s = slice('semver@7.8.6');
    const statement = JSON.parse(Buffer.from(response('semver@7.8.6').attestations[0].bundle.dsseEnvelope.payload, 'base64'));
    assert.equal(integrityToHex(s.dist.integrity), statement.subject[0].digest.sha512);
    assert.equal(integrityToHex(s.dist.integrity), Buffer.from(s.dist.integrity.slice(7), 'base64').toString('hex'));
  });

  test('integrityToHex reads SRI lists and options, and is strict', () => {
    const sha512 = `sha512-${Buffer.alloc(64, 7).toString('base64')}`;
    const sha1 = `sha1-${Buffer.alloc(20, 1).toString('base64')}`;
    const hex = Buffer.alloc(64, 7).toString('hex');
    assert.equal(integrityToHex(`${sha1} ${sha512}`), hex);
    assert.equal(integrityToHex(`${sha512}?opt ${sha512}`), hex);
    assert.equal(integrityToHex(sha1, 'sha1'), Buffer.alloc(20, 1).toString('hex'));
    assert.equal(integrityToHex(sha1), null);
    assert.equal(integrityToHex(`${sha512} sha512-${Buffer.alloc(64, 8).toString('base64')}`), null);
    assert.equal(integrityToHex(`sha512-${Buffer.alloc(32).toString('base64')}`), null);
    assert.equal(integrityToHex('sha512-not*base64'), null);
    assert.equal(integrityToHex(`sha512-${Buffer.alloc(64, 7).toString('base64').replace(/=+$/, '')}`), null);
    assert.equal(integrityToHex(''), null);
    assert.equal(integrityToHex(null), null);
    assert.throws(() => integrityToHex(sha512, 'md5'), TypeError);
  });

  test('packagePurl encodes a scope as npm does', () => {
    assert.equal(packagePurl('semver', '7.8.6'), 'pkg:npm/semver@7.8.6');
    assert.equal(packagePurl('@babel/core', '8.1.0'), 'pkg:npm/%40babel/core@8.1.0');
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyRegistrySignature', () => {
  const input = (slug, over = {}) => {
    const s = slice(slug);
    return { name: s.name, version: s.version, integrity: s.dist.integrity, signatures: s.dist.signatures, publishedAt: s.time, ...over };
  };

  test('every recorded signature verifies, with the key of its time', () => {
    const expected = {
      'lodash@4.17.21': [OLD_KEY],
      'semver@7.5.1': [OLD_KEY],
      '@tanstack__react-query@5.51.1': [OLD_KEY],
      'axios@1.9.0': [NEW_KEY],
      'semver@7.8.6': [NEW_KEY],
      'vite@8.3.5': [NEW_KEY],
      '@babel__core@8.1.0': [NEW_KEY],
    };
    for (const [slug, keyids] of Object.entries(expected)) {
      const r = verifyRegistrySignature(input(slug));
      assert.equal(r.status, 'valid', `${slug}: ${r.reason}`);
      assert.deepEqual(r.keyids, keyids);
    }
    assert.ok(Date.parse(slice('lodash@4.17.21').time) < Date.parse('2025-01-29T00:00:00Z'));
  });

  test('two signatures by the same key both verify, and both must', () => {
    const s = slice('semver@7.8.6');
    assert.equal(s.dist.signatures.length, 2);
    assert.equal(s.dist.signatures[0].keyid, s.dist.signatures[1].keyid);
    assert.notEqual(s.dist.signatures[0].sig, s.dist.signatures[1].sig);
    const r = verifyRegistrySignature(input('semver@7.8.6'));
    assert.equal(r.status, 'valid');
    assert.deepEqual(r.keyids, [NEW_KEY]);
    assert.match(r.reason, /all 2 signatures/);
    const sigs = clone(s.dist.signatures);
    sigs[1].sig = flipBase64(sigs[1].sig, 20);
    const bad = verifyRegistrySignature(input('semver@7.8.6', { signatures: sigs }));
    assert.equal(bad.status, 'invalid');
    assert.match(bad.reason, /signature 2 by key/);
  });

  test('a version without signatures is unsigned', () => {
    const r = verifyRegistrySignature(input('jest@0.0.7'));
    assert.equal(r.status, 'unsigned');
    assert.deepEqual(r.keyids, []);
    assert.equal(verifyRegistrySignature(input('axios@1.9.0', { signatures: [] })).status, 'unsigned');
  });

  test('a changed integrity is invalid', () => {
    const other = slice('semver@7.5.1').dist.integrity;
    const r = verifyRegistrySignature(input('semver@7.8.6', { integrity: other }));
    assert.equal(r.status, 'invalid');
    assert.match(r.reason, /does not verify over semver@7\.8\.6:<integrity>/);
    assert.equal(verifyRegistrySignature(input('axios@1.9.0', { integrity: null })).status, 'invalid');
  });

  test('a signature presented for another version or package is invalid', () => {
    const r = verifyRegistrySignature(input('semver@7.8.6', { version: '7.8.5' }));
    assert.equal(r.status, 'invalid');
    const lodash = slice('lodash@4.17.21');
    const r2 = verifyRegistrySignature(input('semver@7.5.1', { signatures: lodash.dist.signatures }));
    assert.equal(r2.status, 'invalid');
  });

  test('a key that had expired when the version was published is invalid', () => {
    const r = verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: '2025-06-01T00:00:00.000Z' }));
    assert.equal(r.status, 'invalid');
    assert.match(r.reason, /expired 2025-01-29T00:00:00\.000Z/);
    // npm's comparison is strict: published at the expiry instant is too late.
    assert.equal(verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: '2025-01-29T00:00:00.000Z' })).status, 'invalid');
    assert.equal(verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: Date.parse('2025-01-28T23:59:59.999Z') })).status, 'valid');
    assert.equal(verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: new Date('2021-02-20T15:42:16.891Z') })).status, 'valid');
    const garbled = verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: 'yesterday' }));
    assert.equal(garbled.status, 'invalid');
    assert.match(garbled.reason, /not a date/);
    // The current key has no expiry, so the time doesn't matter.
    assert.equal(verifyRegistrySignature(input('axios@1.9.0', { publishedAt: '2099-01-01T00:00:00Z' })).status, 'valid');
  });

  test('without a publish time, npm\'s 2015-01-01 cutoff applies', () => {
    assert.equal(verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: undefined })).status, 'valid');
    const keys = clone(NPM_REGISTRY_KEYS);
    keys[0].expires = '2014-12-31T00:00:00.000Z';
    const r = verifyRegistrySignature(input('lodash@4.17.21', { publishedAt: null }), keys);
    assert.equal(r.status, 'invalid');
    assert.match(r.reason, /no publish time/);
  });

  test('an unknown keyid is unknown-key, and a bad signature still wins', () => {
    const s = slice('axios@1.9.0');
    const sigs = [{ keyid: 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', sig: s.dist.signatures[0].sig }];
    const r = verifyRegistrySignature(input('axios@1.9.0', { signatures: sigs }));
    assert.equal(r.status, 'unknown-key');
    assert.deepEqual(r.keyids, [sigs[0].keyid]);
    // One good signature does not make up for one under an unknown key (npm aborts on it).
    const mixed = verifyRegistrySignature(input('axios@1.9.0', { signatures: [...s.dist.signatures, ...sigs] }));
    assert.equal(mixed.status, 'unknown-key');
    const bad = [{ ...s.dist.signatures[0], sig: flipBase64(s.dist.signatures[0].sig, 30) }, ...sigs];
    assert.equal(verifyRegistrySignature(input('axios@1.9.0', { signatures: bad })).status, 'invalid');
    // A pinned key set without the current key.
    assert.equal(verifyRegistrySignature(input('axios@1.9.0'), [NPM_REGISTRY_KEYS[0]]).status, 'unknown-key');
  });

  test('malformed signatures are invalid', () => {
    const s = slice('axios@1.9.0');
    for (const signatures of [{ keyid: NEW_KEY }, [null], [{ keyid: NEW_KEY }], [{ keyid: NEW_KEY, sig: 'not base64!' }], [{ keyid: NEW_KEY, sig: '' }]]) {
      assert.equal(verifyRegistrySignature(input('axios@1.9.0', { signatures })).status, 'invalid', JSON.stringify(signatures));
    }
    assert.equal(verifyRegistrySignature(input('axios@1.9.0', { signatures: [{ ...s.dist.signatures[0], sig: `${s.dist.signatures[0].sig}AA==` }] })).status, 'invalid');
  });

  test('keys: the response shape, other registries\' keys, and keys the orb cannot use', () => {
    assert.equal(verifyRegistrySignature(input('axios@1.9.0'), readJson('signatures/npm-keys.json')).status, 'valid');
    // A registry whose keyids aren't fingerprints, with a PEM key.
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const msg = 'left-pad@1.3.0:sha512-abc';
    const sig = crypto.sign('sha256', Buffer.from(msg), privateKey).toString('base64');
    const keys = [{ keyid: 'corp-2026', pem: publicKey.export({ type: 'spki', format: 'pem' }), expires: null }];
    const ok = verifyRegistrySignature({ name: 'left-pad', version: '1.3.0', integrity: 'sha512-abc', signatures: [{ keyid: 'corp-2026', sig }] }, keys);
    assert.equal(ok.status, 'valid');
    // A SHA256: keyid that is not the key's fingerprint is unusable.
    const lying = [{ ...NPM_REGISTRY_KEYS[1], key: NPM_REGISTRY_KEYS[0].key }];
    const r = verifyRegistrySignature(input('axios@1.9.0'), lying);
    assert.equal(r.status, 'unknown-key');
    assert.match(r.reason, /not the fingerprint/);
    const otherScheme = [{ ...NPM_REGISTRY_KEYS[1], scheme: 'ed25519' }];
    assert.match(verifyRegistrySignature(input('axios@1.9.0'), otherScheme).reason, /scheme/);
    const twice = [NPM_REGISTRY_KEYS[1], { ...NPM_REGISTRY_KEYS[1], expires: '2030-01-01T00:00:00Z' }];
    assert.match(verifyRegistrySignature(input('axios@1.9.0'), twice).reason, /listed twice/);
    assert.throws(() => verifyRegistrySignature(input('axios@1.9.0'), 'keys'), TypeError);
    assert.throws(() => verifyRegistrySignature({ version: '1.0.0' }), TypeError);
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyAttestations: recorded attestations', () => {
  const identities = {
    'semver@7.5.1': {
      sourceRepositoryUri: 'https://github.com/npm/node-semver',
      sourceRepositoryId: '1357199',
      sourceRepositoryOwnerId: '6078720',
      sourceRef: 'refs/heads/main',
      sourceDigest: 'aa016a67162c195938f7873ea29a73dac47ff9ba',
      buildConfigUri: 'https://github.com/npm/node-semver/.github/workflows/release.yml@refs/heads/main',
      signerUri: 'https://github.com/npm/node-semver/.github/workflows/release.yml@refs/heads/main',
      sourceRepositoryVisibility: null,
      buildType: 'https://github.com/npm/cli/gha/v2',
    },
    'semver@7.8.6': {
      sourceRepositoryUri: 'https://github.com/npm/node-semver',
      sourceRepositoryId: '1357199',
      sourceRepositoryOwnerId: '6078720',
      sourceRef: 'refs/heads/main',
      sourceDigest: 'b37b033b585ad5e575afeccadb426ea41bc6cea4',
      // A reusable workflow signed it: the SAN is not the repository's workflow.
      buildConfigUri: 'https://github.com/npm/node-semver/.github/workflows/release.yml@refs/heads/main',
      signerUri: 'https://github.com/npm/node-semver/.github/workflows/release-integration.yml@refs/heads/main',
      san: 'https://github.com/npm/node-semver/.github/workflows/release-integration.yml@refs/heads/main',
      sourceRepositoryVisibility: 'public',
      buildTrigger: 'push',
    },
    'axios@1.9.0': {
      sourceRepositoryUri: 'https://github.com/axios/axios',
      sourceRepositoryId: '23088740',
      sourceRepositoryOwnerId: '32372333',
      sourceRef: 'refs/heads/v1.x',
      sourceDigest: 'cdcfd214c169a1acba8e267ab8e77ff4dfec3105',
      buildConfigUri: 'https://github.com/axios/axios/.github/workflows/publish.yml@refs/heads/v1.x',
    },
    'vite@8.3.5': {
      sourceRepositoryUri: 'https://github.com/vitejs/vite',
      sourceRepositoryId: '257485422',
      sourceRepositoryOwnerId: '65625612',
      buildConfigUri: 'https://github.com/vitejs/vite/.github/workflows/publish.yml@refs/heads/main',
    },
    '@babel__core@8.1.0': {
      sourceRepositoryUri: 'https://github.com/babel/babel',
      sourceRepositoryId: '24560307',
      sourceRepositoryOwnerId: '9637642',
      sourceRef: 'refs/tags/v8.1.0',
      sourceDigest: '541bdc8bb8c084f9a3621553d4ada500565cc48f',
      buildConfigUri: 'https://github.com/babel/babel/.github/workflows/release.yml@refs/tags/v8.1.0',
    },
    '@tanstack__react-query@5.51.1': {
      sourceRepositoryUri: 'https://github.com/TanStack/query',
      sourceRepositoryId: '207645083',
      sourceRepositoryOwnerId: '72518640',
      buildConfigUri: 'https://github.com/TanStack/query/.github/workflows/ci.yml@refs/heads/main',
    },
  };

  for (const slug of ATTESTED) {
    test(`${slug} verifies, with the expected identity`, () => {
      const r = verifyFixture(slug);
      assert.equal(r.summary.status, 'valid', r.summary.reason);
      assert.equal(r.summary.provenance, 'valid');
      for (const a of r.attestations) assert.equal(a.status, 'valid', `${a.predicateType}: ${a.reason}`);
      const id = r.summary.identity;
      assert.equal(id.issuer, GITHUB);
      assert.equal(id.runnerEnvironment, 'github-hosted');
      for (const [k, v] of Object.entries(identities[slug])) assert.equal(id[k], v, k);
      assert.deepEqual(id.workflow, {
        repository: id.sourceRepositoryUri,
        path: id.buildConfigUri.slice(id.sourceRepositoryUri.length + 1, id.buildConfigUri.lastIndexOf('@')),
        ref: id.sourceRef,
      });
      assert.equal(of(r, 'provenance').identity, id);
      assert.equal(of(r, 'provenance').signer, 'fulcio-certificate');
    });
  }

  test('the publish attestations are signed by the registry key of their time', () => {
    const keyOf = (slug) => of(verifyFixture(slug), 'publish');
    for (const [slug, keyid] of [['semver@7.5.1', OLD_KEY], ['@tanstack__react-query@5.51.1', OLD_KEY], ['axios@1.9.0', NEW_KEY], ['semver@7.8.6', NEW_KEY], ['vite@8.3.5', NEW_KEY]]) {
      const p = keyOf(slug);
      assert.equal(p.status, 'valid');
      assert.equal(p.signer, 'npm-registry-key');
      assert.equal(p.keyid, keyid);
      assert.equal(p.registry, 'https://registry.npmjs.org');
      assert.equal(p.identity, null);
    }
  });

  test('the fixtures cover bundles v0.1 to v0.3, SLSA v0.2 and v1, both tlog kinds and a timestamp', () => {
    const seen = { media: new Set(), predicates: new Set(), kinds: new Set(), statements: new Set() };
    for (const slug of ATTESTED) {
      for (const a of response(slug).attestations) {
        seen.media.add(a.bundle.mediaType);
        seen.predicates.add(a.predicateType);
        for (const e of a.bundle.verificationMaterial.tlogEntries) seen.kinds.add(`${e.kindVersion.kind}/${e.kindVersion.version}`);
        seen.statements.add(JSON.parse(Buffer.from(a.bundle.dsseEnvelope.payload, 'base64'))._type);
      }
    }
    assert.deepEqual([...seen.media].sort(), [
      'application/vnd.dev.sigstore.bundle+json;version=0.1',
      'application/vnd.dev.sigstore.bundle+json;version=0.2',
      'application/vnd.dev.sigstore.bundle.v0.3+json',
    ]);
    assert.deepEqual([...seen.predicates].sort(), [PUBLISH_ATTESTATION, SLSA_PROVENANCE_V02, SLSA_PROVENANCE_V1].sort());
    assert.deepEqual([...seen.kinds].sort(), ['dsse/0.0.1', 'intoto/0.0.2']);
    assert.equal(seen.statements.size, 2);
    const vite = of(verifyFixture('vite@8.3.5'), 'provenance');
    assert.deepEqual(vite.timestamps, ['2026-10-21T06:35:40.000Z']);
    assert.equal(vite.integratedTime, '2026-10-21T06:35:40.000Z');
  });

  test('a version with provenance but no publish attestation', () => {
    const r = verifyFixture('@babel__core@8.1.0');
    assert.equal(r.attestations.length, 1);
    assert.equal(r.summary.publish, null);
    assert.equal(r.summary.provenance, 'valid');
    assert.equal(r.summary.status, 'valid');
  });

  test('a version with a publish attestation but no provenance', () => {
    const resp = response('semver@7.8.6');
    resp.attestations = resp.attestations.filter((a) => a.predicateType === PUBLISH_ATTESTATION);
    const r = verifyFixture('semver@7.8.6', resp);
    assert.deepEqual([r.summary.status, r.summary.publish, r.summary.provenance, r.summary.identity], ['valid', 'valid', null, null]);
  });

  test('no attestations, and malformed responses', () => {
    assert.deepEqual(verifyFixture('axios@1.9.0', { attestations: [] }).summary, { status: 'none', publish: null, provenance: null, identity: null, reason: null });
    for (const resp of [null, {}, { attestations: 'x' }, { error: 'Not found' }]) {
      const r = verifyFixture('axios@1.9.0', resp);
      assert.equal(r.summary.status, 'invalid');
      assert.deepEqual(r.attestations, []);
    }
    const r = verifyFixture('axios@1.9.0', { attestations: [null, { predicateType: 7 }] });
    assert.deepEqual(r.attestations.map((a) => a.status), ['invalid', 'invalid']);
    assert.throws(() => verifyAttestations({ attestations: [] }, { version: '1.0.0' }), TypeError);
  });

  test('the same provenance twice is still valid', () => {
    const resp = response('axios@1.9.0');
    resp.attestations.push(clone(resp.attestations[1]));
    const r = verifyFixture('axios@1.9.0', resp);
    assert.equal(r.summary.provenance, 'valid');
    assert.equal(r.summary.identity.sourceRepositoryId, '23088740');
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyAttestations: tampering is invalid', () => {
  test('another integrity: the subject digest does not match', () => {
    const r = verifyFixture('semver@7.8.6', undefined, { integrity: slice('semver@7.5.1').dist.integrity });
    assertStatus(r, 'publish', 'invalid', /sha512 digest is not the integrity's/);
    assertStatus(r, 'provenance', 'invalid', /sha512 digest is not the integrity's/);
    const sha1 = verifyFixture('semver@7.8.6', undefined, { integrity: `sha1-${slice('semver@7.8.6').dist.shasum}` });
    assertStatus(sha1, 'provenance', 'invalid', /no sha512 digest/);
  });

  test('another package or version: the subject name does not match', () => {
    const r = verifyFixture('semver@7.8.6', undefined, { version: '7.8.5' });
    assertStatus(r, 'provenance', 'invalid', /subject "pkg:npm\/semver@7\.8\.6" is not pkg:npm\/semver@7\.8\.5/);
    const scoped = verifyFixture('@babel__core@8.1.0', undefined, { name: 'babel-core' });
    assertStatus(scoped, 'provenance', 'invalid', /%40babel\/core/);
    const swapped = verifyFixture('semver@7.8.6', response('axios@1.9.0'));
    assertStatus(swapped, 'publish', 'invalid', /subject/);
    assertStatus(swapped, 'provenance', 'invalid', /subject/);
  });

  test('a subject digest rewritten to match another tarball breaks the DSSE signature', () => {
    const evil = `sha512-${crypto.createHash('sha512').update('evil').digest('base64')}`;
    const resp = response('semver@7.8.6');
    for (const a of resp.attestations) {
      const st = JSON.parse(Buffer.from(a.bundle.dsseEnvelope.payload, 'base64'));
      st.subject[0].digest.sha512 = integrityToHex(evil);
      a.bundle.dsseEnvelope.payload = Buffer.from(JSON.stringify(st)).toString('base64');
    }
    const r = verifyFixture('semver@7.8.6', resp, { integrity: evil });
    assertStatus(r, 'publish', 'invalid', /DSSE signature does not verify with the npm registry key/);
    assertStatus(r, 'provenance', 'invalid', /DSSE signature does not verify with the certificate's key/);
  });

  test('one changed byte of a DSSE payload', () => {
    for (const kind of ['publish', 'provenance']) {
      const resp = editBundle(response('axios@1.9.0'), kind, (b) => {
        const p = Buffer.from(b.dsseEnvelope.payload, 'base64');
        const i = p.indexOf('axios');
        p[i] = 'A'.charCodeAt(0);
        b.dsseEnvelope.payload = p.toString('base64');
      });
      assertStatus(verifyFixture('axios@1.9.0', resp), kind, 'invalid', /DSSE signature does not verify/);
    }
  });

  test('a changed DSSE signature', () => {
    for (const kind of ['publish', 'provenance']) {
      const resp = editBundle(response('vite@8.3.5'), kind, (b) => { b.dsseEnvelope.signatures[0].sig = flipBase64(b.dsseEnvelope.signatures[0].sig, 40); });
      assertStatus(verifyFixture('vite@8.3.5', resp), kind, 'invalid', /DSSE signature does not verify/);
    }
  });

  test('the certificate: another package\'s, or one changed byte', () => {
    const other = response('axios@1.9.0').attestations[1].bundle.verificationMaterial.x509CertificateChain.certificates[0].rawBytes;
    const swapped = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.verificationMaterial.certificate.rawBytes = other; });
    assertStatus(verifyFixture('semver@7.8.6', swapped), 'provenance', 'invalid', /DSSE signature does not verify with the certificate's key/);
    // A changed source repository in the certificate: the key still signs, but the log names
    // the original certificate.
    const changed = editBundle(response('semver@7.8.6'), 'provenance', (b) => {
      const der = Buffer.from(b.verificationMaterial.certificate.rawBytes, 'base64');
      const i = der.indexOf('https://github.com/npm/node-semver');
      der[i + 'https://github.com/npm/'.length] = 'N'.charCodeAt(0);
      b.verificationMaterial.certificate.rawBytes = der.toString('base64');
    });
    assertStatus(verifyFixture('semver@7.8.6', changed), 'provenance', 'invalid', /names another signer/);
    const garbage = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.verificationMaterial.certificate.rawBytes = Buffer.from('not a certificate').toString('base64'); });
    assertStatus(verifyFixture('semver@7.8.6', garbage), 'provenance', 'invalid', /does not parse/);
  });

  test('the signed entry timestamp, integratedTime and log index', () => {
    const cases = [
      [(e) => { e.inclusionPromise.signedEntryTimestamp = flipBase64(e.inclusionPromise.signedEntryTimestamp, 12); }, /SET\) does not verify/],
      [(e) => { e.integratedTime = String(Number(e.integratedTime) + 3600); }, /SET\) does not verify/],
      [(e) => { e.logIndex = String(Number(e.logIndex) + 1); }, /SET\) does not verify/],
      [(e) => { e.integratedTime = '-5'; }, /integratedTime is not a non-negative integer/],
    ];
    for (const slug of ['semver@7.5.1', 'semver@7.8.6']) {
      for (const [fn, pattern] of cases) {
        for (const kind of ['publish', 'provenance']) {
          const resp = editBundle(response(slug), kind, (b) => fn(b.verificationMaterial.tlogEntries[0]));
          assertStatus(verifyFixture(slug, resp), kind, 'invalid', pattern);
        }
      }
    }
  });

  test('the log entry\'s body must describe this envelope and signer', () => {
    // The publish attestation's entry presented with the provenance.
    const resp = response('semver@7.8.6');
    const pub = resp.attestations[0].bundle.verificationMaterial.tlogEntries[0];
    resp.attestations[1].bundle.verificationMaterial.tlogEntries[0].canonicalizedBody = pub.canonicalizedBody;
    assertStatus(verifyFixture('semver@7.8.6', resp), 'provenance', 'invalid', /another payload/);
    const kind = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.verificationMaterial.tlogEntries[0].kindVersion.version = '0.0.2'; });
    assertStatus(verifyFixture('semver@7.8.6', kind), 'provenance', 'unsupported', /kind dsse 0\.0\.2/);
  });

  test('the inclusion proof and the checkpoint', () => {
    const cases = [
      [(p) => { p.hashes[3] = flipBase64(p.hashes[3], 5); }, /does not lead to the root hash/],
      [(p) => { p.rootHash = flipBase64(p.rootHash, 5); }, /does not lead to the root hash/],
      [(p) => { p.treeSize = String(Number(p.treeSize) + 1); }, /inclusion proof/],
      [(p) => { p.logIndex = String(Number(p.logIndex) - 1); }, /does not lead to the root hash/],
      [(p) => { p.hashes.pop(); }, /inclusion proof/],
      [(p) => { p.checkpoint.envelope = p.checkpoint.envelope.replace(/(— \S+ )(\S+)/, (m, a, s) => a + flipBase64(s, 40)); }, /checkpoint: not signed/],
      [(p) => { p.checkpoint.envelope = p.checkpoint.envelope.replace(/^(.*\n)(\d+)\n/, (m, a, n) => `${a}${Number(n) - 1}\n`); }, /checkpoint: its tree size/],
      [(p) => { const [o, ...rest] = p.checkpoint.envelope.split('\n'); p.checkpoint.envelope = [`x${o}`, ...rest].join('\n'); }, /checkpoint: origin/],
      [(p) => { p.checkpoint.envelope = p.checkpoint.envelope.replace('— rekor.sigstore.dev ', '— rekor.example.com '); }, /checkpoint: not signed/],
    ];
    for (const slug of ['axios@1.9.0', 'semver@7.8.6']) {
      for (const [fn, pattern] of cases) {
        for (const kind of ['publish', 'provenance']) {
          const resp = editBundle(response(slug), kind, (b) => fn(b.verificationMaterial.tlogEntries[0].inclusionProof));
          assertStatus(verifyFixture(slug, resp), kind, 'invalid', pattern);
        }
      }
    }
  });

  test('a bundle from v0.2 on must carry an inclusion proof; v0.1 need not', () => {
    const resp = editBundle(response('semver@7.8.6'), 'provenance', (b) => { delete b.verificationMaterial.tlogEntries[0].inclusionProof; });
    assertStatus(verifyFixture('semver@7.8.6', resp), 'provenance', 'invalid', /must carry an inclusion proof/);
    const old = response('semver@7.5.1');
    assert.ok(old.attestations.every((a) => !a.bundle.verificationMaterial.tlogEntries[0].inclusionProof));
    assert.equal(verifyFixture('semver@7.5.1', old).summary.status, 'valid');
  });

  test('the RFC 3161 timestamp', () => {
    const edit = (fn) => editBundle(response('vite@8.3.5'), 'provenance', (b) => {
      const ts = b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0];
      const der = Buffer.from(ts.signedTimestamp, 'base64');
      fn(der);
      ts.signedTimestamp = der.toString('base64');
    });
    // The CMS signature (the last bytes of the token).
    assertStatus(verifyFixture('vite@8.3.5', edit((d) => { d[d.length - 5] ^= 1; })), 'provenance', 'invalid', /timestamp: not signed by a pinned timestamp authority/);
    // The TSTInfo: its imprint, then its genTime.
    const tst = (d) => d.indexOf(Buffer.from('0420', 'hex'), d.indexOf(Buffer.from('2b0601040183bf3002', 'hex')));
    assertStatus(verifyFixture('vite@8.3.5', edit((d) => { d[tst(d) + 10] ^= 1; })), 'provenance', 'invalid', /timestamp: it is not over this signature/);
    assertStatus(verifyFixture('vite@8.3.5', edit((d) => { const i = d.indexOf('20261021'); d[i + 9] ^= 1; })), 'provenance', 'invalid', /timestamp: the message digest/);
    const noTsa = clone(TRUSTED_ROOT);
    noTsa.timestampAuthorities = [];
    assertStatus(verifyFixture('vite@8.3.5', undefined, { trustedRoot: noTsa }), 'provenance', 'invalid', /timestamp authority/);
    const garbage = editBundle(response('vite@8.3.5'), 'provenance', (b) => { b.verificationMaterial.timestampVerificationData.rfc3161Timestamps[0].signedTimestamp = 'AAAA'; });
    assertStatus(verifyFixture('vite@8.3.5', garbage), 'provenance', 'invalid', /DER/);
  });

  test('the npm registry key: expired at signing time, unknown, or not the one named', () => {
    const expired = clone(NPM_REGISTRY_KEYS);
    expired[1].expires = '2025-01-01T00:00:00.000Z';
    assertStatus(verifyFixture('axios@1.9.0', undefined, { npmKeys: expired }), 'publish', 'invalid', /expired 2025-01-01T00:00:00\.000Z, before the signing time 2025-04-24/);
    const oldExpired = clone(NPM_REGISTRY_KEYS);
    oldExpired[0].expires = '2024-01-01T00:00:00.000Z';
    assertStatus(verifyFixture('@tanstack__react-query@5.51.1', undefined, { npmKeys: oldExpired }), 'publish', 'invalid', /expired/);
    // A key the orb doesn't pin: never valid, and not a verdict either.
    assertStatus(verifyFixture('axios@1.9.0', undefined, { npmKeys: [NPM_REGISTRY_KEYS[0]] }), 'publish', 'unsupported', /does not pin/);
    // The hint and the DSSE keyid must agree.
    const hint = editBundle(response('axios@1.9.0'), 'publish', (b) => { b.verificationMaterial.publicKey.hint = OLD_KEY; });
    assertStatus(verifyFixture('axios@1.9.0', hint), 'publish', 'invalid', /keyid is not the key hint/);
    // Both pointed at the old key: its signature check fails.
    const both = editBundle(response('axios@1.9.0'), 'publish', (b) => {
      b.verificationMaterial.publicKey.hint = OLD_KEY;
      b.dsseEnvelope.signatures[0].keyid = OLD_KEY;
    });
    assertStatus(verifyFixture('axios@1.9.0', both), 'publish', 'invalid', /does not verify with the npm registry key/);
  });

  test('the wrong kind of signer for the predicate', () => {
    const resp = response('axios@1.9.0');
    const [pub, prov] = resp.attestations;
    const certAsPublish = clone(pub);
    certAsPublish.bundle.verificationMaterial = clone(prov.bundle.verificationMaterial);
    const keyAsProvenance = clone(prov);
    keyAsProvenance.bundle.verificationMaterial = clone(pub.bundle.verificationMaterial);
    const r = verifyFixture('axios@1.9.0', { attestations: [certAsPublish, keyAsProvenance] });
    assertStatus(r, 'publish', 'invalid', /must be signed with an npm registry key/);
    assertStatus(r, 'provenance', 'invalid', /must be signed with a Fulcio certificate/);
    const relabelled = editBundle(response('axios@1.9.0'), 'provenance', (b, a) => { a.predicateType = SLSA_PROVENANCE_V02; });
    assertStatus(verifyFixture('axios@1.9.0', relabelled), 'provenance', 'invalid', /predicate type .* is not the attestation's/);
  });

  test('trust material that does not cover the signing', () => {
    const run = (edit) => {
      const root = clone(TRUSTED_ROOT);
      edit(root);
      return verifyFixture('semver@7.8.6', undefined, { trustedRoot: root });
    };
    assertStatus(run((r) => { r.ctlogs = []; }), 'provenance', 'invalid', /no embedded SCT verifies/);
    assertStatus(run((r) => { r.ctlogs.forEach((l) => { l.publicKey.validFor.end = '2023-01-01T00:00:00Z'; }); }), 'provenance', 'invalid', /no embedded SCT verifies/);
    assertStatus(run((r) => { r.certificateAuthorities = []; }), 'provenance', 'invalid', /does not chain to a pinned Fulcio CA/);
    assertStatus(run((r) => { r.certificateAuthorities[1].validFor.end = '2026-01-01T00:00:00Z'; }), 'provenance', 'invalid', /does not chain/);
    assertStatus(run((r) => { r.certificateAuthorities = [r.certificateAuthorities[0], { ...r.timestampAuthorities[0], subject: {} }]; }), 'provenance', 'invalid', /does not chain/);
    assertStatus(run((r) => { r.tlogs[0].publicKey.validFor.start = '2026-11-03T00:00:00Z'; }), 'provenance', 'invalid', /was not valid at/);
    assertStatus(run((r) => { r.tlogs[0].publicKey.rawBytes = r.ctlogs[1].publicKey.rawBytes; }), 'provenance', 'invalid', /SET\) does not verify/);
  });
});

// ---------------------------------------------------------------------------------------------
describe('verifyAttestations: what is not implemented is unsupported, never valid', () => {
  test('an unknown bundle media type', () => {
    for (const mediaType of ['application/vnd.dev.sigstore.bundle+json;version=0.4', 'application/vnd.dev.sigstore.bundle.v0.4+json', undefined]) {
      const resp = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.mediaType = mediaType; });
      assertStatus(verifyFixture('semver@7.8.6', resp), 'provenance', 'unsupported', /media type/);
    }
  });

  test('a message-signature bundle', () => {
    const resp = editBundle(response('semver@7.8.6'), 'provenance', (b) => {
      b.messageSignature = { messageDigest: { algorithm: 'SHA2_256', digest: 'AAAA' }, signature: b.dsseEnvelope.signatures[0].sig };
      delete b.dsseEnvelope;
    });
    assertStatus(verifyFixture('semver@7.8.6', resp), 'provenance', 'unsupported', /message-signature/);
  });

  test('a DSSE payload that is not in-toto', () => {
    const resp = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.dsseEnvelope.payloadType = 'application/json'; });
    assertStatus(verifyFixture('semver@7.8.6', resp), 'provenance', 'unsupported', /payload type/);
  });

  test('a Rekor v2 entry, or an entry without a signed entry timestamp', () => {
    const v2log = TRUSTED_ROOT.tlogs[1].logId.keyId;
    const v2 = editBundle(response('semver@7.8.6'), 'provenance', (b) => {
      const e = b.verificationMaterial.tlogEntries[0];
      b.verificationMaterial.tlogEntries[0] = {
        logIndex: '12345',
        logId: { keyId: v2log },
        kindVersion: { kind: 'dsse', version: '0.0.2' },
        canonicalizedBody: e.canonicalizedBody,
        inclusionProof: e.inclusionProof,
      };
    });
    assertStatus(verifyFixture('semver@7.8.6', v2), 'provenance', 'unsupported', /Rekor v2/);
    const noSet = editBundle(response('semver@7.8.6'), 'provenance', (b) => { delete b.verificationMaterial.tlogEntries[0].inclusionPromise; });
    assertStatus(verifyFixture('semver@7.8.6', noSet), 'provenance', 'unsupported', /no signed entry timestamp/);
    const v2key = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.verificationMaterial.tlogEntries[0].logId.keyId = v2log; });
    assertStatus(verifyFixture('semver@7.8.6', v2key), 'provenance', 'unsupported', /PKIX_ED25519/);
  });

  test('a log, or a log entry kind, the orb does not know', () => {
    const unknownLog = editBundle(response('semver@7.8.6'), 'provenance', (b) => { b.verificationMaterial.tlogEntries[0].logId.keyId = Buffer.alloc(32, 9).toString('base64'); });
    assertStatus(verifyFixture('semver@7.8.6', unknownLog), 'provenance', 'unsupported', /not in the pinned trusted root/);
    const noLogs = clone(TRUSTED_ROOT);
    noLogs.tlogs = [];
    assertStatus(verifyFixture('semver@7.8.6', undefined, { trustedRoot: noLogs }), 'publish', 'unsupported', /not in the pinned trusted root/);
    const kind = editBundle(response('semver@7.8.6'), 'publish', (b) => { b.verificationMaterial.tlogEntries[0].kindVersion = { kind: 'hashedrekord', version: '0.0.1' }; });
    assertStatus(verifyFixture('semver@7.8.6', kind), 'publish', 'unsupported', /hashedrekord/);
  });

  test('a provenance with nothing else verifies to unsupported, not valid, in the summary', () => {
    const resp = editBundle(response('axios@1.9.0'), 'provenance', (b) => { b.mediaType = 'application/vnd.dev.sigstore.bundle.v0.4+json'; });
    const r = verifyFixture('axios@1.9.0', resp);
    assert.deepEqual([r.summary.status, r.summary.publish, r.summary.provenance, r.summary.identity], ['unsupported', 'valid', 'unsupported', null]);
    assert.match(r.summary.reason, /media type/);
  });
});

// ---------------------------------------------------------------------------------------------
// A synthetic Sigstore: everything a real one has, with keys generated here.

const OIDS = {
  ecdsaSha256: '1.2.840.10045.4.3.2',
  cn: '2.5.4.3',
  basicConstraints: '2.5.29.19',
  keyUsage: '2.5.29.15',
  extKeyUsage: '2.5.29.37',
  san: '2.5.29.17',
  codeSigning: '1.3.6.1.5.5.7.3.3',
  sct: '1.3.6.1.4.1.11129.2.4.2',
};
const der = {
  len(n) {
    if (n < 128) return Buffer.from([n]);
    const bytes = [];
    for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
    return Buffer.from([0x80 | bytes.length, ...bytes]);
  },
  tlv(tag, ...parts) {
    const body = Buffer.concat(parts);
    return Buffer.concat([Buffer.from([tag]), der.len(body.length), body]);
  },
  seq: (...p) => der.tlv(0x30, ...p),
  set: (...p) => der.tlv(0x31, ...p),
  int: (n) => der.tlv(0x02, Buffer.from([n])),
  bool: () => der.tlv(0x01, Buffer.from([0xff])),
  octet: (b) => der.tlv(0x04, b),
  utf8: (s) => der.tlv(0x0c, Buffer.from(s)),
  ia5: (s) => der.tlv(0x16, Buffer.from(s)),
  bits: (b) => der.tlv(0x03, Buffer.from([0]), b),
  oid(s) {
    const arcs = s.split('.').map(Number);
    const out = [];
    for (const v of [arcs[0] * 40 + arcs[1], ...arcs.slice(2)]) {
      const b = [v & 0x7f];
      for (let x = Math.floor(v / 128); x > 0; x = Math.floor(x / 128)) b.unshift(0x80 | (x & 0x7f));
      out.push(...b);
    }
    return der.tlv(0x06, Buffer.from(out));
  },
  utc(ms) {
    const d = new Date(ms).toISOString();
    return der.tlv(0x17, Buffer.from(`${d.slice(2, 4)}${d.slice(5, 7)}${d.slice(8, 10)}${d.slice(11, 13)}${d.slice(14, 16)}${d.slice(17, 19)}Z`));
  },
};
const ecKeys = () => crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spkiOf = (key) => key.export({ type: 'spki', format: 'der' });
const pem = (certDer) => `-----BEGIN CERTIFICATE-----\n${certDer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
const u16 = (n) => Buffer.from([n >> 8, n & 0xff]);

function makeCert({ subject, issuer, serial = 1, notBefore, notAfter, publicKey, signingKey, extensions, sct }) {
  const name = (cn) => (cn ? der.seq(der.set(der.seq(der.oid(OIDS.cn), der.utf8(cn)))) : der.seq());
  const tbsOf = (exts) => der.seq(
    der.tlv(0xa0, der.int(2)), der.int(serial), der.seq(der.oid(OIDS.ecdsaSha256)), name(issuer),
    der.seq(der.utc(notBefore), der.utc(notAfter)), name(subject), spkiOf(publicKey),
    der.tlv(0xa3, der.seq(...exts.map(([o, critical, value]) => der.seq(der.oid(o), ...(critical ? [der.bool()] : []), der.octet(value))))),
  );
  let exts = extensions;
  if (sct) {
    const pre = tbsOf(exts);
    const ts = Buffer.alloc(8);
    ts.writeBigUInt64BE(BigInt(sct.time));
    const issuerKeyHash = sha256(spkiOf(sct.issuerKey));
    const signed = Buffer.concat([Buffer.from([0, 0]), ts, Buffer.from([0, 1]), issuerKeyHash, Buffer.from([pre.length >> 16, (pre.length >> 8) & 0xff, pre.length & 0xff]), pre, u16(0)]);
    const sig = crypto.sign('sha256', signed, sct.logKey.privateKey);
    const one = Buffer.concat([Buffer.from([0]), sha256(spkiOf(sct.logKey.publicKey)), ts, u16(0), Buffer.from([4, 3]), u16(sig.length), sig]);
    const list = Buffer.concat([u16(one.length + 2), u16(one.length), one]);
    exts = [...exts, [OIDS.sct, false, der.octet(list)]];
  }
  const tbs = tbsOf(exts);
  return der.seq(tbs, der.seq(der.oid(OIDS.ecdsaSha256)), der.bits(crypto.sign('sha256', tbs, signingKey)));
}

const T = Date.parse('2026-06-01T12:00:00.000Z');
const ID = {
  issuer: GITHUB,
  repo: 'https://github.com/example/widget',
  ref: 'refs/heads/main',
  commit: '0123456789abcdef0123456789abcdef01234567',
  repoId: '424242',
  ownerId: '777',
  path: '.github/workflows/release.yml',
};
const configUri = (id = ID) => `${id.repo}/${id.path}@${id.ref}`;

function makeAuthority() {
  const ca = ecKeys();
  const rekor = ecKeys();
  const ct = ecKeys();
  const npm = ecKeys();
  const root = makeCert({
    subject: 'test-fulcio', issuer: 'test-fulcio', notBefore: Date.UTC(2020, 0, 1), notAfter: Date.UTC(2040, 0, 1),
    publicKey: ca.publicKey, signingKey: ca.privateKey,
    extensions: [[OIDS.basicConstraints, true, der.seq(der.bool())], [OIDS.keyUsage, true, der.tlv(0x03, Buffer.from([1, 0x06]))]],
  });
  const log = (k, url) => ({
    baseUrl: url,
    hashAlgorithm: 'SHA2_256',
    publicKey: { rawBytes: spkiOf(k.publicKey).toString('base64'), keyDetails: 'PKIX_ECDSA_P256_SHA_256', validFor: { start: '2020-01-01T00:00:00Z' } },
    logId: { keyId: sha256(spkiOf(k.publicKey)).toString('base64') },
  });
  return {
    ca, rekor, ct, npm, root,
    trustedRoot: {
      mediaType: 'application/vnd.dev.sigstore.trustedroot+json;version=0.1',
      tlogs: [log(rekor, 'https://rekor.test')],
      certificateAuthorities: [{ subject: { commonName: 'test-fulcio' }, uri: 'https://fulcio.test', certChain: { certificates: [{ rawBytes: root.toString('base64') }] }, validFor: { start: '2020-01-01T00:00:00Z' } }],
      ctlogs: [log(ct, 'https://ct.test')],
      timestampAuthorities: [],
    },
    npmKeys: [{ keyid: npmKeyId(npm.publicKey), keytype: 'ecdsa-sha2-nistp256', scheme: 'ecdsa-sha2-nistp256', key: spkiOf(npm.publicKey).toString('base64'), expires: null }],
  };
}
const AUTH = makeAuthority();

function makeLeaf(auth, publicKey, opts = {}) {
  const id = { ...ID, ...opts.id };
  const fulcio = (arc, value, enc = der.utf8) => [`1.3.6.1.4.1.57264.1.${arc}`, false, enc(value)];
  const extensions = [
    [OIDS.keyUsage, true, der.tlv(0x03, Buffer.from([7, 0x80]))],
    ...(opts.eku === false ? [] : [[OIDS.extKeyUsage, false, der.seq(der.oid(OIDS.codeSigning))]]),
    ...(opts.ca ? [[OIDS.basicConstraints, true, der.seq(der.bool())]] : []),
    [OIDS.san, true, der.seq(der.tlv(0x86, Buffer.from(opts.san ?? configUri(id))))],
    ['1.3.6.1.4.1.57264.1.1', false, Buffer.from(id.issuer)],
    fulcio(8, id.issuer, opts.stringEncoding),
    fulcio(9, opts.san ?? configUri(id)),
    fulcio(11, 'github-hosted'),
    fulcio(12, id.repo),
    fulcio(13, id.commit),
    fulcio(14, id.ref),
    fulcio(15, id.repoId),
    fulcio(17, id.ownerId),
    fulcio(18, configUri(id)),
  ];
  const issuer = opts.issuer ?? AUTH.ca;
  const notBefore = opts.notBefore ?? T - 30000;
  return makeCert({
    subject: null, issuer: 'test-fulcio', serial: 99, notBefore, notAfter: opts.notAfter ?? notBefore + 600000,
    publicKey, signingKey: issuer.privateKey, extensions,
    sct: opts.sct === false ? null : { time: opts.sctTime ?? notBefore + 500, logKey: opts.ctKey ?? auth.ct, issuerKey: issuer.publicKey },
  });
}

function statementFor(kind, { name = 'widget', version = '1.0.0', integrity, predicate, type, subjects, predicateType } = {}) {
  const subject = subjects ?? [{ name: packagePurl(name, version), digest: { sha512: integrityToHex(integrity) } }];
  if (kind === 'publish') {
    return { _type: type ?? 'https://in-toto.io/Statement/v0.1', subject, predicateType: predicateType ?? PUBLISH_ATTESTATION, predicate: predicate ?? { name, version, registry: 'https://registry.npmjs.org' } };
  }
  if (kind === 'v0.2') {
    return {
      _type: type ?? 'https://in-toto.io/Statement/v0.1', subject, predicateType: SLSA_PROVENANCE_V02,
      predicate: predicate ?? {
        buildType: 'https://github.com/npm/cli/gha/v2',
        builder: { id: 'https://github.com/actions/runner' },
        invocation: {
          configSource: { uri: `git+${ID.repo}@${ID.ref}`, digest: { sha1: ID.commit }, entryPoint: ID.path },
          environment: { GITHUB_REPOSITORY_ID: ID.repoId, GITHUB_REPOSITORY_OWNER_ID: ID.ownerId },
        },
      },
    };
  }
  return {
    _type: type ?? 'https://in-toto.io/Statement/v1', subject, predicateType: predicateType ?? SLSA_PROVENANCE_V1,
    predicate: predicate ?? {
      buildDefinition: {
        buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
        externalParameters: { workflow: { ref: ID.ref, repository: ID.repo, path: ID.path } },
        internalParameters: { github: { event_name: 'push', repository_id: ID.repoId, repository_owner_id: ID.ownerId } },
        resolvedDependencies: [{ uri: `git+${ID.repo}@${ID.ref}`, digest: { gitCommit: ID.commit } }],
      },
      runDetails: { builder: { id: 'https://github.com/actions/runner/github-hosted' }, metadata: { invocationId: 'run/1' } },
    },
  };
}

// RFC 6962 Merkle tree, the reference for inclusion proofs.
const leafHash = (d) => sha256(Buffer.concat([Buffer.from([0]), d]));
const nodeHash = (l, r) => sha256(Buffer.concat([Buffer.from([1]), l, r]));
const split = (n) => 2 ** Math.floor(Math.log2(n - 1));
const mth = (hs) => (hs.length === 1 ? hs[0] : nodeHash(mth(hs.slice(0, split(hs.length))), mth(hs.slice(split(hs.length)))));
function auditPath(m, hs) {
  if (hs.length === 1) return [];
  const k = split(hs.length);
  return m < k ? [...auditPath(m, hs.slice(0, k)), mth(hs.slice(k))] : [...auditPath(m - k, hs.slice(k)), mth(hs.slice(0, k))];
}
function canonical(v) {
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonical(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

// One attestation, signed and logged as the registry would.
function makeAttestation(auth, statement, opts = {}) {
  const signer = opts.signer ?? (statement.predicateType === PUBLISH_ATTESTATION ? 'key' : 'cert');
  const mediaType = opts.mediaType ?? (signer === 'key' ? 'application/vnd.dev.sigstore.bundle+json;version=0.2' : 'application/vnd.dev.sigstore.bundle.v0.3+json');
  const time = opts.time ?? T;
  const payload = Buffer.from(JSON.stringify(statement));
  const payloadType = 'application/vnd.in-toto+json';
  const pae = Buffer.concat([Buffer.from(`DSSEv1 ${payloadType.length} ${payloadType} ${payload.length} `), payload]);
  let vm;
  let signingKey;
  let verifier;
  let keyid = '';
  if (signer === 'key') {
    signingKey = auth.npm.privateKey;
    keyid = auth.npmKeys[0].keyid;
    vm = { publicKey: { hint: keyid } };
    verifier = auth.npm.publicKey.export({ type: 'spki', format: 'pem' });
  } else {
    const leafKeys = ecKeys();
    const leaf = makeLeaf(auth, leafKeys.publicKey, opts.leaf);
    signingKey = leafKeys.privateKey;
    vm = mediaType.includes('v0.3') ? { certificate: { rawBytes: leaf.toString('base64') } } : { x509CertificateChain: { certificates: [{ rawBytes: leaf.toString('base64') }, { rawBytes: auth.root.toString('base64') }] } };
    verifier = pem(leaf);
  }
  const sig = crypto.sign('sha256', pae, signingKey);
  const envelope = { payload: payload.toString('base64'), payloadType, signatures: [{ sig: sig.toString('base64'), keyid }] };
  const kind = opts.tlogKind ?? 'dsse';
  const body = kind === 'dsse'
    ? { apiVersion: '0.0.1', kind: 'dsse', spec: { envelopeHash: { algorithm: 'sha256', value: sha256(JSON.stringify(envelope)).toString('hex') }, payloadHash: { algorithm: 'sha256', value: sha256(payload).toString('hex') }, signatures: [{ signature: sig.toString('base64'), verifier: Buffer.from(verifier).toString('base64') }] } }
    : { apiVersion: '0.0.2', kind: 'intoto', spec: { content: { envelope: { payloadType, signatures: [{ sig: Buffer.from(sig.toString('base64')).toString('base64'), publicKey: Buffer.from(verifier).toString('base64') }] }, hash: { algorithm: 'sha256', value: sha256(JSON.stringify(envelope)).toString('hex') }, payloadHash: { algorithm: 'sha256', value: sha256(payload).toString('hex') } } } };
  const canonicalizedBody = Buffer.from(JSON.stringify(body)).toString('base64');
  const logId = auth.trustedRoot.tlogs[0].logId.keyId;
  const integratedTime = Math.floor(time / 1000);
  const logIndex = 5000;
  const set = canonical({ body: canonicalizedBody, integratedTime, logID: Buffer.from(logId, 'base64').toString('hex'), logIndex });
  const entry = {
    logIndex: String(logIndex), logId: { keyId: logId }, kindVersion: { kind: body.kind, version: body.apiVersion }, integratedTime: String(integratedTime),
    inclusionPromise: { signedEntryTimestamp: crypto.sign('sha256', Buffer.from(set), auth.rekor.privateKey).toString('base64') },
    canonicalizedBody,
  };
  if (opts.proof !== false) {
    const { size = 7, index = 4, origin = 'rekor.test - 4242', signerName = 'rekor.test' } = opts.tree ?? {};
    const leaves = Array.from({ length: size }, (_, i) => (i === index ? leafHash(Buffer.from(canonicalizedBody, 'base64')) : leafHash(Buffer.from(`leaf ${i}`))));
    const rootHash = mth(leaves);
    const note = `${origin}\n${size}\n${rootHash.toString('base64')}\n`;
    const noteSig = crypto.sign('sha256', Buffer.from(note), auth.rekor.privateKey);
    const hint = Buffer.from(logId, 'base64').subarray(0, 4);
    entry.inclusionProof = {
      logIndex: String(index), rootHash: rootHash.toString('base64'), treeSize: String(size),
      hashes: auditPath(index, leaves).map((h) => h.toString('base64')),
      checkpoint: { envelope: `${note}\n— ${signerName} ${Buffer.concat([hint, noteSig]).toString('base64')}\n` },
    };
  }
  return { predicateType: statement.predicateType, bundle: { mediaType, verificationMaterial: { ...vm, tlogEntries: [entry], timestampVerificationData: {} }, dsseEnvelope: envelope } };
}

const INTEGRITY = `sha512-${crypto.createHash('sha512').update('widget-1.0.0.tgz').digest('base64')}`;
function synth(attestations, opts = {}) {
  return verifyAttestations({ attestations }, { name: 'widget', version: '1.0.0', integrity: INTEGRITY, trustedRoot: AUTH.trustedRoot, npmKeys: AUTH.npmKeys, ...opts });
}
const publish = (opts = {}, st = {}) => makeAttestation(AUTH, statementFor('publish', { integrity: INTEGRITY, ...st }), opts);
const provenance = (opts = {}, st = {}) => makeAttestation(AUTH, statementFor(opts.v02 ? 'v0.2' : 'v1', { integrity: INTEGRITY, ...st }), opts);

describe('verifyAttestations: a synthetic Sigstore', () => {
  test('a publish attestation and a provenance verify, with the identity from the certificate', () => {
    const r = synth([publish(), provenance()]);
    assert.equal(r.summary.status, 'valid', r.summary.reason);
    assert.deepEqual(r.summary.identity, {
      issuer: GITHUB,
      san: configUri(),
      signerUri: configUri(),
      signerDigest: null,
      runnerEnvironment: 'github-hosted',
      sourceRepositoryUri: ID.repo,
      sourceRepositoryId: ID.repoId,
      sourceRepositoryOwnerUri: null,
      sourceRepositoryOwnerId: ID.ownerId,
      sourceRepositoryVisibility: null,
      sourceRef: ID.ref,
      sourceDigest: ID.commit,
      buildConfigUri: configUri(),
      buildConfigDigest: null,
      buildTrigger: null,
      runInvocationUri: null,
      buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
      workflow: { repository: ID.repo, path: ID.path, ref: ID.ref },
    });
    assert.equal(of(r, 'provenance').integratedTime, new Date(T).toISOString());
  });

  test('every bundle version, both tlog kinds, SLSA v0.2, and a chain in the bundle', () => {
    const v = (mediaType, extra = {}) => ({ mediaType, ...extra });
    const cases = [
      publish(v('application/vnd.dev.sigstore.bundle+json;version=0.1', { proof: false, tlogKind: 'intoto' })),
      provenance(v('application/vnd.dev.sigstore.bundle+json;version=0.1', { proof: false, v02: true })),
      provenance(v('application/vnd.dev.sigstore.bundle+json;version=0.2', { tlogKind: 'intoto' })),
      provenance(v('application/vnd.dev.sigstore.bundle+json;version=0.3')),
    ];
    const r = synth(cases);
    assert.deepEqual(r.attestations.map((a) => a.status), ['valid', 'valid', 'valid', 'valid'], r.summary.reason);
    assert.equal(r.attestations[1].identity.buildType, 'https://github.com/npm/cli/gha/v2');
    assert.deepEqual(r.attestations[1].identity.workflow, { repository: ID.repo, path: ID.path, ref: ID.ref });
  });

  test('inclusion proofs for every leaf of trees of 1 to 12 entries', () => {
    for (let size = 1; size <= 12; size++) {
      for (let index = 0; index < size; index++) {
        const r = synth([publish({ tree: { size, index } })]);
        assert.equal(r.summary.status, 'valid', `size ${size} index ${index}: ${r.summary.reason}`);
      }
    }
    // A proof for one index presented as another's.
    const a = publish({ tree: { size: 9, index: 4 } });
    a.bundle.verificationMaterial.tlogEntries[0].inclusionProof.logIndex = '5';
    assertStatus(synth([a]), 'publish', 'invalid', /inclusion proof/);
  });

  test('the checkpoint must come from the log', () => {
    assertStatus(synth([publish({ tree: { origin: 'rekor.other - 1' } })]), 'publish', 'invalid', /checkpoint: origin/);
    assertStatus(synth([publish({ tree: { signerName: 'rekor.other' } })]), 'publish', 'invalid', /checkpoint: not signed/);
    assert.equal(synth([publish({ tree: { origin: 'rekor.test' } })]).summary.status, 'valid');
  });

  test('the provenance predicate must agree with the certificate', () => {
    const v1 = (edit) => {
      const st = statementFor('v1', { integrity: INTEGRITY });
      edit(st.predicate.buildDefinition);
      return makeAttestation(AUTH, st);
    };
    const cases = [
      [(bd) => { bd.externalParameters.workflow.repository = 'https://github.com/example/other'; }, /source repository/],
      [(bd) => { bd.externalParameters.workflow.path = '.github/workflows/other.yml'; }, /workflow/],
      [(bd) => { bd.externalParameters.workflow.ref = 'refs/heads/dev'; }, /source ref/],
      [(bd) => { bd.internalParameters.github.repository_id = '1'; }, /repository ID/],
      [(bd) => { bd.internalParameters.github.repository_owner_id = '1'; }, /repository owner ID/],
      [(bd) => { bd.resolvedDependencies[0].digest.gitCommit = 'f'.repeat(40); }, /source commit/],
      [(bd) => { delete bd.externalParameters.workflow; }, /names no workflow/],
    ];
    for (const [edit, pattern] of cases) assertStatus(synth([v1(edit)]), 'provenance', 'invalid', pattern);
    const v02 = statementFor('v0.2', { integrity: INTEGRITY });
    v02.predicate.invocation.configSource.uri = 'git+https://github.com/example/other@refs/heads/main';
    assertStatus(synth([makeAttestation(AUTH, v02)]), 'provenance', 'invalid', /source repository/);
    // A build type the orb doesn't know: the certificate's identity, without a workflow.
    const other = statementFor('v1', { integrity: INTEGRITY });
    other.predicate.buildDefinition = { buildType: 'https://gitlab.com/gitlab-org/gitlab-runner/-/blob/v1/PROVENANCE.md', externalParameters: {} };
    const r = synth([makeAttestation(AUTH, other)]);
    assert.equal(r.summary.provenance, 'valid');
    assert.equal(r.summary.identity.workflow, null);
    assert.equal(r.summary.identity.sourceRepositoryId, ID.repoId);
  });

  test('a reusable workflow: the signer is not the build config', () => {
    const san = 'https://github.com/example/shared/.github/workflows/publish.yml@refs/heads/main';
    const r = synth([provenance({ leaf: { san } })]);
    assert.equal(r.summary.provenance, 'valid');
    assert.equal(r.summary.identity.signerUri, san);
    assert.equal(r.summary.identity.san, san);
    assert.equal(r.summary.identity.buildConfigUri, configUri());
  });

  test('the statement: subjects, statement type and predicate', () => {
    const two = [{ name: packagePurl('widget', '1.0.0'), digest: { sha512: integrityToHex(INTEGRITY) } }, { name: 'pkg:npm/other@1.0.0', digest: { sha512: '00' } }];
    assertStatus(synth([provenance({}, { subjects: two })]), 'provenance', 'invalid', /exactly one subject/);
    assertStatus(synth([provenance({}, { subjects: [] })]), 'provenance', 'invalid', /exactly one subject/);
    assertStatus(synth([publish({}, { predicate: { name: 'widget', version: '2.0.0' } })]), 'publish', 'invalid', /publish attestation: it is for/);
    const bare = statementFor('publish', { integrity: INTEGRITY });
    delete bare.predicate;
    assertStatus(synth([makeAttestation(AUTH, bare)]), 'publish', 'invalid', /no predicate/);
    assertStatus(synth([provenance({}, { type: 'https://in-toto.io/Statement/v2' })]), 'provenance', 'unsupported', /statement type/);
    // A predicate type the orb doesn't implement verifies, but is only unsupported.
    const r = synth([makeAttestation(AUTH, statementFor('v1', { integrity: INTEGRITY, predicateType: 'https://example.com/predicate/v1' }))]);
    assert.equal(r.attestations[0].status, 'unsupported');
    assert.equal(r.attestations[0].kind, null);
    assert.match(r.attestations[0].reason, /signature verifies/);
    assert.deepEqual([r.summary.status, r.summary.publish, r.summary.provenance], ['unsupported', null, null]);
  });

  test('the Fulcio certificate', () => {
    const cases = [
      [{ eku: false }, /code-signing/],
      [{ ca: true }, /is a CA certificate/],
      [{ notBefore: T + 1000 }, /outside its validity/],
      [{ notBefore: T - 700000 }, /outside its validity/],
      [{ issuer: ecKeys() }, /does not chain to a pinned Fulcio CA/],
      [{ sct: false }, /no embedded SCT/],
      [{ ctKey: ecKeys() }, /no embedded SCT verifies/],
      [{ sctTime: T + 3600000 }, /no embedded SCT verifies/],
      [{ stringEncoding: der.ia5 }, /not a UTF8String/],
    ];
    for (const [leaf, pattern] of cases) assertStatus(synth([provenance({ leaf })]), 'provenance', 'invalid', pattern);
    const later = clone(AUTH.trustedRoot);
    later.certificateAuthorities[0].validFor.start = '2026-07-01T00:00:00Z';
    assertStatus(synth([provenance()], { trustedRoot: later }), 'provenance', 'invalid', /does not chain/);
  });

  test('the registry key\'s expiry is checked at the log\'s time', () => {
    const keys = clone(AUTH.npmKeys);
    keys[0].expires = new Date(T).toISOString();
    assertStatus(synth([publish()], { npmKeys: keys }), 'publish', 'invalid', /expired/);
    // The same array, changed: the verifier must not reuse what it read before.
    keys[0].expires = new Date(T + 1000).toISOString();
    assert.equal(synth([publish()], { npmKeys: keys }).summary.status, 'valid');
  });

  test('two valid provenance attestations naming different sources', () => {
    const other = provenance({ leaf: { id: { repo: 'https://github.com/example/fork', repoId: '1' } } }, {
      predicate: {
        buildDefinition: {
          buildType: 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1',
          externalParameters: { workflow: { ref: ID.ref, repository: 'https://github.com/example/fork', path: ID.path } },
        },
      },
    });
    assert.equal(of(synth([other]), 'provenance').status, 'valid');
    const r = synth([provenance(), other]);
    assert.deepEqual([r.summary.status, r.summary.provenance, r.summary.identity], ['invalid', 'invalid', null]);
    assert.match(r.summary.reason, /different sources/);
  });

  test('certificateIdentity reads Fulcio\'s extensions', () => {
    const id = certificateIdentity(makeLeaf(AUTH, ecKeys().publicKey));
    assert.equal(id.issuerV1, GITHUB);
    assert.equal(id.issuer, GITHUB);
    assert.equal(id.sourceRepositoryUri, ID.repo);
    assert.equal(id.san, configUri());
    const real = response('semver@7.8.6').attestations[1].bundle.verificationMaterial.certificate.rawBytes;
    assert.equal(certificateIdentity(Buffer.from(real, 'base64')).buildTrigger, 'push');
  });
});
