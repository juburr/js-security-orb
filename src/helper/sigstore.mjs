// sigstore.mjs: npm registry signatures and Sigstore attestation bundles, verified with
// node:crypto against pinned trust material. A pure library: no I/O, no imports from the orb's
// other modules, Node 22 or later.
//
// Pinned data, and where it came from (2026-11-02):
//
// - NPM_REGISTRY_KEYS is the `keys` array of GET https://registry.npmjs.org/-/npm/v1/keys
//   (served from Cloudflare's cache, last-modified 2026-10-29). It was cross-checked against the
//   Sigstore TUF target `registry.npmjs.org/keys.json` (delegated role `registry.npmjs.org`,
//   version 9, target sha256 160677eb6e1c7083c89b166b20f8fe4e837fb71181506aff1991b80b89184f7d),
//   which npm itself prefers: the same key bytes, and each key's validFor.end equals `expires`
//   here. Each keyid is the OpenSSH SHA256 fingerprint of its key (npmKeyId); the tests check
//   both copies and the fingerprints.
// - TRUSTED_ROOT is Sigstore's public-good trusted_root.json, byte for byte, as the TUF target of
//   https://tuf-repo-cdn.sigstore.dev (root v16, timestamp v824, snapshot v166, targets v14),
//   sha256 TRUSTED_ROOT_SHA256. It was fetched by a TUF client walk (every root signed by the
//   previous root's threshold and its own, then timestamp, snapshot, targets and the target's
//   length and hashes) anchored twice: at the root embedded in @sigstore/tuf 5.0.0 (npm 12.2.1,
//   root v15) and at the one in @sigstore/tuf 3.1.1 (npm 10.9.4, root v12). Both walks gave the
//   same bytes, as did the copy the orb's research recorded the same day.
//
// To refresh either: walk the TUF repository the same way from a root you already trust (an
// @sigstore/tuf seeds.json, or the previous walk's root), take the targets `trusted_root.json`
// and `registry.npmjs.org/keys.json`, compare the keys with /-/npm/v1/keys, paste them here,
// update TRUSTED_ROOT_SHA256 and the dates above, and run the tests. A new Fulcio CA, Rekor or
// CT log key, TSA, or npm registry key needs an orb release: until then, what it signed is
// reported as unsupported (or, for registry signatures, unknown-key), never valid.
//
// What verifyAttestations checks, per attestation (the npm registry's
// GET /-/npm/v1/attestations/<name>@<version> response):
// - the bundle media type (v0.1, v0.2, v0.3) and a DSSE envelope with one signature over an
//   in-toto Statement (v0.1 or v1) whose predicate type is the attestation's;
// - exactly one subject, named pkg:npm/<name>@<version> (a scope's @ as %40, as npm writes it),
//   whose sha512 digest is the hex of the integrity's sha512;
// - the DSSE signature over the PAE, before anything reads the payload: the publish attestation
//   with the npm registry key its hint names (which must not have expired at any signing time);
//   SLSA provenance with a Fulcio certificate: not a CA, with the code-signing extended key
//   usage, valid at every signing time, chaining to a pinned Fulcio CA valid at every signing
//   time, and carrying an embedded SCT from a pinned CT log, timed within its validity;
// - every Rekor v1 transparency log entry: its body (dsse 0.0.1, or intoto 0.0.2) names this
//   payload, signature and signer; the signed entry timestamp (SET) verifies with the pinned log
//   key valid at integratedTime; the RFC 6962 inclusion proof (required from bundle v0.2 on)
//   leads to the root of a checkpoint signed by that log;
// - every RFC 3161 timestamp (a granted TimeStampResp, or a bare token): its imprint is the hash
//   of the DSSE signature, its signed attributes hold the TSTInfo's digest, and it is signed by
//   a pinned timestamp authority (time-stamping usage) valid at its time;
// - the predicate: the publish attestation's name and version; for GitHub Actions provenance
//   (SLSA v1 workflow/v1, and npm's SLSA v0.2 gha/v2), that the repository, workflow, ref,
//   commit and repository IDs it names agree with the certificate's.
// Rekor v2 entries (no SET), unknown bundle media types, message signatures, statement types,
// predicate types, logs, npm registry keys and key types are `unsupported`, never `valid`.
// What isn't checked: the checkpoint's extension lines; whether a tlog entry's envelopeHash
// matches (sigstore-js doesn't either; the payload hash and signature are); policy on the
// identity (the caller's: issuer, repository, workflow).

import crypto from 'node:crypto';

// ---------------------------------------------------------------------------------------------
// Pinned data

export const NPM_REGISTRY_KEYS = deepFreeze([
  {
    expires: '2025-01-29T00:00:00.000Z',
    keyid: 'SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA',
    keytype: 'ecdsa-sha2-nistp256',
    scheme: 'ecdsa-sha2-nistp256',
    key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE1Olb3zMAFFxXKHiIkQO5cJ3Yhl5i6UPp+IhuteBJbuHcA5UogKo0EWtlWwW6KSaKoTNEYL7JlCQiVnkhBktUgg==',
  },
  {
    expires: null,
    keyid: 'SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U',
    keytype: 'ecdsa-sha2-nistp256',
    scheme: 'ecdsa-sha2-nistp256',
    key: 'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEY6Ya7W++7aUPzvMTrezH6Ycx3c+HOKYCcNGybJZSCJq/fd7Qa8uuAKtdIkUQtQiEKERhAmE5lMMJhP8OkDOa2g==',
  },
]);

export const TRUSTED_ROOT_SHA256 = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66';

// The TUF target's exact bytes (it holds no backslash, backtick or "${").
export const TRUSTED_ROOT_JSON = `{
  "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
  "tlogs": [
    {
      "baseUrl": "https://rekor.sigstore.dev",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2G2Y+2tabdTV5BcGiBIx0a9fAFwrkBbmLSGtks4L3qX6yYY0zufBnhC8Ur/iy55GhWP/9A/bY2LhC30M9+RYtw==",
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {
          "start": "2021-01-12T11:53:27Z"
        }
      },
      "logId": {
        "keyId": "wNI9atQGlz+VWfO6LRygH4QUfY/8W4RFwiT5i5WRgB0="
      }
    },
    {
      "baseUrl": "https://log2025-1.rekor.sigstore.dev",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MCowBQYDK2VwAyEAt8rlp1knGwjfbcXAYPYAkn0XiLz1x8O4t0YkEhie244=",
        "keyDetails": "PKIX_ED25519",
        "validFor": {
          "start": "2025-09-23T00:00:00Z"
        }
      },
      "logId": {
        "keyId": "zxGZFVvd0FEmjR8WrFwMdcAJ9vtaY/QXf44Y1wUeP6A="
      }
    }
  ],
  "certificateAuthorities": [
    {
      "subject": {
        "organization": "sigstore.dev",
        "commonName": "sigstore"
      },
      "uri": "https://fulcio.sigstore.dev",
      "certChain": {
        "certificates": [
          {
            "rawBytes": "MIIB+DCCAX6gAwIBAgITNVkDZoCiofPDsy7dfm6geLbuhzAKBggqhkjOPQQDAzAqMRUwEwYDVQQKEwxzaWdzdG9yZS5kZXYxETAPBgNVBAMTCHNpZ3N0b3JlMB4XDTIxMDMwNzAzMjAyOVoXDTMxMDIyMzAzMjAyOVowKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTB2MBAGByqGSM49AgEGBSuBBAAiA2IABLSyA7Ii5k+pNO8ZEWY0ylemWDowOkNa3kL+GZE5Z5GWehL9/A9bRNA3RbrsZ5i0JcastaRL7Sp5fp/jD5dxqc/UdTVnlvS16an+2Yfswe/QuLolRUCrcOE2+2iA5+tzd6NmMGQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwHQYDVR0OBBYEFMjFHQBBmiQpMlEk6w2uSu1KBtPsMB8GA1UdIwQYMBaAFMjFHQBBmiQpMlEk6w2uSu1KBtPsMAoGCCqGSM49BAMDA2gAMGUCMH8liWJfMui6vXXBhjDgY4MwslmN/TJxVe/83WrFomwmNf056y1X48F9c4m3a3ozXAIxAKjRay5/aj/jsKKGIkmQatjI8uupHr/+CxFvaJWmpYqNkLDGRU+9orzh5hI2RrcuaQ=="
          }
        ]
      },
      "validFor": {
        "start": "2021-03-07T03:20:29Z",
        "end": "2022-12-31T23:59:59.999Z"
      }
    },
    {
      "subject": {
        "organization": "sigstore.dev",
        "commonName": "sigstore"
      },
      "uri": "https://fulcio.sigstore.dev",
      "certChain": {
        "certificates": [
          {
            "rawBytes": "MIICGjCCAaGgAwIBAgIUALnViVfnU0brJasmRkHrn/UnfaQwCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMjA0MTMyMDA2MTVaFw0zMTEwMDUxMzU2NThaMDcxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEeMBwGA1UEAxMVc2lnc3RvcmUtaW50ZXJtZWRpYXRlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE8RVS/ysH+NOvuDZyPIZtilgUF9NlarYpAd9HP1vBBH1U5CV77LSS7s0ZiH4nE7Hv7ptS6LvvR/STk798LVgMzLlJ4HeIfF3tHSaexLcYpSASr1kS0N/RgBJz/9jWCiXno3sweTAOBgNVHQ8BAf8EBAMCAQYwEwYDVR0lBAwwCgYIKwYBBQUHAwMwEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQU39Ppz1YkEZb5qNjpKFWixi4YZD8wHwYDVR0jBBgwFoAUWMAeX5FFpWapesyQoZMi0CrFxfowCgYIKoZIzj0EAwMDZwAwZAIwPCsQK4DYiZYDPIaDi5HFKnfxXx6ASSVmERfsynYBiX2X6SJRnZU84/9DZdnFvvxmAjBOt6QpBlc4J/0DxvkTCqpclvziL6BCCPnjdlIB3Pu3BxsPmygUY7Ii2zbdCdliiow="
          },
          {
            "rawBytes": "MIIB9zCCAXygAwIBAgIUALZNAPFdxHPwjeDloDwyYChAO/4wCgYIKoZIzj0EAwMwKjEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MREwDwYDVQQDEwhzaWdzdG9yZTAeFw0yMTEwMDcxMzU2NTlaFw0zMTEwMDUxMzU2NThaMCoxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjERMA8GA1UEAxMIc2lnc3RvcmUwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAT7XeFT4rb3PQGwS4IajtLk3/OlnpgangaBclYpsYBr5i+4ynB07ceb3LP0OIOZdxexX69c5iVuyJRQ+Hz05yi+UF3uBWAlHpiS5sh0+H2GHE7SXrk1EC5m1Tr19L9gg92jYzBhMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRYwB5fkUWlZql6zJChkyLQKsXF+jAfBgNVHSMEGDAWgBRYwB5fkUWlZql6zJChkyLQKsXF+jAKBggqhkjOPQQDAwNpADBmAjEAj1nHeXZp+13NWBNa+EDsDP8G1WWg1tCMWP/WHPqpaVo0jhsweNFZgSs0eE7wYI4qAjEA2WB9ot98sIkoF3vZYdd3/VtWB5b9TNMea7Ix/stJ5TfcLLeABLE4BNJOsQ4vnBHJ"
          }
        ]
      },
      "validFor": {
        "start": "2022-04-13T20:06:15Z"
      }
    }
  ],
  "ctlogs": [
    {
      "baseUrl": "https://ctfe.sigstore.dev/test",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbfwR+RJudXscgRBRpKX1XFDy3PyudDxz/SfnRi1fT8ekpfBd2O1uoz7jr3Z8nKzxA69EUQ+eFCFI3zeubPWU7w==",
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {
          "start": "2021-03-14T00:00:00Z",
          "end": "2022-10-31T23:59:59.999Z"
        }
      },
      "logId": {
        "keyId": "CGCS8ChS/2hF0dFrJ4ScRWcYrBY9wzjSbea8IgY2b3I="
      }
    },
    {
      "baseUrl": "https://ctfe.sigstore.dev/2022",
      "hashAlgorithm": "SHA2_256",
      "publicKey": {
        "rawBytes": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEiPSlFi0CmFTfEjCUqF9HuCEcYXNKAaYalIJmBZ8yyezPjTqhxrKBpMnaocVtLJBI1eM3uXnQzQGAJdJ4gs9Fyw==",
        "keyDetails": "PKIX_ECDSA_P256_SHA_256",
        "validFor": {
          "start": "2022-10-20T00:00:00Z"
        }
      },
      "logId": {
        "keyId": "3T0wasbHETJjGR4cmWc3AqJKXrjePK3/h4pygC8p7o4="
      }
    }
  ],
  "timestampAuthorities": [
    {
      "subject": {
        "organization": "sigstore.dev",
        "commonName": "sigstore-tsa-selfsigned"
      },
      "uri": "https://timestamp.sigstore.dev/api/v1/timestamp",
      "certChain": {
        "certificates": [
          {
            "rawBytes": "MIICEDCCAZagAwIBAgIUOhNULwyQYe68wUMvy4qOiyojiwwwCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMC4xFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEVMBMGA1UEAxMMc2lnc3RvcmUtdHNhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE4ra2Z8hKNig2T9kFjCAToGG30jky+WQv3BzL+mKvh1SKNR/UwuwsfNCg4sryoYAd8E6isovVA3M4aoNdm9QDi50Z8nTEyvqgfDPtTIwXItfiW/AFf1V7uwkbkAoj0xxco2owaDAOBgNVHQ8BAf8EBAMCB4AwHQYDVR0OBBYEFIn9eUOHz9BlRsMCRscsc1t9tOsDMB8GA1UdIwQYMBaAFJjsAe9/u1H/1JUeb4qImFMHic6/MBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMAoGCCqGSM49BAMDA2gAMGUCMDtpsV/6KaO0qyF/UMsX2aSUXKQFdoGTptQGc0ftq1csulHPGG6dsmyMNd3JB+G3EQIxAOajvBcjpJmKb4Nv+2Taoj8Uc5+b6ih6FXCCKraSqupe07zqswMcXJTe1cExvHvvlw=="
          },
          {
            "rawBytes": "MIIB9zCCAXygAwIBAgIUV7f0GLDOoEzIh8LXSW80OJiUp14wCgYIKoZIzj0EAwMwOTEVMBMGA1UEChMMc2lnc3RvcmUuZGV2MSAwHgYDVQQDExdzaWdzdG9yZS10c2Etc2VsZnNpZ25lZDAeFw0yNTA0MDgwNjU5NDNaFw0zNTA0MDYwNjU5NDNaMDkxFTATBgNVBAoTDHNpZ3N0b3JlLmRldjEgMB4GA1UEAxMXc2lnc3RvcmUtdHNhLXNlbGZzaWduZWQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQUQNtfRT/ou3YATa6wB/kKTe70cfJwyRIBovMnt8RcJph/COE82uyS6FmppLLL1VBPGcPfpQPYJNXzWwi8icwhKQ6W/Qe2h3oebBb2FHpwNJDqo+TMaC/tdfkv/ElJB72jRTBDMA4GA1UdDwEB/wQEAwIBBjASBgNVHRMBAf8ECDAGAQH/AgEAMB0GA1UdDgQWBBSY7AHvf7tR/9SVHm+KiJhTB4nOvzAKBggqhkjOPQQDAwNpADBmAjEAwGEGrfGZR1cen1R8/DTVMI943LssZmJRtDp/i7SfGHmGRP6gRbuj9vOK3b67Z0QQAjEAuT2H673LQEaHTcyQSZrkp4mX7WwkmF+sVbkYY5mXN+RMH13KUEHHOqASaemYWK/E"
          }
        ]
      },
      "validFor": {
        "start": "2025-07-04T00:00:00Z"
      }
    }
  ]
}
`;

export const TRUSTED_ROOT = deepFreeze(JSON.parse(TRUSTED_ROOT_JSON));

// ---------------------------------------------------------------------------------------------
// Constants

export const PUBLISH_ATTESTATION = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
export const SLSA_PROVENANCE_V02 = 'https://slsa.dev/provenance/v0.2';
export const SLSA_PROVENANCE_V1 = 'https://slsa.dev/provenance/v1';

const PREDICATE_KIND = new Map([
  [PUBLISH_ATTESTATION, 'publish'],
  [SLSA_PROVENANCE_V02, 'provenance'],
  [SLSA_PROVENANCE_V1, 'provenance'],
]);
const BUNDLE_VERSIONS = new Map([
  ['application/vnd.dev.sigstore.bundle+json;version=0.1', 1],
  ['application/vnd.dev.sigstore.bundle+json;version=0.2', 2],
  ['application/vnd.dev.sigstore.bundle+json;version=0.3', 3],
  ['application/vnd.dev.sigstore.bundle.v0.3+json', 3],
]);
const STATEMENT_TYPES = new Set(['https://in-toto.io/Statement/v0.1', 'https://in-toto.io/Statement/v1']);
const IN_TOTO = 'application/vnd.in-toto+json';
const GHA_WORKFLOW_V1 = 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1';
const NPM_GHA_V2 = 'https://github.com/npm/cli/gha/v2';
// pacote's MISSING_TIME_CUTOFF: a version without a publish time counts as published then.
const MISSING_TIME_CUTOFF = Date.parse('2015-01-01T00:00:00.000Z');

const OID = {
  codeSigning: '1.3.6.1.5.5.7.3.3',
  timeStamping: '1.3.6.1.5.5.7.3.8',
  extKeyUsage: '2.5.29.37',
  basicConstraints: '2.5.29.19',
  subjectAltName: '2.5.29.17',
  subjectKeyId: '2.5.29.14',
  sctList: '1.3.6.1.4.1.11129.2.4.2',
  signedData: '1.2.840.113549.1.7.2',
  tstInfo: '1.2.840.113549.1.9.16.1.4',
  contentType: '1.2.840.113549.1.9.3',
  messageDigest: '1.2.840.113549.1.9.4',
};
const DIGEST_OIDS = new Map([
  ['2.16.840.1.101.3.4.2.1', 'sha256'],
  ['2.16.840.1.101.3.4.2.2', 'sha384'],
  ['2.16.840.1.101.3.4.2.3', 'sha512'],
]);
const ECDSA_SIG_OIDS = new Map([
  ['1.2.840.10045.4.3.2', 'sha256'],
  ['1.2.840.10045.4.3.3', 'sha384'],
  ['1.2.840.10045.4.3.4', 'sha512'],
]);
// Fulcio's certificate extensions, 1.3.6.1.4.1.57264.1.x. Arcs 1 to 6 hold raw strings
// (deprecated); arcs 8 and later a DER UTF8String.
const FULCIO_ARCS = new Map([
  [1, 'issuerV1'], [8, 'issuer'], [9, 'signerUri'], [10, 'signerDigest'], [11, 'runnerEnvironment'],
  [12, 'sourceRepositoryUri'], [13, 'sourceDigest'], [14, 'sourceRef'], [15, 'sourceRepositoryId'],
  [16, 'sourceRepositoryOwnerUri'], [17, 'sourceRepositoryOwnerId'], [18, 'buildConfigUri'],
  [19, 'buildConfigDigest'], [20, 'buildTrigger'], [21, 'runInvocationUri'], [22, 'sourceRepositoryVisibility'],
]);
const FULCIO_PREFIX = '1.3.6.1.4.1.57264.1.';

// ---------------------------------------------------------------------------------------------
// Small helpers

function deepFreeze(value) {
  if (value && typeof value === 'object') {
    for (const v of Object.values(value)) deepFreeze(v);
    Object.freeze(value);
  }
  return value;
}

class Outcome extends Error {
  constructor(status, reason) {
    super(reason);
    this.status = status;
  }
}
function invalid(reason) { throw new Outcome('invalid', reason); }
function unsupported(reason) { throw new Outcome('unsupported', reason); }
function must(condition, reason) { if (!condition) invalid(reason); }

const B64_RE = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
// Strict base64 (standard alphabet, padded, canonical): the bytes, or null.
function b64(s) {
  if (typeof s !== 'string' || !B64_RE.test(s)) return null;
  const buf = Buffer.from(s, 'base64');
  return buf.toString('base64') === s ? buf : null;
}
const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
const iso = (ms) => new Date(ms).toISOString();

function toTime(v) {
  if (v instanceof Date) return v.getTime();
  if (typeof v === 'number') return Number.isFinite(v) ? v : NaN;
  if (typeof v === 'string' && v) return Date.parse(v);
  return NaN;
}
// A decimal integer field (Rekor writes int64 as strings).
function intField(v, what) {
  const s = typeof v === 'number' ? String(v) : v;
  must(typeof s === 'string' && /^(0|[1-9][0-9]*)$/.test(s) && Number.isSafeInteger(Number(s)), `${what} is not a non-negative integer`);
  return Number(s);
}
function verifySig(hash, data, key, signature) {
  if (!key || !signature || !signature.length) return false;
  try {
    return crypto.verify(hash, data, key, signature);
  } catch {
    return false;
  }
}
function isP256(key) {
  return key.asymmetricKeyType === 'ec' && key.asymmetricKeyDetails?.namedCurve === 'prime256v1';
}
function spkiKey(der) {
  try {
    return crypto.createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    return null;
  }
}
function inWindow(t, w) { return t >= w.start && t <= w.end; }
function windowOf(validFor, what) {
  const start = Date.parse(validFor?.start);
  const end = validFor?.end == null ? Infinity : Date.parse(validFor.end);
  if (Number.isNaN(start) || Number.isNaN(end)) throw new TypeError(`trusted root: ${what} has no readable validFor`);
  return { start, end };
}
const q = (v) => JSON.stringify(v);

// ---------------------------------------------------------------------------------------------
// Exported helpers

// The hex of an SRI string's digest for `algorithm` (sha512 by default), or null when the string
// is malformed, has no such digest, or has two different ones.
export function integrityToHex(sri, algorithm = 'sha512') {
  const sizes = { sha1: 20, sha256: 32, sha384: 48, sha512: 64 };
  if (!sizes[algorithm]) throw new TypeError(`integrityToHex: unknown algorithm ${algorithm}`);
  if (typeof sri !== 'string') return null;
  const found = new Set();
  for (const token of sri.trim().split(/\s+/)) {
    if (!token) continue;
    const m = /^([a-z0-9]+)-([A-Za-z0-9+/]+={0,2})(?:\?[\x21-\x7e]*)?$/.exec(token);
    if (!m) return null;
    if (m[1] !== algorithm) continue;
    const buf = b64(m[2]);
    if (!buf || buf.length !== sizes[algorithm]) return null;
    found.add(buf.toString('hex'));
  }
  return found.size === 1 ? [...found][0] : null;
}

// The package URL npm puts in an attestation's subject: pkg:npm/%40scope/name@version.
export function packagePurl(name, version) {
  return `pkg:npm/${name.startsWith('@') ? `%40${name.slice(1)}` : name}@${version}`;
}

// The npm registry's keyid for a P-256 key (base64 SPKI DER, or a KeyObject): the OpenSSH
// SHA256 fingerprint, over the SSH wire encoding of the key, unpadded base64.
export function npmKeyId(key) {
  const k = typeof key === 'string' ? spkiKey(Buffer.from(key, 'base64')) : key;
  if (!k || !isP256(k)) throw new TypeError('npmKeyId: not a P-256 public key');
  const jwk = k.export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const str = (b) => {
    const len = Buffer.alloc(4);
    len.writeUInt32BE(b.length);
    return Buffer.concat([len, b]);
  };
  const blob = Buffer.concat([str(Buffer.from('ecdsa-sha2-nistp256')), str(Buffer.from('nistp256')), str(point)]);
  return `SHA256:${sha256(blob).toString('base64').replace(/=+$/, '')}`;
}

// ---------------------------------------------------------------------------------------------
// Registry keys

// Prepared keys and trust material are cached by content (a caller may change its own arrays
// between calls), except the pinned, deep-frozen constants, which are cached by identity.
const pinnedCache = new WeakMap();
const contentCache = new Map();
function cached(kind, value, pinned, build) {
  if (value === pinned) {
    let v = pinnedCache.get(value);
    if (!v) pinnedCache.set(value, (v = build()));
    return v;
  }
  const key = `${kind}\n${JSON.stringify(value)}`;
  let v = contentCache.get(key);
  if (!v) {
    v = build();
    if (contentCache.size >= 32) contentCache.clear();
    contentCache.set(key, v);
  }
  return v;
}

// keys: an array in the /-/npm/v1/keys shape ({keyid, key: base64 SPKI DER | pem, scheme,
// expires}), or that response itself ({keys: [...]}). A key the orb can't use (another scheme,
// another curve, unreadable, a SHA256: keyid that isn't its fingerprint, an unreadable expiry, a
// keyid listed twice with different material) stays in the map with an `error`, so signatures
// under it are unknown-key, not unsigned.
function prepareKeys(keys) {
  const list = Array.isArray(keys) ? keys : Array.isArray(keys?.keys) ? keys.keys : null;
  if (!list) throw new TypeError('registry keys must be an array, or {keys: [...]}');
  return cached('keys', list, NPM_REGISTRY_KEYS, () => buildKeys(list));
}
function buildKeys(list) {
  const map = new Map();
  for (const k of list) {
    if (!k || typeof k.keyid !== 'string' || !k.keyid) throw new TypeError('a registry key has no keyid');
    let entry;
    try {
      const scheme = k.scheme ?? 'ecdsa-sha2-nistp256';
      const keytype = k.keytype ?? scheme;
      if (scheme !== 'ecdsa-sha2-nistp256' || keytype !== 'ecdsa-sha2-nistp256') throw new Error(`scheme ${scheme} is not ecdsa-sha2-nistp256`);
      let pub = null;
      if (typeof k.key === 'string') {
        const der = b64(k.key);
        if (!der) throw new Error('its key is not base64');
        pub = spkiKey(der);
      } else if (typeof k.pem === 'string') {
        try { pub = crypto.createPublicKey(k.pem); } catch { pub = null; }
      }
      if (!pub) throw new Error('its key is not a readable SPKI public key');
      if (!isP256(pub)) throw new Error('its key is not a P-256 key');
      if (k.keyid.startsWith('SHA256:') && npmKeyId(pub) !== k.keyid) throw new Error('its keyid is not the fingerprint of its key');
      let expires = null;
      if (k.expires != null) {
        expires = toTime(k.expires);
        if (Number.isNaN(expires)) throw new Error(`its expiry ${q(k.expires)} is not a date`);
      }
      entry = { keyid: k.keyid, pub, spki: pub.export({ format: 'der', type: 'spki' }), expires, error: null };
    } catch (e) {
      entry = { keyid: k.keyid, error: e.message };
    }
    const prev = map.get(k.keyid);
    if (prev && !(prev.spki && entry.spki && prev.spki.equals(entry.spki) && prev.expires === entry.expires)) {
      entry = { keyid: k.keyid, error: 'it is listed twice, with different material' };
    }
    map.set(k.keyid, entry);
  }
  return map;
}

// Verifies dist.signatures for one version: ECDSA P-256 / SHA-256 over
// `${name}@${version}:${integrity}`, where integrity is the one the caller binds (the
// lockfile's). Like npm, every signature must verify with a known key that had not expired when
// the version was published (publishedAt: the packument's time[version]; without one, npm's
// 2015-01-01 cutoff). Two signatures by one key (the registry has published those since
// 2026-07) must both verify.
// Returns {status: 'valid'|'invalid'|'unsigned'|'unknown-key', keyids, reason}: invalid wins over
// unknown-key, since a bad signature under a known key is a verdict.
export function verifyRegistrySignature({ name, version, integrity, signatures, publishedAt } = {}, keys = NPM_REGISTRY_KEYS) {
  if (typeof name !== 'string' || !name || typeof version !== 'string' || !version) {
    throw new TypeError('verifyRegistrySignature needs a name and a version');
  }
  const keyMap = prepareKeys(keys);
  if (signatures == null || (Array.isArray(signatures) && signatures.length === 0)) {
    return { status: 'unsigned', keyids: [], reason: 'the registry has no signature for this version' };
  }
  if (!Array.isArray(signatures)) return { status: 'invalid', keyids: [], reason: 'dist.signatures is not an array' };
  const keyids = [];
  for (const s of signatures) if (s && typeof s.keyid === 'string' && !keyids.includes(s.keyid)) keyids.push(s.keyid);
  if (typeof integrity !== 'string' || !integrity) {
    return { status: 'invalid', keyids, reason: 'there is no integrity to verify the signatures over' };
  }
  const message = Buffer.from(`${name}@${version}:${integrity}`, 'utf8');
  const hasTime = publishedAt != null;
  const when = hasTime ? toTime(publishedAt) : MISSING_TIME_CUTOFF;
  const problems = [];
  const unknown = [];
  signatures.forEach((s, i) => {
    const n = signatures.length > 1 ? `signature ${i + 1} ` : 'the signature ';
    if (!s || typeof s !== 'object' || typeof s.keyid !== 'string' || typeof s.sig !== 'string') {
      problems.push(`${n}is malformed`);
      return;
    }
    const k = keyMap.get(s.keyid);
    if (!k || k.error) {
      unknown.push(k ? `${s.keyid} (${k.error})` : s.keyid);
      return;
    }
    if (k.expires !== null) {
      if (Number.isNaN(when)) {
        problems.push(`${n}is by key ${s.keyid}, which expired ${iso(k.expires)}, and the publish time ${q(publishedAt)} is not a date`);
        return;
      }
      if (!(when < k.expires)) {
        const at = hasTime ? `the version was published ${iso(when)}` : 'the version has no publish time (npm then uses 2015-01-01)';
        problems.push(`${n}is by key ${s.keyid}, which expired ${iso(k.expires)}, but ${at}`);
        return;
      }
    }
    const sig = b64(s.sig);
    if (!verifySig('sha256', message, k.pub, sig)) problems.push(`${n}by key ${s.keyid} does not verify over ${name}@${version}:<integrity>`);
  });
  if (problems.length) return { status: 'invalid', keyids, reason: problems.join('; ') };
  if (unknown.length) {
    return { status: 'unknown-key', keyids, reason: `signed with a key the orb does not know: ${[...new Set(unknown)].join(', ')}` };
  }
  return { status: 'valid', keyids, reason: signatures.length > 1 ? `all ${signatures.length} signatures verify` : 'the signature verifies' };
}

// ---------------------------------------------------------------------------------------------
// DER

function derAt(buf, off, end) {
  must(off + 2 <= end, 'DER: truncated');
  const tag = buf[off];
  must((tag & 0x1f) !== 0x1f, 'DER: high tag numbers are not used here');
  let len = buf[off + 1];
  let hdr = 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    must(n >= 1 && n <= 4 && off + 2 + n <= end, 'DER: bad length');
    must(buf[off + 2] !== 0, 'DER: non-minimal length');
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + buf[off + 2 + i];
    must(len >= 128, 'DER: non-minimal length');
    hdr += n;
  }
  const start = off + hdr;
  const stop = start + len;
  must(stop <= end, 'DER: element overruns its container');
  return { tag, start, end: stop, raw: buf.subarray(off, stop), body: buf.subarray(start, stop) };
}
// The single element a buffer holds, with nothing after it.
function derTop(buf, tag) {
  const n = derAt(buf, 0, buf.length);
  must(n.end === buf.length, 'DER: trailing data');
  if (tag !== undefined) must(n.tag === tag, 'DER: unexpected element');
  return n;
}
function derKids(buf, node) {
  const out = [];
  let off = node.start;
  while (off < node.end) {
    const k = derAt(buf, off, node.end);
    out.push(k);
    off = k.end;
  }
  return out;
}
function derOid(node) {
  must(node.tag === 0x06 && node.body.length > 0, 'DER: expected an OID');
  const arcs = [];
  let v = 0;
  let fresh = true;
  for (const byte of node.body) {
    must(!(fresh && byte === 0x80), 'DER: non-minimal OID');
    v = v * 128 + (byte & 0x7f);
    fresh = !(byte & 0x80);
    if (fresh) {
      arcs.push(v);
      v = 0;
    }
  }
  must(fresh, 'DER: truncated OID');
  const first = arcs.shift();
  const head = first < 40 ? [0, first] : first < 80 ? [1, first - 40] : [2, first - 80];
  return [...head, ...arcs].join('.');
}
function derLen(n) {
  if (n < 128) return Buffer.from([n]);
  const bytes = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) bytes.unshift(v & 0xff);
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}
const derWrap = (tag, body) => Buffer.concat([Buffer.from([tag]), derLen(body.length), body]);

// A certificate's TBS parts and extensions: {tbs, tbsKids, extWrap, exts: Map(oid -> {value, raw})}.
function certParts(der) {
  const cert = derTop(der, 0x30);
  const [tbs] = derKids(der, cert);
  must(tbs && tbs.tag === 0x30, 'certificate: no TBSCertificate');
  const tbsKids = derKids(der, tbs);
  const extWrap = tbsKids.find((k) => k.tag === 0xa3) || null;
  const exts = new Map();
  if (extWrap) {
    const [seq, ...rest] = derKids(der, extWrap);
    must(seq && seq.tag === 0x30 && !rest.length, 'certificate: malformed extensions');
    for (const e of derKids(der, seq)) {
      must(e.tag === 0x30, 'certificate: malformed extension');
      const parts = derKids(der, e);
      must(parts.length === 2 || (parts.length === 3 && parts[1].tag === 0x01), 'certificate: malformed extension');
      const id = derOid(parts[0]);
      const value = parts[parts.length - 1];
      must(value.tag === 0x04, 'certificate: malformed extension value');
      must(!exts.has(id), `certificate: extension ${id} appears twice`);
      exts.set(id, { value: value.body, raw: e.raw });
    }
  }
  const hasVersion = tbsKids[0]?.tag === 0xa0;
  return { tbs, tbsKids, extWrap, exts, serial: tbsKids[hasVersion ? 1 : 0], issuer: tbsKids[hasVersion ? 3 : 2] };
}
// Whether basicConstraints says cA (X509Certificate.ca also wants keyCertSign, so it can't tell).
function basicConstraintsCa(parts) {
  const e = parts.exts.get(OID.basicConstraints);
  if (!e) return false;
  const [first] = derKids(e.value, derTop(e.value, 0x30));
  return first?.tag === 0x01 && first.body.length === 1 && first.body[0] !== 0;
}
function extKeyUsages(parts) {
  const e = parts.exts.get(OID.extKeyUsage);
  if (!e) return [];
  const seq = derTop(e.value, 0x30);
  return derKids(e.value, seq).map(derOid);
}

// The identity Fulcio wrote into a certificate, from its extensions and SAN (the first URI or
// e-mail address). Values are strings, or null when absent.
export function certificateIdentity(certDer) {
  const parts = certParts(Buffer.from(certDer));
  const id = {};
  for (const name of FULCIO_ARCS.values()) id[name] = null;
  for (const [oid, { value }] of parts.exts) {
    if (!oid.startsWith(FULCIO_PREFIX)) continue;
    const arc = Number(oid.slice(FULCIO_PREFIX.length));
    const name = FULCIO_ARCS.get(arc);
    if (!name) continue;
    if (arc < 8) {
      id[name] = value.toString('utf8');
    } else {
      const s = derTop(value);
      must(s.tag === 0x0c, `certificate: Fulcio extension ${oid} is not a UTF8String`);
      id[name] = s.body.toString('utf8');
    }
  }
  id.san = null;
  const san = parts.exts.get(OID.subjectAltName);
  if (san) {
    const seq = derTop(san.value, 0x30);
    for (const g of derKids(san.value, seq)) {
      if (g.tag === 0x86 || g.tag === 0x81) {
        id.san = g.body.toString('utf8');
        break;
      }
    }
  }
  return id;
}

// ---------------------------------------------------------------------------------------------
// Trusted root

function prepareTrust(root) {
  if (!root || typeof root !== 'object') throw new TypeError('trustedRoot must be a trusted_root.json object');
  return cached('trust', root, TRUSTED_ROOT, () => buildTrust(root));
}
function buildTrust(root) {
  if (typeof root.mediaType !== 'string' || !root.mediaType.startsWith('application/vnd.dev.sigstore.trustedroot')) {
    throw new TypeError('trustedRoot is not a Sigstore trusted root');
  }
  const certOf = (c, what) => {
    const der = b64(c?.rawBytes);
    if (!der) throw new TypeError(`trusted root: ${what} has an unreadable certificate`);
    try {
      return new crypto.X509Certificate(der);
    } catch {
      throw new TypeError(`trusted root: ${what} has an unreadable certificate`);
    }
  };
  const logOf = (l, what) => {
    const der = b64(l?.publicKey?.rawBytes);
    const key = der ? spkiKey(der) : null;
    if (typeof l?.logId?.keyId !== 'string') throw new TypeError(`trusted root: ${what} has no log ID`);
    let host = null;
    try { host = new URL(l.baseUrl).host; } catch { host = null; }
    return {
      logId: l.logId.keyId,
      baseUrl: l.baseUrl,
      host,
      keyDetails: l.publicKey?.keyDetails,
      // Only ECDSA P-256 logs are implemented (Rekor v1 and CT); Rekor v2's Ed25519 is not.
      key: key && isP256(key) && l.publicKey?.keyDetails === 'PKIX_ECDSA_P256_SHA_256' ? key : null,
      window: windowOf(l.publicKey?.validFor, what),
    };
  };
  const chainOf = (a, what) => {
    const certs = a?.certChain?.certificates;
    if (!Array.isArray(certs) || !certs.length) throw new TypeError(`trusted root: ${what} has no certificate chain`);
    return { chain: certs.map((c) => certOf(c, what)), window: windowOf(a.validFor, what), uri: a.uri ?? null };
  };
  return {
    tlogs: (root.tlogs || []).map((l, i) => logOf(l, `tlog ${i + 1}`)),
    ctlogs: (root.ctlogs || []).map((l, i) => logOf(l, `ctlog ${i + 1}`)),
    cas: (root.certificateAuthorities || []).map((a, i) => chainOf(a, `certificate authority ${i + 1}`)),
    tsas: (root.timestampAuthorities || []).map((a, i) => chainOf(a, `timestamp authority ${i + 1}`)),
  };
}

const certWindow = (c) => ({ start: Date.parse(c.validFrom), end: Date.parse(c.validTo) });

// Whether `leaf` chains through `chain` (issuer first, ending self-signed), every certificate
// valid at every time in `times`.
function chainsTo(leaf, chain, times) {
  let child = leaf;
  for (const parent of chain) {
    if (!parent.ca || !child.checkIssued(parent) || !child.verify(parent.publicKey)) return false;
    const w = certWindow(parent);
    if (!times.every((t) => inWindow(t, w))) return false;
    child = parent;
  }
  return child.checkIssued(child) && child.verify(child.publicKey);
}

// ---------------------------------------------------------------------------------------------
// Transparency log (Rekor v1)

// RFC 6962 / RFC 9162 2.1.3.2: the root an inclusion proof leads to.
function rootFromInclusion(index, size, leaf, proof) {
  must(index < size, 'inclusion proof: index is not below the tree size');
  let fn = index;
  let sn = size - 1;
  let r = leaf;
  for (const p of proof) {
    must(sn !== 0, 'inclusion proof: too long');
    if (fn % 2 === 1 || fn === sn) {
      r = sha256(Buffer.concat([Buffer.from([1]), p, r]));
      if (fn % 2 === 0) {
        while (fn % 2 === 0 && fn !== 0) {
          fn = Math.floor(fn / 2);
          sn = Math.floor(sn / 2);
        }
      }
    } else {
      r = sha256(Buffer.concat([Buffer.from([1]), r, p]));
    }
    fn = Math.floor(fn / 2);
    sn = Math.floor(sn / 2);
  }
  must(sn === 0, 'inclusion proof: too short');
  return r;
}

// A signed note (https://github.com/transparency-dev/formats/blob/main/log/README.md): origin,
// tree size, root hash, a blank line, then "— <name> <base64(keyhint || signature)>" lines.
function verifyCheckpoint(text, log, size, root) {
  must(typeof text === 'string', 'checkpoint: missing');
  const sep = text.indexOf('\n\n');
  must(sep > 0, 'checkpoint: malformed');
  const note = text.slice(0, sep + 1);
  const lines = note.slice(0, -1).split('\n');
  must(lines.length >= 3, 'checkpoint: malformed');
  const [origin, sizeLine, rootLine] = lines;
  must(log.host && (origin === log.host || origin.startsWith(`${log.host} - `)), `checkpoint: origin ${q(origin)} is not ${log.host}`);
  must(/^(0|[1-9][0-9]*)$/.test(sizeLine) && Number(sizeLine) === size, 'checkpoint: its tree size is not the inclusion proof\'s');
  const rootHash = b64(rootLine);
  must(rootHash && rootHash.equals(root), 'checkpoint: its root hash is not the inclusion proof\'s');
  const hint = b64(log.logId)?.subarray(0, 4);
  let signed = false;
  for (const line of text.slice(sep + 2).split('\n')) {
    const m = /^— (\S+) (\S+)$/.exec(line);
    if (!m || m[1] !== log.host) continue;
    const raw = b64(m[2]);
    if (!raw || raw.length < 5 || !hint || !raw.subarray(0, 4).equals(hint)) continue;
    if (verifySig('sha256', Buffer.from(note, 'utf8'), log.key, raw.subarray(4))) signed = true;
  }
  must(signed, 'checkpoint: not signed by the transparency log');
}

function verifyInclusion(proof, body, log) {
  must(proof && typeof proof === 'object', 'inclusion proof: malformed');
  const index = intField(proof.logIndex, 'inclusion proof log index');
  const size = intField(proof.treeSize, 'inclusion proof tree size');
  must(Array.isArray(proof.hashes), 'inclusion proof: no hashes');
  const hashes = proof.hashes.map((h) => {
    const buf = b64(h);
    must(buf && buf.length === 32, 'inclusion proof: a hash is not 32 bytes');
    return buf;
  });
  const root = b64(proof.rootHash);
  must(root && root.length === 32, 'inclusion proof: the root hash is not 32 bytes');
  const leaf = sha256(Buffer.concat([Buffer.from([0]), body]));
  must(rootFromInclusion(index, size, leaf, hashes).equals(root), 'inclusion proof: it does not lead to the root hash');
  verifyCheckpoint(proof.checkpoint?.envelope, log, size, root);
}

// Canonical JSON (RFC 8785) of the SET payload, which holds only strings and integers.
function canonicalJson(v) {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`;
  if (v && typeof v === 'object') return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canonicalJson(v[k])}`).join(',')}}`;
  return JSON.stringify(v);
}

// Verifies one tlog entry against the envelope and signer; returns integratedTime in ms.
function verifyTlogEntry(entry, env, payload, signature, signerMatches, trust, bundleVersion) {
  must(entry && typeof entry === 'object', 'tlog entry: malformed');
  const kv = entry.kindVersion;
  must(kv && typeof kv.kind === 'string' && typeof kv.version === 'string', 'tlog entry: no kindVersion');
  const logId = entry.logId?.keyId;
  must(typeof logId === 'string', 'tlog entry: no log ID');
  const log = trust.tlogs.find((l) => l.logId === logId);
  if (!log) unsupported(`tlog entry: log ${logId} is not in the pinned trusted root`);
  if (!entry.inclusionPromise) unsupported('tlog entry: no signed entry timestamp (Rekor v2 entries are not implemented)');
  if (!log.key) unsupported(`tlog entry: log ${log.baseUrl} uses ${log.keyDetails}, which is not implemented`);
  if (!((kv.kind === 'dsse' && kv.version === '0.0.1') || (kv.kind === 'intoto' && kv.version === '0.0.2'))) {
    unsupported(`tlog entry: kind ${kv.kind} ${kv.version} is not implemented`);
  }
  const seconds = intField(entry.integratedTime, 'tlog entry integratedTime');
  const t = seconds * 1000;
  must(inWindow(t, log.window), `tlog entry: the key of ${log.baseUrl} was not valid at ${iso(t)}`);
  const logIndex = intField(entry.logIndex, 'tlog entry log index');
  const bodyBytes = b64(entry.canonicalizedBody);
  must(bodyBytes, 'tlog entry: the body is not base64');
  let body;
  try {
    body = JSON.parse(bodyBytes.toString('utf8'));
  } catch {
    invalid('tlog entry: the body is not JSON');
  }
  must(body && body.kind === kv.kind && body.apiVersion === kv.version, 'tlog entry: the body\'s kind is not its kindVersion');
  const payloadHash = sha256(payload).toString('hex');
  if (kv.kind === 'dsse') {
    const s = body.spec;
    must(s?.payloadHash?.algorithm === 'sha256' && s.payloadHash.value === payloadHash, 'tlog entry: it is for another payload');
    must(Array.isArray(s.signatures) && s.signatures.length === 1, 'tlog entry: it does not hold one signature');
    must(b64(s.signatures[0]?.signature)?.equals(signature), 'tlog entry: it is for another signature');
    must(signerMatches(b64(s.signatures[0].verifier)?.toString('utf8')), 'tlog entry: it names another signer');
  } else {
    const c = body.spec?.content;
    must(c?.payloadHash?.algorithm === 'sha256' && c.payloadHash.value === payloadHash, 'tlog entry: it is for another payload');
    must(c.envelope?.payloadType === env.payloadType, 'tlog entry: it is for another payload type');
    must(Array.isArray(c.envelope.signatures) && c.envelope.signatures.length === 1, 'tlog entry: it does not hold one signature');
    // intoto 0.0.2 encodes the signature and the public key in base64 twice.
    const inner = b64(c.envelope.signatures[0]?.sig)?.toString('utf8');
    must(b64(inner)?.equals(signature), 'tlog entry: it is for another signature');
    must(signerMatches(b64(c.envelope.signatures[0].publicKey)?.toString('utf8')), 'tlog entry: it names another signer');
  }
  const set = canonicalJson({ body: entry.canonicalizedBody, integratedTime: seconds, logID: b64(logId)?.toString('hex'), logIndex });
  must(verifySig('sha256', Buffer.from(set), log.key, b64(entry.inclusionPromise.signedEntryTimestamp)), 'tlog entry: the signed entry timestamp (SET) does not verify');
  if (entry.inclusionProof != null) verifyInclusion(entry.inclusionProof, bodyBytes, log);
  else must(bundleVersion < 2, 'tlog entry: bundles from v0.2 on must carry an inclusion proof');
  return t;
}

// ---------------------------------------------------------------------------------------------
// RFC 3161 timestamps

function generalizedTime(node) {
  must(node.tag === 0x18, 'timestamp: genTime is not a GeneralizedTime');
  const m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(node.body.toString('latin1'));
  must(m, 'timestamp: unreadable genTime');
  const ms = m[7] ? Number(m[7].padEnd(3, '0').slice(0, 3)) : 0;
  return Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]), ms);
}
const unsignedHex = (buf) => buf.toString('hex').replace(/^(00)+(?=.)/, '').toUpperCase();
const algorithmOid = (der, node) => {
  must(node.tag === 0x30, 'timestamp: malformed algorithm identifier');
  return derOid(derKids(der, node)[0] || {});
};

// Verifies an RFC 3161 timestamp token over `signature` (the DSSE signature); returns genTime.
// `der` is a TimeStampResp (what Sigstore bundles hold) or a bare TimeStampToken.
function verifyTimestamp(der, signature, trust) {
  let ci = derTop(der, 0x30);
  const top = derKids(der, ci);
  if (top[0]?.tag === 0x30) {
    must(top.length === 2, 'timestamp: malformed TimeStampResp');
    const [status] = derKids(der, top[0]);
    must(status?.tag === 0x02 && status.body.length === 1 && status.body[0] <= 1, 'timestamp: the response does not grant a timestamp');
    ci = top[1];
    must(ci.tag === 0x30, 'timestamp: malformed TimeStampResp');
  }
  const [type, wrapped] = derKids(der, ci);
  must(type && derOid(type) === OID.signedData && wrapped?.tag === 0xa0, 'timestamp: not CMS SignedData');
  const [sd] = derKids(der, wrapped);
  must(sd?.tag === 0x30, 'timestamp: malformed SignedData');
  const parts = derKids(der, sd);
  must(parts.length >= 4 && parts[0].tag === 0x02 && parts[1].tag === 0x31 && parts[2].tag === 0x30, 'timestamp: malformed SignedData');
  const signerInfos = parts[parts.length - 1];
  must(signerInfos.tag === 0x31, 'timestamp: no signer infos');
  const [eType, eWrap] = derKids(der, parts[2]);
  must(eType && derOid(eType) === OID.tstInfo && eWrap?.tag === 0xa0, 'timestamp: the content is not a TSTInfo');
  const [eContent] = derKids(der, eWrap);
  must(eContent?.tag === 0x04, 'timestamp: malformed content');
  const tstBytes = eContent.body;
  const tst = derKids(tstBytes, derTop(tstBytes, 0x30));
  must(tst.length >= 5 && tst[0].tag === 0x02 && tst[2].tag === 0x30, 'timestamp: malformed TSTInfo');
  const [imprintAlg, imprintHash] = derKids(tstBytes, tst[2]);
  const imprintDigest = DIGEST_OIDS.get(algorithmOid(tstBytes, imprintAlg || {}));
  if (!imprintDigest) unsupported('timestamp: its imprint hash algorithm is not implemented');
  must(imprintHash?.tag === 0x04 && imprintHash.body.equals(crypto.createHash(imprintDigest).update(signature).digest()), 'timestamp: it is not over this signature');
  const genTime = generalizedTime(tst[4]);

  const infos = derKids(der, signerInfos);
  must(infos.length === 1 && infos[0].tag === 0x30, 'timestamp: it must have one signer');
  const si = derKids(der, infos[0]);
  must(si.length >= 6 && si[0].tag === 0x02, 'timestamp: malformed signer info');
  const [, sid, digestAlg, attrs, sigAlg, sigValue] = si;
  must(attrs.tag === 0xa0 && sigValue.tag === 0x04, 'timestamp: the signer info has no signed attributes');
  const digest = DIGEST_OIDS.get(algorithmOid(der, digestAlg));
  if (!digest) unsupported('timestamp: its digest algorithm is not implemented');
  const sigHash = ECDSA_SIG_OIDS.get(algorithmOid(der, sigAlg));
  if (!sigHash) unsupported('timestamp: its signature algorithm is not implemented');
  let contentTypeOk = false;
  let digestOk = false;
  for (const a of derKids(der, attrs)) {
    must(a.tag === 0x30, 'timestamp: malformed attribute');
    const [aType, aValues] = derKids(der, a);
    must(aValues?.tag === 0x31, 'timestamp: malformed attribute');
    const values = derKids(der, aValues);
    const id = derOid(aType);
    if (id === OID.contentType) {
      must(!contentTypeOk && values.length === 1, 'timestamp: malformed content type attribute');
      contentTypeOk = derOid(values[0]) === OID.tstInfo;
    } else if (id === OID.messageDigest) {
      must(!digestOk && values.length === 1 && values[0].tag === 0x04, 'timestamp: malformed message digest attribute');
      digestOk = values[0].body.equals(crypto.createHash(digest).update(tstBytes).digest());
      must(digestOk, 'timestamp: the message digest is not the TSTInfo\'s');
    }
  }
  must(contentTypeOk && digestOk, 'timestamp: the signed attributes lack the content type or message digest');
  const signedAttrs = Buffer.from(attrs.raw);
  signedAttrs[0] = 0x31; // signed as a SET OF
  for (const tsa of trust.tsas) {
    if (!inWindow(genTime, tsa.window)) continue;
    const [leaf, ...issuers] = tsa.chain;
    if (!inWindow(genTime, certWindow(leaf)) || !chainsTo(leaf, issuers, [genTime])) continue;
    const leafParts = certParts(leaf.raw);
    if (!extKeyUsages(leafParts).includes(OID.timeStamping)) continue;
    if (sid.tag === 0x30) {
      const [issuer, serial] = derKids(der, sid);
      if (!issuer || !serial || !issuer.raw.equals(leafParts.issuer.raw) || unsignedHex(serial.body) !== unsignedHex(leafParts.serial.body)) continue;
    } else if (sid.tag === 0x80) {
      const ski = leafParts.exts.get(OID.subjectKeyId);
      if (!ski || !derTop(ski.value, 0x04).body.equals(sid.body)) continue;
    } else {
      continue;
    }
    if (verifySig(sigHash, signedAttrs, leaf.publicKey, sigValue.body)) return genTime;
  }
  invalid(`timestamp: not signed by a pinned timestamp authority valid at ${iso(genTime)}`);
  return NaN;
}

// ---------------------------------------------------------------------------------------------
// Fulcio certificates

// RFC 6962 3.2: at least one embedded SCT must verify against a pinned CT log, over the
// precertificate (the TBS without the SCT extension) and the issuer's key hash. Fulcio gets the
// SCT as it issues the certificate (0 to 1 s after notBefore in every sample).
function verifySct(leafDer, leafWindow, issuer, trust) {
  const parts = certParts(leafDer);
  const sctExt = parts.exts.get(OID.sctList);
  must(sctExt, 'certificate: no embedded SCT');
  const list = derTop(sctExt.value, 0x04).body;
  must(list.length >= 2 && list.readUInt16BE(0) === list.length - 2, 'certificate: malformed SCT list');
  const scts = [];
  for (let off = 2; off < list.length;) {
    must(off + 2 <= list.length, 'certificate: malformed SCT list');
    const len = list.readUInt16BE(off);
    must(off + 2 + len <= list.length, 'certificate: malformed SCT list');
    scts.push(list.subarray(off + 2, off + 2 + len));
    off += 2 + len;
  }
  const extSeq = derKids(leafDer, parts.extWrap)[0];
  const kept = derKids(leafDer, extSeq).filter((e) => derOid(derKids(leafDer, e)[0]) !== OID.sctList).map((e) => e.raw);
  const extensions = derWrap(0xa3, derWrap(0x30, Buffer.concat(kept)));
  const preTbs = derWrap(0x30, Buffer.concat(parts.tbsKids.map((k) => (k === parts.extWrap ? extensions : k.raw))));
  const issuerKeyHash = sha256(issuer.publicKey.export({ format: 'der', type: 'spki' }));
  const len3 = Buffer.from([(preTbs.length >> 16) & 0xff, (preTbs.length >> 8) & 0xff, preTbs.length & 0xff]);
  for (const s of scts) {
    if (s.length < 47 || s[0] !== 0) continue; // v1 only
    const logId = s.subarray(1, 33).toString('base64');
    const timestamp = s.subarray(33, 41);
    const extLen = s.readUInt16BE(41);
    const sigOff = 43 + extLen;
    if (sigOff + 4 > s.length) continue;
    if (s[sigOff] !== 4 || s[sigOff + 1] !== 3) continue; // SHA-256, ECDSA
    const sigLen = s.readUInt16BE(sigOff + 2);
    if (sigOff + 4 + sigLen !== s.length) continue;
    const log = trust.ctlogs.find((c) => c.logId === logId);
    const t = Number(timestamp.readBigUInt64BE());
    // The SCT's time must fall in the log key's validity and the certificate's.
    if (!log || !log.key || !inWindow(t, log.window) || !inWindow(t, { start: leafWindow.start, end: leafWindow.end + 999 })) continue;
    const signed = Buffer.concat([
      Buffer.from([0, 0]), timestamp, Buffer.from([0, 1]), issuerKeyHash, len3, preTbs,
      s.subarray(41, 43), s.subarray(43, sigOff),
    ]);
    if (verifySig('sha256', signed, log.key, s.subarray(sigOff + 4))) return;
  }
  invalid('certificate: no embedded SCT verifies against a pinned CT log');
}

// The leaf must be an end-entity code-signing certificate valid at every signing time, chaining
// to a pinned Fulcio CA valid at every signing time, with a verifying SCT.
function verifyFulcioCertificate(leaf, leafDer, times, trust) {
  const parts = certParts(leafDer);
  must(!leaf.ca && !basicConstraintsCa(parts), 'certificate: it is a CA certificate');
  must(extKeyUsages(parts).includes(OID.codeSigning), 'certificate: it lacks the code-signing extended key usage');
  const w = certWindow(leaf);
  for (const t of times) {
    must(inWindow(t, w), `certificate: signing time ${iso(t)} is outside its validity (${iso(w.start)} to ${iso(w.end)})`);
  }
  for (const ca of trust.cas) {
    if (!times.every((t) => inWindow(t, ca.window))) continue;
    if (!chainsTo(leaf, ca.chain, times)) continue;
    verifySct(leafDer, w, ca.chain[0], trust);
    return;
  }
  invalid('certificate: it does not chain to a pinned Fulcio CA valid at signing time');
}

// ---------------------------------------------------------------------------------------------
// Predicates

function agree(certValue, claimed, what) {
  if (certValue == null || claimed == null) return;
  must(String(certValue) === String(claimed), `provenance: its ${what} ${q(String(claimed))} is not the certificate's ${q(certValue)}`);
}

function checkPublishPredicate(p, name, version) {
  must(p && typeof p === 'object', 'publish attestation: no predicate');
  must(p.name === name && p.version === version, `publish attestation: it is for ${q(p.name)}@${q(p.version)}`);
  return typeof p.registry === 'string' ? p.registry : null;
}

// The identity: the certificate's, with the workflow the predicate names when its build type is
// a GitHub Actions one the orb knows, after checking the two agree.
function provenanceIdentity(leafDer, statement) {
  const cert = certificateIdentity(leafDer);
  const p = statement.predicate;
  must(p && typeof p === 'object', 'provenance: no predicate');
  let workflow = null;
  let buildType = null;
  if (statement.predicateType === SLSA_PROVENANCE_V1) {
    const bd = p.buildDefinition;
    must(bd && typeof bd === 'object', 'provenance: no build definition');
    buildType = typeof bd.buildType === 'string' ? bd.buildType : null;
    if (buildType === GHA_WORKFLOW_V1) {
      const wf = bd.externalParameters?.workflow;
      must(wf && typeof wf.repository === 'string' && typeof wf.path === 'string' && typeof wf.ref === 'string', 'provenance: it names no workflow');
      workflow = { repository: wf.repository, path: wf.path, ref: wf.ref };
      const gh = bd.internalParameters?.github;
      agree(cert.sourceRepositoryId, gh?.repository_id, 'repository ID');
      agree(cert.sourceRepositoryOwnerId, gh?.repository_owner_id, 'repository owner ID');
      const dep = Array.isArray(bd.resolvedDependencies) ? bd.resolvedDependencies[0] : null;
      agree(cert.sourceDigest, dep?.digest?.gitCommit, 'source commit');
    }
  } else {
    buildType = typeof p.buildType === 'string' ? p.buildType : null;
    if (buildType === NPM_GHA_V2) {
      const cs = p.invocation?.configSource;
      must(cs && typeof cs.uri === 'string' && typeof cs.entryPoint === 'string', 'provenance: it names no workflow');
      const m = /^git\+(https:\/\/[^@]+)@(refs\/.+)$/.exec(cs.uri);
      must(m, `provenance: unreadable config source ${q(cs.uri)}`);
      workflow = { repository: m[1], path: cs.entryPoint, ref: m[2] };
      const env = p.invocation.environment;
      agree(cert.sourceRepositoryId, env?.GITHUB_REPOSITORY_ID, 'repository ID');
      agree(cert.sourceRepositoryOwnerId, env?.GITHUB_REPOSITORY_OWNER_ID, 'repository owner ID');
      agree(cert.sourceDigest, cs.digest?.sha1, 'source commit');
    }
  }
  if (workflow) {
    agree(cert.sourceRepositoryUri, workflow.repository, 'source repository');
    agree(cert.sourceRef, workflow.ref, 'source ref');
    agree(cert.buildConfigUri, `${workflow.repository}/${workflow.path}@${workflow.ref}`, 'workflow');
  }
  return {
    issuer: cert.issuer ?? cert.issuerV1,
    san: cert.san,
    signerUri: cert.signerUri,
    signerDigest: cert.signerDigest,
    runnerEnvironment: cert.runnerEnvironment,
    sourceRepositoryUri: cert.sourceRepositoryUri,
    sourceRepositoryId: cert.sourceRepositoryId,
    sourceRepositoryOwnerUri: cert.sourceRepositoryOwnerUri,
    sourceRepositoryOwnerId: cert.sourceRepositoryOwnerId,
    sourceRepositoryVisibility: cert.sourceRepositoryVisibility,
    sourceRef: cert.sourceRef,
    sourceDigest: cert.sourceDigest,
    buildConfigUri: cert.buildConfigUri,
    buildConfigDigest: cert.buildConfigDigest,
    buildTrigger: cert.buildTrigger,
    runInvocationUri: cert.runInvocationUri,
    buildType,
    workflow,
  };
}

// ---------------------------------------------------------------------------------------------
// Attestations

// Whether the PEM a log entry names is the signer: the same SPKI, or the same certificate (the
// first of the PEM).
function samePublicKey(pem, spki) {
  try {
    return crypto.createPublicKey(pem).export({ format: 'der', type: 'spki' }).equals(spki);
  } catch {
    return false;
  }
}
function sameCertificate(pem, der) {
  try {
    return new crypto.X509Certificate(pem).raw.equals(der);
  } catch {
    return false;
  }
}

const pae = (type, payload) => Buffer.concat([Buffer.from(`DSSEv1 ${Buffer.byteLength(type)} ${type} ${payload.length} `), payload]);

function verifyBundle(a, ctx) {
  must(a && typeof a === 'object' && typeof a.predicateType === 'string', 'malformed attestation');
  const b = a.bundle;
  must(b && typeof b === 'object', 'the attestation has no bundle');
  const bundleVersion = BUNDLE_VERSIONS.get(b.mediaType);
  if (!bundleVersion) unsupported(`bundle media type ${q(b.mediaType)} is not implemented`);
  const env = b.dsseEnvelope;
  if (!env) {
    if (b.messageSignature) unsupported('message-signature bundles are not implemented');
    invalid('the bundle has no DSSE envelope');
  }
  const vm = b.verificationMaterial;
  must(vm && typeof vm === 'object', 'the bundle has no verification material');
  if (env.payloadType !== IN_TOTO) unsupported(`DSSE payload type ${q(env.payloadType)} is not implemented`);
  must(Array.isArray(env.signatures) && env.signatures.length === 1, 'the DSSE envelope must hold exactly one signature');
  const payload = b64(env.payload);
  must(payload && payload.length, 'the DSSE payload is not base64');
  const signature = b64(env.signatures[0]?.sig);
  must(signature && signature.length, 'the DSSE signature is not base64');

  // The signer, and the DSSE signature over the payload, before anything reads the payload.
  const kind = PREDICATE_KIND.get(a.predicateType) ?? null;
  const message = pae(env.payloadType, payload);
  const materials = ['publicKey', 'certificate', 'x509CertificateChain'].filter((m) => vm[m] != null);
  must(materials.length === 1, 'the verification material must hold exactly one key, certificate or chain');
  let signer;
  if (materials[0] === 'publicKey') {
    must(kind !== 'provenance', 'SLSA provenance must be signed with a Fulcio certificate, not a key');
    const hint = vm.publicKey.hint;
    must(typeof hint === 'string' && hint, 'the public key has no hint');
    must(env.signatures[0].keyid === hint, 'the DSSE signature\'s keyid is not the key hint');
    const k = ctx.keys.get(hint);
    if (!k) unsupported(`signed with npm registry key ${hint}, which the orb does not pin`);
    if (k.error) unsupported(`signed with npm registry key ${hint}, which the orb cannot use: ${k.error}`);
    must(verifySig('sha256', message, k.pub, signature), 'the DSSE signature does not verify with the npm registry key');
    signer = { key: k, matches: (pem) => samePublicKey(pem, k.spki) };
  } else {
    must(kind !== 'publish', 'the publish attestation must be signed with an npm registry key');
    const raw = materials[0] === 'certificate' ? b64(vm.certificate.rawBytes) : b64(vm.x509CertificateChain.certificates?.[0]?.rawBytes);
    must(raw, 'the certificate is not base64');
    let leaf;
    try {
      leaf = new crypto.X509Certificate(raw);
    } catch {
      invalid('the certificate does not parse');
    }
    must(leaf.raw.equals(raw), 'the certificate has trailing data');
    if (!isP256(leaf.publicKey)) unsupported('the certificate\'s key is not ECDSA P-256');
    must(verifySig('sha256', message, leaf.publicKey, signature), 'the DSSE signature does not verify with the certificate\'s key');
    signer = { leaf, raw, matches: (pem) => sameCertificate(pem, raw) };
  }

  // The signed statement, which binds the attestation to this package.
  let st;
  try {
    st = JSON.parse(payload.toString('utf8'));
  } catch {
    invalid('the DSSE payload is not JSON');
  }
  must(st && typeof st === 'object' && !Array.isArray(st), 'the DSSE payload is not an in-toto statement');
  if (!STATEMENT_TYPES.has(st._type)) unsupported(`in-toto statement type ${q(st._type)} is not implemented`);
  must(st.predicateType === a.predicateType, `the statement's predicate type ${q(st.predicateType)} is not the attestation's`);
  must(Array.isArray(st.subject) && st.subject.length === 1, 'the statement must have exactly one subject');
  const subject = st.subject[0];
  must(subject && subject.name === ctx.purl, `the subject ${q(subject?.name)} is not ${ctx.purl}`);
  must(ctx.digest, 'the integrity has no sha512 digest to compare with the subject\'s');
  must(subject.digest && subject.digest.sha512 === ctx.digest, 'the subject\'s sha512 digest is not the integrity\'s');

  // When it was signed: every transparency log entry, then every RFC 3161 timestamp.
  must(Array.isArray(vm.tlogEntries) && vm.tlogEntries.length >= 1, 'the bundle has no transparency log entry');
  const logTimes = vm.tlogEntries.map((e) => verifyTlogEntry(e, env, payload, signature, signer.matches, ctx.trust, bundleVersion));
  const stamps = [];
  const tsd = vm.timestampVerificationData;
  if (tsd != null) {
    must(typeof tsd === 'object', 'malformed timestamp verification data');
    const list = tsd.rfc3161Timestamps ?? [];
    must(Array.isArray(list), 'malformed RFC 3161 timestamps');
    for (const ts of list) {
      const der = b64(ts?.signedTimestamp);
      must(der, 'an RFC 3161 timestamp is not base64');
      stamps.push(verifyTimestamp(der, signature, ctx.trust));
    }
  }
  const times = [...logTimes, ...stamps];

  // The signer at those times.
  if (signer.key) {
    for (const t of times) {
      must(signer.key.expires === null || t < signer.key.expires, `npm registry key ${signer.key.keyid} expired ${iso(signer.key.expires ?? 0)}, before the signing time ${iso(t)}`);
    }
  } else {
    verifyFulcioCertificate(signer.leaf, signer.raw, times, ctx.trust);
  }

  const result = {
    signer: signer.key ? 'npm-registry-key' : 'fulcio-certificate',
    keyid: signer.key ? signer.key.keyid : null,
    integratedTime: iso(logTimes[0]),
    timestamps: stamps.map(iso),
    registry: null,
    identity: null,
  };
  if (kind === 'publish') result.registry = checkPublishPredicate(st.predicate, ctx.name, ctx.version);
  else if (kind === 'provenance') result.identity = provenanceIdentity(signer.raw, st);
  else unsupported(`predicate type ${q(a.predicateType)} is not implemented (its signature verifies)`);
  return result;
}

function worst(statuses) {
  if (!statuses.length) return null;
  if (statuses.includes('invalid')) return 'invalid';
  if (statuses.includes('unsupported')) return 'unsupported';
  return 'valid';
}

const IDENTITY_KEYS = ['issuer', 'sourceRepositoryUri', 'sourceRepositoryId', 'sourceRepositoryOwnerId', 'sourceRef', 'sourceDigest', 'buildConfigUri', 'signerUri'];

// Verifies every attestation in a GET /-/npm/v1/attestations/<name>@<version> response, for the
// package the caller names with the integrity it binds (the lockfile's).
// Returns {attestations: [result], summary}. A result is
//   {predicateType, mediaType, kind: 'publish'|'provenance'|null, status: 'valid'|'invalid'|
//    'unsupported', reason, signer: 'npm-registry-key'|'fulcio-certificate'|null, keyid,
//    integratedTime, timestamps, registry (publish), identity (valid provenance; else null)}.
// The summary is {status: 'valid'|'invalid'|'unsupported'|'none', publish, provenance, identity,
// reason}: publish and provenance are the worst status among attestations of that kind (invalid,
// then unsupported, then valid), or null when there is none; identity is the valid provenance's,
// or null. Two valid provenance attestations naming different sources make provenance invalid.
export function verifyAttestations(response, { name, version, integrity, trustedRoot = TRUSTED_ROOT, npmKeys = NPM_REGISTRY_KEYS } = {}) {
  if (typeof name !== 'string' || !name || typeof version !== 'string' || !version) {
    throw new TypeError('verifyAttestations needs a name and a version');
  }
  const ctx = {
    name,
    version,
    purl: packagePurl(name, version),
    digest: integrityToHex(integrity),
    trust: prepareTrust(trustedRoot),
    keys: prepareKeys(npmKeys),
  };
  if (!response || typeof response !== 'object' || !Array.isArray(response.attestations)) {
    return {
      attestations: [],
      summary: { status: 'invalid', publish: null, provenance: null, identity: null, reason: 'the response holds no attestations array' },
    };
  }
  const attestations = response.attestations.map((a) => {
    const predicateType = typeof a?.predicateType === 'string' ? a.predicateType : null;
    const out = {
      predicateType,
      mediaType: typeof a?.bundle?.mediaType === 'string' ? a.bundle.mediaType : null,
      kind: PREDICATE_KIND.get(predicateType) ?? null,
      status: 'invalid',
      reason: null,
      signer: null,
      keyid: null,
      integratedTime: null,
      timestamps: [],
      registry: null,
      identity: null,
    };
    try {
      Object.assign(out, verifyBundle(a, ctx));
      out.status = 'valid';
      out.reason = out.kind === 'publish' ? `signed by npm registry key ${out.keyid}` : `signed by ${out.identity.san ?? 'a Fulcio certificate'}`;
    } catch (e) {
      out.status = e instanceof Outcome ? e.status : 'invalid';
      out.reason = e instanceof Outcome ? e.message : `verification error: ${e.message}`;
      out.identity = null;
      out.registry = null;
    }
    return out;
  });
  const reasons = [];
  const publish = worst(attestations.filter((r) => r.kind === 'publish').map((r) => r.status));
  const prov = attestations.filter((r) => r.kind === 'provenance');
  let provenance = worst(prov.map((r) => r.status));
  let identity = null;
  if (provenance === 'valid') {
    const ids = prov.map((r) => r.identity);
    if (ids.every((i) => IDENTITY_KEYS.every((k) => i[k] === ids[0][k]))) identity = ids[0];
    else {
      provenance = 'invalid';
      reasons.push('two provenance attestations name different sources');
    }
  }
  for (const r of attestations) if (r.status !== 'valid') reasons.push(`${r.predicateType ?? 'an attestation'}: ${r.reason}`);
  let status = attestations.length ? worst(attestations.map((r) => r.status)) : 'none';
  if (provenance === 'invalid') status = 'invalid';
  return {
    attestations,
    summary: { status, publish, provenance, identity, reason: reasons.length ? reasons.join('; ') : null },
  };
}
