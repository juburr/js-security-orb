#!/usr/bin/env node
// A stand-in npm registry on 127.0.0.1 for the helper's tests.
//
//   node tests/fake_registry.mjs DIR [LOG]
//
// listens on a random port and prints it on stdout. It serves, from DIR:
//
//   GET  /<name>                                  packuments/<name>.json (a scoped
//                                                 name is packuments/@scope/name.json),
//                                                 with an ETag; If-None-Match gives 304
//   GET  /-/npm/v1/attestations/<name>@<version>  attestations/<name>@<version>.json
//   GET  /-/npm/v1/keys                           keys.json
//   POST /-/npm/v1/security/advisories/bulk       the entries of advisories.json
//                                                 ({name: [advisory]}) whose
//                                                 vulnerable_versions match one of the
//                                                 versions asked for, as the real
//                                                 endpoint does (node-semver satisfies,
//                                                 default options); gzip bodies are read
//
// Anything else is 404 {"error":"Not found"}. DIR/_overrides.json, when present,
// maps "METHOD /path" to {status, body, headers} and takes precedence. Files are
// read on every request, so a test can change them while the server runs.
// Every request is appended to LOG as a JSON line: {method, path, headers, body}
// (body only for POST, decompressed). Responses are gzipped when the client
// accepts it.
//
// Tests can also import startFakeRegistry({dir, log}) and run it in-process.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const NAME_RE = /^(?:@[A-Za-z0-9~-][A-Za-z0-9._~-]*\/)?[A-Za-z0-9~-][A-Za-z0-9._~-]*$/;

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return undefined; }
}

// --- node-semver's satisfies() with default options, for the grammar of the
// bulk endpoint's ranges: one or two comparators, < <= > >= =, partial versions.

function parseVersion(v) {
  const m = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/.exec(v);
  return m ? { t: [+m[1], +m[2], +m[3]], pre: m[4] ? m[4].split('.') : [] } : null;
}

function comparePre(a, b) {
  if (!a.length || !b.length) return (b.length ? 1 : 0) - (a.length ? 1 : 0);
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    if (a[i] === undefined) return -1;
    if (b[i] === undefined) return 1;
    const na = /^\d+$/.test(a[i]);
    const nb = /^\d+$/.test(b[i]);
    if (na && nb && +a[i] !== +b[i]) return +a[i] < +b[i] ? -1 : 1;
    if (na !== nb) return na ? -1 : 1;
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

function compare(a, b) {
  for (let i = 0; i < 3; i++) if (a.t[i] !== b.t[i]) return a.t[i] < b.t[i] ? -1 : 1;
  return comparePre(a.pre, b.pre);
}

// Comparators, with partial versions desugared as node-semver does.
function parseRange(range) {
  const out = [];
  for (const c of range.trim().split(/\s+/)) {
    const m = /^(<=|>=|<|>|=)?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?$/.exec(c);
    if (!m) throw new Error(`unsupported range ${range}`);
    const op = m[1] || '=';
    const [x, y, z] = [+m[2], m[3] === undefined ? null : +m[3], m[4] === undefined ? null : +m[4]];
    const v = (t, pre = []) => ({ t, pre });
    if (z !== null) { out.push({ op, v: v([x, y, z], m[5] ? m[5].split('.') : []) }); continue; }
    const lo = y === null ? [x, 0, 0] : [x, y, 0];
    const hi = y === null ? [x + 1, 0, 0] : [x, y + 1, 0];
    if (op === '>=') out.push({ op: '>=', v: v(lo) });
    else if (op === '>') out.push({ op: '>=', v: v(hi) });
    else if (op === '<') out.push({ op: '<', v: v(lo, ['0']) });
    else if (op === '<=') out.push({ op: '<', v: v(hi, ['0']) });
    else out.push({ op: '>=', v: v(lo) }, { op: '<', v: v(hi, ['0']) });
  }
  return out;
}

export function satisfies(version, range) {
  const ver = parseVersion(version);
  if (!ver) return false;
  const comps = parseRange(range);
  for (const { op, v } of comps) {
    const c = compare(ver, v);
    const ok = { '<': c < 0, '<=': c <= 0, '>': c > 0, '>=': c >= 0, '=': c === 0 }[op];
    if (!ok) return false;
  }
  if (ver.pre.length) {
    return comps.some(({ v }) => v.pre.length && v.t.every((n, i) => n === ver.t[i]));
  }
  return true;
}

// --- the server

function send(req, res, status, body, headers = {}) {
  let data = Buffer.isBuffer(body) ? body : Buffer.from(typeof body === 'string' ? body : JSON.stringify(body));
  const h = { 'Content-Type': 'application/json', ...headers };
  if (status !== 304 && /\bgzip\b/.test(req.headers['accept-encoding'] ?? '') && data.length) {
    data = zlib.gzipSync(data);
    h['Content-Encoding'] = 'gzip';
  }
  res.writeHead(status, h);
  res.end(status === 304 ? undefined : data);
}

function handle(dir, req, res, body) {
  const url = req.url.split('?')[0];
  const overrides = readJson(path.join(dir, '_overrides.json')) ?? {};
  const o = overrides[`${req.method} ${url}`];
  if (o) return send(req, res, o.status ?? 200, o.body ?? '', o.headers ?? {});
  if (req.method === 'POST' && url === '/-/npm/v1/security/advisories/bulk') {
    if (!/^application\/json/.test(req.headers['content-type'] ?? '')) return send(req, res, 400, { statusCode: 400, error: 'Bad Request', message: 'Invalid request payload input' });
    if (body.length > 10485760) return send(req, res, 413, { statusCode: 413, error: 'Request Entity Too Large' });
    let query;
    try { query = JSON.parse(body.toString('utf8')); } catch { return send(req, res, 400, { statusCode: 400, error: 'Bad Request', message: 'Invalid request payload JSON format' }); }
    if (query === null || typeof query !== 'object' || Array.isArray(query) || Object.values(query).some((v) => !Array.isArray(v))) {
      return send(req, res, 400, { statusCode: 400, error: 'Bad Request', message: 'Invalid request payload input' });
    }
    const all = readJson(path.join(dir, 'advisories.json')) ?? {};
    const out = {};
    for (const [name, versions] of Object.entries(query)) {
      const hits = (all[name] ?? []).filter((a) => versions.some((v) => satisfies(String(v), a.vulnerable_versions)));
      if (hits.length) out[name] = hits;
    }
    return send(req, res, 200, out);
  }
  if (req.method !== 'GET') return send(req, res, 405, { code: 'MethodNotAllowedError', message: `${req.method} is not allowed` });
  let file = null;
  if (url === '/-/npm/v1/keys') file = path.join(dir, 'keys.json');
  else if (url.startsWith('/-/npm/v1/attestations/')) {
    const spec = decodeURIComponent(url.slice('/-/npm/v1/attestations/'.length));
    const at = spec.lastIndexOf('@');
    if (at > 0 && NAME_RE.test(spec.slice(0, at)) && /^[0-9A-Za-z.+-]+$/.test(spec.slice(at + 1))) file = path.join(dir, 'attestations', `${spec}.json`);
  } else {
    let name;
    try { name = decodeURIComponent(url.slice(1)); } catch { name = ''; }
    if (NAME_RE.test(name)) file = path.join(dir, 'packuments', `${name}.json`);
  }
  let data;
  try { data = file && fs.readFileSync(file); } catch { data = null; }
  if (!data) return send(req, res, 404, { error: 'Not found' });
  const etag = `W/"${crypto.createHash('sha256').update(data).digest('hex').slice(0, 16)}"`;
  if (req.headers['if-none-match'] === etag) return send(req, res, 304, '', { ETag: etag });
  return send(req, res, 200, data, { ETag: etag });
}

/**
 * Starts the fake registry.
 * @param {{dir: string, log?: string|null, port?: number}} options
 * @returns {Promise<{port: number, url: string, close: () => Promise<void>}>} url ends in /
 */
export function startFakeRegistry({ dir, log = null, port = 0 }) {
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      let body = Buffer.concat(chunks);
      if (req.headers['content-encoding'] === 'gzip' && body.length) {
        try { body = zlib.gunzipSync(body); } catch { return send(req, res, 400, { error: 'bad gzip' }); }
      }
      if (log) {
        const entry = { method: req.method, path: req.url, headers: req.headers };
        if (req.method === 'POST') entry.body = body.toString('utf8');
        fs.appendFileSync(log, JSON.stringify(entry) + '\n');
      }
      try { handle(dir, req, res, body); } catch (e) { send(req, res, 500, { error: String(e.message) }); }
    });
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      const p = server.address().port;
      resolve({ port: p, url: `http://127.0.0.1:${p}/`, close: () => new Promise((r) => { server.closeAllConnections(); server.close(() => r()); }) });
    });
  });
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  const [dir, log] = process.argv.slice(2);
  if (!dir) {
    process.stderr.write('ERROR: usage: node tests/fake_registry.mjs DIR [LOG]\n');
    process.exit(2);
  }
  const { port } = await startFakeRegistry({ dir: path.resolve(dir), log: log ? path.resolve(log) : null });
  process.stdout.write(`${port}\n`);
}
