// Unit tests of src/helper/licenses.mjs, offline: the embedded SPDX list, the
// strict expression parser, license fields, the policy, clarify, and the
// command end to end through core's runCommand against tests/fake_registry.mjs,
// serving tests/fixtures/licenses/registry, with the lockfiles beside it.

import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import * as core from '../../src/helper/core.mjs';
import * as L from '../../src/helper/licenses.mjs';
import { startFakeRegistry } from '../fake_registry.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(HERE, '..', '..');
const FIXTURES = path.join(HERE, '..', 'fixtures', 'licenses');
const MODULE = path.join(ROOT, 'src', 'helper', 'licenses.mjs');
const tmpdir = (prefix = 'licenses-test-') => fs.mkdtempSync(path.join(os.tmpdir(), prefix));
const policy = (value = L.DEFAULT_ALLOWED_LICENSES) => L.parseAllowedLicenses(value);
const verdict = (expr, allowed) => L.judge(L.parseSpdx(expr).node, policy(allowed));

// ---------------------------------------------------------------------------
// The SPDX License List
// ---------------------------------------------------------------------------

describe('the embedded SPDX License List', () => {
  test('is 3.29.0, with every identifier but the six deprecated X+ ones', () => {
    assert.equal(L.SPDX_LIST_VERSION, '3.29.0');
    // 740 licenses (32 deprecated, six of them GPL-2.0+ and the like) and 86 exceptions (1 deprecated).
    assert.deepEqual(L.spdxCounts(), { licenses: 708, deprecatedLicenses: 26, exceptions: 85, deprecatedExceptions: 1 });
    assert.equal(L.lookupLicense('GPL-2.0+'), null);
  });

  test('lookups ignore case and give the list\'s spelling', () => {
    assert.deepEqual(L.lookupLicense('apache-2.0'), { id: 'Apache-2.0', deprecated: false });
    assert.deepEqual(L.lookupLicense('GPL-2.0'), { id: 'GPL-2.0', deprecated: true });
    assert.deepEqual(L.lookupLicense('blueoak-1.0.0'), { id: 'BlueOak-1.0.0', deprecated: false });
    assert.deepEqual(L.lookupException('LLVM-EXCEPTION'), { id: 'LLVM-exception', deprecated: false });
    assert.deepEqual(L.lookupException('Nokia-Qt-exception-1.1'), { id: 'Nokia-Qt-exception-1.1', deprecated: true });
    assert.equal(L.lookupLicense('Classpath-exception-2.0'), null);
    assert.equal(L.lookupException('MIT'), null);
  });

  test('the default allowlist is current identifiers', () => {
    for (const id of core.splitList(L.DEFAULT_ALLOWED_LICENSES)) assert.deepEqual(L.lookupLicense(id), { id, deprecated: false }, id);
    assert.deepEqual(policy().list, core.splitList(L.DEFAULT_ALLOWED_LICENSES));
  });
});

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

describe('parseSpdx', () => {
  test('valid expressions, normalized', () => {
    const cases = [
      ['MIT', 'MIT'],
      ['mit', 'MIT'],
      [' (MIT OR Apache-2.0) ', 'MIT OR Apache-2.0'],
      ['MIT and apache-2.0 or isc', 'MIT AND Apache-2.0 OR ISC'],
      ['MIT OR Apache-2.0 AND BSD-3-Clause', 'MIT OR Apache-2.0 AND BSD-3-Clause'],
      ['(MIT OR Apache-2.0) AND BSD-3-Clause', '(MIT OR Apache-2.0) AND BSD-3-Clause'],
      ['((MIT OR Apache-2.0) AND (BSD-2-Clause OR GPL-3.0-only)) OR LGPL-2.1-only', '(MIT OR Apache-2.0) AND (BSD-2-Clause OR GPL-3.0-only) OR LGPL-2.1-only'],
      ['(MIT OR (ISC OR 0BSD))', 'MIT OR ISC OR 0BSD'],
      ['((MIT))', 'MIT'],
      ['Apache-2.0+', 'Apache-2.0+'],
      ['GPL-2.0-or-later+', 'GPL-2.0-or-later'],
      ['GPL-2.0-only WITH Classpath-exception-2.0', 'GPL-2.0-only WITH Classpath-exception-2.0'],
      ['GPL-2.0+ with classpath-exception-2.0', 'GPL-2.0-or-later WITH Classpath-exception-2.0'],
      ['Apache-2.0 WITH LLVM-exception OR MIT', 'Apache-2.0 WITH LLVM-exception OR MIT'],
      ['LicenseRef-Corp-1.0', 'LicenseRef-Corp-1.0'],
      ['DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2', 'DocumentRef-spdx-tool-1.2:LicenseRef-MIT-Style-2'],
      ['LicenseRef-X WITH Classpath-exception-2.0', 'LicenseRef-X WITH Classpath-exception-2.0'],
      ['MIT WITH AdditionRef-Extra', 'MIT WITH AdditionRef-Extra'],
      ['MIT\tOR\tISC', 'MIT OR ISC'],
    ];
    for (const [input, expression] of cases) assert.equal(L.parseSpdx(input).expression, expression, input);
  });

  test('the tree: WITH binds tighter than AND, AND than OR', () => {
    assert.deepEqual(L.parseSpdx('MIT OR Apache-2.0 AND GPL-2.0-only WITH Classpath-exception-2.0').node, {
      type: 'or',
      args: [
        { type: 'license', id: 'MIT', plus: false },
        { type: 'and', args: [
          { type: 'license', id: 'Apache-2.0', plus: false },
          { type: 'with', license: { type: 'license', id: 'GPL-2.0-only', plus: false }, exception: { id: 'Classpath-exception-2.0', ref: false } },
        ] },
      ],
    });
  });

  test('deprecated identifiers are valid; the GNU bare forms become -only and -or-later', () => {
    assert.deepEqual(L.parseSpdx('GPL-2.0'), { node: { type: 'license', id: 'GPL-2.0-only', plus: false }, expression: 'GPL-2.0-only', deprecated: ['GPL-2.0'], rewritten: [{ from: 'GPL-2.0', to: 'GPL-2.0-only' }] });
    assert.deepEqual(L.parseSpdx('GPL-2.0+').rewritten, [{ from: 'GPL-2.0+', to: 'GPL-2.0-or-later' }]);
    assert.equal(L.parseSpdx('LGPL-2.1+ OR agpl-3.0').expression, 'LGPL-2.1-or-later OR AGPL-3.0-only');
    assert.equal(L.parseSpdx('GFDL-1.3').expression, 'GFDL-1.3-only');
    const only = L.parseSpdx('GPL-2.0-only+');
    assert.deepEqual([only.expression, only.deprecated, only.rewritten], ['GPL-2.0-or-later', [], [{ from: 'GPL-2.0-only+', to: 'GPL-2.0-or-later' }]]);
    // Other deprecated identifiers stay as they are, and are reported.
    const other = L.parseSpdx('BSD-2-Clause-NetBSD OR StandardML-NJ');
    assert.deepEqual([other.expression, other.deprecated, other.rewritten], ['BSD-2-Clause-NetBSD OR StandardML-NJ', ['BSD-2-Clause-NetBSD', 'StandardML-NJ'], []]);
    assert.deepEqual(L.parseSpdx('GPL-2.0-only WITH Nokia-Qt-exception-1.1').deprecated, ['Nokia-Qt-exception-1.1']);
  });

  test('invalid expressions, with the column where they stop making sense', () => {
    const cases = [
      ['', /the expression is empty/, 1],
      ['   ', /the expression is empty/, 1],
      ['MIT OR', /a license is missing after OR/, 7],
      ['MIT OR )', /a license is missing after OR/, 8],
      ['AND MIT', /expected a license, not AND/, 1],
      ['MIT AND (Apache-2.0', /a "\)" is missing for the "\(" at column 9/, 20],
      ['()', /a license is missing after "\("/, 2],
      ['MIT)', /unexpected "\)"/, 4],
      ['MIT MIT', /expected AND, OR or WITH here, not "MIT"/, 5],
      ['MIT (Apache-2.0)', /expected AND, OR or WITH before "\("/, 5],
      ['(MIT Apache-2.0)', /expected AND, OR, WITH or "\)" here, not "Apache-2.0"/, 6],
      ['Apache2', /"Apache2" is not an SPDX license identifier/, 1],
      ['MIT OR Apache2', /"Apache2" is not an SPDX license identifier/, 8],
      ['Public Domain', /"Public" is not an SPDX license identifier/, 1],
      ['MIT/X11', /unexpected character "\/"/, 4],
      ['MIT\nOR ISC', /a line break/, 4],
      ['MIT +', /"\+" must follow a license identifier, with no space before it/, 5],
      ['(MIT)+', /"\+" must follow a license identifier/, 6],
      ['MIT++', /a second "\+"/, 5],
      ['LicenseRef-X+', /"\+" can't follow a LicenseRef/, 13],
      ['Classpath-exception-2.0', /Classpath-exception-2.0 is a license exception, which must follow WITH/, 1],
      ['MIT WITH Apache-2.0', /Apache-2.0 is a license, not a license exception/, 10],
      ['MIT WITH', /a license exception is missing after WITH/, 9],
      ['MIT WITH OR', /expected a license exception after WITH, not "OR"/, 10],
      ['MIT WITH Foo-exception', /"Foo-exception" is not an SPDX license exception identifier/, 10],
      ['(MIT) WITH Classpath-exception-2.0', /WITH must follow a license identifier, not a parenthesized expression/, 7],
      ['AdditionRef-X', /AdditionRef-X is an AdditionRef, which must follow WITH/, 1],
      ['LicenseRef-', /needs an idstring after LicenseRef-/, 1],
      ['licenseref-corp', /must start with LicenseRef-, in that case/, 1],
      ['Foo:LicenseRef-X', /a ":" belongs only in DocumentRef-…:LicenseRef-…/, 4],
      ['MIT OR UNLICENSED', /UNLICENSED can't be part of an expression/, 8],
      ['NOASSERTION', /NOASSERTION says there is no license information/, 1],
      ['MIT OR café', /unexpected character "é"/, 11],
    ];
    for (const [input, message, column] of cases) {
      assert.throws(() => L.parseSpdx(input), (e) => {
        assert.ok(e instanceof L.SpdxError, `${JSON.stringify(input)}: ${e}`);
        assert.match(e.message, message, JSON.stringify(input));
        assert.equal(e.column, column, `${JSON.stringify(input)}: ${e.message}`);
        return true;
      });
    }
    assert.throws(() => L.parseSpdx(42), /not a string/);
  });

  test('length and nesting are bounded', () => {
    assert.throws(() => L.parseSpdx('MIT OR '.repeat(200) + 'MIT'), /longer than 1000 characters/);
    assert.equal(L.parseSpdx('('.repeat(32) + 'MIT' + ')'.repeat(32)).expression, 'MIT');
    assert.throws(() => L.parseSpdx('('.repeat(40) + 'MIT' + ')'.repeat(40)), (e) => e.column === 33 && /nested too deeply/.test(e.message));
  });
});

// ---------------------------------------------------------------------------
// License fields
// ---------------------------------------------------------------------------

describe('license fields', () => {
  test('readLicenseString: the forms that name no license', () => {
    assert.deepEqual(L.readLicenseString('UNLICENSED'), { status: 'unknown', reason: 'unlicensed' });
    assert.deepEqual(L.readLicenseString(' unlicenced '), { status: 'unknown', reason: 'unlicensed' });
    assert.deepEqual(L.readLicenseString('SEE LICENSE IN LICENSE.md'), { status: 'unknown', reason: 'see-license-in', file: 'LICENSE.md' });
    assert.deepEqual(L.readLicenseString('See licence in ./COPYING'), { status: 'unknown', reason: 'see-license-in', file: './COPYING' });
    assert.deepEqual(L.readLicenseString('  '), { status: 'unknown', reason: 'missing' });
    assert.deepEqual(L.readLicenseString('BSD'), { status: 'unknown', reason: 'invalid', text: 'BSD', error: '"BSD" is not an SPDX license identifier', column: 1 });
    assert.equal(L.readLicenseString('SEE LICENSE IN').reason, 'invalid');
    const ok = L.readLicenseString('(ISC)');
    assert.deepEqual([ok.status, ok.expression], ['ok', 'ISC']);
  });

  test('licenseOfManifest: license, its legacy forms, and the licenses fallback', () => {
    const of = (doc) => {
      const r = L.licenseOfManifest(doc);
      return [r.field, r.read.status === 'ok' ? r.read.expression : r.read.reason];
    };
    assert.deepEqual(of({ license: 'MIT' }), ['license', 'MIT']);
    assert.deepEqual(of({ license: { type: 'BSD-3-Clause', url: 'https://example.com' } }), ['license (object)', 'BSD-3-Clause']);
    assert.deepEqual(of({ license: { name: 'ISC' } }), ['license (object)', 'ISC']);
    assert.deepEqual(of({ license: ['MIT', { type: 'Apache-2.0' }] }), ['license (array)', 'MIT OR Apache-2.0']);
    assert.deepEqual(of({ licenses: [{ type: 'MIT', url: 'x' }] }), ['licenses', 'MIT']);
    assert.deepEqual(of({ licenses: [{ type: 'MIT' }, { type: 'GPL-2.0' }] }), ['licenses', 'MIT OR GPL-2.0-only']);
    assert.deepEqual(of({ licenses: { type: 'ISC' } }), ['licenses (object)', 'ISC']);
    // license wins over licenses; an empty one falls back.
    assert.deepEqual(of({ license: 'ISC', licenses: [{ type: 'MIT' }] }), ['license', 'ISC']);
    assert.deepEqual(of({ license: '', licenses: [{ type: 'MIT' }] }), ['licenses', 'MIT']);
    assert.deepEqual(of({ license: null, licenses: [{ type: 'MIT' }] }), ['licenses', 'MIT']);
    assert.deepEqual(of({ license: [], licenses: [] }), [null, 'missing']);
    assert.deepEqual(of({}), [null, 'missing']);
    // An invalid license doesn't fall back.
    assert.deepEqual(of({ license: 'BSD', licenses: [{ type: 'MIT' }] }), ['license', 'invalid']);
    assert.deepEqual(of({ license: 42 }), ['license', 'malformed']);
    assert.deepEqual(of({ license: { url: 'https://example.com' } }), ['license', 'malformed']);
    assert.deepEqual(of({ licenses: ['MIT', 7] }), ['licenses', 'malformed']);
    const bad = L.licenseOfManifest({ licenses: [{ type: 'MIT' }, { type: 'Apache2' }] }).read;
    assert.deepEqual([bad.reason, bad.item, bad.text, bad.column], ['invalid', 'licenses[1]', 'Apache2', 1]);
    assert.deepEqual(L.licenseOfManifest({ license: ['UNLICENSED'] }).read, { status: 'unknown', reason: 'unlicensed', item: 'license[0]' });
  });
});

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

describe('policy', () => {
  test('allowed_licenses: identifiers in any case, refs exactly, exceptions', () => {
    const p = policy('mit, apache-2.0\nLicenseRef-Corp  LLVM-exception AdditionRef-Extra MIT BSD-2-Clause-NetBSD');
    assert.deepEqual(p.list, ['MIT', 'Apache-2.0', 'LicenseRef-Corp', 'LLVM-exception', 'AdditionRef-Extra', 'BSD-2-Clause-NetBSD']);
    assert.deepEqual([...p.licenses], ['MIT', 'Apache-2.0', 'BSD-2-Clause-NetBSD']);
    assert.deepEqual([...p.refs], ['LicenseRef-Corp']);
    assert.deepEqual([...p.exceptions], ['LLVM-exception']);
    assert.deepEqual([...p.additionRefs], ['AdditionRef-Extra']);
  });

  test('allowed_licenses: bad values are usage errors', () => {
    const bad = [
      ['', /allowed_licenses is empty/],
      [' , ', /allowed_licenses is empty/],
      ['MIT,Apache2', /allowed_licenses: "Apache2" is not an identifier of the SPDX License List 3\.29\.0/],
      ['MIT OR ISC', /"OR" is not an identifier/],
      ['GPL-2.0', /GPL-2\.0 is a deprecated SPDX identifier, which this check reads as GPL-2\.0-only.*List GPL-2\.0-only or GPL-2\.0-or-later instead/],
      ['GPL-2.0+', /takes identifiers, not GPL-2\.0\+: list GPL-2\.0-or-later/],
      ['Apache-2.0+', /takes identifiers, not Apache-2\.0\+: list Apache-2\.0, which allows Apache-2\.0\+ too/],
      ['UNLICENSED', /UNLICENSED means no license is granted/],
      ['LicenseRef-', /"LicenseRef-" is not an identifier/],
    ];
    for (const [value, message] of bad) assert.throws(() => policy(value), (e) => e instanceof core.UsageError && message.test(e.message), value);
  });

  test('OR needs one allowed side, AND every part', () => {
    assert.deepEqual(verdict('MIT OR GPL-3.0-only'), { ok: true, bad: [] });
    assert.deepEqual(verdict('MIT AND GPL-3.0-only'), { ok: false, bad: ['GPL-3.0-only'] });
    assert.deepEqual(verdict('GPL-3.0-only OR AGPL-3.0-only'), { ok: false, bad: ['GPL-3.0-only', 'AGPL-3.0-only'] });
    assert.deepEqual(verdict('(MIT OR GPL-3.0-only) AND (ISC OR AGPL-3.0-only)'), { ok: true, bad: [] });
    assert.deepEqual(verdict('(MIT OR GPL-3.0-only) AND (CC-BY-4.0 OR AGPL-3.0-only)'), { ok: false, bad: ['CC-BY-4.0', 'AGPL-3.0-only'] });
    assert.deepEqual(verdict('MIT AND CC-BY-4.0 OR Apache-2.0'), { ok: true, bad: [] });
    assert.deepEqual(verdict('mit', 'MIT'), { ok: true, bad: [] });
  });

  test('WITH needs its license, and its exception once exceptions are listed', () => {
    const expr = 'GPL-2.0-only WITH Classpath-exception-2.0';
    assert.deepEqual(verdict(expr), { ok: false, bad: ['GPL-2.0-only'] });
    assert.deepEqual(verdict(expr, 'GPL-2.0-only'), { ok: true, bad: [] });
    assert.deepEqual(verdict(expr, 'GPL-2.0-only Classpath-exception-2.0'), { ok: true, bad: [] });
    assert.deepEqual(verdict(expr, 'GPL-2.0-only LLVM-exception'), { ok: false, bad: ['the exception Classpath-exception-2.0'] });
    assert.deepEqual(verdict(expr, 'MIT LLVM-exception'), { ok: false, bad: ['GPL-2.0-only', 'the exception Classpath-exception-2.0'] });
    assert.deepEqual(verdict('MIT WITH AdditionRef-Extra', 'MIT'), { ok: false, bad: ['the exception AdditionRef-Extra'] });
    assert.deepEqual(verdict('MIT WITH AdditionRef-Extra', 'MIT AdditionRef-Extra'), { ok: true, bad: [] });
  });

  test('or-later is allowed by the version it starts from; refs only when listed exactly', () => {
    assert.equal(verdict('GPL-2.0-or-later', 'GPL-2.0-only').ok, true);
    assert.equal(verdict('GPL-2.0+', 'GPL-2.0-only').ok, true);
    assert.equal(verdict('GPL-2.0-or-later', 'GPL-2.0-or-later').ok, true);
    assert.equal(verdict('GPL-2.0-only', 'GPL-2.0-or-later').ok, false);
    assert.equal(verdict('GPL-2.0', 'GPL-2.0-or-later').ok, false);
    assert.equal(verdict('GPL-2.0-or-later', 'GPL-3.0-only').ok, false);
    assert.equal(verdict('Apache-2.0+').ok, true);
    assert.deepEqual(verdict('MPL-1.1+'), { ok: false, bad: ['MPL-1.1+'] });
    assert.equal(verdict('LicenseRef-Corp', 'LicenseRef-Corp').ok, true);
    assert.equal(verdict('LicenseRef-corp', 'LicenseRef-Corp').ok, false);
    assert.equal(verdict('DocumentRef-a:LicenseRef-Corp', 'LicenseRef-Corp').ok, false);
    assert.equal(verdict('DocumentRef-a:LicenseRef-Corp', 'DocumentRef-a:LicenseRef-Corp').ok, true);
  });

  test('explainDenied', () => {
    assert.equal(L.explainDenied(L.parseSpdx('MIT AND CC-BY-4.0').node, ['CC-BY-4.0']), 'CC-BY-4.0 is not in allowed_licenses');
    assert.equal(L.explainDenied(L.parseSpdx('MIT AND CC-BY-4.0').node, ['CC-BY-4.0', 'X']), 'CC-BY-4.0, X are not in allowed_licenses');
    assert.equal(L.explainDenied(L.parseSpdx('GPL-3.0-only OR AGPL-3.0-only').node, ['GPL-3.0-only', 'AGPL-3.0-only']),
      'none of its choices is in allowed_licenses (GPL-3.0-only, AGPL-3.0-only)');
  });
});

// ---------------------------------------------------------------------------
// clarify
// ---------------------------------------------------------------------------

describe('clarify', () => {
  test('parses lines, normalizing each expression', () => {
    const c = L.parseClarify(['busboy@1.6.0=MIT', '@corp/* = LicenseRef-Corp', 'jszip = (mit or gpl-3.0-or-later)']);
    assert.deepEqual(c.map((x) => [x.key, x.glob, x.version, x.expression]), [
      ['busboy@1.6.0', false, '1.6.0', 'MIT'],
      ['@corp/*', true, null, 'LicenseRef-Corp'],
      ['jszip', false, null, 'MIT OR GPL-3.0-or-later'],
    ]);
  });

  test('the exact version wins, then a name, then a glob; the first among equals', () => {
    const c = L.parseClarify(['re*=ISC', 'relicensed=GPL-3.0-only', 'relicensed@1.0.0=MIT', 're*@2.0.0=0BSD', 'rel*=Apache-2.0', 'r*@3.0.0=BSD-2-Clause']);
    const pick = (name, version) => L.findClarification(c, name, version)?.expression ?? null;
    assert.equal(pick('relicensed', '1.0.0'), 'MIT');
    assert.equal(pick('relicensed', '2.0.0'), 'GPL-3.0-only');
    assert.equal(pick('relicensed', '3.0.0'), 'GPL-3.0-only');
    assert.equal(pick('rest', '2.0.0'), '0BSD');
    assert.equal(pick('rest', '3.0.0'), 'BSD-2-Clause');
    assert.equal(pick('rest', '1.0.0'), 'ISC');
    assert.equal(pick('release', '1.0.0'), 'ISC');
    assert.equal(pick('other', '1.0.0'), null);
    assert.equal(pick('@scope/relicensed', '1.0.0'), null);
  });

  test('bad lines are usage errors, naming the column in the expression', () => {
    const bad = [
      ['busboy', /clarify takes lines name=EXPRESSION or name@version=EXPRESSION/],
      ['=MIT', /clarify takes lines/],
      ['busboy=', /clarify takes lines/],
      ['not a name=MIT', /clarify: "not a name" is not a package name/],
      ['busboy=MIT OR Apache2', /clarify: "busboy=MIT OR Apache2" doesn't give an SPDX expression: "Apache2" is not an SPDX license identifier \(column 8 of the expression\)/],
      ['busboy=UNLICENSED', /UNLICENSED names no license/],
      ['busboy=SEE LICENSE IN LICENSE', /SEE LICENSE IN LICENSE names no license/],
      ['busboy=GPL-2.0', /uses GPL-2\.0, a deprecated SPDX identifier; write GPL-2\.0-only instead/],
      ['busboy=LGPL-2.1+ OR MIT', /uses LGPL-2\.1\+, a deprecated SPDX identifier; write LGPL-2\.1-or-later instead/],
    ];
    for (const [line, message] of bad) assert.throws(() => L.parseClarify([line]), (e) => e instanceof core.UsageError && message.test(e.message), line);
    assert.throws(() => L.parseClarify(['a=MIT', 'a = ISC']), /clarify names a twice/);
    assert.equal(L.parseClarify(['a=MIT', 'a@1.0.0=ISC']).length, 2);
  });
});

// ---------------------------------------------------------------------------
// The command
// ---------------------------------------------------------------------------

describe('the licenses command', () => {
  let reg;
  let regB;
  let log;
  let logB;
  const work = tmpdir('licenses-work-');

  before(async () => {
    log = path.join(work, 'a.log');
    logB = path.join(work, 'b.log');
    reg = await startFakeRegistry({ dir: path.join(FIXTURES, 'registry'), log });
    regB = await startFakeRegistry({ dir: path.join(FIXTURES, 'registry'), log: logB });
  });
  after(async () => {
    await reg.close();
    await regB.close();
  });

  const requests = (file = log) => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []);
  const reset = () => { fs.rmSync(log, { force: true }); fs.rmSync(logB, { force: true }); };

  // Runs the command in tests/fixtures/licenses/DIR (or an absolute directory),
  // with a fresh cache and output directory.
  const run = async (dir, params = {}, { registry = reg } = {}) => {
    reset();
    const out = tmpdir('licenses-out-');
    const env = {
      PATH: process.env.PATH,
      HOME: process.env.HOME,
      XDG_CACHE_HOME: path.join(out, 'cache'),
      PARAM_REGISTRY: registry ? registry.url : undefined,
      PARAM_OUTPUT_DIR: path.join(out, 'reports'),
      ...Object.fromEntries(Object.entries(params).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, v])),
    };
    for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
    const stdout = [];
    const stderr = [];
    const code = await core.runCommand('licenses', L.run, { env, cwd: path.isAbsolute(dir) ? dir : path.join(FIXTURES, dir), stdout: (s) => stdout.push(s), stderr: (s) => stderr.push(s) });
    const reports = path.join(out, 'reports');
    const name = params.report_name ?? 'licenses';
    const readJson = (f) => (fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf8')) : null);
    const json = readJson(path.join(reports, `${name}.json`));
    return {
      code, out: stdout.join(''), err: stderr.join(''), reports, json,
      sarif: readJson(path.join(reports, `${name}.sarif`)),
      record: readJson(path.join(reports, `${name}.run-record.json`)),
      junit: fs.existsSync(path.join(reports, 'junit', `${name}.xml`)) ? fs.readFileSync(path.join(reports, 'junit', `${name}.xml`), 'utf8') : null,
      status: Object.fromEntries((json?.results ?? []).map((r) => [`${r.name}@${r.version}`, `${r.status} ${r.license ?? r.reason}`])),
    };
  };

  const NPM = 'tests/fixtures/licenses/npm/package-lock.json';
  const PNPM = 'tests/fixtures/licenses/pnpm/pnpm-lock.yaml';
  const lineOf = (rel, needle) => fs.readFileSync(path.join(ROOT, rel), 'utf8').split('\n').findIndex((l) => l.includes(needle)) + 1;

  test('npm, from the registry: every kind of license field', async () => {
    const r = await run('npm', { run_record: 'true' });
    assert.equal(r.code, 1, r.err);
    assert.deepEqual(r.status, {
      '@scope/pkg@1.0.0': 'allowed Apache-2.0',
      'and-pkg@1.0.0': 'denied MIT AND CC-BY-4.0',
      'array-license@0.0.11': 'unknown invalid',
      'bad-type@1.0.0': 'unknown malformed',
      'deprecated-id@1.4.2': 'allowed BSD-3-Clause OR GPL-2.0-only',
      'dev-only@1.0.0': 'denied GPL-3.0-only',
      'dual-pkg@2.0.0': 'allowed MIT OR GPL-3.0-or-later',
      'free-text@0.0.0': 'unknown invalid',
      'ghost-pkg@1.0.0': 'unknown not-on-registry',
      'gpl-pkg@1.0.0': 'denied GPL-3.0-only',
      'gpl-plus@1.0.0': 'denied GPL-2.0-or-later',
      'legacy-array-multi@0.2.3': 'unknown invalid',
      'legacy-array@1.6.0': 'allowed MIT',
      'legacy-object@0.1.0': 'allowed BSD-3-Clause',
      'licenseref-pkg@1.0.0': 'denied LicenseRef-Corp-Proprietary',
      'mit-pkg@1.0.0': 'allowed MIT',
      'mit-pkg@9.9.9': 'unknown not-on-registry',
      'nested@3.0.0': 'allowed (MIT OR Apache-2.0) AND (BSD-2-Clause OR GPL-3.0-only) OR LGPL-2.1-only',
      'no-license@0.0.1': 'unknown missing',
      'npmjs-dep@1.0.0': 'allowed MIT',
      'relicensed@1.0.0': 'denied GPL-3.0-only',
      'relicensed@2.0.0': 'allowed MIT',
      'see-license@1.0.0': 'unknown see-license-in',
      'unlicensed-pkg@1.0.0': 'unknown unlicensed',
      'with-exception@1.0.0': 'denied GPL-2.0-only WITH Classpath-exception-2.0',
      'wrong-case@1.0.0': 'allowed Apache-2.0',
    });
    const byName = Object.fromEntries(r.json.results.map((x) => [`${x.name}@${x.version}`, x]));
    assert.deepEqual(byName['deprecated-id@1.4.2'].deprecated_ids, ['GPL-2.0']);
    assert.deepEqual([byName['legacy-object@0.1.0'].field, byName['legacy-array@1.6.0'].field, byName['array-license@0.0.11'].field], ['license (object)', 'licenses', 'license (array)']);
    assert.deepEqual(byName['legacy-array@1.6.0'].raw, [{ type: 'MIT', url: 'https://github.com/example/legacy-array/raw/master/LICENSE' }]);
    assert.deepEqual(byName['mit-pkg@1.0.0'].lockfiles, [NPM]);

    // Findings: one per package and lockfile, at its first line there.
    assert.equal(r.json.findings.length, 16);
    const finding = (name, version) => r.json.findings.filter((f) => f.package.name === name && f.package.version === version);
    assert.deepEqual(finding('and-pkg', '1.0.0').map((f) => [f.kind, f.rule, f.level, f.lockfile, f.line, f.message]), [[
      'denied', 'licenses/denied', 'error', NPM, lineOf(NPM, '"node_modules/and-pkg"'),
      'and-pkg@1.0.0 is licensed MIT AND CC-BY-4.0: CC-BY-4.0 is not in allowed_licenses.',
    ]]);
    assert.deepEqual(finding('and-pkg', '1.0.0')[0].details, { license: 'MIT AND CC-BY-4.0', raw: '(MIT AND CC-BY-4.0)', field: 'license', not_allowed: ['CC-BY-4.0'] });
    assert.deepEqual(finding('relicensed', '1.0.0')[0].details.alias, 'relicensed-old');
    const messages = Object.fromEntries(r.json.findings.map((f) => [`${f.package.name}@${f.package.version}`, f.message]));
    assert.equal(messages['with-exception@1.0.0'], 'with-exception@1.0.0 is licensed GPL-2.0-only WITH Classpath-exception-2.0: GPL-2.0-only is not in allowed_licenses.');
    assert.equal(messages['array-license@0.0.11'], 'array-license@0.0.11: license[1] "Apache2" is not an SPDX expression ("Apache2" is not an SPDX license identifier, column 1).');
    assert.equal(messages['free-text@0.0.0'], 'free-text@0.0.0: license "Public Domain" is not an SPDX expression ("Public" is not an SPDX license identifier, column 1).');
    assert.equal(messages['legacy-array-multi@0.2.3'], 'legacy-array-multi@0.2.3: licenses[0] "AFLv2.1" is not an SPDX expression ("AFLv2.1" is not an SPDX license identifier, column 1).');
    assert.equal(messages['bad-type@1.0.0'], 'bad-type@1.0.0: license is 42, neither an SPDX expression nor a legacy {type} object.');
    assert.equal(messages['see-license@1.0.0'], 'see-license@1.0.0 says SEE LICENSE IN LICENSE.md: its terms are in a file, which this check doesn\'t read.');
    assert.equal(messages['unlicensed-pkg@1.0.0'], 'unlicensed-pkg@1.0.0 is UNLICENSED: its authors grant no license to use it.');
    assert.equal(messages['no-license@0.0.1'], 'no-license@0.0.1 names no license: its registry metadata has neither license nor licenses.');
    assert.equal(messages['ghost-pkg@1.0.0'], `ghost-pkg@1.0.0: ${reg.url} has no package ghost-pkg (HTTP 404). If it comes from another registry, map its scope to it with scopes.`);
    assert.equal(messages['mit-pkg@9.9.9'], `mit-pkg@9.9.9: ${reg.url} lists no version 9.9.9 of mit-pkg. If it comes from another registry, map its scope to it with scopes.`);

    // Skipped entries, with a warning for git and tarball URLs. npmjs-dep, recorded on
    // registry.npmjs.org, was read from registry, which npm installs it from in its place.
    assert.deepEqual(r.json.skipped.map((s) => [s.kind, s.name]), [
      ['workspace', 'licenses-fixture'], ['local', 'local-lib'], ['workspace', '@fixture/app'], ['git', 'git-dep'], ['remote', 'remote-dep'],
    ]);
    assert.match(r.err, /^WARN: 2 packages were not checked, since packages from git or a tarball URL have no registry metadata: git-dep@1\.0\.0, remote-dep@1\.0\.0\. They are listed under skipped in the report\.$/m);
    assert.equal(byName['npmjs-dep@1.0.0'].registry, reg.url);

    // The summary: counts per license expression.
    const s = r.json.summary;
    assert.deepEqual([s.source, s.spdx_license_list, s.packages, s.allowed, s.denied, s.unknown, s.clarified, s.skipped], ['registry', '3.29.0', 26, 10, 7, 9, 0, 5]);
    assert.deepEqual(s.licenses.slice(0, 4), [{ license: 'MIT', packages: 4 }, { license: 'GPL-3.0-only', packages: 3 }, { license: '(not on the registry)', packages: 2 }, { license: 'Apache-2.0', packages: 2 }]);
    for (const l of ['42', '(none)', 'Public Domain', 'SEE LICENSE IN LICENSE.md', 'UNLICENSED', '["AFLv2.1","BSD"]', '["MIT","Apache2"]']) {
      assert.deepEqual(s.licenses.find((x) => x.license === l), { license: l, packages: 1 }, l);
    }
    assert.equal(s.licenses.reduce((n, x) => n + x.packages, 0), 26);
    assert.deepEqual(s.unknown_reasons, { invalid: 3, malformed: 1, 'not-on-registry': 2, missing: 1, 'see-license-in': 1, unlicensed: 1 });
    assert.match(r.out, /^Read the licenses of 26 packages from the registry: 10 allowed, 7 denied, 9 unknown; 5 not checked\.$/m);
    assert.match(r.out, /^ {7}4 {2}MIT$/m);
    assert.match(r.err, /^ERROR: 16 findings of licenses fail the gate\.$/m);

    // Requests: one packument per name, full documents, none for what is skipped.
    const paths = requests().map((q) => q.path).sort();
    assert.deepEqual(paths, ['/@scope%2Fpkg', ...['and-pkg', 'array-license', 'bad-type', 'deprecated-id', 'dev-only', 'dual-pkg', 'free-text', 'ghost-pkg', 'gpl-pkg', 'gpl-plus',
      'legacy-array', 'legacy-array-multi', 'legacy-object', 'licenseref-pkg', 'mit-pkg', 'nested', 'no-license', 'npmjs-dep', 'relicensed', 'see-license', 'unlicensed-pkg',
      'with-exception', 'wrong-case'].map((n) => `/${n}`)].sort());
    for (const q of requests()) assert.equal(q.headers.accept, 'application/json');

    // SARIF, JUnit and the run record.
    const run0 = r.sarif.runs[0];
    assert.equal(run0.tool.driver.name, 'js-security-orb licenses');
    assert.deepEqual(run0.tool.driver.rules.map((x) => [x.id, x.properties.tags.includes('license')]).sort(), [['licenses/denied', true], ['licenses/unknown', true]]);
    assert.equal(run0.results.length, 16);
    const sarifAnd = run0.results.find((x) => x.message.text.startsWith('and-pkg@'));
    assert.deepEqual([sarifAnd.ruleId, sarifAnd.locations[0].physicalLocation.artifactLocation.uri, sarifAnd.locations[0].physicalLocation.region.startLine],
      ['licenses/denied', NPM, lineOf(NPM, '"node_modules/and-pkg"')]);
    assert.match(r.junit, /tests="16" failures="16" errors="0" skipped="0"/);
    assert.equal(r.record.command, 'licenses');
    assert.equal(r.record.outcome, 'findings');
    assert.equal(r.record.exit_code, 1);
    assert.equal(r.record.results.length, 26);
    assert.ok(r.record.results.every((x) => x && typeof x === 'object' && !Array.isArray(x)));
    assert.deepEqual([r.record.counts.packages, r.record.counts.denied, r.record.counts.unknown, r.record.counts.skipped], [26, 7, 9, 5]);
    assert.equal(r.record.parameters.allowed_licenses, L.DEFAULT_ALLOWED_LICENSES);
    assert.equal(r.record.parameters.offline, 'false');
  });

  test('report_only passes with a warning; include_dev: false leaves dev packages out', async () => {
    const r = await run('npm', { report_only: 'true', include_dev: 'false' });
    assert.equal(r.code, 0, r.err);
    assert.match(r.err, /^WARN: 15 findings of licenses fail the gate\./m);
    assert.match(r.err, /^WARN: report_only is true, so this step passes/m);
    assert.equal(r.status['dev-only@1.0.0'], undefined);
    assert.equal(r.json.outcome, 'findings-reported');
  });

  test('clarify: the exact version wins, clarified packages aren\'t fetched, unused lines warn', async () => {
    const clarify = [
      '# comments and blank lines are fine',
      '',
      'relicensed=GPL-3.0-only',
      'relicensed@1.0.0=MIT',
      'unlicensed-pkg=LicenseRef-Corp',
      'see-license@1.0.0 = Apache-2.0 OR GPL-3.0-only',
      'no-such-package=MIT',
      '@scope/*=ISC',
    ].join('\n');
    const r = await run('npm', { clarify, allowed_licenses: `${L.DEFAULT_ALLOWED_LICENSES},LicenseRef-Corp`, report_only: 'true' });
    assert.equal(r.code, 0, r.err);
    assert.equal(r.status['relicensed@1.0.0'], 'allowed MIT');
    assert.equal(r.status['relicensed@2.0.0'], 'denied GPL-3.0-only');
    assert.equal(r.status['unlicensed-pkg@1.0.0'], 'allowed LicenseRef-Corp');
    assert.equal(r.status['see-license@1.0.0'], 'allowed Apache-2.0 OR GPL-3.0-only');
    assert.equal(r.status['@scope/pkg@1.0.0'], 'allowed ISC');
    const byName = Object.fromEntries(r.json.results.map((x) => [`${x.name}@${x.version}`, x]));
    assert.deepEqual([byName['relicensed@1.0.0'].field, byName['relicensed@1.0.0'].clarified_by], ['clarify', 'relicensed@1.0.0=MIT']);
    assert.equal(byName['relicensed@2.0.0'].clarified_by, 'relicensed=GPL-3.0-only');
    assert.equal(r.json.summary.clarified, 5);
    const paths = requests().map((q) => q.path);
    for (const p of ['/relicensed', '/unlicensed-pkg', '/see-license', '/@scope%2Fpkg']) assert.ok(!paths.includes(p), p);
    assert.ok(paths.includes('/mit-pkg'));
    assert.match(r.err, /^WARN: clarify: "no-such-package=MIT" matches no package whose license this check reads, so it is unused\.$/m);
    assert.doesNotMatch(r.err, /clarify: "relicensed/);
  });

  test('allowed_licenses: exceptions, -only for -or-later, refs', async () => {
    const r = await run('npm', { allowed_licenses: 'MIT GPL-2.0-only Apache-2.0 LicenseRef-Corp-Proprietary', report_only: 'true' });
    assert.equal(r.status['with-exception@1.0.0'], 'allowed GPL-2.0-only WITH Classpath-exception-2.0');
    assert.equal(r.status['gpl-plus@1.0.0'], 'allowed GPL-2.0-or-later');
    assert.equal(r.status['licenseref-pkg@1.0.0'], 'allowed LicenseRef-Corp-Proprietary');
    assert.equal(r.status['deprecated-id@1.4.2'], 'allowed BSD-3-Clause OR GPL-2.0-only');
    assert.equal(r.status['legacy-object@0.1.0'], 'denied BSD-3-Clause');
    const withExc = await run('npm', { allowed_licenses: 'MIT GPL-2.0-only LLVM-exception', report_only: 'true' });
    assert.equal(withExc.status['with-exception@1.0.0'], 'denied GPL-2.0-only WITH Classpath-exception-2.0');
    const f = withExc.json.findings.find((x) => x.package.name === 'with-exception');
    assert.equal(f.message, 'with-exception@1.0.0 is licensed GPL-2.0-only WITH Classpath-exception-2.0: the exception Classpath-exception-2.0 is not in allowed_licenses.');
    assert.equal(withExc.status['deprecated-id@1.4.2'], 'allowed BSD-3-Clause OR GPL-2.0-only');
    const or = withExc.json.findings.find((x) => x.package.name === 'nested');
    assert.equal(or.message, 'nested@3.0.0 is licensed (MIT OR Apache-2.0) AND (BSD-2-Clause OR GPL-3.0-only) OR LGPL-2.1-only: '
      + 'none of its choices is in allowed_licenses (BSD-2-Clause, GPL-3.0-only, LGPL-2.1-only).');
    assert.deepEqual(or.details.not_allowed, ['BSD-2-Clause', 'GPL-3.0-only', 'LGPL-2.1-only']);
  });

  test('offline: npm lockfiles only, and no request at all', async () => {
    const r = await run('npm', { offline: 'true', report_only: 'true' });
    assert.equal(r.code, 0, r.err);
    assert.deepEqual(requests(), []);
    assert.equal(r.json.summary.source, 'lockfile');
    assert.equal(r.status['legacy-array@1.6.0'], 'unknown missing');
    assert.equal(r.status['legacy-object@0.1.0'], 'allowed BSD-3-Clause');
    // An array in the lockfile's license is its items OR-ed, as the registry's is read.
    assert.equal(r.status['array-license@0.0.11'], 'unknown invalid');
    assert.equal(r.json.results.find((x) => x.name === 'array-license').raw, 'MIT OR Apache2');
    assert.equal(r.status['ghost-pkg@1.0.0'], 'allowed MIT');
    assert.equal(r.status['npmjs-dep@1.0.0'], 'allowed MIT', 'the lockfile records its license, whatever its registry');
    assert.equal(r.status['gpl-plus@1.0.0'], 'denied GPL-2.0-or-later');
    assert.equal(r.status['free-text@0.0.0'], 'unknown invalid');
    assert.ok(r.json.results.every((x) => x.field === 'lockfile'));
    assert.deepEqual(r.json.skipped.map((s) => s.kind), ['workspace', 'local', 'workspace', 'git', 'remote']);
    const f = r.json.findings.find((x) => x.package.name === 'legacy-array');
    assert.equal(f.message, `legacy-array@1.6.0 has no license in ${NPM}: it names none, or only in the legacy licenses array, which npm leaves out of lockfiles. Check it without offline to read that array.`);
    const free = r.json.findings.find((x) => x.package.name === 'free-text');
    assert.match(free.message, new RegExp(`^free-text@0\\.0\\.0: license "Public Domain" in ${NPM.replace(/\./g, '\\.')} is not an SPDX expression`));

    for (const [dir, what] of [['pnpm', 'a pnpm lockfile'], ['npm-v1', 'an npm lockfile of version 1']]) {
      const bad = await run(dir, { offline: 'true', report_only: 'true' });
      assert.equal(bad.code, 1, dir);
      assert.deepEqual(requests(), []);
      assert.match(bad.err, new RegExp(`^ERROR: tests/fixtures/licenses/${dir}/[a-z-]+\\.(?:yaml|json) is ${what}, which records no licenses: offline needs npm lockfiles of version 2 or 3`, 'm'));
      assert.match(bad.err, /^ERROR: There is no verdict, so this step fails whatever report_only says\./m);
      assert.equal(bad.json.outcome, 'error');
    }
  });

  test('pnpm, from the registry, with a scope registry', async () => {
    const r = await run('pnpm', { scopes: `@scope=${regB.url}` });
    assert.equal(r.code, 1);
    assert.deepEqual(r.status, {
      '@scope/pkg@1.0.0': 'allowed Apache-2.0', 'gpl-pkg@1.0.0': 'denied GPL-3.0-only', 'legacy-array@1.6.0': 'allowed MIT', 'mit-pkg@1.0.0': 'allowed MIT',
    });
    assert.deepEqual(r.json.skipped.map((s) => [s.kind, s.name]), [['workspace', '.'], ['link', 'linked-lib'], ['git', 'git-dep'], ['local', 'local-lib']]);
    assert.deepEqual(r.json.findings.map((f) => [f.lockfile, f.line, f.package.name]), [[PNPM, lineOf(PNPM, 'gpl-pkg@1.0.0:'), 'gpl-pkg']]);
    assert.deepEqual(requests().map((q) => q.path).sort(), ['/gpl-pkg', '/legacy-array', '/mit-pkg']);
    assert.deepEqual(requests(logB).map((q) => q.path), ['/@scope%2Fpkg']);
  });

  test('other registries are never contacted; a scope registry on another origin that answers 401 is skipped', async () => {
    const dir = tmpdir('licenses-registries-');
    const lock = { name: 'r', version: '1.0.0', lockfileVersion: 3, requires: true, packages: { '': { name: 'r', version: '1.0.0' } } };
    const add = (name, resolved) => {
      const doc = JSON.parse(fs.readFileSync(path.join(FIXTURES, 'registry', 'packuments', `${name}.json`), 'utf8'));
      const [version] = Object.keys(doc.versions);
      lock.packages[`node_modules/${name}`] = { version, integrity: doc.versions[version].dist?.integrity ?? 'sha512-AAAA', ...(resolved ? { resolved } : {}) };
    };
    add('mit-pkg', 'https://npm.elsewhere.example/mit-pkg/-/mit-pkg-1.0.0.tgz');
    add('gpl-pkg', 'https://registry.npmjs.org/gpl-pkg/-/gpl-pkg-1.0.0.tgz');
    add('@scope/pkg');
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify(lock, null, 2));
    const regDir = tmpdir('licenses-registry-');
    fs.cpSync(path.join(FIXTURES, 'registry'), regDir, { recursive: true });
    fs.writeFileSync(path.join(regDir, '_overrides.json'), JSON.stringify({ 'GET /@scope%2Fpkg': { status: 401, body: '{}' } }));
    const locked = await startFakeRegistry({ dir: regDir });
    try {
      const r = await run(dir, { scopes: `@scope=${locked.url}` });
      assert.equal(r.code, 1, r.err);
      assert.deepEqual(r.status, { 'gpl-pkg@1.0.0': 'denied GPL-3.0-only' });
      assert.deepEqual(r.json.skipped.map((s) => [s.name, s.reason]), [
        ['r', 'one of the project\'s own workspace packages'],
        ['mit-pkg', 'the lockfile records https://npm.elsewhere.example/, which is neither registry nor a scope\'s registry (scopes, or .npmrc)'],
        ['@scope/pkg', `${locked.url} answered HTTP 401, and the token goes only to registry's origin`],
      ]);
      assert.ok(r.err.includes(`WARN: 1 package was not checked, since ${locked.url} answered HTTP 401, and the token goes only to registry's origin: @scope/pkg@1.0.0. It is listed under skipped in the report.\n`), r.err);
      assert.match(r.err, /^WARN: 1 package was not checked, since the lockfile records https:\/\/npm\.elsewhere\.example\/, which is neither/m);
      assert.deepEqual(requests().map((q) => q.path), ['/gpl-pkg']);
    } finally {
      await locked.close();
    }
  });

  test('a registry that can\'t be read is no verdict, even with report_only', async () => {
    const dir = tmpdir('licenses-registry-');
    fs.cpSync(path.join(FIXTURES, 'registry'), dir, { recursive: true });
    fs.writeFileSync(path.join(dir, '_overrides.json'), JSON.stringify({ 'GET /gpl-pkg': { status: 403, body: '{}' }, 'GET /mit-pkg': { status: 403, body: '{}' } }));
    const broken = await startFakeRegistry({ dir });
    try {
      const r = await run('pnpm', { report_only: 'true' }, { registry: broken });
      assert.equal(r.code, 1);
      assert.match(r.err, new RegExp(`^ERROR: Could not read the registry metadata of 2 packages \\(gpl-pkg@1\\.0\\.0, mit-pkg@1\\.0\\.0\\) from ${broken.url.replace(/\./g, '\\.')}: HTTP 403\\. If the registry needs a login, set token`, 'm'));
      assert.match(r.out, /^Read the licenses of 2 packages from the registry: 2 allowed, 0 denied, 0 unknown; 4 not checked\. The check is incomplete \(see the errors\), so it has no verdict\.$/m);
      assert.equal(r.json.outcome, 'error');
      assert.equal(r.status['legacy-array@1.6.0'], 'allowed MIT');
    } finally {
      await broken.close();
    }
  });

  test('nothing to check is no verdict unless allow_empty', async () => {
    const dir = tmpdir('licenses-empty-');
    fs.writeFileSync(path.join(dir, 'package-lock.json'), JSON.stringify({
      name: 'empty', version: '1.0.0', lockfileVersion: 3, requires: true,
      packages: { '': { name: 'empty', version: '1.0.0' }, 'node_modules/git-dep': { version: '1.0.0', resolved: 'git+ssh://git@github.com/example/git-dep.git#0123456789abcdef0123456789abcdef01234567' } },
    }));
    const r = await run(dir);
    assert.equal(r.code, 1);
    assert.match(r.err, /checked nothing/);
    assert.deepEqual(requests(), []);
    const ok = await run(dir, { allow_empty: 'true' });
    assert.equal(ok.code, 0, ok.err);
    assert.deepEqual([ok.json.summary.packages, ok.json.summary.skipped], [0, 2]);
  });

  test('a bad parameter exits 2 before any request, and clears the old reports', async () => {
    const bad = [
      [{ allowed_licenses: 'MIT,Apache2' }, /^ERROR: allowed_licenses: "Apache2" is not an identifier of the SPDX License List 3\.29\.0/m],
      [{ allowed_licenses: '' }, /^ERROR: allowed_licenses is empty/m],
      [{ allowed_licenses: 'GPL-2.0' }, /^ERROR: allowed_licenses: GPL-2\.0 is a deprecated SPDX identifier/m],
      [{ clarify: 'mit-pkg=MIT OR' }, /^ERROR: clarify: "mit-pkg=MIT OR" doesn't give an SPDX expression: a license is missing after OR \(column 7 of the expression\)/m],
      [{ clarify: 'mit-pkg' }, /^ERROR: clarify takes lines/m],
      [{ offline: 'maybe' }, /^ERROR: offline must be true or false/m],
      [{ registry: 'http://registry.example.com/' }, /^ERROR: registry must be an https URL/m],
    ];
    for (const [params, message] of bad) {
      const out = tmpdir('licenses-out-');
      fs.mkdirSync(path.join(out, 'junit'));
      for (const f of ['licenses.json', 'licenses.sarif', 'junit/licenses.xml']) fs.writeFileSync(path.join(out, f), 'old');
      reset();
      const stderr = [];
      const env = { PATH: process.env.PATH, HOME: process.env.HOME, XDG_CACHE_HOME: path.join(out, 'cache'), PARAM_REGISTRY: reg.url, PARAM_OUTPUT_DIR: out,
        ...Object.fromEntries(Object.entries(params).map(([k, v]) => [`PARAM_${k.toUpperCase()}`, v])) };
      const code = await core.runCommand('licenses', L.run, { env, cwd: path.join(FIXTURES, 'npm'), stdout: () => {}, stderr: (s) => stderr.push(s) });
      assert.equal(code, 2, JSON.stringify(params));
      assert.match(stderr.join(''), message);
      assert.deepEqual(requests(), [], JSON.stringify(params));
      assert.deepEqual(['licenses.json', 'licenses.sarif', 'junit/licenses.xml'].map((f) => fs.existsSync(path.join(out, f))), [false, false, false]);
    }
  });

  test('runs as a program, as the orb\'s script runs it', () => {
    const out = tmpdir('licenses-out-');
    const env = { PATH: process.env.PATH, HOME: process.env.HOME, PARAM_OUTPUT_DIR: out, PARAM_OFFLINE: 'true', PARAM_REPORT_NAME: 'lic' };
    const r = spawnSync(process.execPath, [MODULE], { cwd: path.join(FIXTURES, 'npm'), env, encoding: 'utf8' });
    assert.equal(r.status, 1, r.stderr);
    assert.match(r.stdout, /^Read the licenses of 26 packages from the lockfiles/m);
    assert.equal(JSON.parse(fs.readFileSync(path.join(out, 'lic.json'), 'utf8')).summary.source, 'lockfile');
    const usage = spawnSync(process.execPath, [MODULE], { cwd: path.join(FIXTURES, 'npm'), env: { ...env, PARAM_ALLOWED_LICENSES: 'nope' }, encoding: 'utf8' });
    assert.equal(usage.status, 2);
    assert.match(usage.stderr, /^ERROR: allowed_licenses: "nope"/m);
  });
});
