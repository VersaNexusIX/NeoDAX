#!/usr/bin/env node
/**
 * NeoDAX basic test suite
 * Run: npm test
 * Or:  node test/basic.js
 */
'use strict';

const path   = require('path');
const assert = require('assert');

let passed = 0;
let failed = 0;

function test(name, fn) {
    try {
        fn();
        console.log(`  ✓  ${name}`);
        passed++;
    } catch (e) {
        console.log(`  ✗  ${name}`);
        console.log(`     ${e.message}`);
        failed++;
    }
}

function skip(name, reason) {
    console.log(`  ·  ${name}  (skipped: ${reason})`);
}

// ── Load module ──────────────────────────────────────────────────────

let neodax;
try {
    neodax = require('../index.js');
} catch (e) {
    console.error('\n  [FATAL] Could not load neodax:', e.message);
    console.error('  Run `npm run build` first\n');
    process.exit(1);
}

console.log('\n  NeoDAX basic tests\n');

// ── version ──────────────────────────────────────────────────────────

test('version() returns a string', () => {
    const v = neodax.version();
    assert.strictEqual(typeof v, 'string');
    assert.match(v, /^\d+\.\d+\.\d+$/);
});

test('version() is 1.0.0', () => {
    assert.strictEqual(neodax.version(), '1.0.0');
});

// ── detect binary ────────────────────────────────────────────────────

const fs      = require('fs');
const TEST_BIN = process.env.NEODAX_TEST_BIN
    || (fs.existsSync('/bin/ls')      ? '/bin/ls'
      : fs.existsSync('/usr/bin/ls')  ? '/usr/bin/ls'
      : null);

if (!TEST_BIN) {
    skip('Binary analysis tests', 'no test binary found (set NEODAX_TEST_BIN)');
} else {
    console.log(`\n  Using test binary: ${TEST_BIN}\n`);

    test('load() returns a NeoDAXBinary', () => {
        const bin = neodax.load(TEST_BIN);
        assert.ok(bin, 'bin is null');
        assert.ok(typeof bin.arch === 'string', 'arch not a string');
        bin.close();
    });

    test('load() throws on missing file', () => {
        assert.throws(() => neodax.load('/nonexistent/path/to/binary'),
            /not found|ENOENT|Failed/i);
    });

    neodax.withBinary(TEST_BIN, bin => {

        test('arch is a non-empty string', () => {
            assert.ok(bin.arch && bin.arch.length > 0);
        });

        test('format is a non-empty string', () => {
            assert.ok(bin.format && bin.format.length > 0);
        });

        test('entry is a bigint', () => {
            assert.strictEqual(typeof bin.entry, 'bigint');
            assert.ok(bin.entry > 0n);
        });

        test('sha256 is a 64-char hex string', () => {
            assert.match(bin.sha256, /^[0-9a-f]{64}$/);
        });

        test('sections() returns a non-empty array', () => {
            const secs = bin.sections();
            assert.ok(Array.isArray(secs));
            assert.ok(secs.length > 0, 'no sections');
        });

        test('sections() have required fields', () => {
            const s = bin.sections()[0];
            assert.ok(typeof s.name   === 'string');
            assert.ok(typeof s.type   === 'string');
            assert.ok(typeof s.vaddr  === 'bigint');
            assert.ok(typeof s.size   === 'bigint');
        });

        test('symbols() returns an array', () => {
            const syms = bin.symbols();
            assert.ok(Array.isArray(syms));
        });

        test('functions() returns a non-empty array', () => {
            const fns = bin.functions();
            assert.ok(Array.isArray(fns));
            assert.ok(fns.length > 0, 'no functions detected');
        });

        test('functions() have start/end bigints', () => {
            const fn = bin.functions()[0];
            assert.strictEqual(typeof fn.start, 'bigint');
            assert.strictEqual(typeof fn.end,   'bigint');
            assert.ok(fn.end >= fn.start);
        });

        test('xrefs() returns an array', () => {
            const xr = bin.xrefs();
            assert.ok(Array.isArray(xr));
        });

        test('sectionByName(".text") returns section', () => {
            const sec = bin.sectionByName('.text');
            assert.ok(sec !== null, '.text not found');
            assert.strictEqual(sec.name, '.text');
        });

        test('sectionByName("nonexistent") returns null', () => {
            const sec = bin.sectionByName('__nonexistent__');
            assert.strictEqual(sec, null);
        });

        test('sectionAt(entry) returns a section', () => {
            const sec = bin.sectionAt(bin.entry);
            assert.ok(sec !== null, 'no section at entry point');
        });

        test('readBytes(entry, 4) returns Uint8Array of length 4', () => {
            const bytes = bin.readBytes(bin.entry, 4);
            assert.ok(bytes instanceof Uint8Array, 'not a Uint8Array');
            assert.strictEqual(bytes.length, 4);
        });

        test('hottestFunctions(5) returns up to 5 entries', () => {
            const hot = bin.hottestFunctions(5);
            assert.ok(Array.isArray(hot));
            assert.ok(hot.length <= 5);
            if (hot.length > 0) {
                assert.ok(typeof hot[0].callCount === 'number');
                assert.ok(typeof hot[0].function  === 'object');
            }
        });

        test('disasmJson(".text") returns instructions', () => {
            const insns = bin.disasmJson('.text', { limit: 20 });
            assert.ok(Array.isArray(insns));
            assert.ok(insns.length > 0, 'no instructions');
            const i = insns[0];
            assert.ok(typeof i.mnemonic === 'string');
            assert.ok(typeof i.address  === 'bigint');
            assert.ok(Array.isArray(i.bytes));
        });

        test('strings() returns ASCII strings', () => {
            const ss = bin.strings();
            assert.ok(Array.isArray(ss));
        });

        test('unicodeStrings() returns an array', () => {
            const us = bin.unicodeStrings();
            assert.ok(Array.isArray(us));
        });

        test('blocks() returns an array', () => {
            const bl = bin.blocks();
            assert.ok(Array.isArray(bl));
        });

        test('analyze() returns full result object', () => {
            const r = bin.analyze();
            assert.ok(r.info);
            assert.ok(Array.isArray(r.functions));
            assert.ok(Array.isArray(r.symbols));
            assert.ok(Array.isArray(r.xrefs));
            assert.ok(typeof r.analysisTimeMs === 'number');
        });

        test('entropy() returns a string', () => {
            const s = bin.entropy();
            assert.strictEqual(typeof s, 'string');
            assert.ok(s.length > 0);
        });

        test('rda() returns a string', () => {
            const s = bin.rda('.text');
            assert.strictEqual(typeof s, 'string');
            assert.ok(s.length > 0);
        });

        test('ivf() returns a string', () => {
            const s = bin.ivf();
            assert.strictEqual(typeof s, 'string');
        });

    }); // withBinary
}

// ── Results ──────────────────────────────────────────────────────────

console.log(`\n  ${passed} passed  ${failed} failed\n`);

if (failed > 0) process.exit(1);
