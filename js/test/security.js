#!/usr/bin/env node
'use strict';

const assert = require('assert');
const http   = require('http');
const path   = require('path');
const fs     = require('fs');

process.env.HOST             = '127.0.0.1';
process.env.PORT             = '0';
process.env.NEODAX_API_TOKEN = 'test-secret-token-120';
process.env.NEODAX_ROOT      = '/bin';

const neodax     = require('../index.js');
const { server } = require('../server/server.js');

let passed = 0;
let failed = 0;

async function test(name, fn) {
    try {
        await fn();
        console.log(`  ✓  ${name}`);
        passed++;
    } catch (e) {
        console.log(`  ✗  ${name}`);
        console.log(`     ${e.message}`);
        failed++;
    }
}

function req(port, method, urlPath, headers = {}, body = null) {
    return new Promise((resolve, reject) => {
        const r = http.request({ hostname: '127.0.0.1', port, method, path: urlPath, headers }, res => {
            const chunks = [];
            res.on('data', c => chunks.push(c));
            res.on('end', () => resolve({
                status:  res.statusCode,
                headers: res.headers,
                body:    Buffer.concat(chunks),
            }));
        });
        r.on('error', reject);
        if (body !== null) r.write(body);
        r.end();
    });
}

(async () => {
    console.log('\n  NeoDAX v1.2.0 security & API verification\n');

    await test('N-API double close and post-close access are safe', () => {
        const bin = neodax.load('/bin/ls');
        bin.close();
        bin.close();
        assert.throws(() => bin.sections(), /already closed/i);
    });

    await test('N-API readBytes rejects negative and oversized lengths safely', () => {
        neodax.withBinary('/bin/ls', bin => {
            assert.strictEqual(bin.readBytes(bin.entry, -1), null);
            assert.strictEqual(bin.readBytes(bin.entry, 0), null);
            assert.strictEqual(bin.readBytes(bin.entry, 100000), null);
        });
    });

    await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
    const port = server.address().port;

    try {
        await test('GET /ui returns strict CSP nonce and security headers', async () => {
            const res = await req(port, 'GET', '/ui');
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
            assert.strictEqual(res.headers['x-frame-options'], 'DENY');
            const csp = res.headers['content-security-policy'] || '';
            assert.match(csp, /script-src 'nonce-[A-Za-z0-9+/=]+'/);
            assert.doesNotMatch(csp, /unsafe-inline/);
            const html = res.body.toString('utf8');
            assert.ok(!html.includes('__CSP_NONCE__'));
            assert.ok(!html.includes('JetBrains Mono'));
            assert.ok(html.includes('Silkscreen'));
            assert.ok(html.includes('#CCFF00'));
        });

        await test('GET /api/og/banner.jpg returns JPEG image', async () => {
            const res = await req(port, 'GET', '/api/og/banner.jpg');
            assert.strictEqual(res.status, 200);
            assert.strictEqual(res.headers['content-type'], 'image/jpeg');
            assert.strictEqual(res.body[0], 0xff);
            assert.strictEqual(res.body[1], 0xd8);
        });

        await test('POST /api/info rejects missing token with 401', async () => {
            const res = await req(port, 'POST', '/api/info', { 'Content-Type': 'application/json' }, JSON.stringify({ file: '/bin/ls' }));
            assert.strictEqual(res.status, 401);
        });

        await test('POST /api/info rejects untrusted Origin with 403', async () => {
            const res = await req(port, 'POST', '/api/info', {
                'Content-Type':  'application/json',
                'Origin':        'https://evil.example',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/bin/ls' }));
            assert.strictEqual(res.status, 403);
            assert.strictEqual(res.headers['access-control-allow-origin'], undefined);
        });

        await test('POST /api/info blocks path traversal outside NEODAX_ROOT', async () => {
            const res = await req(port, 'POST', '/api/info', {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/etc/passwd' }));
            assert.strictEqual(res.status, 403);
        });

        await test('POST /api/save-daxc blocks non-.daxc and outside-root writes', async () => {
            const res = await req(port, 'POST', '/api/save-daxc', {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/bin/ls', output: '/tmp/pwn.sh' }));
            assert.strictEqual(res.status, 400);
        });

        await test('POST /api/disasm/json applies offset before limit', async () => {
            const res1 = await req(port, 'POST', '/api/disasm/json', {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/bin/ls', section: '.text', offset: 0, limit: 5 }));
            const res2 = await req(port, 'POST', '/api/disasm/json', {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/bin/ls', section: '.text', offset: 2, limit: 2 }));
            assert.strictEqual(res1.status, 200);
            assert.strictEqual(res2.status, 200);
            const j1 = JSON.parse(res1.body.toString('utf8'));
            const j2 = JSON.parse(res2.body.toString('utf8'));
            assert.strictEqual(j2.instructions.length, 2);
            assert.strictEqual(j2.instructions[0].address, j1.instructions[2].address);
        });

        await test('POST /api/read-bytes rejects invalid address with 400', async () => {
            const res = await req(port, 'POST', '/api/read-bytes', {
                'Content-Type':  'application/json',
                'Authorization': 'Bearer test-secret-token-120',
            }, JSON.stringify({ file: '/bin/ls', address: 'not-a-hex', length: 4 }));
            assert.strictEqual(res.status, 400);
        });

        await test('GET /unknown returns DESIGN.md 404 HTML page', async () => {
            const res = await req(port, 'GET', '/nonexistent-route');
            assert.strictEqual(res.status, 404);
            assert.match(res.headers['content-type'], /text\/html/);
            assert.ok(res.body.toString('utf8').includes('404'));
        });
    } finally {
        server.close();
    }

    console.log(`\n  ${passed} passed  ${failed} failed\n`);
    process.exit(failed > 0 ? 1 : 0);
})();
