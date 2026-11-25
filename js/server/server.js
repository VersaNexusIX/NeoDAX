'use strict';

const http   = require('http');
const path   = require('path');
const fs     = require('fs');
const crypto = require('crypto');

process.on('uncaughtException', (err) => {
    console.error(`\n  [!] uncaught exception — ${err.message || err}\n`);
});

process.on('unhandledRejection', (reason) => {
    console.error(`\n  [!] unhandled promise rejection — ${reason}\n`);
});

try {
    process.on('SIGSEGV', () => {
        process.stderr.write('\n  [!] SIGSEGV — native addon crash\n');
        process.exit(139);
    });
    process.on('SIGBUS', () => {
        process.stderr.write('\n  [!] SIGBUS — native addon bus error\n');
        process.exit(138);
    });
} catch (_) {}

let neodax;
try {
    neodax = require(path.join(__dirname, '..', 'index.js'));
} catch (e) {
    console.error(`\n  [!] Failed to load NeoDAX native addon:\n      ${e.message}\n`);
    console.error('  Run: make js\n');
    process.exit(1);
}

function loadDaxNg() {
    const candidates = [
        path.join(__dirname, '..', '..', 'config.dax-ng'),
        path.join(__dirname, '..', 'config.dax-ng'),
        path.join(process.cwd(), 'config.dax-ng'),
    ];
    const cfg = {};
    for (const p of candidates) {
        if (!fs.existsSync(p)) continue;
        for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
            const t = line.trim();
            if (!t || t.startsWith('#') || t.startsWith('[')) continue;
            const eq = t.indexOf('=');
            if (eq < 0) continue;
            cfg[t.slice(0, eq).trim()] = t.slice(eq + 1).trim();
        }
        break;
    }
    return cfg;
}

const CFG            = loadDaxNg();
const PORT           = parseInt(process.env.PORT || CFG.port || '7070', 10);
const HOST           = process.env.HOST || CFG.host || '127.0.0.1';
const MAX_BODY       = parseInt(process.env.NEODAX_MAX_BODY || CFG.max_body_bytes || '5242880', 10);
const API_TOKEN      = process.env.NEODAX_API_TOKEN || CFG.api_token || '';
const ALLOWED_ROOT   = process.env.NEODAX_ROOT || CFG.allowed_root || '';
const RATE_LIMIT     = parseInt(process.env.NEODAX_RATE_LIMIT || CFG.rate_limit || '300', 10);
const ALLOW_REMOTE   = process.env.NEODAX_ALLOW_UNAUTH_REMOTE === '1';
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

if (!LOOPBACK_HOSTS.has(HOST) && !API_TOKEN && !ALLOW_REMOTE) {
    console.error('\n  [!] Refusing to bind non-loopback host without NEODAX_API_TOKEN.');
    console.error('  Set NEODAX_API_TOKEN=<secret> or bind HOST=127.0.0.1.\n');
    process.exit(1);
}

const ALLOWED_ORIGINS = new Set([
    `http://127.0.0.1:${PORT}`,
    `http://localhost:${PORT}`,
    ...(process.env.NEODAX_ALLOWED_ORIGINS || CFG.allowed_origins || '')
        .split(',')
        .map(s => s.trim())
        .filter(Boolean),
]);

const CANONICAL_ROOT = ALLOWED_ROOT ? fs.realpathSync(path.resolve(ALLOWED_ROOT)) : '';
const UI_PATH        = path.join(__dirname, 'ui.html');
const OG_BANNER_PATH = path.join(__dirname, 'og-banner.jpg');
const RATE_BUCKETS   = new Map();

function securityHeaders(extra = {}) {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options':        'DENY',
        'Referrer-Policy':        'no-referrer',
        'Permissions-Policy':     'camera=(), microphone=(), geolocation=()',
        ...extra,
    };
}

function corsHeaders(req) {
    const origin = req.headers.origin;
    if (!origin || !ALLOWED_ORIGINS.has(origin)) return {};
    return {
        'Access-Control-Allow-Origin':  origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-NeoDAX-Token',
        'Vary':                         'Origin',
    };
}

function checkRateLimit(req) {
    if (RATE_LIMIT <= 0) return true;
    const ip  = req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const win = 60000;
    let entry = RATE_BUCKETS.get(ip);
    if (!entry || now - entry.start > win) {
        entry = { start: now, count: 0 };
        RATE_BUCKETS.set(ip, entry);
    }
    entry.count++;
    if (RATE_BUCKETS.size > 1024) {
        for (const [k, v] of RATE_BUCKETS) {
            if (now - v.start > win) RATE_BUCKETS.delete(k);
        }
    }
    return entry.count <= RATE_LIMIT;
}

function isAuthorized(req) {
    if (!API_TOKEN) return true;
    const auth   = req.headers.authorization || '';
    const header = req.headers['x-neodax-token'] || '';
    const token  = auth.startsWith('Bearer ') ? auth.slice(7) : String(header);
    const a      = Buffer.from(token);
    const b      = Buffer.from(API_TOKEN);
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
}

function isWithinRoot(targetPath, rootDir) {
    const rel = path.relative(rootDir, targetPath);
    return rel === '' || (!rel.startsWith('..') && !path.isAbsolute(rel));
}

function resolveInputFile(filePath) {
    if (typeof filePath !== 'string' || !filePath.trim() || filePath.includes('\0')) {
        return { error: 'Invalid file path', status: 400 };
    }
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
        return { error: 'File not found', status: 404 };
    }
    let real;
    try {
        real = fs.realpathSync(resolved);
    } catch (_) {
        return { error: 'File not accessible', status: 403 };
    }
    if (CANONICAL_ROOT && !isWithinRoot(real, CANONICAL_ROOT)) {
        return { error: 'Access denied: path outside allowed root', status: 403 };
    }
    let st;
    try {
        st = fs.statSync(real);
    } catch (_) {
        return { error: 'File not accessible', status: 403 };
    }
    if (!st.isFile()) {
        return { error: 'Target must be a regular file', status: 400 };
    }
    return { path: real };
}

function resolveOutputDaxc(outPath) {
    if (typeof outPath !== 'string' || !outPath.trim() || outPath.includes('\0')) {
        return { error: 'Invalid output path', status: 400 };
    }
    if (!outPath.endsWith('.daxc')) {
        return { error: 'Output path must end with .daxc', status: 400 };
    }
    const baseRoot = CANONICAL_ROOT || fs.realpathSync(process.cwd());
    const resolved = path.resolve(outPath);
    const parent   = path.dirname(resolved);
    if (!fs.existsSync(parent)) {
        return { error: 'Output directory does not exist', status: 400 };
    }
    const realParent = fs.realpathSync(parent);
    if (!isWithinRoot(realParent, baseRoot)) {
        return { error: 'Output path outside allowed directory', status: 403 };
    }
    const finalPath = path.join(realParent, path.basename(resolved));
    if (fs.existsSync(finalPath)) {
        const lst = fs.lstatSync(finalPath);
        if (lst.isSymbolicLink() || !lst.isFile()) {
            return { error: 'Refusing to overwrite non-regular file or symlink', status: 403 };
        }
    }
    return { path: finalPath };
}

function parseAddr(v) {
    if (typeof v === 'bigint') return v >= 0n ? v : null;
    if (typeof v === 'number') return Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null;
    if (typeof v === 'string' && /^(0x[0-9a-fA-F]+|\d+)$/.test(v.trim())) {
        try { return BigInt(v.trim()); } catch (_) { return null; }
    }
    return null;
}

function parseBoundedInt(v, fallback, min, max) {
    if (v === undefined || v === null || v === '') return fallback;
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) return null;
    return n;
}

function parseBody(req) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let bytes    = 0;
        let done     = false;
        req.on('data', (chunk) => {
            if (done) return;
            bytes += chunk.length;
            if (bytes > MAX_BODY) {
                done = true;
                req.destroy();
                const e = new Error('Payload too large');
                e.statusCode = 413;
                reject(e);
                return;
            }
            chunks.push(chunk);
        });
        req.on('end', () => {
            if (done) return;
            done = true;
            try {
                const raw = Buffer.concat(chunks).toString('utf8');
                const parsed = raw ? JSON.parse(raw) : {};
                if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
                    const e = new Error('JSON object body required');
                    e.statusCode = 400;
                    reject(e);
                    return;
                }
                resolve(parsed);
            } catch (_) {
                const e = new Error('Invalid JSON');
                e.statusCode = 400;
                reject(e);
            }
        });
        req.on('error', (e) => {
            if (!done) { done = true; reject(e); }
        });
    });
}

function send(req, res, status, body) {
    const data = typeof body === 'string' ? body : JSON.stringify(body, (_, v) =>
        typeof v === 'bigint' ? '0x' + v.toString(16) : v
    );
    res.writeHead(status, securityHeaders({
        'Content-Type':  'application/json; charset=utf-8',
        'Cache-Control': 'no-store',
        ...corsHeaders(req),
    }));
    res.end(data);
}

function err(req, res, status, msg) {
    send(req, res, status, { error: msg });
}

function withFile(req, res, filePath, cb) {
    const check = resolveInputFile(filePath);
    if (check.error) return err(req, res, check.status, check.error);
    let bin;
    try {
        bin = neodax.load(check.path);
        cb(bin);
    } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        try { err(req, res, 500, msg); } catch (_) {}
    } finally {
        try { if (bin) bin.close(); } catch (_) {}
    }
}

function renderNotFoundHtml(nonce) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta name="theme-color" content="#0D0D0D">
<meta name="color-scheme" content="dark">
<title>404 — Route Not Found | NeoDAX v${neodax.version()}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=Plus+Jakarta+Sans:wght@400;600&family=Silkscreen:wght@400;700&display=swap" rel="stylesheet">
<style nonce="${nonce}">
*{box-sizing:border-box;border-radius:0!important;box-shadow:none!important;text-shadow:none!important}
html,body{margin:0;min-height:100vh;background:#0D0D0D;color:#F2F2EE;font-family:"Plus Jakarta Sans",Arial,sans-serif;display:grid;place-items:center;padding:24px;text-align:center}
h1{font-family:"Silkscreen",monospace;font-size:clamp(64px,16vw,136px);line-height:1;margin:0 0 18px;color:#CCFF00;letter-spacing:.06em}
p{margin:0 auto 28px;max-width:52ch;color:#8A8A85;line-height:1.65;font-size:15px}
a{display:inline-block;background:#CCFF00;color:#0D0D0D;border:1px solid #CCFF00;padding:12px 24px;font-family:"Silkscreen",monospace;font-size:12px;letter-spacing:.08em;text-transform:uppercase;text-decoration:none;clip-path:polygon(0 4px,4px 4px,4px 0,calc(100% - 4px) 0,calc(100% - 4px) 4px,100% 4px,100% calc(100% - 4px),calc(100% - 4px) calc(100% - 4px),calc(100% - 4px) 100%,4px 100%,4px calc(100% - 4px),0 calc(100% - 4px))}
a:hover{background:#F2F2EE;border-color:#F2F2EE}
</style>
</head>
<body>
<main>
<h1>404</h1>
<p>The requested NeoDAX endpoint or page does not exist on this workbench instance.</p>
<a href="/ui">OPEN WORKBENCH</a>
</main>
</body>
</html>`;
}

const ROUTES = {
    'GET /':                       handleRoot,
    'GET /api/health':             handleHealth,
    'POST /api/info':              handleInfo,
    'POST /api/sections':          handleSections,
    'POST /api/symbols':           handleSymbols,
    'POST /api/functions':         handleFunctions,
    'POST /api/xrefs':             handleXrefs,
    'POST /api/xrefs-to':          handleXrefsTo,
    'POST /api/xrefs-from':        handleXrefsFrom,
    'POST /api/blocks':            handleBlocks,
    'POST /api/unicode':           handleUnicode,
    'POST /api/strings':           handleStrings,
    'POST /api/sym-at':            handleSymAt,
    'POST /api/func-at':           handleFuncAt,
    'POST /api/section-at':        handleSectionAt,
    'POST /api/read-bytes':        handleReadBytes,
    'POST /api/hottest':           handleHottest,
    'POST /api/disasm':            handleDisasm,
    'POST /api/disasm/json':       handleDisasmJson,
    'POST /api/disasm/func':       handleDisasmFunc,
    'POST /api/disasm/range':      handleDisasmRange,
    'POST /api/analyze':           handleAnalyze,
    'POST /api/entropy':           handleEntropy,
    'POST /api/rda':               handleRda,
    'POST /api/ivf':               handleIvf,
    'POST /api/cfg':               handleCfg,
    'POST /api/cfg/json':          handleCfgJson,
    'POST /api/callgraph':         handleCallgraph,
    'POST /api/callgraph/json':    handleCallgraphJson,
    'POST /api/loops':             handleLoops,
    'POST /api/switch-detect':     handleSwitchDetect,
    'POST /api/poly':              handlePoly,
    'POST /api/poly/json':         handlePolyJson,
    'POST /api/aire':              handleAire,
    'POST /api/aire/json':         handleAireJson,
    'POST /api/vm-trace':          handleVmTrace,
    'POST /api/obfuscation-score': handleObfuscationScore,
    'POST /api/vm-detect':         handleVmDetect,
    'POST /api/symexec':           handleSymexec,
    'POST /api/ssa':               handleSsa,
    'POST /api/decompile':         handleDecompile,
    'POST /api/emulate':           handleEmulate,
    'POST /api/save-daxc':         handleSaveDaxc,
    'POST /api/comment':           handleComment,
};

function handleRoot(req, res) {
    send(req, res, 200, {
        name:         'NeoDAX API',
        version:      neodax.version(),
        ui:           'GET /ui',
        health:       'GET /api/health',
        sandbox:      Boolean(CANONICAL_ROOT),
        authRequired: Boolean(API_TOKEN),
        endpoints:    Object.keys(ROUTES)
            .filter(k => k.startsWith('POST'))
            .map(k => { const [method, route] = k.split(' '); return { method, route }; }),
    });
}

function handleHealth(req, res) {
    send(req, res, 200, {
        status:       'ok',
        version:      neodax.version(),
        sandbox:      Boolean(CANONICAL_ROOT),
        authRequired: Boolean(API_TOKEN),
    });
}

async function handleInfo(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.info));
}

async function handleSections(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { sections: bin.sections() }));
}

async function handleSymbols(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        let s = bin.symbols();
        if (typeof b.filter === 'string' && b.filter) s = s.filter(x => x.name.includes(b.filter) || x.demangled.includes(b.filter));
        if (typeof b.type === 'string' && b.type) s = s.filter(x => x.type === b.type);
        send(req, res, 200, { symbols: s });
    });
}

async function handleFunctions(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        let f = bin.functions();
        if (typeof b.filter === 'string' && b.filter) f = f.filter(x => x.name.includes(b.filter));
        send(req, res, 200, { functions: f });
    });
}

async function handleXrefs(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { xrefs: bin.xrefs() }));
}

async function handleXrefsTo(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null) return err(req, res, 400, 'body.file and valid body.address required');
    withFile(req, res, b.file, bin => send(req, res, 200, { xrefs: bin.xrefsTo(addr) }));
}

async function handleXrefsFrom(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null) return err(req, res, 400, 'body.file and valid body.address required');
    withFile(req, res, b.file, bin => send(req, res, 200, { xrefs: bin.xrefsFrom(addr) }));
}

async function handleBlocks(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { blocks: bin.blocks() }));
}

async function handleUnicode(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { unicodeStrings: bin.unicodeStrings() }));
}

async function handleStrings(req, res) {
    const b      = await parseBody(req);
    const minLen = parseBoundedInt(b.minLen, 0, 0, 4096);
    if (!b.file || minLen === null) return err(req, res, 400, 'body.file and valid minLen required');
    withFile(req, res, b.file, bin => {
        let s = bin.strings();
        if (typeof b.filter === 'string' && b.filter) {
            const q = b.filter.toLowerCase();
            s = s.filter(x => x.value.toLowerCase().includes(q));
        }
        if (minLen > 0) s = s.filter(x => x.length >= minLen);
        send(req, res, 200, { strings: s });
    });
}

async function handleSymAt(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null) return err(req, res, 400, 'body.file and valid body.address required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.symAt(addr) || null));
}

async function handleFuncAt(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null) return err(req, res, 400, 'body.file and valid body.address required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.funcAt(addr) || null));
}

async function handleSectionAt(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null) return err(req, res, 400, 'body.file and valid body.address required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.sectionAt(addr) || null));
}

async function handleReadBytes(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    const len  = parseBoundedInt(b.length, null, 1, 65536);
    if (!b.file || addr === null || len === null) {
        return err(req, res, 400, 'body.file, valid body.address, and body.length (1..65536) required');
    }
    withFile(req, res, b.file, bin => {
        const bytes = bin.readBytes(addr, len);
        send(req, res, 200, { bytes: bytes ? Array.from(bytes) : null });
    });
}

async function handleHottest(req, res) {
    const b = await parseBody(req);
    const n = parseBoundedInt(b.n, 20, 1, 500);
    if (!b.file || n === null) return err(req, res, 400, 'body.file and valid n (1..500) required');
    withFile(req, res, b.file, bin => send(req, res, 200, { hottest: bin.hottestFunctions(n) }));
}

async function handleDisasm(req, res) {
    const b   = await parseBody(req);
    const sec = typeof b.section === 'string' && b.section ? b.section : '.text';
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { section: sec, text: bin.disasm(sec) }));
}

async function handleDisasmJson(req, res) {
    const b      = await parseBody(req);
    const sec    = typeof b.section === 'string' && b.section ? b.section : '.text';
    const offset = parseBoundedInt(b.offset, 0, 0, 10000000);
    const limit  = parseBoundedInt(b.limit, 0, 0, 100000);
    if (!b.file || offset === null || limit === null) {
        return err(req, res, 400, 'body.file and valid offset/limit required');
    }
    withFile(req, res, b.file, bin => {
        let items = bin.disasmJson(sec);
        if (typeof b.group === 'string' && b.group) items = items.filter(x => x.group === b.group);
        if (offset > 0) items = items.slice(offset);
        if (limit > 0) items = items.slice(0, limit);
        send(req, res, 200, { section: sec, count: items.length, instructions: items });
    });
}

async function handleDisasmFunc(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, 0, 0, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { funcIdx: fi, output: bin.disasmFunc(fi) });
    });
}

async function handleDisasmRange(req, res) {
    const b      = await parseBody(req);
    const addr   = parseAddr(b.address);
    const nInsns = parseBoundedInt(b.nInsns, 32, 1, 4096);
    if (!b.file || addr === null || nInsns === null) {
        return err(req, res, 400, 'body.file, valid body.address, and nInsns (1..4096) required');
    }
    withFile(req, res, b.file, bin => send(req, res, 200, { address: b.address, output: bin.disasmRange(addr, nInsns) }));
}

async function handleAnalyze(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.analyze()));
}

async function handleEntropy(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { output: bin.entropy() }));
}

async function handleRda(req, res) {
    const b   = await parseBody(req);
    const sec = typeof b.section === 'string' && b.section ? b.section : '.text';
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.symbols();
        send(req, res, 200, { output: bin.rda(sec) });
    });
}

async function handleIvf(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.ivf() });
    });
}

async function handleCfg(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, 0, 0, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { funcIdx: fi, output: bin.cfg(fi) });
    });
}

async function handleCfgJson(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, 0, 0, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { funcIdx: fi, blocks: bin.cfgJson(fi) });
    });
}

async function handleCallgraph(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { output: bin.callgraph() }));
}

async function handleCallgraphJson(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, bin.callgraphJson()));
}

async function handleLoops(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, -1, -1, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.loops(fi) });
    });
}

async function handleSwitchDetect(req, res) {
    const b   = await parseBody(req);
    const sec = typeof b.section === 'string' && b.section ? b.section : '.text';
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { output: bin.switchDetect(sec) }));
}

async function handlePoly(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { output: bin.poly() }));
}

async function handlePolyJson(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => send(req, res, 200, { regions: bin.polyJson() }));
}

async function handleAire(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.aire() });
    });
}

async function handleAireJson(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { insights: bin.aireJson() });
    });
}

async function handleVmTrace(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.vmTrace() });
    });
}

async function handleObfuscationScore(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, bin.obfuscationScore());
    });
}

async function handleVmDetect(req, res) {
    const b = await parseBody(req);
    if (!b.file) return err(req, res, 400, 'body.file required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { vms: bin.vmDetect() });
    });
}

async function handleSymexec(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, -1, -1, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.symexec(fi) });
    });
}

async function handleSsa(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, -1, -1, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.ssa(fi) });
    });
}

async function handleDecompile(req, res) {
    const b  = await parseBody(req);
    const fi = parseBoundedInt(b.funcIdx, -1, -1, 100000);
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.decompile(fi) });
    });
}

async function handleEmulate(req, res) {
    const b    = await parseBody(req);
    const fi   = parseBoundedInt(b.funcIdx, 0, 0, 100000);
    const regs = (b.initRegs && typeof b.initRegs === 'object' && !Array.isArray(b.initRegs)) ? b.initRegs : {};
    if (!b.file || fi === null) return err(req, res, 400, 'body.file and valid funcIdx required');
    withFile(req, res, b.file, bin => {
        bin.functions();
        send(req, res, 200, { output: bin.emulate(fi, regs) });
    });
}

async function handleSaveDaxc(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.output) return err(req, res, 400, 'body.file + body.output required');
    const outCheck = resolveOutputDaxc(b.output);
    if (outCheck.error) return err(req, res, outCheck.status, outCheck.error);
    withFile(req, res, b.file, bin => {
        const ok = bin.saveDaxc(outCheck.path);
        send(req, res, 200, { ok });
    });
}

async function handleComment(req, res) {
    const b    = await parseBody(req);
    const addr = parseAddr(b.address);
    if (!b.file || addr === null || typeof b.text !== 'string' || !b.text.trim()) {
        return err(req, res, 400, 'body.file, valid body.address, and body.text required');
    }
    if (b.text.length > 250) return err(req, res, 400, 'Comment exceeds 250 characters');
    const outCheck = b.output ? resolveOutputDaxc(b.output) : null;
    if (outCheck && outCheck.error) return err(req, res, outCheck.status, outCheck.error);
    withFile(req, res, b.file, bin => {
        bin.addComment(addr, b.text);
        const saved = outCheck ? bin.saveDaxc(outCheck.path) : false;
        send(req, res, 200, { ok: true, saved });
    });
}

const server = http.createServer(async (req, res) => {
    req.setTimeout(15000);
    const pathname = (req.url || '/').split('?')[0];

    if (req.method === 'OPTIONS') {
        const origin = req.headers.origin;
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
            res.writeHead(403, securityHeaders({ 'Content-Type': 'application/json; charset=utf-8' }));
            return res.end(JSON.stringify({ error: 'Origin not allowed' }));
        }
        res.writeHead(204, securityHeaders(corsHeaders(req)));
        return res.end();
    }

    if (req.method === 'GET' && pathname === '/api/og/banner.jpg') {
        try {
            const img = fs.readFileSync(OG_BANNER_PATH);
            res.writeHead(200, securityHeaders({
                'Content-Type':  'image/jpeg',
                'Cache-Control': 'public, max-age=86400',
            }));
            return res.end(img);
        } catch (_) {
            return err(req, res, 404, 'Banner not found');
        }
    }

    if (req.method === 'GET' && (pathname === '/ui' || pathname === '/ui/')) {
        try {
            const nonce = crypto.randomBytes(16).toString('base64');
            const html  = fs.readFileSync(UI_PATH, 'utf8').replaceAll('__CSP_NONCE__', nonce);
            const csp   = [
                "default-src 'self'",
                `script-src 'nonce-${nonce}'`,
                `style-src 'self' 'nonce-${nonce}' https://fonts.googleapis.com`,
                "font-src 'self' https://fonts.gstatic.com",
                "img-src 'self' data:",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "base-uri 'self'",
                "form-action 'self'",
            ].join('; ');
            res.writeHead(200, securityHeaders({
                'Content-Type':            'text/html; charset=utf-8',
                'Content-Security-Policy': csp,
                'Cache-Control':           'no-store',
            }));
            return res.end(html);
        } catch (e) {
            return err(req, res, 500, 'UI unavailable');
        }
    }

    if (pathname.startsWith('/api/')) {
        const origin = req.headers.origin;
        if (origin && !ALLOWED_ORIGINS.has(origin)) {
            return err(req, res, 403, 'Origin not allowed');
        }
        if (!checkRateLimit(req)) {
            return err(req, res, 429, 'Rate limit exceeded');
        }
        if (pathname !== '/api/health' && !isAuthorized(req)) {
            return err(req, res, 401, 'Unauthorized');
        }
    }

    const key     = `${req.method} ${pathname}`;
    const handler = ROUTES[key];
    if (!handler) {
        if (req.method === 'GET' && !pathname.startsWith('/api/')) {
            const nonce = crypto.randomBytes(16).toString('base64');
            res.writeHead(404, securityHeaders({
                'Content-Type':            'text/html; charset=utf-8',
                'Content-Security-Policy': `default-src 'self'; style-src 'nonce-${nonce}' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; frame-ancestors 'none'`,
            }));
            return res.end(renderNotFoundHtml(nonce));
        }
        return err(req, res, 404, `No route: ${key}`);
    }

    try {
        await handler(req, res);
    } catch (e) {
        const code = e && e.statusCode ? e.statusCode : 500;
        const msg  = (e && e.message) ? e.message : String(e);
        if (code >= 500) console.error(`  [!] request error on ${key} — ${msg}`);
        try { err(req, res, code, msg); } catch (_) {}
    }
});

server.headersTimeout = 10000;
server.requestTimeout = 30000;

if (require.main === module) {
    server.listen(PORT, HOST, () => {
        let v = '1.2.0';
        try { v = neodax.version(); } catch (_) {}
        console.log(`\n  NeoDAX API Server v${v}  →  http://${HOST}:${PORT}/ui`);
        console.log(`  Security: loopback=${LOOPBACK_HOSTS.has(HOST)} auth=${Boolean(API_TOKEN)} sandbox=${Boolean(CANONICAL_ROOT)}\n`);
    });
}

module.exports = { server, ALLOWED_ORIGINS, parseAddr, parseBoundedInt };
