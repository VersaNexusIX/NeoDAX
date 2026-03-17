'use strict';

const http  = require('http');
const path  = require('path');
const fs    = require('fs');
const neodax = require(require('path').join(__dirname, '..', 'index.js'));

const PORT = parseInt(process.env.PORT || '7070', 10);

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', c => { raw += c; if (raw.length > 5 * 1024 * 1024) reject(new Error('body too large')); });
        req.on('end', () => {
            try { resolve(raw ? JSON.parse(raw) : {}); }
            catch (e) { reject(new Error('invalid JSON')); }
        });
        req.on('error', reject);
    });
}

function send(res, status, body) {
    const data = typeof body === 'string' ? body : JSON.stringify(body, (_, v) =>
        typeof v === 'bigint' ? '0x' + v.toString(16) : v
    );
    res.writeHead(status, {
        'Content-Type':  'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end(data);
}

function err(res, status, msg) {
    send(res, status, { error: msg });
}

function withFile(res, filePath, cb) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) {
        return err(res, 404, `File not found: ${resolved}`);
    }
    let bin;
    try {
        bin = neodax.load(resolved);
        cb(bin);
    } catch (e) {
        err(res, 500, e.message || String(e));
    } finally {
        if (bin) bin.close();
    }
}

const UI_PATH = require('path').join(__dirname, 'ui.html');

const ROUTES = {
    'GET /':                    handleRoot,
    'POST /api/info':           handleInfo,
    'POST /api/sections':       handleSections,
    'POST /api/symbols':        handleSymbols,
    'POST /api/functions':      handleFunctions,
    'POST /api/xrefs':          handleXrefs,
    'POST /api/unicode':        handleUnicode,
    'POST /api/disasm':         handleDisasm,
    'POST /api/disasm/json':    handleDisasmJson,
    'POST /api/analyze':        handleAnalyze,
    'POST /api/sym-at':         handleSymAt,
    'POST /api/func-at':        handleFuncAt,
    'POST /api/strings':        handleStrings,
    'POST /api/blocks':         handleBlocks,
    'POST /api/xrefs-to':       handleXrefsTo,
    'POST /api/xrefs-from':     handleXrefsFrom,
    'POST /api/hottest':        handleHottest,
    'POST /api/read-bytes':     handleReadBytes,
    'POST /api/section-at':     handleSectionAt,
    'POST /api/symexec':        handleSymexec,
    'POST /api/ssa':            handleSsa,
    'POST /api/decompile':      handleDecompile,
    'POST /api/emulate':        handleEmulate,
    'POST /api/entropy':        handleEntropy,
    'POST /api/rda':            handleRda,
    'POST /api/ivf':            handleIvf,
};

function handleRoot(req, res) {
    send(res, 200, {
        name:    'NeoDAX API',
        version: neodax.version(),
        ui:      'GET /ui',
        endpoints: Object.keys(ROUTES)
            .filter(k => !k.startsWith('GET'))
            .map(k => {
                const [method, route] = k.split(' ');
                return { method, route };
            }),
    });
}

async function handleInfo(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, bin.info));
}

async function handleSections(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { sections: bin.sections() }));
}

async function handleSymbols(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { symbols: bin.symbols() }));
}

async function handleFunctions(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { functions: bin.functions() }));
}

async function handleXrefs(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { xrefs: bin.xrefs() }));
}

async function handleUnicode(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { unicodeStrings: bin.unicodeStrings() }));
}

async function handleDisasm(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => {
        const text = bin.disasm(body.section || '.text');
        send(res, 200, { section: body.section || '.text', text });
    });
}

async function handleDisasmJson(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => {
        let insns = bin.disasmJson(body.section || '.text');
        if (body.group)   insns = insns.filter(i => i.group === body.group);
        if (body.limit)   insns = insns.slice(0, parseInt(body.limit, 10));
        if (body.offset)  insns = insns.slice(parseInt(body.offset, 10));
        send(res, 200, { section: body.section || '.text', count: insns.length, instructions: insns });
    });
}

async function handleAnalyze(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, bin.analyze()));
}

async function handleSymAt(req, res) {
    const body = await parseBody(req);
    if (!body.file)    return err(res, 400, 'body.file required');
    if (!body.address) return err(res, 400, 'body.address required (hex string e.g. "0x4000")');
    withFile(res, body.file, bin => {
        const addr = BigInt(body.address);
        const sym = bin.symAt(addr);
        send(res, 200, sym || null);
    });
}

async function handleFuncAt(req, res) {
    const body = await parseBody(req);
    if (!body.file)    return err(res, 400, 'body.file required');
    if (!body.address) return err(res, 400, 'body.address required (hex string e.g. "0x4000")');
    withFile(res, body.file, bin => {
        const addr = BigInt(body.address);
        const fn = bin.funcAt(addr);
        send(res, 200, fn || null);
    });
}


async function handleStrings(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { strings: bin.strings() }));
}

async function handleBlocks(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { blocks: bin.blocks() }));
}

async function handleXrefsTo(req, res) {
    const body = await parseBody(req);
    if (!body.file || !body.address) return err(res, 400, 'body.file + body.address required');
    withFile(res, body.file, bin => send(res, 200, { xrefs: bin.xrefsTo(BigInt(body.address)) }));
}

async function handleXrefsFrom(req, res) {
    const body = await parseBody(req);
    if (!body.file || !body.address) return err(res, 400, 'body.file + body.address required');
    withFile(res, body.file, bin => send(res, 200, { xrefs: bin.xrefsFrom(BigInt(body.address)) }));
}

async function handleHottest(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const n = parseInt(body.n || '20', 10);
    withFile(res, body.file, bin => send(res, 200, { hottest: bin.hottestFunctions(n) }));
}

async function handleReadBytes(req, res) {
    const body = await parseBody(req);
    if (!body.file || !body.address || !body.length) return err(res, 400, 'body.file + body.address + body.length required');
    withFile(res, body.file, bin => {
        const bytes = bin.readBytes(BigInt(body.address), parseInt(body.length, 10));
        send(res, 200, { bytes: bytes ? Array.from(bytes) : null });
    });
}

async function handleSectionAt(req, res) {
    const body = await parseBody(req);
    if (!body.file || !body.address) return err(res, 400, 'body.file + body.address required');
    withFile(res, body.file, bin => send(res, 200, bin.sectionAt(BigInt(body.address)) || null));
}


async function handleSymexec(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const funcIdx = body.funcIdx !== undefined ? parseInt(body.funcIdx, 10) : -1;
    withFile(res, body.file, bin => {
        bin.functions();
        send(res, 200, { output: bin.symexec(funcIdx) });
    });
}

async function handleSsa(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const funcIdx = body.funcIdx !== undefined ? parseInt(body.funcIdx, 10) : -1;
    withFile(res, body.file, bin => {
        bin.functions();
        send(res, 200, { output: bin.ssa(funcIdx) });
    });
}

async function handleDecompile(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const funcIdx = body.funcIdx !== undefined ? parseInt(body.funcIdx, 10) : -1;
    withFile(res, body.file, bin => {
        bin.functions();
        send(res, 200, { output: bin.decompile(funcIdx) });
    });
}

async function handleEmulate(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const funcIdx = body.funcIdx !== undefined ? parseInt(body.funcIdx, 10) : 0;
    const initRegs = body.initRegs || {};
    withFile(res, body.file, bin => {
        bin.functions();
        send(res, 200, { output: bin.emulate(funcIdx, initRegs) });
    });
}


async function handleEntropy(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => send(res, 200, { output: bin.entropy() }));
}

async function handleRda(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    const section = body.section || '.text';
    withFile(res, body.file, bin => {
        bin.symbols();
        send(res, 200, { output: bin.rda(section) });
    });
}

async function handleIvf(req, res) {
    const body = await parseBody(req);
    if (!body.file) return err(res, 400, 'body.file required');
    withFile(res, body.file, bin => {
        bin.functions();
        send(res, 200, { output: bin.ivf() });
    });
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {
            'Access-Control-Allow-Origin':  '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        });
        return res.end();
    }

    if (req.method === 'GET' && (req.url === '/ui' || req.url === '/ui/')) {
        const html = fs.readFileSync(UI_PATH, 'utf8');
        const patched = html.replace(
            "window.NEODAX_API_URL || 'http://localhost:7070'",
            `'http://localhost:${PORT}'`
        );
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        return res.end(patched);
    }

    const key = `${req.method} ${req.url.split('?')[0]}`;
    const handler = ROUTES[key];

    if (!handler) {
        return err(res, 404, `No route: ${key}`);
    }

    try {
        await handler(req, res);
    } catch (e) {
        err(res, 500, e.message || String(e));
    }
});

server.listen(PORT, '0.0.0.0', () => {
    console.log(`\n  ███╗   ██╗███████╗ ██████╗`);
    console.log(`  ████╗  ██║██╔════╝██╔═══██╗`);
    console.log(`  ██╔██╗ ██║█████╗  ██║   ██║   NeoDAX API Server v${neodax.version()}`);
    console.log(`  ██║╚██╗██║██╔══╝  ██║   ██║   http://localhost:${PORT}`);
    console.log(`  ██║ ╚████║███████╗╚██████╔╝`);
    console.log(`  ╚═╝  ╚═══╝╚══════╝ ╚═════╝`);
    console.log(`\n  Listening on port ${PORT}`);
    console.log(`  GET  /              — API index`);
    console.log(`  POST /api/info      — binary metadata`);
    console.log(`  POST /api/sections  — section table`);
    console.log(`  POST /api/symbols   — symbol table`);
    console.log(`  POST /api/functions — function list`);
    console.log(`  POST /api/xrefs     — cross-references`);
    console.log(`  POST /api/unicode   — unicode strings`);
    console.log(`  POST /api/disasm    — plain-text disassembly`);
    console.log(`  POST /api/disasm/json — structured disassembly`);
    console.log(`  POST /api/analyze   — full analysis`);
  console.log(`  POST /api/strings   — ASCII string scan`);
  console.log(`  POST /api/blocks    — CFG basic blocks`);
  console.log(`  POST /api/xrefs-to  — xrefs targeting address`);
  console.log(`  POST /api/xrefs-from — xrefs from address`);
  console.log(`  POST /api/hottest   — hottest functions by call count`);
  console.log(`  POST /api/read-bytes — read raw bytes at address\n`);
});
