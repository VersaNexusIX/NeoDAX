'use strict';

const http   = require('http');
const path   = require('path');
const fs     = require('fs');

/* ── Fault isolation: catch any unhandled exception or fatal signal ──────── */
process.on('uncaughtException', (err) => {
    console.error(`\n  [!] uncaught exception — ${err.message || err}\n`);
    /* Do not exit — keep the server alive so clients get 500 instead of ECONNREFUSED */
});

process.on('unhandledRejection', (reason) => {
    console.error(`\n  [!] unhandled promise rejection — ${reason}\n`);
});

/* SIGSEGV/SIGBUS trap: on fatal native crash, print a diagnostic before dying.
   Node's native addon segfault normally kills silently — this gives one line. */
let _sigInstalled = false;
try {
    process.on('SIGSEGV', () => {
        process.stderr.write('\n  [!] SIGSEGV — native addon crash (check binary format or report a bug)\n');
        process.exit(139);
    });
    process.on('SIGBUS', () => {
        process.stderr.write('\n  [!] SIGBUS — native addon bus error\n');
        process.exit(138);
    });
    _sigInstalled = true;
} catch (_) { /* some platforms don't allow SIGSEGV handlers — ignore */ }

/* ── Load native addon with a safety net ────────────────────────────────── */
let neodax;
try {
    neodax = require(require('path').join(__dirname, '..', 'index.js'));
} catch (e) {
    console.error(`\n  [!] Failed to load NeoDAX native addon:\n      ${e.message}\n`);
    console.error('  Make sure you ran: make js\n');
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

const CFG      = loadDaxNg();
const PORT     = parseInt(process.env.PORT || CFG.port || '7070', 10);
const HOST     = process.env.HOST || CFG.host || '0.0.0.0';
const MAX_BODY = parseInt(CFG.max_body_bytes || '5242880', 10);

function parseBody(req) {
    return new Promise((resolve, reject) => {
        let raw = '';
        req.on('data', c => { raw += c; if (raw.length > MAX_BODY) reject(new Error('body too large')); });
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
        'Content-Type':                 'application/json',
        'Access-Control-Allow-Origin':  '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
    });
    res.end(data);
}

function err(res, status, msg) { send(res, status, { error: msg }); }

function withFile(res, filePath, cb) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) return err(res, 404, `File not found: ${resolved}`);
    let bin;
    try {
        bin = neodax.load(resolved);
        cb(bin);
    } catch (e) {
        /* Catch both JS exceptions and any native addon errors that
           propagate as JS — genuine SIGSEGV won't reach here, but
           thrown napi_throw_error() results will. */
        const msg = (e && e.message) ? e.message : String(e);
        try { err(res, 500, msg); } catch (_) { /* response already sent */ }
    } finally {
        try { if (bin) bin.close(); } catch (_) { /* ignore close errors */ }
    }
}

const UI_PATH = path.join(__dirname, 'ui.html');

const ROUTES = {
    'GET /':                       handleRoot,
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
    send(res, 200, {
        name: 'NeoDAX API', version: neodax.version(), ui: 'GET /ui',
        endpoints: Object.keys(ROUTES).filter(k => k.startsWith('POST'))
            .map(k => { const [m,r] = k.split(' '); return {method:m, route:r}; }),
    });
}

async function handleInfo(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, bin.info));
}
async function handleSections(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { sections: bin.sections() }));
}
async function handleSymbols(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => {
        let s = bin.symbols();
        if (b.filter) s = s.filter(x => x.name.includes(b.filter) || x.demangled.includes(b.filter));
        if (b.type)   s = s.filter(x => x.type === b.type);
        send(res, 200, { symbols: s });
    });
}
async function handleFunctions(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => {
        let f = bin.functions();
        if (b.filter) f = f.filter(x => x.name.includes(b.filter));
        send(res, 200, { functions: f });
    });
}
async function handleXrefs(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { xrefs: bin.xrefs() }));
}
async function handleXrefsTo(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res, 200, { xrefs: bin.xrefsTo(BigInt(b.address)) }));
}
async function handleXrefsFrom(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res, 200, { xrefs: bin.xrefsFrom(BigInt(b.address)) }));
}
async function handleBlocks(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { blocks: bin.blocks() }));
}
async function handleUnicode(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { unicodeStrings: bin.unicodeStrings() }));
}
async function handleStrings(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => {
        let s = bin.strings();
        if (b.filter) s = s.filter(x => x.value.toLowerCase().includes(b.filter.toLowerCase()));
        if (b.minLen) s = s.filter(x => x.length >= parseInt(b.minLen,10));
        send(res, 200, { strings: s });
    });
}
async function handleSymAt(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res, 200, bin.symAt(BigInt(b.address)) || null));
}
async function handleFuncAt(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res, 200, bin.funcAt(BigInt(b.address)) || null));
}
async function handleSectionAt(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res, 200, bin.sectionAt(BigInt(b.address)) || null));
}
async function handleReadBytes(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address || !b.length) return err(res,400,'body.file + body.address + body.length required');
    withFile(res, b.file, bin => {
        const bytes = bin.readBytes(BigInt(b.address), parseInt(b.length,10));
        send(res, 200, { bytes: bytes ? Array.from(bytes) : null });
    });
}
async function handleHottest(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { hottest: bin.hottestFunctions(parseInt(b.n||'20',10)) }));
}
async function handleDisasm(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { section: b.section||'.text', text: bin.disasm(b.section||'.text') }));
}
async function handleDisasmJson(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => {
        let i = bin.disasmJson(b.section||'.text');
        if (b.group)  i = i.filter(x => x.group === b.group);
        if (b.limit)  i = i.slice(0, parseInt(b.limit,10));
        if (b.offset) i = i.slice(parseInt(b.offset,10));
        send(res, 200, { section: b.section||'.text', count: i.length, instructions: i });
    });
}
async function handleDisasmFunc(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : 0;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{funcIdx:fi, output:bin.disasmFunc(fi)}); });
}
async function handleDisasmRange(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address) return err(res,400,'body.file + body.address required');
    withFile(res, b.file, bin => send(res,200,{address:b.address, output:bin.disasmRange(BigInt(b.address),parseInt(b.nInsns||'32',10))}));
}
async function handleAnalyze(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, bin.analyze()));
}
async function handleEntropy(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { output: bin.entropy() }));
}
async function handleRda(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.symbols(); send(res,200,{output:bin.rda(b.section||'.text')}); });
}
async function handleIvf(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.ivf()}); });
}
async function handleCfg(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : 0;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{funcIdx:fi,output:bin.cfg(fi)}); });
}
async function handleCfgJson(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : 0;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{funcIdx:fi,blocks:bin.cfgJson(fi)}); });
}
async function handleCallgraph(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { output: bin.callgraph() }));
}
async function handleCallgraphJson(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, bin.callgraphJson()));
}
async function handleLoops(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : -1;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.loops(fi)}); });
}
async function handleSwitchDetect(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res,200,{output:bin.switchDetect(b.section||'.text')}));
}
async function handlePoly(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { output: bin.poly() }));
}
async function handlePolyJson(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => send(res, 200, { regions: bin.polyJson() }));
}
async function handleAire(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.aire()}); });
}
async function handleAireJson(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{insights:bin.aireJson()}); });
}
async function handleVmTrace(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.vmTrace()}); });
}
async function handleObfuscationScore(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,bin.obfuscationScore()); });
}
async function handleVmDetect(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{vms:bin.vmDetect()}); });
}
async function handleSymexec(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : -1;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.symexec(fi)}); });
}
async function handleSsa(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : -1;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.ssa(fi)}); });
}
async function handleDecompile(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : -1;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.decompile(fi)}); });
}
async function handleEmulate(req, res) {
    const b = await parseBody(req); if (!b.file) return err(res,400,'body.file required');
    const fi = b.funcIdx !== undefined ? parseInt(b.funcIdx,10) : 0;
    withFile(res, b.file, bin => { bin.functions(); send(res,200,{output:bin.emulate(fi,b.initRegs||{})}); });
}
async function handleSaveDaxc(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.output) return err(res,400,'body.file + body.output required');
    withFile(res, b.file, bin => { const ok = bin.saveDaxc(path.resolve(b.output)); send(res,200,{ok}); });
}
async function handleComment(req, res) {
    const b = await parseBody(req);
    if (!b.file || !b.address || !b.text) return err(res,400,'body.file + body.address + body.text required');
    withFile(res, b.file, bin => { bin.addComment(BigInt(b.address), b.text); send(res,200,{ok:true}); });
}

const server = http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') {
        res.writeHead(204, {'Access-Control-Allow-Origin':'*','Access-Control-Allow-Methods':'GET, POST, OPTIONS','Access-Control-Allow-Headers':'Content-Type'});
        return res.end();
    }
    if (req.method === 'GET' && (req.url === '/ui' || req.url === '/ui/')) {
        try {
            const html = fs.readFileSync(UI_PATH, 'utf8');
            const patched = html.replace("window.NEODAX_API_URL || 'http://localhost:7070'", `'http://localhost:${PORT}'`);
            res.writeHead(200, {'Content-Type':'text/html; charset=utf-8'});
            return res.end(patched);
        } catch (e) {
            return err(res, 500, `UI not found: ${e.message}`);
        }
    }
    const key = `${req.method} ${req.url.split('?')[0]}`;
    const handler = ROUTES[key];
    if (!handler) return err(res, 404, `No route: ${key}`);
    try {
        await handler(req, res);
    } catch (e) {
        const msg = (e && e.message) ? e.message : String(e);
        console.error(`  [!] request error on ${key} — ${msg}`);
        try { err(res, 500, msg); } catch (_) { /* already sent */ }
    }
});

server.listen(PORT, HOST, () => {
    let v = '1.1.1';
    try { v = neodax.version(); } catch (_) { /* version() should never fail, but guard anyway */ }
    console.log(`\n  NeoDAX API Server v${v}  →  http://localhost:${PORT}/ui\n`);
    const groups = [
        ['Core',        ['info','sections','symbols','functions','xrefs','xrefs-to','xrefs-from','blocks','unicode','strings','sym-at','func-at','section-at','read-bytes','hottest']],
        ['Disasm',      ['disasm','disasm/json','disasm/func','disasm/range']],
        ['Analysis',    ['analyze','entropy','rda','ivf']],
        ['CFG/Graphs',  ['cfg','cfg/json','callgraph','callgraph/json','loops','switch-detect']],
        ['Obfuscation', ['poly','poly/json','aire','aire/json','vm-trace','obfuscation-score','vm-detect']],
        ['Advanced',    ['symexec','ssa','decompile','emulate']],
        ['Snapshot',    ['save-daxc','comment']],
    ];
    for (const [g, routes] of groups) {
        console.log(`  ${g}`);
        for (const r of routes) console.log(`    POST /api/${r}`);
        console.log('');
    }
});
