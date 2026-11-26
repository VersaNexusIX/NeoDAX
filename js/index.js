'use strict';

const path = require('path');
const fs   = require('fs');

function _findAddon() {
    const local = path.join(__dirname, 'neodax.node');
    if (fs.existsSync(local)) return local;

    const platform = process.platform === 'linux'  ? 'linux'  :
                     process.platform === 'darwin'  ? 'darwin' : process.platform;
    const arch     = process.arch === 'x64'   ? 'x64'   :
                     process.arch === 'arm64' ? 'arm64' : process.arch;
    const prebuilt = path.join(__dirname, 'prebuilds', `neodax-${platform}-${arch}.node`);
    if (fs.existsSync(prebuilt)) return prebuilt;

    throw new Error(
        `NeoDAX native addon not found.\n\n` +
        `  Checked:\n    ${local}\n    ${prebuilt}\n\n` +
        `  Build it:\n    cd ${path.join(__dirname, '..')} && make js\n` +
        `  Or:  npm run build\n`
    );
}

const ADDON_PATH = _findAddon();
const N = require(ADDON_PATH);

function _bigint(v)  { return typeof v === 'bigint' ? v : BigInt(v); }
function _num(v)     { return typeof v === 'number'  ? v : Number(v); }

class NeoDAXBinary {
    #h; #info; #closed = false;

    constructor(handle) {
        this.#h    = handle;
        this.#info = handle.info;
    }

    
    get info()       { return this.#info; }
    get arch()       { return this.#info.arch; }
    get format()     { return this.#info.format; }
    get os()         { return this.#info.os; }
    get entry()      { return this.#info.entry; }
    get base()       { return this.#info.base; }
    get sha256()     { return this.#info.sha256; }
    get buildId()    { return this.#info.buildId; }
    get isPie()      { return this.#info.isPie; }
    get isStripped() { return this.#info.isStripped; }
    get hasDebug()   { return this.#info.hasDebug; }
    get file()       { return this.#info.file; }
    get loadTimeMs() { return this.#h.loadTimeMs || 0; }

    #c() { if (this.#closed) throw new Error('NeoDAXBinary: already closed'); }


    /* ── core structures ── */
    sections()                          { this.#c(); return N.sections(this.#h); }
    symbols()                           { this.#c(); return N.symbols(this.#h); }
    functions()                         { this.#c(); return N.functions(this.#h); }
    xrefs()                             { this.#c(); return N.xrefs(this.#h); }
    xrefsTo(addr)                       { this.#c(); return N.xrefsTo(this.#h, _bigint(addr)); }
    xrefsFrom(addr)                     { this.#c(); return N.xrefsFrom(this.#h, _bigint(addr)); }
    blocks()                            { this.#c(); return N.blocks(this.#h); }
    unicodeStrings()                    { this.#c(); return N.unicodeStrings(this.#h); }
    strings()                           { this.#c(); return N.strings(this.#h); }
    symAt(addr)                         { this.#c(); return N.symAt(this.#h, _bigint(addr)); }
    funcAt(addr)                        { this.#c(); return N.funcAt(this.#h, _bigint(addr)); }
    sectionByName(name)                 { this.#c(); return N.sectionByName(this.#h, name); }
    sectionAt(addr)                     { this.#c(); return N.sectionAt(this.#h, _bigint(addr)); }
    readBytes(addr, len)                { this.#c(); return N.readBytes(this.#h, _bigint(addr), _num(len)); }
    hottestFunctions(n = 20)            { this.#c(); return N.hottestFunctions(this.#h, _num(n)); }

    /* ── disassembly ── */
    disasm(section = '.text')           { this.#c(); return N.disasm(this.#h, section); }
    disasmRange(addr, nInsns = 32)      { this.#c(); return N.disasmRange(this.#h, _bigint(addr), _num(nInsns)); }
    disasmJson(section = '.text', opts = {}) { this.#c(); return N.disasmJson(this.#h, section, opts); }
    disasmFunc(funcIdx = 0)             { this.#c(); return N.disasmFunc(this.#h, _num(funcIdx)); }

    /* ── full analysis ── */
    analyze()                           { this.#c(); return N.analyze(this.#h); }

    /* ── CFG / graphs ── */
    cfg(funcIdx = 0)                    { this.#c(); return N.cfg(this.#h, _num(funcIdx)); }
    cfgJson(funcIdx = 0)                { this.#c(); return N.cfgJson(this.#h, _num(funcIdx)); }
    loops(funcIdx = -1)                 { this.#c(); return N.loops(this.#h, _num(funcIdx)); }
    callgraph()                         { this.#c(); return N.callgraph(this.#h); }
    callgraphJson()                     { this.#c(); return N.callgraphJson(this.#h); }
    switchDetect(section = '.text')     { this.#c(); return N.switchDetect(this.#h, section); }

    /* ── obfuscation ── */
    poly()                              { this.#c(); return N.poly(this.#h); }
    polyJson()                          { this.#c(); return N.polyJson(this.#h); }
    aire()                              { this.#c(); return N.aire(this.#h); }
    aireJson()                          { this.#c(); return N.aireJson(this.#h); }
    vmTrace()                           { this.#c(); return N.vmTrace(this.#h); }
    obfuscationScore()                  { this.#c(); return N.obfuscationScore(this.#h); }
    vmDetect()                          { this.#c(); return N.vmDetect(this.#h); }

    /* ── advanced analysis ── */
    symexec(funcIdx = -1)               { this.#c(); return N.symexec(this.#h, _num(funcIdx)); }
    ssa(funcIdx = -1)                   { this.#c(); return N.ssa(this.#h, _num(funcIdx)); }
    decompile(funcIdx = -1)             { this.#c(); return N.decompile(this.#h, _num(funcIdx)); }

    /* ── emulation ── */
    emulate(funcIdx = 0, initRegs = {}) {
        this.#c();
        return N.emulate(this.#h, _num(funcIdx), initRegs);
    }
    emulateByName(name, initRegs = {}) {
        this.#c();
        const fns = N.functions(this.#h);
        const idx = fns.findIndex(f => f.name === name || f.name === `sub_${name}`);
        if (idx < 0) throw new Error(`Function '${name}' not found`);
        return N.emulate(this.#h, idx, initRegs);
    }
    emulateAt(addr, initRegs = {}) {
        this.#c();
        const fns = N.functions(this.#h);
        const a   = _bigint(addr);
        const idx = fns.findIndex(f => f.start === a);
        if (idx < 0) throw new Error(`No function at 0x${a.toString(16)}`);
        return N.emulate(this.#h, idx, initRegs);
    }

    /* ── entropy / scan ── */
    entropy()                           { this.#c(); return N.entropy(this.#h); }
    rda(section = '.text')              { this.#c(); return N.rda(this.#h, section); }
    ivf()                               { this.#c(); return N.ivf(this.#h); }

    /* ── snapshot / annotations ── */
    saveDaxc(outPath)                   { this.#c(); return N.saveDaxc(this.#h, outPath); }
    addComment(addr, text)              { this.#c(); return N.addComment(this.#h, _bigint(addr), text); }

    
    close()            { if (!this.#closed) { N.close(this.#h._handle); this.#closed = true; } }
    [Symbol.dispose]() { this.close(); }

    toString() {
        return `NeoDAXBinary { file: '${this.file}', arch: '${this.arch}', `+
               `format: '${this.format}', functions: ${this.#info.nfunctions} }`;
    }
}

function load(filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) throw new Error(`File not found: ${resolved}`);
    return new NeoDAXBinary(N.load(resolved));
}

function version() { return N.version(); }

function withBinary(filePath, cb) {
    const bin = load(filePath);
    try     { return cb(bin); }
    finally { bin.close(); }
}

async function withBinaryAsync(filePath, cb) {
    const bin = load(filePath);
    try     { return await cb(bin); }
    finally { bin.close(); }
}

module.exports = { load, version, withBinary, withBinaryAsync, NeoDAXBinary };
