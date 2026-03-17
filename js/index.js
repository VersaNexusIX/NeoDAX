'use strict';

const path = require('path');
const fs   = require('fs');

function _findAddon() {
    const local = path.join(__dirname, 'neodax.node');
    if (fs.existsSync(local)) return local;

    // Try prebuilt binary
    const platform = process.platform === 'linux'  ? 'linux'  :
                     process.platform === 'darwin'  ? 'darwin' : process.platform;
    const arch     = process.arch === 'x64'   ? 'x64'   :
                     process.arch === 'arm64' ? 'arm64' : process.arch;
    const prebuilt = path.join(__dirname, 'prebuilds', `neodax-${platform}-${arch}.node`);
    if (fs.existsSync(prebuilt)) return prebuilt;

    throw new Error(
        `NeoDAX native addon not found.\n\n` +
        `  Checked:\n` +
        `    ${local}\n` +
        `    ${prebuilt}\n\n` +
        `  Build it first:\n` +
        `    cd ${path.join(__dirname, '..')} && make js\n` +
        `  Or inside the js/ dir:\n` +
        `    npm run build\n`
    );
}

const ADDON_PATH = _findAddon();
const N = require(ADDON_PATH);

class NeoDAXBinary {
    #h; #info; #closed = false;

    constructor(handle) { this.#h = handle; this.#info = handle.info; }

    get info()       { return this.#info; }
    get arch()       { return this.#info.arch; }
    get format()     { return this.#info.format; }
    get os()         { return this.#info.os; }
    get entry()      { return this.#info.entry; }
    get sha256()     { return this.#info.sha256; }
    get buildId()    { return this.#info.buildId; }
    get isPie()      { return this.#info.isPie; }
    get isStripped() { return this.#info.isStripped; }
    get hasDebug()   { return this.#info.hasDebug; }
    get file()       { return this.#info.file; }
    get loadTimeMs() { return this.#h.loadTimeMs || 0; }

    #c() { if (this.#closed) throw new Error('NeoDAXBinary: closed'); }

    sections()            { this.#c(); return N.sections(this.#h); }
    symbols()             { this.#c(); return N.symbols(this.#h); }
    functions()           { this.#c(); return N.functions(this.#h); }
    xrefs()               { this.#c(); return N.xrefs(this.#h); }
    xrefsTo(addr)         { this.#c(); return N.xrefsTo(this.#h, _bigint(addr)); }
    xrefsFrom(addr)       { this.#c(); return N.xrefsFrom(this.#h, _bigint(addr)); }
    blocks()              { this.#c(); return N.blocks(this.#h); }
    unicodeStrings()      { this.#c(); return N.unicodeStrings(this.#h); }
    strings()             { this.#c(); return N.strings(this.#h); }
    symAt(addr)           { this.#c(); return N.symAt(this.#h, _bigint(addr)); }
    funcAt(addr)          { this.#c(); return N.funcAt(this.#h, _bigint(addr)); }
    sectionByName(name)   { this.#c(); return N.sectionByName(this.#h, name); }
    sectionAt(addr)       { this.#c(); return N.sectionAt(this.#h, _bigint(addr)); }
    readBytes(addr, len)  { this.#c(); return N.readBytes(this.#h, _bigint(addr), len); }
    hottestFunctions(n=20){ this.#c(); return N.hottestFunctions(this.#h, n); }

    disasm(section = '.text')          { this.#c(); return N.disasm(this.#h, section); }
    disasmJson(section = '.text', opts = {}) { this.#c(); return N.disasmJson(this.#h, section, opts); }

    analyze() { this.#c(); return N.analyze(this.#h); }

    symexec(funcIdx = -1)   { this.#c(); return N.symexec(this.#h, funcIdx); }
    ssa(funcIdx = -1)        { this.#c(); return N.ssa(this.#h, funcIdx); }
    decompile(funcIdx = -1)  { this.#c(); return N.decompile(this.#h, funcIdx); }
    emulate(funcIdx = 0, initRegs = {}) { this.#c(); return N.emulate(this.#h, funcIdx, initRegs); }

    entropy()              { this.#c(); return N.entropy(this.#h); }
    rda(section = '.text') { this.#c(); return N.rda(this.#h, section); }
    ivf()                  { this.#c(); return N.ivf(this.#h); }

    close() { if (!this.#closed) { N.close(this.#h._handle); this.#closed = true; } }
    [Symbol.dispose]() { this.close(); }
}

function _bigint(v) { return typeof v === 'bigint' ? v : BigInt(v); }

function load(filePath) {
    const resolved = path.resolve(filePath);
    if (!fs.existsSync(resolved)) throw new Error(`File not found: ${resolved}`);
    return new NeoDAXBinary(N.load(resolved));
}

function version() { return N.version(); }

function withBinary(filePath, cb) {
    const bin = load(filePath);
    try { return cb(bin); } finally { bin.close(); }
}

async function withBinaryAsync(filePath, cb) {
    const bin = load(filePath);
    try { return await cb(bin); } finally { bin.close(); }
}

module.exports = { load, version, withBinary, withBinaryAsync, NeoDAXBinary };
