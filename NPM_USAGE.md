# Using NeoDAX in a Backend Project

This guide explains how to add NeoDAX as an npm dependency in any Node.js backend project — **no manual compilation needed**.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## How It Works

NeoDAX is a **native Node.js addon** (`.node` file). The `npm install` process automatically compiles the C source into a platform-specific binary. No separate build step required on the consumer side.

```
npm install neodax
        ↓
  postinstall script runs
        ↓
  checks for prebuilt binary (prebuilds/<platform>-<arch>.node)
        ↓  if not found:
  compiles from source using clang/gcc + Node headers
        ↓
  neodax.node ready
```

---

## Installation

```bash
npm install neodax
# or
yarn add neodax
# or
pnpm add neodax
```

**Requirements for compilation (if no prebuild):**
- C compiler: `clang` or `gcc`
- Node.js dev headers (usually bundled with Node)
- `make` (optional — installer falls back to direct compile)

**Termux/Android:**
```bash
pkg install nodejs clang
npm install neodax
```

---

## Basic Usage

```js
const neodax = require('neodax');

// One-liner with auto-close
neodax.withBinary('/path/to/binary', bin => {
    console.log(bin.arch);          // 'AArch64 (ARM64)'
    console.log(bin.sha256);        // 'a3f8bc...'
    console.log(bin.isPie);         // true

    const fns  = bin.functions();   // detected functions
    const syms = bin.symbols();     // symbol table
    const xr   = bin.xrefs();       // cross-references

    console.log(fns.length, 'functions,', syms.length, 'symbols');
});
```

---

## Express.js Backend Example

```bash
mkdir my-re-backend && cd my-re-backend
npm init -y
npm install express neodax
```

```js
// app.js
const express = require('express');
const neodax  = require('neodax');
const path    = require('path');

const app = express();
app.use(express.json());

// POST /analyze — analyze an uploaded binary path
app.post('/analyze', async (req, res) => {
    const { file } = req.body;
    if (!file) return res.status(400).json({ error: 'body.file required' });

    try {
        const result = neodax.withBinary(file, bin => ({
            arch:       bin.arch,
            format:     bin.format,
            sha256:     bin.sha256,
            isPie:      bin.isPie,
            isStripped: bin.isStripped,
            entry:      String(bin.entry),
            functions:  bin.functions().length,
            symbols:    bin.symbols().length,
            xrefs:      bin.xrefs().length,
            sections:   bin.sections().map(s => ({
                name: s.name,
                type: s.type,
                size: String(s.size),
            })),
        }));
        res.json(result);
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /disasm — disassemble a section
app.post('/disasm', (req, res) => {
    const { file, section = '.text', limit = 200 } = req.body;
    if (!file) return res.status(400).json({ error: 'body.file required' });

    try {
        const insns = neodax.withBinary(file, bin =>
            bin.disasmJson(section, { limit: parseInt(limit, 10) })
               .map(i => ({
                   address:  String(i.address),
                   mnemonic: i.mnemonic,
                   operands: i.operands,
                   group:    i.group,
                   symbol:   i.symbol,
               }))
        );
        res.json({ section, count: insns.length, instructions: insns });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /entropy — entropy scan
app.post('/entropy', (req, res) => {
    const { file } = req.body;
    if (!file) return res.status(400).json({ error: 'body.file required' });
    try {
        const output = neodax.withBinary(file, bin => bin.entropy());
        res.json({ output });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

// POST /decompile — decompile a function by index
app.post('/decompile', (req, res) => {
    const { file, funcIdx = 0 } = req.body;
    if (!file) return res.status(400).json({ error: 'body.file required' });
    try {
        const output = neodax.withBinary(file, bin =>
            bin.decompile(parseInt(funcIdx, 10))
        );
        res.json({ output });
    } catch (e) {
        res.status(500).json({ error: e.message });
    }
});

app.listen(3000, () => console.log('RE backend running on :3000'));
```

```bash
node app.js

# Test
curl -s -X POST http://localhost:3000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls"}' | jq .
```

---

## Fastify Backend Example

```bash
npm install fastify neodax
```

```js
// server.js
const Fastify = require('fastify');
const neodax  = require('neodax');

const app = Fastify({ logger: true });

app.post('/api/info', async (req) => {
    const { file } = req.body;
    return neodax.withBinary(file, bin => bin.info);
});

app.post('/api/functions', async (req) => {
    const { file } = req.body;
    return neodax.withBinary(file, bin => ({
        functions: bin.functions().map(f => ({
            name:       f.name,
            start:      String(f.start),
            size:       String(f.size),
            insnCount:  f.insnCount,
            hasCalls:   f.hasCalls,
            hasLoops:   f.hasLoops,
        }))
    }));
});

app.post('/api/full', async (req) => {
    const { file } = req.body;
    // Full analysis pipeline — symbols, funcs, xrefs, CFG, unicode
    return neodax.withBinary(file, bin => {
        const r = bin.analyze();
        return {
            info:      r.info,
            functions: r.functions.length,
            xrefs:     r.xrefs.length,
            blocks:    r.blocks.length,
            timing:    r.analysisTimeMs,
        };
    });
});

app.listen({ port: 3000 }, err => {
    if (err) { app.log.error(err); process.exit(1); }
});
```

---

## TypeScript Example

```bash
npm install neodax
# TypeScript declarations are bundled — no @types/neodax needed
```

```ts
// analyze.ts
import { withBinary, BinaryInfo, Function, Section } from 'neodax';

interface AnalysisReport {
    info:      BinaryInfo;
    topFuncs:  Function[];
    sections:  Section[];
}

export function analyzeFile(filePath: string): AnalysisReport {
    return withBinary(filePath, bin => ({
        info:     bin.info,
        topFuncs: bin.hottestFunctions(10).map(h => h.function),
        sections: bin.sections(),
    }));
}

// Async version
export async function analyzeAsync(filePath: string) {
    const { withBinaryAsync } = await import('neodax');
    return withBinaryAsync(filePath, async bin => {
        const r = bin.analyze();
        return {
            sha256:    r.info.sha256,
            functions: r.functions.length,
            isPacked:  bin.entropy().includes('PACKED'),
        };
    });
}
```

---

## Advanced: Long-running Analysis Service

For a server that analyzes many binaries, reuse binary handles to avoid repeated parsing:

```js
const neodax = require('neodax');

// Cache parsed binaries keyed by SHA-256
const cache = new Map();

function getOrLoad(filePath) {
    const bin = neodax.load(filePath);
    const key = bin.sha256;
    if (cache.has(key)) {
        bin.close(); // close the duplicate
        return cache.get(key);
    }
    cache.set(key, bin);
    return bin;
}

// Clean up on process exit
process.on('exit',    () => cache.forEach(b => b.close()));
process.on('SIGINT',  () => { cache.forEach(b => b.close()); process.exit(0); });
process.on('SIGTERM', () => { cache.forEach(b => b.close()); process.exit(0); });
```

---

## Handling BigInt in JSON Responses

NeoDAX uses `bigint` for all addresses. JSON.stringify doesn't handle bigint natively. Two options:

```js
// Option 1: Convert to hex strings before sending
const insns = bin.disasmJson('.text', { limit: 100 }).map(i => ({
    ...i,
    address: `0x${i.address.toString(16)}`,
}));

// Option 2: Custom JSON replacer
const replacer = (_, v) => typeof v === 'bigint' ? `0x${v.toString(16)}` : v;
res.json(JSON.parse(JSON.stringify(data, replacer)));

// Option 3: Use the built-in REST server (handles bigint automatically)
// node node_modules/neodax/server/server.js
// → http://localhost:7070
```

---

## Built-in REST Server (zero extra code)

NeoDAX ships its own REST server with 26 endpoints and a web UI:

```bash
# Start from node_modules
node node_modules/neodax/server/server.js

# Custom port
PORT=8080 node node_modules/neodax/server/server.js

# Programmatic start
const { createServer } = require('neodax/server/server');
createServer({ port: 8080 });
```

All endpoints: `POST /api/<name>` with `{ "file": "/absolute/path" }` — see `js/README.md` for the full list.

Web UI: `http://localhost:7070/ui`

---

## API Surface (quick reference)

```js
const neodax = require('neodax');

// Module-level
neodax.load(path)                    // → NeoDAXBinary
neodax.version()                     // → '1.0.0'
neodax.withBinary(path, cb)         // → T  (auto-close)
neodax.withBinaryAsync(path, cb)    // → Promise<T>

// NeoDAXBinary properties
bin.arch / .format / .os / .entry / .sha256 / .isPie / .isStripped / .hasDebug

// Analysis
bin.sections()           bin.symbols()           bin.functions()
bin.xrefs()              bin.xrefsTo(addr)       bin.xrefsFrom(addr)
bin.blocks()             bin.unicodeStrings()    bin.strings()
bin.hottest(n)           bin.analyze()

// Lookup
bin.symAt(addr)          bin.funcAt(addr)
bin.sectionByName(name)  bin.sectionAt(addr)
bin.readBytes(addr, len)

// Disassembly
bin.disasm(section?)
bin.disasmJson(section?, { limit, offset })

// Advanced (ARM64)
bin.symexec(funcIdx?)    bin.ssa(funcIdx?)
bin.decompile(funcIdx?)  bin.emulate(funcIdx?, initRegs?)

// Detection
bin.entropy()            bin.rda(section?)       bin.ivf()

// Formats: ELF32/64 · PE32/PE64+ · Mach-O 64/FAT · Raw

// Lifecycle
bin.close()
```
