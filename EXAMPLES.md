# Usage Examples

Common recipes for using NeoDAX from the CLI, JavaScript API, and REST server.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## CLI Recipes

### Analyze a stripped Android binary

```bash
./neodax -x -u ./libsomething.so
```

### Find all functions in a binary

```bash
./neodax -f -y ./binary | grep "│ \[" 
```

### Check if a binary is packed or encrypted

```bash
./neodax -e ./binary | grep -E "PACKED|HIGH ENTROPY"
```

### Find dead code after jump tricks

```bash
./neodax -R ./binary | grep "DEAD:"
```

### Find privileged instructions in a userspace binary

```bash
./neodax -V ./binary | grep PRIV
```

### Decompile an ARM64 binary to pseudo-C

```bash
./neodax -f -D ./arm64_binary
```

### Emulate function 0 and see register state

```bash
./neodax -f -I ./arm64_binary
```

### Extract all Unicode strings

```bash
./neodax -u -n ./binary | grep -v "^$\|Encoding\|─\|═\|Address"
```

### Full analysis, save to file, no color

```bash
./neodax -X -n ./binary > report.txt 2>&1
```

### Save analysis snapshot and reload later

```bash
./neodax -x -o snap.daxc ./binary
./neodax -c snap.daxc > annotated.S
```

### Analyze a specific address range

```bash
./neodax -A 0x4000 -E 0x4200 -g ./binary
```

### Compare two versions of a binary

```bash
./neodax -f -n ./binary_v1 > v1.txt
./neodax -f -n ./binary_v2 > v2.txt
diff v1.txt v2.txt
```

---

## JavaScript Recipes

### Get a quick summary of any binary

```js
const neodax = require('neodax');

neodax.withBinary(process.argv[2], bin => {
    const { info } = bin;
    console.log(`File:     ${info.file}`);
    console.log(`Format:   ${info.format}  Arch: ${info.arch}`);
    console.log(`SHA-256:  ${info.sha256}`);
    console.log(`PIE: ${info.isPie}  Stripped: ${info.isStripped}`);
    console.log(`Sections: ${bin.sections().length}`);
    console.log(`Functions: ${bin.functions().length}`);
    console.log(`Xrefs:    ${bin.xrefs().length}`);
});
```

### Find all functions larger than 1KB

```js
neodax.withBinary('./binary', bin => {
    const big = bin.functions()
        .filter(f => Number(f.size) > 1024)
        .sort((a, b) => Number(b.size) - Number(a.size));
    big.forEach(f => console.log(`${f.name}  ${Number(f.size)} bytes`));
});
```

### Scan for suspicious patterns (packed, invalid, dead code)

```js
neodax.withBinary('./binary', bin => {
    const ent = bin.entropy();
    const ivf = bin.ivf();

    const isPacked  = ent.includes('PACKED');
    const hasInvalid = ivf.includes('INVALID');
    const hasDead    = ivf.includes('DEAD');
    const hasPriv    = ivf.includes('PRIV');

    console.log({ isPacked, hasInvalid, hasDead, hasPriv });
});
```

### Get all cross-references to a specific function

```js
neodax.withBinary('./binary', bin => {
    const fns = bin.functions();
    const target = fns.find(f => f.name.includes('decrypt'));
    if (!target) return console.log('not found');

    const callers = bin.xrefsTo(target.start);
    callers.forEach(x => console.log(`called from: ${x.from}`));
});
```

### Read the first 16 bytes at the entry point

```js
neodax.withBinary('./binary', bin => {
    const bytes = bin.readBytes(bin.entry, 16);
    console.log(Array.from(bytes).map(b => b.toString(16).padStart(2,'0')).join(' '));
});
```

### Symbolic execution — trace register flow through a function

```js
neodax.withBinary('./arm64_binary', bin => {
    const fns = bin.functions();
    // Find 'tricky' or take function index 0
    const idx = fns.findIndex(f => f.name.includes('tricky')) ?? 0;
    console.log(bin.symexec(idx));
});
```

### Decompile a function by name

```js
neodax.withBinary('./arm64_binary', bin => {
    const fns = bin.functions();
    const idx = fns.findIndex(f => f.name === 'chaos');
    if (idx === -1) return console.log('function not found');
    console.log(bin.decompile(idx));
});
```

### Emulate ARM64 function with specific input

```js
neodax.withBinary('./arm64_binary', bin => {
    // Emulate function 0 with x0=1337, x1=42
    const trace = bin.emulate(0, { '0': 1337n, '1': 42n });
    console.log(trace);
    // Look for the return value line
    const retLine = trace.split('\n').find(l => l.includes('ret'));
    console.log('Return:', retLine);
});
```

### Batch analysis — scan a directory

```js
const neodax = require('neodax');
const fs     = require('fs');
const path   = require('path');

const dir    = process.argv[2] || '.';
const files  = fs.readdirSync(dir).filter(f => {
    const full = path.join(dir, f);
    try {
        const buf = Buffer.allocUnsafe(4);
        const fd  = fs.openSync(full, 'r');
        fs.readSync(fd, buf, 0, 4, 0);
        fs.closeSync(fd);
        // ELF magic
        return buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46;
    } catch (_) { return false; }
});

for (const f of files) {
    try {
        neodax.withBinary(path.join(dir, f), bin => {
            const isPacked = bin.entropy().includes('PACKED');
            console.log(`${f.padEnd(30)} ${bin.arch.padEnd(15)} packed=${isPacked}`);
        });
    } catch (e) {
        console.log(`${f.padEnd(30)} ERROR: ${e.message}`);
    }
}
```

---

## Express.js Backend Integration

See [NPM_USAGE.md](NPM_USAGE.md) for a complete Express.js example with analyze, disasm, entropy, and decompile endpoints.

---

## REST API Recipes

```bash
# Start the server
node js/server/server.js

# Binary info
curl -s -X POST http://localhost:7070/api/info \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls"}' | jq '{arch,format,sha256,isPie}'

# List functions
curl -s -X POST http://localhost:7070/api/functions \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls"}' | jq '.functions | length'

# Structured disassembly — first 20 instructions
curl -s -X POST http://localhost:7070/api/disasm/json \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls","section":".text","limit":20}' \
  | jq '.instructions[] | "\(.address) \(.mnemonic) \(.operands)"'

# Entropy analysis
curl -s -X POST http://localhost:7070/api/entropy \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls"}' | jq '.output'

# Decompile function 0
curl -s -X POST http://localhost:7070/api/decompile \
  -H 'Content-Type: application/json' \
  -d '{"file":"/path/to/arm64_binary","funcIdx":0}' | jq '.output'

# Hottest functions (top 5)
curl -s -X POST http://localhost:7070/api/hottest \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls","n":5}' \
  | jq '.hottest[] | "\(.callCount)x \(.function.name)"'

# Read bytes at entry point
curl -s -X POST http://localhost:7070/api/read-bytes \
  -H 'Content-Type: application/json' \
  -d '{"file":"/bin/ls","address":"0x401060","length":8}' | jq '.bytes'
```
