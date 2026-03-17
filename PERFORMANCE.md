# Performance Guide

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Typical Analysis Times

Measured on a mid-range ARM64 Android device (Termux), analyzing `/bin/ls` (~200 KB ELF, ~160 functions):

| Analysis | Flag | Time |
|---|---|---|
| Disassembly only | *(default)* | ~3 ms |
| Standard full | `-x` | ~12 ms |
| + Entropy | `-x -e` | ~15 ms |
| + Recursive descent | `-x -R` | ~25 ms |
| + Symbolic execution | `-x -P` | ~20 ms |
| + Decompile | `-x -D` | ~22 ms |
| + Emulate | `-x -I` | ~18 ms |
| Full everything | `-X` | ~40 ms |

For a 5 MB binary (~2000 functions): `-X` typically completes in 200–400 ms.

---

## Performance Characteristics by Module

### Loader (`loader.c`)
O(sections + symbols). Dominated by `mmap`/`read` — purely I/O bound. Scales linearly with file size.

### Xref Builder (`analysis.c` — `dax_xref_build`)
O(instructions). Single pass through all code sections. Very fast — typically < 2 ms even for large binaries.

### CFG Builder (`cfg.c`)
O(instructions × 2) for the two-pass algorithm. The pre-pass and main pass each walk instructions once. Block boundary lookup is linear scan O(nblocks) — could be O(log n) with a sorted array, but nblocks is typically < 8192.

### Entropy (`entropy.c`)
O(sections × size / step). For a 1 MB `.text` section with 64B step: ~15,000 window evaluations, each O(256). About 4 million byte-frequency counts total. Fast in practice.

### Recursive Descent (`entropy.c`)
O(reachable\_instructions × queue\_size). BFS with a visited set — each instruction decoded at most once. Dominates for large binaries with many functions.

### Symbolic Execution (`symexec.c`)
O(function\_instructions × pool\_depth). The expression pool is bounded at 1024 nodes per function. Fast for small functions, slower for functions with many nested operations.

### Emulator (`emulate.c`)
O(steps). Hard limit of 8192 instructions per function. Page allocation is O(npages) on first write — bounded at 64 pages.

---

## JS API Performance

The N-API boundary adds negligible overhead for large return values (arrays of structs are returned by value). The main cost is always the C-side analysis, not the JS/C boundary crossing.

**Repeated analysis on the same binary:**

`withBinary` opens and closes the binary on every call. For a service that analyzes the same binary multiple times, cache the loaded handle:

```js
const cache = new Map();

function getCached(filePath) {
    const bin = neodax.load(filePath);
    const key = bin.sha256;
    if (cache.has(key)) { bin.close(); return cache.get(key); }
    cache.set(key, bin);
    return bin;
}
```

This avoids re-parsing ELF headers, re-loading symbols, and re-building xrefs on every request.

---

## Memory Usage

| Component | Approximate |
|---|---|
| Base `dax_binary_t` struct | ~8 KB (stack/static fields) |
| Raw file data (`bin->data`) | = file size |
| Symbols array | `nsymbols × ~420 bytes` |
| Xrefs array | `nxrefs × 24 bytes` |
| Functions array | `nfunctions × ~180 bytes` |
| Blocks array | `nblocks × ~80 bytes` |
| Unicode strings | `nustrings × ~560 bytes` |

For `/bin/ls` (~200 KB): total heap ~3 MB including raw file data.

---

## Profiling

```bash
# Linux with perf
perf stat ./neodax -X /bin/ls

# Linux with valgrind callgrind
valgrind --tool=callgrind ./neodax -x /bin/ls
callgrind_annotate callgrind.out.*

# Time individual modules
time ./neodax -x /bin/ls > /dev/null
time ./neodax -x -R /bin/ls > /dev/null
```

---

## Known Bottlenecks

1. **Block boundary lookup in CFG** — `find_block_by_addr()` is O(n) linear scan. For binaries with > 8000 blocks this becomes noticeable. A hash map or sorted array with binary search would be O(1)/O(log n).

2. **Recursive descent visited set** — `rda_is_visited()` is O(n) linear scan over up to 65536 entries. A hash set would reduce this to O(1).

3. **Large `.dynstr` UTF-16LE scan** — The unicode scanner skips known bad sections, but for binaries with many rodata sections the scan is still O(section_size). Pre-filtering by section type reduces this significantly for most binaries.

These are tracked for improvement in future releases.
