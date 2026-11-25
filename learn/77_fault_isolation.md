# Fault Isolation — How NeoDAX Handles Bad Binaries

**Level:** 7 - Integration and Automation  
**Prerequisites:** 76_building_plugins.md  
**What You Will Learn:** How NeoDAX's microkernel-style fault isolation protects analysis sessions from crashing on malformed or adversarial binaries, and how to use this when building tools on top of NeoDAX.

## The Problem

Binary analysis tools deal with untrusted input by definition. Malformed ELF headers, truncated section data, corrupt symbol tables, and deliberately adversarial encodings are routine. Without protection, a single bad section can crash the entire analysis session — losing all results computed so far.

## The Solution: Independent Passes

NeoDAX uses a fault isolation model inspired by microkernel design. Each of the 32 analysis passes in the pipeline runs as an independent service. If one pass encounters a structural error:

1. It records a fault message via `dax_fault_set()`
2. It returns early — no crash
3. The pipeline prints a recovery notice on stderr
4. The next pass runs normally

This means a binary with a corrupt `.symtab` and a valid `.text` section will still produce complete disassembly, CFG, and entropy output — only the symbol pass is skipped.

## What Recovery Looks Like

When a pass faults, you see this on stderr:

```
  [!] pass 'cfg-build' recovered from fault — func index out of bounds
```

The `[!]` marker is yellow in color mode. Analysis continues after this line. All passes that succeeded before and after the faulted one produce normal output.

This is expected behavior on malformed binaries — it is not a NeoDAX bug.

## The Three Layers

### Layer 1 — Input validation at every entry point

Every public function in NeoDAX starts by validating its inputs before touching any data. If the binary struct is NULL, has no data, has a zero size, or has a counter outside its legal range, the function records a fault and returns immediately.

```c
/* at the top of every analysis function */
DAX_GUARD_BIN(bin);          /* returns void if bin is bad */
DAX_GUARD_BIN_RET(bin, -1);  /* returns -1 if bin is bad */
```

### Layer 2 — Overflow-safe arithmetic

Every section offset calculation uses the subtraction form, which cannot overflow:

```c
/* safe — no overflow possible */
if (sec->size > bin->size - sec->offset) continue;

/* unsafe — could overflow when sec->offset is huge */
if (sec->offset + sec->size > bin->size) continue;
```

All loop bounds are clamped to their defined maximums:

```c
for (i = 0; i < bin->nfunctions && i < DAX_MAX_FUNCTIONS; i++) { ... }
```

### Layer 3 — Pass wrapper in `main.c`

Every top-level module call uses `DAX_RUN_PASS`:

```c
DAX_RUN_PASS("cfg-build", opts.color,
    dax_cfg_build(&bin, code, sz, base, fi));
```

This macro clears the global fault register, runs the call, then checks if the call set it. On fault, it emits the yellow `[!]` line and resets for the next pass.

## Testing Fault Recovery

You can verify fault isolation on any system:

```bash
# Truncated ELF header
echo -n $'\x7fELF' > /tmp/bad.elf
./neodax -X /tmp/bad.elf
# → prints recovery notices for each pass that can't proceed, then exits

# Random bytes
dd if=/dev/urandom bs=1024 count=1 of=/tmp/random.bin 2>/dev/null
./neodax -X /tmp/random.bin
# → some passes produce partial output, others print recovery notices

# Zero-filled file
dd if=/dev/zero bs=4096 count=1 of=/tmp/zeros.bin 2>/dev/null
./neodax /tmp/zeros.bin
# → loader rejects it cleanly, no crash
```

None of these should cause a segfault. If one does, it is a bug — report it via `SECURITY.md`.

## Counter Normalization

After each loader phase, NeoDAX calls `dax_clamp_counts()` to normalize all struct counters:

```c
dax_clamp_counts(&bin);
```

This clamps `nsections`, `nfunctions`, `nsymbols`, `nxrefs`, `nblocks`, and all other counters to their legal `DAX_MAX_*` upper bounds. A binary with a corrupt section count field (e.g. `nsections = 0xFFFFFFFF`) becomes `nsections = 128` after clamping — safe for all downstream loops.

## Decode Loop Budgets

Decode loops that iterate over function bytes have a built-in budget:

```c
DAX_BUDGET_INIT(65536);       /* max 65536 instructions per function */
while (off < end) {
    DAX_BUDGET_CHECK();        /* breaks and sets fault if budget hits zero */
    /* ... decode ... */
}
```

A function containing a corrupt instruction stream that would otherwise spin forever is limited to 65536 iterations before the loop exits and the next function is tried.

## Using Fault Isolation in Your Own Tools

If you build tools on top of the NeoDAX C API, follow the same pattern.

### Include the guard header

```c
#include "dax.h"
#include "dax_guard.h"
```

### Guard every entry point

```c
void my_analyze(dax_binary_t *bin, int func_idx, FILE *out) {
    DAX_GUARD_BIN(bin);
    if (!out) return;
    if (!dax_func_idx_ok(bin, func_idx)) {
        dax_fault_set("my_analyze: func index out of bounds");
        return;
    }
    /* safe to proceed */
}
```

### Use safe accessors instead of raw array access

```c
/* instead of: bin->sections[si] (no bounds check) */
uint8_t *p = dax_sec_ptr(bin, si);
if (!p) { dax_fault_set("section not readable"); return; }

/* instead of: bin->functions[fi] */
dax_func_t *fn = dax_func_ptr(bin, fi);
if (!fn) return;
```

### Use overflow-safe section bounds

```c
for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
    dax_section_t *sec = &bin->sections[si];
    if (sec->size == 0) continue;
    if (sec->offset > bin->size) continue;
    if (sec->size > bin->size - sec->offset) continue;  /* overflow-safe */
    /* safe to use sec */
}
```

### Wrap your calls with `DAX_RUN_PASS`

If you are building a pipeline similar to `main.c`:

```c
DAX_RUN_PASS("my-pass", color, my_analyze(&bin, fi, stdout));
```

If `my_analyze` calls `dax_fault_set()`, the wrapper catches it and continues.

## Plugin Writers

If you write a NeoDAX plugin, the same rules apply. Plugins receive a live `dax_binary_t*` — always validate before accessing:

```c
static void on_load(dax_binary_t *bin, dax_opts_t *opts) {
    int si;
    if (!bin || !bin->data || bin->nsections <= 0) return;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (sec->size == 0 || sec->offset > bin->size) continue;
        if (sec->size > bin->size - sec->offset) continue;
        /* safe */
    }
}
```

A plugin that segfaults takes down the whole NeoDAX process — the fault isolation layer does not cross shared library boundaries.

## Global Fault Register

NeoDAX uses a single global fault register for pass-level coordination:

```c
extern volatile int g_dax_fault;     /* 1 = fault occurred */
extern char         g_dax_fault_msg[256]; /* brief reason */
```

`dax_fault_set("reason")` sets these. `DAX_RUN_PASS` clears and checks them. First caller wins — if two sub-functions fault in the same pass, the first message is preserved.

If you call NeoDAX functions directly (not through `DAX_RUN_PASS`), check `g_dax_fault` yourself after each call if you care about partial failures.

## What Does Not Protect You

Fault isolation covers structural errors in `dax_binary_t` data. It does not:

- Prevent crashes from bugs in NeoDAX's own code
- Protect against out-of-bounds writes (only reads are guarded at the structural level)
- Cross shared library boundaries (plugins are unprotected)
- Replace ASAN or sanitizers for thorough security testing

For production use with untrusted binaries, run NeoDAX inside a container or Termux sandbox regardless of fault isolation.

## Practice

1. Create a file containing only `\x7fELF` (truncated) and run `./neodax -X` on it. Count how many passes print recovery notices.
2. Create a Python script that generates 100 random 4 KB files and runs `./neodax` on each. Verify no segfaults occur.
3. Write a plugin with an unguarded `for (si = 0; si < bin->nsections; si++)` loop and load it against the truncated ELF. What happens? Then add `&& si < DAX_MAX_SECTIONS` and the `sec->size > bin->size - sec->offset` check and repeat.

## Next

Continue to `80_common_patterns_reference.md` to begin the Appendix.
