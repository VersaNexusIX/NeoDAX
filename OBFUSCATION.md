# Analyzing Obfuscated Binaries

Practical guide for using NeoDAX against packed, obfuscated, and anti-analysis binaries.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Detecting Obfuscation

### Step 1 — Entropy scan

The first thing to run on any unknown binary:

```bash
./neodax -e ./binary
```

**What to look for:**

| Output | Interpretation |
|--------|---------------|
| `.text` entropy ≥ 7.0 | Section is packed or encrypted — code cannot be analyzed directly |
| `.data` entropy ≥ 7.0 | Encrypted payload likely stored in data section |
| `.text` entropy 5.5–6.8 | Normal for ARM64; slightly elevated for x86-64 — probably fine |
| Multiple sections PACKED | Full packer (UPX, custom) |
| Only one region HIGH | Partial obfuscation or obfuscated function stub |

### Step 2 — Instruction validity filter

```bash
./neodax -V ./binary
```

**Findings and their meaning:**

| Finding | Meaning |
|---------|---------|
| `INVALID` at many addresses | Jump-trick dead bytes, data embedded in `.text`, or truly invalid code |
| `PRIV` (privileged in userspace) | Anti-debug trick or code not meant for CPU execution |
| `DEAD` (bytes after unconditional branch) | Jump tricks — intentional dead bytes to mislead disassemblers |
| `NOP-RUN` (≥ 8 consecutive NOPs) | Alignment padding, or NOP sled (anti-disassembly / shellcode) |
| `INT3-RUN` (≥ 3 consecutive INT3) | Anti-debugging breakpoint spray |

### Step 3 — Recursive descent

```bash
./neodax -R ./binary
```

Shows `[DEAD: 0xstart .. 0xend]` regions that a linear scan would misinterpret as code. High dead-byte percentage indicates heavy obfuscation.

### Step 4 — CFG analysis

```bash
./neodax -C ./binary
```

NeoDAX's two-pass CFG builder correctly handles jump tricks. If a function has an unusually large number of small blocks connected by unconditional branches, this often indicates control-flow flattening obfuscation.

---

## Jump Tricks

Jump tricks insert dead bytes between an unconditional branch and its target:

```asm
b  target          ; real jump
.byte 0xde,0xad    ; dead bytes — linear disassembler tries to decode these
.byte 0xbe,0xef    ; as instructions → garbage output
target:
add  w0, w0, #7    ; real code here
```

**NeoDAX handling:**  
The two-pass CFG builder pre-registers `target` as a block boundary during Pass 1. In Pass 2, after the unconditional `b`, it scans forward to the nearest pre-registered boundary and resumes decoding there. The dead bytes are silently skipped.

You can see this in the output — gaps in the disassembly listing where dead bytes were skipped, and in the IVF output as `DEAD` findings.

---

## Opaque Predicates

Opaque predicates are conditional branches that always take the same direction:

```asm
mov  w8, #0
cmp  w8, #0
b.ne dead_code    ; always NOT taken — w8 is always 0
; real code continues here
dead_code:
.byte 0xff,0xff,0xff,0xff
```

NeoDAX treats both sides of a conditional branch as reachable — it cannot statically determine that the predicate is opaque without concrete input. However:
- The IVF filter will flag the dead branch target as INVALID if it contains invalid bytes
- The entropy analysis will show the dead code region as low-density
- Use `-I` (emulate) with known input to concretely determine which path is taken

---

## Control-Flow Flattening

CFF replaces a function's natural control flow with a dispatcher loop:

```c
// Original
if (a > 0) { doA(); } else { doB(); }

// CFF transformed
state = INITIAL;
while (1) {
    switch (state) {
        case INITIAL: state = (a > 0) ? STATE_A : STATE_B; break;
        case STATE_A: doA(); state = EXIT; break;
        case STATE_B: doB(); state = EXIT; break;
        case EXIT: return;
    }
}
```

**Signs in NeoDAX output:**
- CFG shows a central dispatcher block with many outgoing edges to small blocks
- Many blocks with `→ dispatcher_addr` back edges
- Low instruction count per block
- Switch-table detection (`-W`) may find the dispatch table

---

## Packed Binaries

If entropy shows `.text` ≥ 7.0, the actual code is packed and the section contains a decompression stub + encrypted payload.

```bash
# Identify the unpacking stub (usually low entropy at the start)
./neodax -A 0x1000 -E 0x1200 -x ./packed_binary

# Entropy scan with -e shows which regions are packed vs stub
./neodax -e ./packed_binary
```

For fully packed binaries, NeoDAX analyzes the unpacking stub — it cannot analyze the packed payload until after runtime unpacking. Use dynamic analysis (debugger) to dump the unpacked image, then analyze the dump with NeoDAX.

---

## Anti-Debugging Tricks (x86-64)

Common tricks detectable with `-V`:

| Trick | IVF Finding |
|-------|-------------|
| `int3` spray | `INT3-RUN` |
| `rdtsc` timing check | `PRIV` |
| `cpuid` VM detection | `PRIV` |
| Self-modifying code | `INVALID` at modified locations |

---

## Symbolic Execution Against Obfuscated Code

For functions that apply simple transforms to inputs (like `nightmare4.c`):

```bash
./neodax -f -P ./binary
```

Symbolic execution tracks how transformations compose:
- `add x, #7` → `x_sym + 7`
- `eor x, #0x55` → `(x_sym + 7) ^ 0x55`

This gives you the exact mathematical formula applied to the input, even when the code is split across dead-byte-separated blocks.

---

## Recommended Workflow for Unknown Binaries

```bash
# 1. Quick survey
./neodax -l ./binary              # what sections exist?
./neodax -e ./binary              # any packed regions?

# 2. Validity check
./neodax -V ./binary              # invalid/privileged/dead?

# 3. If not packed — full analysis
./neodax -x -u ./binary          # standard + unicode

# 4. Deeper investigation
./neodax -R ./binary              # what's actually reachable?
./neodax -f -C ./binary           # CFG structure
./neodax -f -P ./binary           # symbolic execution (ARM64)
./neodax -f -D ./binary           # pseudo-C (ARM64)

# 5. Emulate specific function
./neodax -f -I ./binary
# Or via JS API with specific inputs:
# bin.emulate(funcIdx, {'0': 1337n})
```
