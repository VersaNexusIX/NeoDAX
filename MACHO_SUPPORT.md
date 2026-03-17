# Mach-O Support

NeoDAX supports macOS, iOS, and macOS binary formats via a full Mach-O parser.

> **Implementation:** `src/macho.c` · `include/macho.h`  
> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Supported Formats

| Format | Description | Status |
|--------|-------------|--------|
| Mach-O 64-bit LE | ARM64, x86-64 (most common) | ✅ Full |
| Mach-O 64-bit BE | Big-endian (rare, PowerPC era) | ✅ Parsed |
| FAT/Universal | Multiple arch slices in one file | ✅ Full |
| Mach-O 32-bit | Older ARM, x86 | ✅ Parsed |
| dylib (`.dylib`) | Dynamic library | ✅ Sections + symbols |
| bundle | Plugin bundle | ✅ Sections |

---

## Magic Numbers

Mach-O files are detected by their first 4 bytes, read as a little-endian `uint32_t`:

| Value | Bytes on disk | Meaning |
|-------|--------------|---------|
| `0xFEEDFACF` | `CF FA ED FE` | **Mach-O 64-bit LE** — most common (ARM64, x86-64) |
| `0xFEEDFACE` | `CE FA ED FE` | Mach-O 32-bit LE |
| `0xCFFAEDFE` | `FE ED FA CF` | Mach-O 64-bit BE |
| `0xCEFAEDFE` | `FE ED FA CE` | Mach-O 32-bit BE |
| `0xBEBAFECA` | `CA FE BA BE` | **FAT/Universal** |

**Common mistake:** The `_LE` suffix refers to the *file endianness*, not the value you compare against. A little-endian ARM64 binary has bytes `CF FA ED FE` on disk. A little-endian CPU reading those 4 bytes as a `uint32_t` gets `0xFEEDFACF` — this is `MACHO_MAGIC_64_LE`.

---

## FAT / Universal Binaries

macOS ships most system binaries as FAT (universal) binaries containing both ARM64 and x86-64 slices. NeoDAX automatically selects the best slice:

1. Try ARM64 (`CPU_TYPE_ARM64 = 0x0100000C`)
2. Fall back to x86-64 (`CPU_TYPE_X86_64 = 0x01000007`)
3. Fall back to first valid slice

```
FAT header (big-endian on disk)
├── fat_arch[0]: ARM64  @ offset 16384
└── fat_arch[1]: x86-64 @ offset 65536
         ↓
NeoDAX selects fat_arch[0] (ARM64)
data = bin->data + 16384
sz   = slice_size
```

**Important:** Section `fileoff` values in Mach-O are **absolute** from the start of the full file, not from the slice start. `bin->data + section->offset` is always correct.

---

## Load Commands Parsed

| Command | Value | What NeoDAX extracts |
|---------|-------|---------------------|
| `LC_SEGMENT_64` | `0x19` | Sections (name, vaddr, size, fileoff, flags) |
| `LC_SEGMENT` | `0x01` | 32-bit segments |
| `LC_MAIN` | `0x80000028` | Entry point (`text_vmbase + entryoff`) |
| `LC_SYMTAB` | `0x02` | Symbol table (`nlist_64`, strips leading `_`) |
| `LC_UNIX_THREAD` | `0x05` | Fallback entry point for older binaries |

All other load commands are skipped gracefully.

---

## Section Naming

NeoDAX strips the `__` prefix from Mach-O section names to match ELF convention:

| Mach-O | NeoDAX | Type |
|--------|--------|------|
| `__TEXT,__text` | `.text` | code |
| `__TEXT,__stubs` | `.stubs` | plt |
| `__TEXT,__cstring` | `.cstring` | rodata |
| `__TEXT,__const` | `.const` | rodata |
| `__DATA,__data` | `.data` | data |
| `__DATA,__bss` | `.bss` | bss |
| `__DATA,__got` | `.got` | got |
| `__DATA,__la_symbol_ptr` | `.la_symbol_ptr` | got |

---

## Symbol Table

NeoDAX reads `nlist_64` entries from `LC_SYMTAB`. macOS uses a leading underscore convention for C symbols (`_main`, `_printf`) — NeoDAX strips this prefix so symbols appear as `main`, `printf`.

Filtered out:
- STAB debug entries (`n_type & 0xE0 != 0`)
- Undefined symbols (`n_value == 0`)
- Invalid string table offsets

---

## Function Detection on macOS Binaries

macOS ARM64 binaries use different function prologues than Linux. NeoDAX detects all of them:

```asm
; Most common macOS pattern
sub  sp, sp, #48       ← detected as prologue (stack allocation)

; With frame pointer
stp  x29, x30, [sp, #-16]!   ← detected
mov  x29, sp

; With callee-saved registers
stp  x20, x19, [sp, #-32]!   ← detected (any pre-index stp)

; Pointer authentication (iOS/macOS security)
paciasp                ← detected
```

On fully stripped binaries with non-standard prologues, the section entry point is always treated as a function boundary — ensuring `functions().length >= 1`.

---

## macOS Assembly Stubs

| File | Used when | Syntax |
|------|-----------|--------|
| `arch/arm64_macos.S` | macOS ARM64 | Mach-O: `@PAGE`/`@PAGEOFF`, `_symbol`, `__TEXT,__text` |
| `arch/x86_64_macos.S` | macOS x86-64 | Mach-O: `__TEXT,__cstring`, syscall `0x2000004` |
| `arch/arm64_linux.S` | Linux/Android ARM64 | ELF: `:lo12:`, `.section .text` |
| `arch/arm64_bsd.S` | BSD ARM64 | ELF syntax (NOT used on macOS) |

The Makefile automatically selects the right file based on `IS_DARWIN` and architecture.

---

## Limitations

- **No DWARF debug info** — macOS debug info is usually in separate `.dSYM` bundles, not in the binary. NeoDAX does not parse `.dSYM`.
- **No ObjC/Swift metadata** — Objective-C class/method tables and Swift type metadata are not parsed.
- **No code signing** — `LC_CODE_SIGNATURE` is skipped.
- **No dyld info** — `LC_DYLD_INFO` (rebase/bind opcodes) is not parsed; use `otool -l` for that.
- **ARM64e (PAC)** — Pointer authentication codes in ARM64e binaries are treated as NOPs.

---

## CLI Example

```bash
# Analyze macOS /bin/ls (FAT universal binary)
./neodax -x /bin/ls

# Show sections
./neodax -l /bin/ls

# Entropy scan (detect packed regions)
./neodax -e /bin/ls

# Recursive descent
./neodax -R /bin/ls
```

## JS Example

```js
const neodax = require('neodax');

neodax.withBinary('/bin/ls', bin => {
    console.log(bin.arch);      // 'AArch64 (ARM64)' on Apple Silicon
    console.log(bin.format);    // 'ELF64'  (Mach-O reuses this enum)
    console.log(bin.isPie);     // true (MH_DYLIB or PIE)

    const secs = bin.sections();
    secs.forEach(s => console.log(s.name, s.type));
    // .text  code
    // .stubs plt
    // .const rodata
    // .data  data
    // ...
});
```
