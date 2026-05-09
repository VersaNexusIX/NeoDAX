# Frequently Asked Questions

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## General

**Q: What is NeoDAX?**

NeoDAX is a binary analysis framework written in C99 with zero external dependencies. It disassembles ELF and PE binaries for x86-64, AArch64, and RISC-V; builds control-flow graphs; detects entropy anomalies; recursively follows code; validates instructions; lifts to NR (NeoDAX Representation); symbolically executes; and emulates ARM64. It ships both a CLI tool and a Node.js native addon.

---

**Q: What platforms does it run on?**

Linux (x86-64, ARM64), Android/Termux (AArch64), macOS (ARM64, x86-64, RISC-V), FreeBSD, OpenBSD. Windows support is partial (builds with MinGW but less tested).

---

**Q: Does it run on Android?**

Yes. Termux is a first-class target. `pkg install nodejs clang make && make` builds both the CLI and JS addon.

---

**Q: Does NeoDAX execute the binaries it analyzes?**

No - except for the `-I` emulator flag, which runs an isolated concrete emulator that cannot affect the host system. All other analysis (CFG, entropy, RDA, IVF, symbols, xrefs) is purely static.

---

**Q: Why C99 with no dependencies?**

To be maximally portable. NeoDAX runs on ancient Linuxes, Android, BSD, and embedded systems without requiring a package manager or internet access. A stripped binary that needs analysis may come from an environment where you can't `apt install capstone`.

---

## Build

**Q: `make` says `open_memstream` not found.**

`open_memstream` is POSIX but requires Linux glibc ≥ 2.10 or macOS ≥ 10.13. On older systems, use a newer distro or Termux.

**Q: Why does Clang 21 reject `auto` nested functions?**

`auto` nested functions are a GCC extension — not valid C99. This was fixed in NeoDAX v1.0.8. Update to v1.1.1.

**Q: The JS addon crashes immediately after build.**

Check the Node.js major version used to compile matches the one running it. Rebuild with JS mode in setup.sh or `npm run rebuild` after switching Node versions.

**Q: `log2` undefined / linker error.**

The entropy module uses `log2()` from `<math.h>`. The Makefile must contain `LDFLAGS = -lm`. Check with `grep LDFLAGS Makefile`.

---

## Analysis

**Q: CFG shows dead bytes as instructions (`dw`, `v_15`, etc.).**

This happens when the binary uses jump tricks or opaque predicates - unconditional branches followed by intentionally invalid bytes to confuse disassemblers. NeoDAX v1.0.8 fixed this with a two-pass CFG builder that pre-registers branch targets and skips dead bytes. Update to v1.1.1.

**Q: What is AIRE and when should I use it?**

AIRE (Assisted Intelligence Reverse Engineering) is run with `--aire` on the CLI or `aire`/`ai` in the interactive shell. It synthesizes all prior analysis results into ranked, human-readable insights. Use it after running other analysis passes (`-V`, `--poly`, `-I`) to get an interpreted summary of what the binary is doing. AIRE is most useful when you do not yet know what kind of obfuscation a binary uses.

**Q: What does AIRE's Context block tell me?**

After printing insights, AIRE counts which category (`vm-dispatch`, `smc`, `poly`, `anti-debug`, `packer`, etc.) has the most hits and prints a plain-language description of what kind of binary you are looking at. If AIRE says "Focus: VM interpreter / dispatch loop", you should spend your time tracing the dispatch function rather than, say, hunting for packed sections.

**Q: What does AIRE's Next Steps block tell me?**

Three concrete shell commands ranked by usefulness for the dominant context detected. For `vm-dispatch`, you get `run vt` / `cfg <func>` / `xrefs <addr>`. For `packer`, you get `entropy` / `run vt` / `cfg <entry>`. These adapt to what AIRE found — they are not generic suggestions.

**Q: What is `.aire_memory` and can I delete it?**

`.aire_memory` is written to the working directory when AIRE runs. It stores up to 32 entries keyed by binary SHA-256: run count, timestamp, dominant category, top insight, and last interactive command. It is used to show the "Memory recall" banner on subsequent runs of the same binary. Delete it freely — AIRE starts fresh the next run.

**Q: AIRE shows a Memory recall banner but I have never analyzed this binary before.**

The SHA-256 of the binary matched an earlier entry. This can happen if you analyzed an identical copy of the binary from a different path. The SHA-256 key is content-based, not path-based.

**Q: Unicode scanner shows CJK characters for normal ASCII binaries.**

Fixed in v1.0.8. The scanner now requires codepoints `> U+02FF` for UTF-16LE strings, skips `.dynstr`/`.dynsym`, and requires a preceding `0x00` byte as a string boundary marker. Typical ELF binaries now show 0-2 genuine Unicode strings.

**Q: Entropy scan shows HIGH for my `.text` section - is it packed?**

Not necessarily. Some architectures (AArch64 with fixed 4-byte instructions) naturally have higher entropy than x86-64. A `.text` section at 5.5-6.5 bits/byte is normal for ARM64. Values ≥ 7.0 strongly suggest packing.

**Q: Recursive descent shows 60% coverage - is that bad?**

No. 60-80% is normal. The remaining bytes are typically: alignment padding between functions, switch table data embedded in `.text`, jump trick dead bytes, unreachable error paths. Very low coverage (< 40%) may indicate heavy obfuscation.

**Q: Decompiler / NR output says `nop`/`...` for most lines.**

The NR lifter covers all common ARM64 and RISC-V integer instructions (mov/movk/movn, add, sub, mul, div, and, or, eor, xor, lsl, lsr, ror, sext, zext, ldr, str, bl, blr, ret, svc, mrs, cmp, cbz, tbz, all conditional branches). Unsupported instructions (SIMD/NEON, crypto extensions) emit `nop` placeholders. If most of a function is `nop`, it likely uses SIMD heavily.

**Q: What is the difference between DSA and NR?**

NR (NeoDAX Representation) is a static lift — it models code structure, types, and inter-function relationships from the binary alone. DSA (Dynamic Single Assignment) annotates each definition site with concrete values observed during emulation. Use NR to understand structure; use DSA to identify opaque predicates and trace runtime values. Run `--dsa` or `dsa <func>` in the interactive shell.

**Q: The poly map shows `xor-mutation-loop` — what does that mean?**

The binary contains a pattern where a value is loaded (`ldr`), XOR'd with a key (`eor`), then stored back (`str`) to an executable address. This is a classic polymorphic self-decryption stub. The code region being written to will execute as different instructions than what is in the file on disk. Run `-I` (emulator) to observe the decoded bytes, or `-P` (symexec) to track the write symbolically.

**Q: DSA shows `dsa` without arguments used to crash — is that fixed?**

Yes, fixed in v1.1.1. `dsa` without arguments now shows a usage hint and lists the first 10 detected functions instead of segfaulting. Use `dsa <name>` or `dsa all` for full analysis.

**Q: Symbolic execution says `(x0_sym + 0x7) ^ 0x55` - what does that mean?**

The return value depends on the input `x0` (first argument). NeoDAX found the formula but couldn't evaluate it concretely because `x0` was unknown at analysis time. Use `.emulate(idx, {'0': 42n})` to evaluate it for a specific input.

---

## JavaScript / npm

**Q: `require('neodax')` throws "native addon not found".**

Run `npm run build` or `bash build_js.sh` from the NeoDAX root. The addon must be compiled on-device.

**Q: Can I use NeoDAX in a browser?**

No. NeoDAX is a native Node.js addon (`.node` file) - it cannot run in the browser. The REST server can be used as a backend that serves analysis results to a browser frontend.

**Q: `JSON.stringify` throws "BigInt not serializable".**

Addresses in NeoDAX are `bigint` - they don't serialize with `JSON.stringify` by default. Convert them:
```js
const replacer = (_, v) => typeof v === 'bigint' ? `0x${v.toString(16)}` : v;
JSON.stringify(data, replacer);
```

**Q: Is there a TypeScript definition file?**

Yes - `js/index.d.ts` is bundled with the package. No `@types/neodax` needed.

**Q: The REST server is slow for large binaries.**

The server creates a new `NeoDAXBinary` for each request (`withFile`). For a production service, implement a binary cache keyed by SHA-256 to avoid re-parsing on every request. See [NPM_USAGE.md](NPM_USAGE.md) for the cache pattern.

---

## CI/CD

**Q: How do I publish a new version to npm?**

Use the **Release** workflow in GitHub Actions → Actions → Release → Run workflow → enter version. It bumps `package.json`, commits, tags, and triggers the publish pipeline automatically. See [PUBLISHING.md](PUBLISHING.md).

**Q: The nightly build fails on `ubuntu-24.04-arm` - I don't have that runner.**

The ARM64 runner requires GitHub's hosted ARM64 pool, available on GitHub Free with limited minutes. If you hit quota limits, comment out the `linux-arm64` matrix entry in `nightly.yml`.

**Q: How do I add prebuilt binaries to avoid compilation on user machines?**

Build on each platform, copy to `js/prebuilds/neodax-<platform>-<arch>.node`, commit, and publish. See the [PUBLISHING.md](PUBLISHING.md) prebuild section. The CI/CD pipeline does this automatically on tag push.

---

## Mach-O / macOS

**Q: Does NeoDAX support macOS binaries?**

Yes - NeoDAX v1.0.8 added a full Mach-O parser. It handles:
- Single-arch Mach-O (ARM64 and x86-64)
- FAT/universal binaries - automatically selects the ARM64 slice, falls back to x86-64
- Section parsing (`__TEXT,__text` → `.text`, `__DATA,__data` → `.data`, etc.)
- Entry point from `LC_MAIN`
- Symbol table from `LC_SYMTAB`

**Q: macOS `sections()` returns empty array.**

This was caused by inverted Mach-O magic constants in v1.0.8-rc. Fixed in the current release. The real ARM64 LE magic is `0xFEEDFACF` (bytes `CF FA ED FE` on disk). If you see `sections: 0` with a Mach-O binary, you are on a pre-release build - update to the latest.

**Q: macOS `functions()` returns empty on stripped binaries.**

Fixed in v1.0.8. The function detector now recognises macOS ARM64 prologues: `sub sp, sp, #N` (most common pattern), any `stp xN, xM, [sp, #-N]!` pre-index, and uses the section entry point as a function boundary of last resort.

**Q: `arch/arm64_bsd.S` assembler errors on macOS.**

NeoDAX now uses `arch/arm64_macos.S` (Mach-O syntax) on macOS and `arch/x86_64_macos.S` on Intel Mac - selected automatically by the Makefile. The old `arm64_bsd.S` used ELF syntax (`.section .note.GNU-stack,"",@progbits`) which macOS assembler rejects.

---

## npm

**Q: How do I use NeoDAX without git cloning?**

```bash
npm install neodax
```

`npm install` runs the postinstall script which compiles the native addon automatically. No git clone, no manual `make`.

**Q: npm install says "No C compiler found".**

Install clang or gcc:
```bash
# Debian/Ubuntu
sudo apt install build-essential libnode-dev

# macOS
xcode-select --install

# Termux
pkg install clang
```

**Q: Can I ship prebuilt binaries so users don't need to compile?**

Yes - build on each platform, copy `js/neodax.node` to `js/prebuilds/neodax-<platform>-<arch>.node`, commit, then `npm publish`. The installer checks `prebuilds/` first. The CI pipeline does this automatically on tag push via `prebuild.yml`.
