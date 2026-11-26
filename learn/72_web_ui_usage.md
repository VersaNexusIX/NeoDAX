# Web UI Usage

**Level:** 7 - Integration and Automation
**Prerequisites:** 71_building_analysis_scripts.md
**What You Will Learn:** How to use the NeoDAX web interface for interactive binary exploration.

## Accessing the UI

The NeoDAX web interface is hosted at **[neo-dax.vercel.app](https://neo-dax.vercel.app)** — no local server needed for the UI itself.

For REST API access (loading your own binaries), start the local server:

```bash
node js/server/server.js
# API available at http://localhost:7070
```

The port is configurable in `config.dax-ng` under `[server]`.

## Layout

The interface has three zones:

**Header bar** - file path input, ANALYZE button, status indicator, and metadata chips (arch, format, size) that appear after loading.

**Sidebar** - navigation grouped by category:
- Binary: Overview, Sections
- Code: Symbols, Functions, CFG Blocks, Xrefs
- Data: Strings, Unicode
- Disassembly: Disassemble
- Advanced: Decompiler, NR Form, Sym Exec, Emulator
- Detection: Entropy, Recursive Descent, Validity

**Content panel** - the active view for the selected sidebar item.

## Loading a Binary

Type the absolute path to any binary in the file bar and click **ANALYZE** or press Enter:

```
/bin/ls
/data/app/com.example/lib/arm64-v8a/libfoo.so
/home/user/target
```

NeoDAX loads the binary, runs symbol resolution and function detection, and populates all panels automatically. The progress bar shows loading stages.

## Overview Panel

Shows a summary of the binary:
- File path, format, arch, OS pills
- Stat cards: image size, code size, data size, section count, symbol count, function count, xref count, block count
- SHA-256 and Build ID with copy buttons
- Hottest functions (most-called) ranked by call count

## Sections Panel

Table of all sections with name, type, virtual address, file offset, size, flags (`rwx`), and instruction count for executable sections. Click the type badge to filter by type.

## Symbols Panel

Full symbol table with name (demangled where available), address, size, and type tags (function, import, export, weak, local). Use the search box to filter by name. Click an address to copy it.

## Functions Panel

Detected function boundaries with name, start address, end address, and size. Sortable and searchable. Functions detected by heuristic analysis appear without names if the binary is stripped.

## CFG Blocks Panel

Basic blocks from the control flow graph - start address, end address, size in instructions, and edge types (fall, jump, cond_true, cond_false, call, ret). Filter by function using the dropdown.

## Xrefs Panel

Cross-reference table showing caller address, callee address, and type (call, jump, indirect). Use the Xrefs-To and Xrefs-From sub-views to navigate references at a specific address.

## Strings Panel

ASCII strings extracted from all sections. Each entry shows the string value, address, section, and length. Filter by content or minimum length. Click the address to copy.

## Unicode Panel

Unicode strings (UTF-8, UTF-16LE, UTF-16BE, ASCII). Filter by encoding type or search by content.

## Disassembly Panel

Full disassembly with:
- Section selector - choose which executable section to view
- Mode toggle - Structured (table) or Plain text
- Group filter - show only call, branch, return, stack, syscall, nop, etc.
- Limit field - number of instructions to render (default 400)
- Search box - filter by mnemonic or operand text

In Structured mode each row shows address, raw bytes, mnemonic (color-coded by group), operands, and group label. Function boundaries appear as separator rows.

## Advanced Panels

**Decompiler** - select a function and click Decompile to get pseudo-C output. Supported on ARM64 binaries.

**NR Form** - lifts a function to NeoDAX Representation (inter-function IR with type inference). Select a function and click Lift to NR.

**Sym Exec** - symbolic execution for a selected function. Shows path conditions, reached addresses, and constraint sets.

**Emulator** - concrete ARM64 emulation. Select a function, set initial register values for x0/x1/x2, and click Emulate to see the execution trace.

## Detection Panels

**Entropy** - click Scan Entropy to run a sliding-window Shannon entropy scan across all sections. Regions above 6.8 bits/byte are flagged as high-entropy (likely compressed or encrypted). Regions above 7.0 are flagged as packed.

**Recursive Descent** - select a section and click Disassemble to follow control flow from every known entry point, marking bytes that are unreachable from any path as dead.

**Validity** - click Scan to run the Instruction Validity Filter, which reports invalid opcodes, privileged instructions, long NOP runs, and other obfuscation indicators.

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| Enter (in file bar) | Analyze |
| Click address | Copy to clipboard |
| Click copy button | Copy hash |

## Tips

- Use the search box in every panel - it filters in real time without re-querying the server.
- The limit field in Disassembly defaults to 400 for performance. Increase it for full section views.
- The status dot in the header shows green (ready), yellow (busy), or red (error). Check the status text for error details.
- Metadata chips (arch, format, size) appear in the top-right after a binary loads and persist while you navigate panels.

## Practice

1. Start the server and open the UI.
2. Load `/bin/ls` and navigate every panel.
3. Find the `main` function in Functions and note its address.
4. Switch to Disassembly, filter by group `call`, and find all call sites.
5. Run the Entropy scan and check whether any sections are flagged.

## Next

Continue to `73_express_integration.md`.
