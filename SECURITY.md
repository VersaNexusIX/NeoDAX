# Security Policy

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Supported Versions

| Version | Status | Security Updates |
|---------|--------|-----------------|
| 1.1.x   | Active (current) | Yes |
| 1.0.x   | Maintenance | Critical fixes only |
| < 1.0   | End of life | No |

---

## Scope

NeoDAX parses and analyzes untrusted binary files. The following are **in scope**:

- Memory safety bugs when parsing malformed ELF, PE, or Mach-O files (buffer overflows, out-of-bounds reads/writes, use-after-free, integer overflows in size/offset calculations)
- Vulnerabilities in the N-API addon (`neodax.node`) exploitable when processing untrusted binaries via the JS API
- Path traversal in the REST server (`js/server/server.js`)
- Denial-of-service via malformed input (infinite loops, excessive memory allocation)
- Bypass of instruction validity checks in the IVF module that could cause crashes
- Bypass of the fault isolation layer (`dax_guard.h`) that allows a malformed binary to crash the whole program rather than just recovering one pass

**Out of scope:**
- Issues requiring physical access to the machine
- Theoretical vulnerabilities without a practical exploit
- The emulator or symbolic execution producing incorrect output on edge-case inputs (these are accuracy bugs, not security bugs)
- Issues in third-party tools used to build NeoDAX
- Vulnerabilities in binaries *analyzed by* NeoDAX — NeoDAX does not execute analyzed files

---

## Defense-in-Depth Model (v1.1.1+)

As of v1.1.1, NeoDAX uses a three-layer fault isolation model inspired by microkernel design. This significantly reduces the attack surface of malformed-binary inputs:

**Layer 1 — Input validation** (`DAX_GUARD_BIN`, `DAX_GUARD_FUNC`): Every public analysis entry point validates `bin->data`, `bin->size`, and all counter fields against `DAX_MAX_*` bounds before doing any work. A malformed or truncated input cannot cause an immediate NULL deref.

**Layer 2 — Overflow-safe arithmetic**: All section offset calculations use `s->size > bin->size - s->offset` (subtraction form) rather than `s->offset + s->size > bin->size` (addition form), preventing integer overflow from turning an out-of-bounds section into a valid one. ELF `sh_name` indices are checked against the string table size before pointer arithmetic.

**Layer 3 — Pass isolation** (`DAX_RUN_PASS`): Each of the 32 analysis passes in `main.c` runs independently. If a pass sets `g_dax_fault`, the program prints a recovery notice and continues to the next pass. A single corrupt function or section cannot crash the entire analysis session.

These layers reduce but do not eliminate all memory safety risk. Security reports that demonstrate bypass of these layers — causing an actual crash, memory corruption, or code execution — are treated as high-severity bugs.

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

**Preferred:** [GitHub Security Advisories](https://github.com/VersaNexusIX/NeoDAX/security/advisories/new) — private, encrypted channel.

**Alternative:** Open a blank issue titled `[SECURITY] Private report request`. We will respond within 48 hours with a secure communication channel.

### What to include

- Description and potential impact
- Steps to reproduce (minimal command or crafted file)
- Proof-of-concept (crafted binary or command sequence)
- Whether the fault isolation layer (`dax_guard.h`) was bypassed or triggered
- Environment details (OS, architecture, NeoDAX version, compiler)
- Suggested fix, if you have one

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 48 hours |
| Severity assessment | 7 days |
| Fix for critical issues | 30 days |
| Fix for moderate issues | 90 days |
| Public advisory | 7 days after fix ships |

Reporters are credited in the advisory and changelog unless anonymity is requested.

---

## Safe Use

- The **REST server** (`js/server/server.js`) accepts a `file` path in the POST body. Do not expose it to the public internet — it is designed for local or LAN use only.
- The **emulator** (`-I`) runs ARM64 and RISC-V instructions in a sandboxed memory model and cannot affect the host system.
- The **entropy**, **RDA**, and **IVF** modules access binary data in read-only mode.
- The **fault isolation layer** (`dax_guard.h`) provides recovery from corrupt inputs but is not a security sandbox — do not assume it prevents all crashes against adversarially crafted inputs.
- When analyzing samples from untrusted sources, run NeoDAX inside a container, VM, or Termux sandbox.

---

## Disclosure Policy

NeoDAX follows coordinated disclosure: the researcher reports privately, we produce a fix and release it, then a public advisory is published 7 days after the fix ships. Please respect this timeline.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Supported Versions

| Version | Status | Security Updates |
|---------|--------|-----------------|
| 1.1.x   | Active (current) | Yes |
| 1.0.x   | Maintenance | Critical fixes only |
| < 1.0   | End of life | No |

---

## Scope

NeoDAX parses and analyzes untrusted binary files. The following are **in scope**:

- Memory safety bugs when parsing malformed ELF, PE, or Mach-O files (buffer overflows, out-of-bounds reads/writes, use-after-free, integer overflows in size/offset calculations)
- Vulnerabilities in the N-API addon (`neodax.node`) exploitable when processing untrusted binaries via the JS API
- Path traversal in the REST server (`js/server/server.js`)
- Denial-of-service via malformed input (infinite loops, excessive memory allocation)
- Bypass of instruction validity checks in the IVF module that could cause crashes

**Out of scope:**
- Issues requiring physical access to the machine
- Theoretical vulnerabilities without a practical exploit
- The emulator or symbolic execution producing incorrect output on edge-case inputs (these are accuracy bugs, not security bugs)
- Issues in third-party tools used to build NeoDAX
- Vulnerabilities in binaries *analyzed by* NeoDAX — NeoDAX does not execute analyzed files

---

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

**Preferred:** [GitHub Security Advisories](https://github.com/VersaNexusIX/NeoDAX/security/advisories/new) — private, encrypted channel.

**Alternative:** Open a blank issue titled `[SECURITY] Private report request`. We will respond within 48 hours with a secure communication channel.

### What to include

- Description and potential impact
- Steps to reproduce (minimal command or crafted file)
- Proof-of-concept (crafted binary or command sequence)
- Environment details (OS, architecture, NeoDAX version, compiler)
- Suggested fix, if you have one

---

## Response Timeline

| Milestone | Target |
|-----------|--------|
| Acknowledgement | 48 hours |
| Severity assessment | 7 days |
| Fix for critical issues | 30 days |
| Fix for moderate issues | 90 days |
| Public advisory | 7 days after fix ships |

Reporters are credited in the advisory and changelog unless anonymity is requested.

---

## Safe Use

- The **REST server** (`js/server/server.js`) accepts a `file` path in the POST body. Do not expose it to the public internet — it is designed for local or LAN use only.
- The **emulator** (`-I`) runs ARM64 and RISC-V instructions in a sandboxed memory model and cannot affect the host system.
- The **entropy**, **RDA**, and **IVF** modules access binary data in read-only mode.
- When analyzing samples from untrusted sources, run NeoDAX inside a container, VM, or Termux sandbox.

---

## Disclosure Policy

NeoDAX follows coordinated disclosure: the researcher reports privately, we produce a fix and release it, then a public advisory is published 7 days after the fix ships. Please respect this timeline.
