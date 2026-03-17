# Security Policy

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Supported Versions

| Version | Status | Security Updates |
|---------|--------|-----------------|
| 1.0.x | ✅ Active — current | Yes |
| < 1.0 | ❌ Unsupported | No |

---

## Scope

NeoDAX parses and analyzes untrusted binary files. The following are **in scope**:

- Memory safety bugs when parsing malformed ELF/PE files (buffer overflows, OOB reads/writes, use-after-free, integer overflows in size/offset calculations)
- Vulnerabilities in the N-API addon (`neodax.node`) exploitable when processing untrusted binaries via the JS API
- Path traversal in the REST server (`js/server/server.js`)
- Denial-of-service via malformed input (infinite loops, excessive memory allocation)
- Bypass of instruction validity checks in the IVF module that could cause crashes

**Out of scope:**
- Issues requiring physical access
- Theoretical vulnerabilities without a practical exploit
- The emulator/symbolic execution producing incorrect output on edge-case inputs (accuracy bugs, not security bugs)
- Issues in third-party tools used to build NeoDAX
- Vulnerabilities in binaries *analyzed by* NeoDAX — NeoDAX does not execute them

---

## Reporting a Vulnerability

**Do not open a public issue for security vulnerabilities.**

**Preferred:** [GitHub Security Advisories](https://github.com/VersaNexusIX/NeoDAX/security/advisories/new) — private, encrypted report.

**Alternative:** Open a blank issue titled `[SECURITY] Private report request` — we will respond within 48 hours with a secure channel.

### What to include

- Description and impact
- Steps to reproduce (minimal command or file)
- Proof-of-concept (crafted binary or command sequence)
- Environment (OS, arch, NeoDAX version, compiler)
- Suggested fix if you have one

---

## Timeline

| Milestone | Target |
|---|---|
| Acknowledgement | 48 hours |
| Severity assessment | 7 days |
| Fix for critical issues | 30 days |
| Fix for moderate issues | 90 days |
| Public advisory | 7 days after fix ships |

We will credit reporters in the advisory and changelog unless you prefer anonymity.

---

## Safe Use

- The **REST server** (`js/server/server.js`) accepts a `file` path in POST body — do not expose it to the public internet. It is designed for local/LAN use only.
- The **emulator** (`-I`) runs ARM64 instructions in a sandboxed memory model and cannot affect the host system.
- The **entropy**, **RDA**, and **IVF** modules read binary data read-only.
- For analyzing samples from untrusted sources, run NeoDAX inside a container, VM, or Termux sandbox.

---

## Disclosure Policy

Coordinated disclosure: researcher reports privately → we fix → release → public advisory (7 days after fix). Please respect this timeline.
