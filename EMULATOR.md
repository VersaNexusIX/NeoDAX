# NeoDAX Emulator

Concrete ARM64 and RISC-V RV64GC emulator built into NeoDAX. Runs inside a
fully-isolated **Sandbox VM** that prevents emulated code from affecting the
host system in any way.

> **Implementation:** `src/emulate.c`  
> **CLI flags:** `-I` (emulate), `--vm-trace` (VM dispatch trace)  
> **Interactive:** `run <func>`, `step init <func>`, `step <n>`, `vt`, `reg`

---

## Sandbox VM

The emulator wraps every execution inside a sandbox with six independent
protection layers. Malicious or evasive binaries — including those that try
to spawn processes, open files, use the network, or execute shellcode — are
contained and cannot reach the host OS.

### Layer 1 — Memory Isolation

All memory operations go through `emu_read8` / `emu_write8`, which only
touch virtual page tables (`emu_page_t[256]`) or the binary's own read-only
section data. There is no pointer from emulated address space to real host
memory. The virtual address space is bounded:

```
0x0000_0000_0000_0000 .. 0x0000_0000_0001_0000   NULL guard (64 KB) — any access halts
0x0000_0000_0001_0000 .. 0x0000_0000_2000_0000   Binary section data (read-only)
0x0000_0000_2000_0000 .. 0x0000_0000_7fff_0000   Heap (virtual, page-backed)
0x0000_0000_7fff_0000 .. 0x0000_0000_7fff_8000   Stack (512 KB, grows down)
0x0000_0001_0000_0000+                           Ceiling — any access halts
```

Reads outside this range return 0. Writes outside this range are silently
dropped. Both cause a sandbox halt with a descriptive message.

### Layer 2 — Virtual Address Firewall

`emu_sandbox_addr_ok()` is called before every instruction executes and after
every branch. If the PC or a memory address is in the NULL guard (< 64 KB)
or above the 4 GB ceiling, execution halts immediately with:

```
SANDBOX: NULL/low-address access 0x...
SANDBOX: out-of-range address 0x... (max 0x100000000)
SANDBOX: PC escape to 0x... — halted
```

### Layer 3 — Syscall Firewall

Every `svc` (ARM64) or `ecall` (RISC-V) is intercepted by
`emu_simulate_syscall()`. Syscalls are classified into three groups:

**Always blocked — return EPERM:**
| Category | Syscalls |
|---|---|
| Process creation | `execve`, `execveat`, `clone`, `clone3` |
| Network | `socket`, `connect`, `bind`, `accept`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg` |
| Tracing | `ptrace`, `perf_event_open`, `process_vm_readv/writev` |
| Signals to real procs | `kill`, `tkill`, `tgkill` |
| Kernel modules | `init_module`, `finit_module`, `delete_module` |
| Credential escalation | `setuid`, `setgid`, `setreuid`, `setresuid`, `capset` |
| Memory exec (partial) | `mprotect` with `PROT_EXEC` flag set |

**Sandboxed — simulated with fake data:**
| Syscall | Behaviour |
|---|---|
| `openat` / `open` | Returns fake fd=3; no real file is opened |
| `read` | Returns count; no real read happens |
| `write` | Returns count; output discarded |
| `mmap` | Allocates virtual pages; `PROT_EXEC` flag stripped |
| `brk` | Returns fake heap top |
| `getpid` | Returns 1234 |
| `getuid/geteuid/getgid/getegid` | Returns 1000 |
| `getrandom` | Fills buffer with deterministic pattern |
| `nanosleep/clock_nanosleep` | Returns immediately (no real sleep) |
| `exit/exit_group` | Halts emulation cleanly |

**Example firewall output:**
```
[SVC #221 BLOCKED] SANDBOX execve/execveat blocked → EPERM
[SVC #198 BLOCKED] SANDBOX network-syscall blocked → EPERM
[SVC #56]          openat → FAKE fd=3 (sandbox)
```

### Layer 4 — Stack Canary

An 8-byte canary (`0xDEADC0DEDEADBEEF`) is written at both ends of the
virtual stack region before emulation starts. The canary is verified every
32 steps. If either end is overwritten, emulation halts:

```
SANDBOX: stack overflow — top canary smashed @ 0x7fff7ff8
SANDBOX: stack underflow — bottom canary smashed @ 0x7fff0004
```

### Layer 5 — Resource Quotas

| Resource | Limit |
|---|---|
| Max instructions | 65 536 steps |
| Max virtual memory pages | 256 × 4 KB = 1 MB |
| Max call depth | 64 |
| Per-address visit limit | 64 visits before loop-guard halt |

When any limit is hit, emulation halts gracefully with a description — it
never spins forever and never consumes unbounded host memory.

### Layer 6 — Real-time SMC Capture

`emu_write8()` checks every byte write against all code sections. Writes to
executable addresses are recorded in `bin->emu_smc_write_pc[]` and
`bin->emu_smc_target[]` (up to 64 entries). These feeds into the IVF output
as a third SMC pass alongside symexec and static pattern detection.

---

## Sandbox Status Output

Every emulation run ends with a sandbox status line:

```
Sandbox:     contained — no host access   pages_used=14/256  heap=0x20004000
```

If a violation was detected:

```
Sandbox:     VIOLATION DETECTED            pages_used=8/256   heap=0x20001000
Halted:      SANDBOX: PC escape to 0xff00000000 — halted
```

---

## Running the Emulator

### CLI

```bash
# Emulate all functions (up to first 4)
./neodax -I ./binary

# Emulate with full analysis context
./neodax -x -I ./binary

# Emulate + VM dispatch trace
./neodax -I --vm-trace ./binary
```

### Interactive shell

```
> run main           # emulate main() with default registers
> run vm_run         # emulate the VM interpreter
> reg vm_run         # dump register state after emulation

> step init main     # initialise a step session for main()
> step 10            # execute 10 instructions
> step 1             # single-step
```

### JavaScript

```javascript
neodax.withBinary('./binary', bin => {
    bin.analyze();
    // emulate function index 0 with x0=1, x1=0x1000
    const result = bin.emulate(0, [1, 0x1000n]);
    console.log(result);
});
```

---

## Architecture Coverage

| Feature | ARM64 | RISC-V RV64GC |
|---|---|---|
| Integer ops | Full | Full |
| Load/store (all widths) | Full | Full |
| Branches (cond + uncond) | Full | Full |
| FP/SIMD registers | Tracked (128-bit) | Tracked |
| Syscall simulation | Full firewall | Full firewall (a7) |
| Stack canary | ✓ | ✓ |
| Real-time SMC capture | ✓ | ✓ |
| VM dispatch detection | ✓ | ✓ |

---

## VM Dispatch Trace

When `--vm-trace` is enabled, every indirect branch (`br xN`, `jalr`) that
resolves to a different address than the previous step is recorded:

```
══════════════ VM DISPATCH TRACE ══════════════
Step  Dispatch@            Handler@              Opcode  VM_IP
   1  0x0000000000001098   0x000000000000143c    0x00    0x0
   2  0x0000000000001098   0x0000000000001464    0x02    0x1
   3  0x0000000000001098   0x0000000000001498    0x03    0x2
```

This reveals the opcode → handler mapping of VM interpreters without manual
CFG tracing.
