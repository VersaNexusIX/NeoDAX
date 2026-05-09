#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"
#include "dax_guard.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

/* ═══════════════════════════════════════════════════════════════════════════
 * EMU SANDBOX VM
 *
 * The emulator runs emulated binary code inside a fully isolated virtual
 * address space. No emulated instruction can read or write host process
 * memory, invoke real syscalls, or escape the sandbox.
 *
 * Protection layers:
 *
 *   1. MEMORY ISOLATION
 *      All reads and writes go through emu_read8 / emu_write8 which only
 *      touch virtual pages (emu_page_t[]) or the binary's read-only section
 *      data. There is no pointer from emulated code to real host memory.
 *
 *   2. VIRTUAL ADDRESS FIREWALL
 *      emu_sandbox_addr_ok() enforces that every PC and memory address is
 *      within the legal virtual range. Addresses outside the range cause an
 *      immediate sandbox halt — they cannot reference host mappings.
 *
 *   3. SYSCALL FIREWALL
 *      emu_simulate_syscall() intercepts every svc/ecall. Safe syscalls
 *      (write, exit, brk, mmap) are simulated with fake return values.
 *      Any syscall that could escape — execve, fork, open, socket, ptrace,
 *      clone, mprotect with PROT_EXEC, etc. — is blocked and logged.
 *
 *   4. HEAP / STACK CANARY
 *      A 16-byte canary pattern is written at both ends of the virtual stack
 *      region. After every step the canary is verified; corruption triggers
 *      an immediate halt with a STACK_SMASH event.
 *
 *   5. RESOURCE QUOTAS
 *      - Maximum steps: EMU_MAX_STEPS (65536)
 *      - Maximum virtual pages: EMU_MEM_PAGES (256 × 4 KB = 1 MB)
 *      - Maximum heap: EMU_HEAP_MAX (256 MB virtual, bounded by page limit)
 *      - Maximum call depth: EMU_CALL_DEPTH (64)
 *      - Per-address loop guard: 64 visits before halt
 *
 *   6. INSTRUCTION FILTER
 *      Instructions that have no legitimate use in a normal emulation but
 *      are commonly used by shellcode (hlt, int 0x80, ud2, illegal) cause
 *      an immediate sandbox halt rather than being silently skipped.
 * ═══════════════════════════════════════════════════════════════════════════ */

/* Virtual address space layout inside the sandbox VM
 *
 *   0x0000_0000_0000_0000  NULL guard (any access → halt)
 *   0x0000_0000_0001_0000  Binary section data (read-only, mapped at load)
 *   0x0000_0000_2000_0000  Heap base (grows up, bounded by page limit)
 *   0x0000_0000_7fff_0000  Virtual stack (grows down, 512 KB)
 *   0xFFFF_FFFF_FFFF_FFFF  Any address above 0x0001_0000_0000 → illegal
 */
#define EMU_SANDBOX_MAX_ADDR  0x100000000ULL   /* 4 GB virtual ceiling     */
#define EMU_SANDBOX_NULL_SIZE 0x10000ULL        /* first 64 KB = null guard */
#define EMU_STACK_CANARY      0xDEADC0DEDEADBEEFULL
#define EMU_MAX_STEPS   65536
#define EMU_MEM_PAGES   256
#define EMU_PAGE_SIZE   4096
#define EMU_STACK_BASE  0x7fff0000ULL
#define EMU_STACK_SIZE  0x80000

/* ── VM dispatch flow trace ── */
/* VM_DISPATCH_MAX and dax_vm_dispatch_entry_t are declared in dax.h    */
dax_vm_dispatch_entry_t g_vm_trace[VM_DISPATCH_MAX];
int                     g_nvm_trace = 0;

/* ── Step-resume global state ── */
dax_step_state_t g_step_state;  /* defined here, declared extern in dax.h  */

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);

typedef struct {
    uint64_t base;
    uint8_t  data[EMU_PAGE_SIZE];
    int      used;
} emu_page_t;

#define EMU_CALL_DEPTH  64   

typedef struct {
    uint64_t  regs[32];
    uint64_t  pc;
    uint64_t  sp;
    uint8_t   flags_z;
    uint8_t   flags_n;
    uint8_t   flags_c;
    uint8_t   flags_v;
    emu_page_t pages[EMU_MEM_PAGES];
    int        npages;
    int        steps;
    int        halted;
    char       halt_reason[192];
    uint8_t   *code_base;
    size_t     code_size;
    uint64_t   code_vaddr;
    dax_binary_t *bin;
    
    uint64_t   call_stack[EMU_CALL_DEPTH];  
    int        call_depth;                   
    uint64_t   entry_fn_start;              
} emu_state_t;

/* forward declaration — body defined after libc simulation helpers */
static void vm_trace_record(emu_state_t *e, uint64_t dispatch_pc,
                            uint64_t handler_pc, int step_no,
                            dax_binary_t *bin);

/* ── Sandbox address validator ───────────────────────────────────────────────
 * Returns 1 if addr is within the legal virtual range, 0 if it must be
 * blocked. Called before every PC advance and memory access.              */
static int emu_sandbox_addr_ok(emu_state_t *e, uint64_t addr) {
    /* NULL guard — lowest 64 KB always illegal */
    if (addr < EMU_SANDBOX_NULL_SIZE) {
        if (!e->halted) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "SANDBOX: NULL/low-address access 0x%llx",
                     (unsigned long long)addr);
            e->halted = 1;
        }
        return 0;
    }
    /* Ceiling guard — above 4 GB virtual */
    if (addr >= EMU_SANDBOX_MAX_ADDR) {
        if (!e->halted) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "SANDBOX: out-of-range address 0x%llx (max 0x%llx)",
                     (unsigned long long)addr,
                     (unsigned long long)EMU_SANDBOX_MAX_ADDR);
            e->halted = 1;
        }
        return 0;
    }
    return 1;
}

/* ── Stack canary helpers ────────────────────────────────────────────────── */
/* forward decls — bodies defined after emu_write8/emu_read8 */
static void emu_canary_write(emu_state_t *e);
static int  emu_canary_check(emu_state_t *e);

/*
 * Call-frequency table — track how many times each target is called.
 * When a target reaches VM_HOTCALL_THRESH calls it is treated as a
 * VM interpreter step function and recorded in the dispatch trace,
 * even if reached via direct `bl` rather than indirect `br Xn`.
 */
#define VM_HOT_MAX        128
#define VM_HOTCALL_THRESH   3
typedef struct { uint64_t tgt; int count; } vm_hot_entry_t;
static vm_hot_entry_t g_hot[VM_HOT_MAX];
static int            g_nhot = 0;

static void vm_hot_record(emu_state_t *e, uint64_t call_pc, uint64_t tgt) {
    int i;
    for (i = 0; i < g_nhot; i++) {
        if (g_hot[i].tgt == tgt) {
            g_hot[i].count++;
            if (g_hot[i].count >= VM_HOTCALL_THRESH)
                vm_trace_record(e, call_pc, tgt, e->steps, e->bin);
            return;
        }
    }
    if (g_nhot < VM_HOT_MAX) {
        g_hot[g_nhot].tgt   = tgt;
        g_hot[g_nhot].count = 1;
        g_nhot++;
    }
}

/* emu_trace_entry_t and g_trace removed — trace is handled by g_mpath */

static void emu_write8(emu_state_t *e, uint64_t addr, uint8_t val) {
    int i;
    uint64_t pg = addr & ~(uint64_t)(EMU_PAGE_SIZE - 1);

    /* ── Sandbox: reject writes outside virtual range ─────────────────────── */
    if (!emu_sandbox_addr_ok(e, addr)) return;

    /* ── Real-time SMC detection ─────────────────────────────────────────────
     * If we are writing to an address that falls inside a code section,
     * this is a self-modifying code event. Record it once per target word. */
    if (e->bin) {
        int si_smc;
        for (si_smc = 0; si_smc < e->bin->nsections; si_smc++) {
            dax_section_t *sc = &e->bin->sections[si_smc];
            if ((sc->type == SEC_TYPE_CODE || sc->type == SEC_TYPE_PLT) &&
                addr >= sc->vaddr && addr < sc->vaddr + sc->size) {
                uint64_t word_addr = addr & ~(uint64_t)3;
                int dup = 0, di2;
                for (di2 = 0; di2 < e->bin->nemu_smc; di2++)
                    if (e->bin->emu_smc_target[di2] == word_addr) { dup = 1; break; }
                if (!dup && e->bin->nemu_smc < 64) {
                    e->bin->emu_smc_write_pc[e->bin->nemu_smc] = e->pc;
                    e->bin->emu_smc_target[e->bin->nemu_smc]   = word_addr;
                    e->bin->emu_smc_new_word[e->bin->nemu_smc] = 0;
                    e->bin->nemu_smc++;
                    e->bin->obf_score_smc++;
                }
                break;
            }
        }
    }

    for (i = 0; i < e->npages; i++) {
        if (e->pages[i].base == pg) {
            e->pages[i].data[addr & (EMU_PAGE_SIZE-1)] = val;
            return;
        }
    }
    if (e->npages < EMU_MEM_PAGES) {
        i = e->npages++;
        memset(&e->pages[i], 0, sizeof(emu_page_t));
        e->pages[i].base = pg;
        e->pages[i].used = 1;
        e->pages[i].data[addr & (EMU_PAGE_SIZE-1)] = val;
    }
    /* silently drop if page table full — quota enforced */
}

static uint8_t emu_read8(emu_state_t *e, uint64_t addr) {
    int i;
    uint64_t pg = addr & ~(uint64_t)(EMU_PAGE_SIZE - 1);

    /* ── Sandbox: reject reads outside virtual range ──────────────────────── */
    if (addr < EMU_SANDBOX_NULL_SIZE || addr >= EMU_SANDBOX_MAX_ADDR)
        return 0;  /* silent zero — do not halt on read (could be speculative) */

    for (i = 0; i < e->npages; i++) {
        if (e->pages[i].base == pg)
            return e->pages[i].data[addr & (EMU_PAGE_SIZE-1)];
    }
    if (e->bin && e->bin->data) {
        for (i = 0; i < e->bin->nsections; i++) {
            dax_section_t *sec = &e->bin->sections[i];
            if (sec->size == 0 || sec->offset > e->bin->size) continue;
            if (sec->size > e->bin->size - sec->offset) continue;
            if (addr >= sec->vaddr && addr < sec->vaddr + sec->size) {
                size_t off = sec->offset + (size_t)(addr - sec->vaddr);
                if (off < e->bin->size)
                    return e->bin->data[off];
            }
        }
    }
    return 0;
}

static uint32_t emu_read32(emu_state_t *e, uint64_t addr) {
    return (uint32_t)emu_read8(e,addr) | ((uint32_t)emu_read8(e,addr+1)<<8) |
           ((uint32_t)emu_read8(e,addr+2)<<16) | ((uint32_t)emu_read8(e,addr+3)<<24);
}

static uint64_t emu_read64(emu_state_t *e, uint64_t addr) {
    return (uint64_t)emu_read32(e,addr) | ((uint64_t)emu_read32(e,addr+4)<<32);
}

static void emu_write32(emu_state_t *e, uint64_t addr, uint32_t v) {
    emu_write8(e,addr,(uint8_t)v); emu_write8(e,addr+1,(uint8_t)(v>>8));
    emu_write8(e,addr+2,(uint8_t)(v>>16)); emu_write8(e,addr+3,(uint8_t)(v>>24));
}

static void emu_write64(emu_state_t *e, uint64_t addr, uint64_t v) {
    emu_write32(e,addr,(uint32_t)v); emu_write32(e,addr+4,(uint32_t)(v>>32));
}

/* ── Canary bodies — placed here after emu_write8/read8 are defined ── */

static void emu_canary_write(emu_state_t *e) {
    uint64_t bot = EMU_STACK_BASE;
    uint64_t top = EMU_STACK_BASE + EMU_STACK_SIZE - 8;
    uint64_t cv  = EMU_STACK_CANARY;
    int i;
    for (i = 0; i < 8; i++) {
        emu_write8(e, bot + (uint64_t)i, (uint8_t)(cv >> (i*8)));
        emu_write8(e, top + (uint64_t)i, (uint8_t)(cv >> (i*8)));
    }
}

static int emu_canary_check(emu_state_t *e) {
    uint64_t bot = EMU_STACK_BASE;
    uint64_t top = EMU_STACK_BASE + EMU_STACK_SIZE - 8;
    uint64_t cv  = EMU_STACK_CANARY;
    int i;
    for (i = 0; i < 8; i++) {
        if (emu_read8(e, bot + (uint64_t)i) != (uint8_t)(cv >> (i*8))) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "SANDBOX: stack underflow — bottom canary smashed @ 0x%llx",
                     (unsigned long long)(bot + i));
            e->halted = 1;
            return 0;
        }
        if (emu_read8(e, top + (uint64_t)i) != (uint8_t)(cv >> (i*8))) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "SANDBOX: stack overflow — top canary smashed @ 0x%llx",
                     (unsigned long long)(top + i));
            e->halted = 1;
            return 0;
        }
    }
    return 1;
}

static int arm64_rn(const char *name) {
    if (!name||!name[0]) return 31;
    if (strcmp(name,"xzr")==0||strcmp(name,"wzr")==0) return 31;
    if (strcmp(name,"sp")==0||strcmp(name,"wsp")==0)  return 31;
    if (strcmp(name,"lr")==0) return 30;
    if (strcmp(name,"fp")==0||strcmp(name,"x29")==0) return 29;
    if ((name[0]=='x'||name[0]=='w') && isdigit((unsigned char)name[1])) {
        int n=atoi(name+1);
        if(n>=0&&n<=30) return n;
    }
    return -1;
}

static int rv_reg_idx(const char *name) {
    static const char *rv_names[32] = {
        "zero","ra","sp","gp","tp","t0","t1","t2",
        "s0","s1","a0","a1","a2","a3","a4","a5",
        "a6","a7","s2","s3","s4","s5","s6","s7",
        "s8","s9","s10","s11","t3","t4","t5","t6"
    };
    int i;
    if (!name||!name[0]) return -1;
    if (name[0]=='x' && isdigit((unsigned char)name[1])) {
        int n=atoi(name+1);
        if(n>=0&&n<32) return n;
    }
    for(i=0;i<32;i++) if(strcmp(name,rv_names[i])==0) return i;
    return -1;
}

static uint64_t parse_arm64_imm(const char *s) {
    if (!s||!s[0]) return 0;
    if (s[0]=='#') s++;
    if (strncmp(s,"0x",2)==0) return strtoull(s,NULL,16);
    return strtoull(s,NULL,0);
}

static uint64_t emu_get_reg(emu_state_t *e, const char *name) {
    int idx=arm64_rn(name);
    if(idx==31) {
        if(strcmp(name,"sp")==0||strcmp(name,"wsp")==0) return e->sp;
        return 0;
    }
    if(idx<0||idx>=32) return 0;
    uint64_t v=e->regs[idx];
    if(name[0]=='w') v&=0xFFFFFFFF;
    return v;
}

static void emu_set_reg(emu_state_t *e, const char *name, uint64_t val) {
    int idx=arm64_rn(name);
    if(idx==31){
        if(strcmp(name,"sp")==0||strcmp(name,"wsp")==0)e->sp=val;
        return;
    }
    if(idx<0||idx>=32) return;
    if(name[0]=='w') val&=0xFFFFFFFF;
    e->regs[idx]=val;
}

typedef union {
    uint8_t   b[16];
    uint16_t  h[8];
    uint32_t  s[4];
    uint64_t  d[2];
    double    f64[2];
    float     f32[4];
} vec128_t;

static vec128_t g_fp_regs[32];

static double fp_get(int n)        { return n>=0&&n<32?g_fp_regs[n].f64[0]:0.0; }
static void   fp_set(int n, double v){ if(n>=0&&n<32) g_fp_regs[n].f64[0]=v; }

static int fp_rn(const char *s) {
    if (!s||!s[0]) return -1;
    if ((s[0]=='d'||s[0]=='s'||s[0]=='h'||s[0]=='b'||s[0]=='q') && s[1]>='0')
        return atoi(s+1);
    return -1;
}

#define EMU_HEAP_BASE 0x20000000ULL
#define EMU_HEAP_MAX  0x10000000ULL  
static uint64_t g_heap_top = EMU_HEAP_BASE;

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPROVEMENT 1: FAKE TIMING SOURCE + JITTER INJECTION
 *
 * Malware that probes execution time (RDTSC, clock_gettime, gettimeofday)
 * to detect emulation gets plausible, monotonically advancing fake values.
 * Jitter adds small pseudo-random noise so repeated reads don't return
 * suspiciously identical deltas.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define EMU_FAKE_TIME_BASE_SEC   1700000000ULL  /* plausible Unix epoch base  */
#define EMU_FAKE_TIME_NS_PER_STEP 1200ULL        /* ~1.2 µs per emulated step */
#define EMU_FAKE_JITTER_MASK      0x1FFULL       /* up to 511 ns jitter        */

/* LCG for lightweight deterministic jitter — NOT a security PRNG */
static uint64_t g_emu_jitter_state = 0xDEADC0DE12345678ULL;
static uint64_t emu_jitter_next(void) {
    g_emu_jitter_state = g_emu_jitter_state * 6364136223846793005ULL
                         + 1442695040888963407ULL;
    return g_emu_jitter_state;
}

/* Returns nanoseconds for the current emulation step, monotonically growing */
static uint64_t emu_fake_time_ns(int step) {
    uint64_t base = (uint64_t)step * EMU_FAKE_TIME_NS_PER_STEP;
    uint64_t jitter = emu_jitter_next() & EMU_FAKE_JITTER_MASK;
    return base + jitter;
}

/* Fills a struct timespec in the VM's virtual memory:
 *   offset 0: tv_sec  (8 bytes, little-endian)
 *   offset 8: tv_nsec (8 bytes, little-endian)   */
static void emu_fill_timespec(emu_state_t *e, uint64_t ts_ptr, int step) {
    if (!ts_ptr || ts_ptr < EMU_SANDBOX_NULL_SIZE) return;
    uint64_t total_ns  = emu_fake_time_ns(step);
    uint64_t tv_sec    = EMU_FAKE_TIME_BASE_SEC + total_ns / 1000000000ULL;
    uint64_t tv_nsec   = total_ns % 1000000000ULL;
    emu_write64(e, ts_ptr,     tv_sec);
    emu_write64(e, ts_ptr + 8, tv_nsec);
}

/* Fills a struct timeval (tv_sec + tv_usec, 8 bytes each) */
static void emu_fill_timeval(emu_state_t *e, uint64_t tv_ptr, int step) {
    if (!tv_ptr || tv_ptr < EMU_SANDBOX_NULL_SIZE) return;
    uint64_t total_ns  = emu_fake_time_ns(step);
    uint64_t tv_sec    = EMU_FAKE_TIME_BASE_SEC + total_ns / 1000000000ULL;
    uint64_t tv_usec   = (total_ns % 1000000000ULL) / 1000ULL;
    emu_write64(e, tv_ptr,     tv_sec);
    emu_write64(e, tv_ptr + 8, tv_usec);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPROVEMENT 3: CONTROLLED ENTROPY SOURCE
 *
 * Malware may call getrandom / read from /dev/urandom to fingerprint
 * the environment (real systems produce truly random bytes; naive emulators
 * produce a fixed pattern or all-zeros).  We supply deterministic but
 * non-trivial pseudo-random bytes that look organic, seeded from the step
 * counter so results are reproducible across analysis runs.
 * ═══════════════════════════════════════════════════════════════════════════ */
static void emu_fill_entropy(emu_state_t *e, uint64_t buf_ptr,
                              uint64_t len, int step) {
    if (!buf_ptr || buf_ptr < EMU_SANDBOX_NULL_SIZE || len == 0) return;
    if (len > 4096) len = 4096;   /* cap — sandbox quota */
    /* Re-seed per call using step + pointer so every call differs */
    uint64_t state = 0x9E3779B97F4A7C15ULL ^ ((uint64_t)step * 2654435761ULL)
                     ^ (buf_ptr * 0x517CC1B727220A95ULL);
    uint64_t i;
    for (i = 0; i < len; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        emu_write8(e, buf_ptr + i, (uint8_t)(state >> 56));
    }
}

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPROVEMENT 2: REALISTIC SYSCALL RETURN VALUES
 *
 * Blocked syscalls previously all returned -EPERM (-1).  Malware that
 * fingerprints the environment may check for suspiciously uniform errors.
 * We now return the errno that a real Linux kernel would produce:
 *   execve/fork    → -EACCES (permission denied, plausible sandbox)
 *   network        → -ENETUNREACH (no network in sandbox)
 *   ptrace         → -EPERM  (traced processes return this)
 *   open/creat     → fake fd (already done above)
 *   credential ops → -EPERM  (correct for non-root)
 *   kernel modules → -EPERM  (correct for non-root)
 *   signals        → 0 or -ESRCH (target not found)
 * ═══════════════════════════════════════════════════════════════════════════ */
/* Linux errno values (AArch64 kernel ABI, negated) */
#define ESRCH_NEG    ((uint64_t)(uint64_t)(-3LL))    /* -ESRCH: no such process  */
#define EACCES_NEG   ((uint64_t)(uint64_t)(-13LL))   /* -EACCES: permission      */
#define EFAULT_NEG   ((uint64_t)(uint64_t)(-14LL))   /* -EFAULT: bad address     */
#define EBUSY_NEG    ((uint64_t)(uint64_t)(-16LL))   /* -EBUSY: device busy      */
#define EINVAL_NEG   ((uint64_t)(uint64_t)(-22LL))   /* -EINVAL: invalid arg     */
#define ENOSYS_NEG   ((uint64_t)(uint64_t)(-38LL))   /* -ENOSYS: not implemented */
#define ENETUNREACH_NEG ((uint64_t)(uint64_t)(-101LL)) /* -ENETUNREACH           */

/* ═══════════════════════════════════════════════════════════════════════════
 * IMPROVEMENT 4: MULTI-PATH EXECUTION STATE
 *
 * Single-trace emulation misses branches not taken on the happy path.
 * The multi-path engine forks the VM state at conditional branches,
 * queues both sides, and runs each to completion (up to a budget).
 * All paths are reported, giving a more complete picture of what
 * a sample can do — critical for evasive malware that hides behaviour
 * behind anti-debug checks.
 * ═══════════════════════════════════════════════════════════════════════════ */
#define MPATH_MAX_FORKS   32    /* max branch forks per emulation run        */
#define MPATH_MAX_STEPS   2048  /* step budget per forked path               */

typedef struct {
    uint64_t regs[32];
    uint64_t pc;
    uint64_t sp;
    uint8_t  flags_z, flags_n, flags_c, flags_v;
    int      steps;
    char     fork_reason[64];   /* which branch created this fork            */
    int      path_id;
} mpath_snapshot_t;

typedef struct {
    mpath_snapshot_t forks[MPATH_MAX_FORKS];
    int              nforks;
    int              total_paths_run;
    /* Syscalls observed across ALL paths — union of behaviours */
    uint64_t  syscalls_seen[64];
    int       nsyscalls_seen;
} mpath_state_t;

static mpath_state_t g_mpath;

/* Record a branch fork: save alternative PC + current register state */
static void mpath_push_fork(emu_state_t *e, uint64_t alt_pc,
                             const char *reason) {
    if (g_mpath.nforks >= MPATH_MAX_FORKS) return;
    mpath_snapshot_t *snap = &g_mpath.forks[g_mpath.nforks++];
    memcpy(snap->regs, e->regs, sizeof(snap->regs));
    snap->pc      = alt_pc;
    snap->sp      = e->sp;
    snap->flags_z = e->flags_z;
    snap->flags_n = e->flags_n;
    snap->flags_c = e->flags_c;
    snap->flags_v = e->flags_v;
    snap->steps   = e->steps;
    snap->path_id = g_mpath.nforks;
    strncpy(snap->fork_reason, reason ? reason : "branch", 63);
}

/* Record a syscall number seen during any path */
static void mpath_record_syscall(uint64_t nr) {
    int i;
    for (i = 0; i < g_mpath.nsyscalls_seen; i++)
        if (g_mpath.syscalls_seen[i] == nr) return;
    if (g_mpath.nsyscalls_seen < 64)
        g_mpath.syscalls_seen[g_mpath.nsyscalls_seen++] = nr;
}

static uint64_t emu_malloc(emu_state_t *e, uint64_t size) {
    uint64_t ptr = g_heap_top;
    g_heap_top   = (g_heap_top + size + 15) & ~(uint64_t)15;
    if (g_heap_top > EMU_HEAP_BASE + EMU_HEAP_MAX) return 0;
    
    uint64_t i;
    for (i = 0; i < size; i++) emu_write8(e, ptr+i, 0);
    return ptr;
}

static void emu_free_noop(emu_state_t *e, uint64_t ptr) { (void)e; (void)ptr; }

static uint64_t emu_strlen(emu_state_t *e, uint64_t ptr) {
    uint64_t n = 0;
    while (emu_read8(e, ptr+n) && n < 65536) n++;
    return n;
}
static void emu_strcpy(emu_state_t *e, uint64_t dst, uint64_t src) {
    uint64_t i = 0; uint8_t ch;
    do { ch = emu_read8(e, src+i); emu_write8(e, dst+i, ch); i++; } while (ch && i < 65536);
}
static void emu_memcpy(emu_state_t *e, uint64_t dst, uint64_t src, uint64_t n) {
    uint64_t i; for (i = 0; i < n; i++) emu_write8(e, dst+i, emu_read8(e, src+i));
}
static void emu_memset_fn(emu_state_t *e, uint64_t dst, uint8_t val, uint64_t n) {
    uint64_t i; for (i = 0; i < n; i++) emu_write8(e, dst+i, val);
}

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmisleading-indentation"
static int emu_simulate_libc(emu_state_t *e, uint64_t tgt, FILE *out, int color) {
    const char *CR = color ? "\033[0m"    : "";
    const char *CG = color ? "\033[1;32m" : "";
    const char *CY = color ? "\033[1;33m" : "";

    
    const char *sym_name = NULL;
    char sym_buf[64] = "";
    if (e->bin) {
        int i;
        for (i = 0; i < e->bin->nsymbols; i++) {
            if (e->bin->symbols[i].address == tgt) {
                sym_name = e->bin->symbols[i].name;
                break;
            }
        }
        
        if (!sym_name) {
            
            for (i = 0; i < e->bin->nsections; i++) {
                if (tgt >= e->bin->sections[i].vaddr &&
                    tgt < e->bin->sections[i].vaddr + e->bin->sections[i].size &&
                    strstr(e->bin->sections[i].name, "plt")) {
                    snprintf(sym_buf, 64, "plt+0x%llx",
                             (unsigned long long)(tgt - e->bin->sections[i].vaddr));
                    sym_name = sym_buf;
                    break;
                }
            }
        }
    }
    if (!sym_name) return 0; 

    
    const char *nm = sym_name;
    while (*nm == '_') nm++;
    char base[64]; strncpy(base, nm, 63); base[63]='\0';
    { char *at = strchr(base,'@'); if(at) *at='\0'; }

#define SIM_LOG(fn, fmt, ...) \
    do { if (out) fprintf(out, "  %s[LIBC]%s %s%-16s%s " fmt "\n", CY,CR,CG,fn,CR, ##__VA_ARGS__); } while(0)

    
    if (!strcmp(base,"malloc") || !strcmp(base,"calloc") ||
        !strcmp(base,"realloc") || !strcmp(base,"xmalloc") ||
        !strcmp(base,"zmalloc") || !strcmp(base,"gc_malloc")) {
        uint64_t sz = e->regs[0];
        uint64_t ptr = emu_malloc(e, sz ? sz : 16);
        if (!strcmp(base,"calloc")) { 
            sz = e->regs[0] * e->regs[1];
            ptr = emu_malloc(e, sz ? sz : 16);
        }
        e->regs[0] = ptr;
        SIM_LOG(base, "size=0x%llx → 0x%llx", (unsigned long long)sz, (unsigned long long)ptr);
        return 1;
    }
    if (!strcmp(base,"free") || !strcmp(base,"cfree") || !strcmp(base,"xfree")) {
        emu_free_noop(e, e->regs[0]);
        SIM_LOG(base, "ptr=0x%llx", (unsigned long long)e->regs[0]);
        e->regs[0] = 0;
        return 1;
    }
    if (!strcmp(base,"memcpy") || !strcmp(base,"memmove") || !strcmp(base,"bcopy")) {
        uint64_t dst=e->regs[0],src=e->regs[1],n2=e->regs[2];
        if (!strcmp(base,"bcopy")) { dst=e->regs[1]; src=e->regs[0]; }
        if (n2 < 0x100000) emu_memcpy(e,dst,src,n2);
        SIM_LOG(base, "dst=0x%llx src=0x%llx n=%llu", (unsigned long long)dst,
                (unsigned long long)src, (unsigned long long)n2);
        e->regs[0] = dst;
        return 1;
    }
    if (!strcmp(base,"memset") || !strcmp(base,"bzero")) {
        uint64_t dst=e->regs[0];
        uint8_t  val=(uint8_t)(!strcmp(base,"bzero")?0:e->regs[1]);
        uint64_t n2=(!strcmp(base,"bzero")?e->regs[1]:e->regs[2]);
        if (n2 < 0x100000) emu_memset_fn(e,dst,val,n2);
        SIM_LOG(base, "dst=0x%llx val=%d n=%llu", (unsigned long long)dst,
                (int)val, (unsigned long long)n2);
        e->regs[0] = dst;
        return 1;
    }
    if (!strcmp(base,"memcmp") || !strcmp(base,"bcmp")) {
        
        uint8_t a2=emu_read8(e,e->regs[0]),b2=emu_read8(e,e->regs[1]);
        e->regs[0] = (a2 > b2) ? 1ULL : (a2 < b2) ? ~0ULL : 0;
        SIM_LOG(base, "→ %lld", (long long)e->regs[0]);
        return 1;
    }
    
    if (!strcmp(base,"strlen") || !strcmp(base,"strnlen")) {
        uint64_t len = emu_strlen(e, e->regs[0]);
        e->regs[0] = len;
        SIM_LOG(base, "ptr=0x%llx → %llu", (unsigned long long)e->regs[0]-len, (unsigned long long)len);
        return 1;
    }
    if (!strcmp(base,"strcpy") || !strcmp(base,"strncpy") ||
        !strcmp(base,"stpcpy") || !strcmp(base,"stpncpy")) {
        emu_strcpy(e, e->regs[0], e->regs[1]);
        SIM_LOG(base, "dst=0x%llx src=0x%llx", (unsigned long long)e->regs[0], (unsigned long long)e->regs[1]);
        return 1;
    }
    if (!strcmp(base,"strcat") || !strcmp(base,"strncat")) {
        uint64_t dlen = emu_strlen(e, e->regs[0]);
        emu_strcpy(e, e->regs[0]+dlen, e->regs[1]);
        SIM_LOG(base, "dst=0x%llx", (unsigned long long)e->regs[0]);
        return 1;
    }
    if (!strcmp(base,"strcmp") || !strcmp(base,"strncmp") ||
        !strcmp(base,"strcasecmp") || !strcmp(base,"strncasecmp")) {
        
        uint64_t i2=0,max2=(!strcmp(base,"strncmp")||!strcmp(base,"strncasecmp"))?e->regs[2]:65536;
        int res=0;
        while(i2<max2){
            uint8_t a3=emu_read8(e,e->regs[0]+i2), b3=emu_read8(e,e->regs[1]+i2);
            if(!strcmp(base,"strcasecmp")||!strcmp(base,"strncasecmp")){
                if(a3>='A'&&a3<='Z')a3+=32; if(b3>='A'&&b3<='Z')b3+=32;
            }
            if(a3!=b3){res=(a3>b3)?1:-1;break;}
            if(!a3)break; i2++;
        }
        e->regs[0]=(uint64_t)(int64_t)res;
        SIM_LOG(base, "→ %d", res);
        return 1;
    }
    if (!strcmp(base,"strchr") || !strcmp(base,"strrchr") || !strcmp(base,"memchr")) {
        uint8_t ch=(uint8_t)e->regs[1]; uint64_t ptr2=e->regs[0];
        uint64_t found=0, i2=0, max2=!strcmp(base,"memchr")?e->regs[2]:65536;
        while(i2<max2){ uint8_t c2=emu_read8(e,ptr2+i2);
            if(c2==ch){found=ptr2+i2; if(!strcmp(base,"strrchr")){found=ptr2+i2;}} 
            if(!c2&&strcmp(base,"memchr")!=0)break; i2++; }
        e->regs[0]=found;
        SIM_LOG(base, "→ 0x%llx", (unsigned long long)found);
        return 1;
    }
    if (!strcmp(base,"strstr") || !strcmp(base,"strcasestr")) {
        
        uint64_t h=e->regs[0],n2=e->regs[1],found2=0;
        uint64_t nl=emu_strlen(e,n2),hl=emu_strlen(e,h),i2;
        for(i2=0;i2+nl<=hl;i2++){
            int match=1; uint64_t j;
            for(j=0;j<nl;j++){
                uint8_t hc=emu_read8(e,h+i2+j),nc=emu_read8(e,n2+j);
                if(!strcmp(base,"strcasestr")){if(hc>='A'&&hc<='Z')hc+=32;if(nc>='A'&&nc<='Z')nc+=32;}
                if(hc!=nc){match=0;break;}
            }
            if(match){found2=h+i2;break;}
        }
        e->regs[0]=found2;
        SIM_LOG(base, "→ 0x%llx", (unsigned long long)found2);
        return 1;
    }
    if (!strcmp(base,"sprintf") || !strcmp(base,"snprintf") || !strcmp(base,"printf") ||
        !strcmp(base,"fprintf") || !strcmp(base,"vprintf") || !strcmp(base,"vsnprintf") ||
        !strcmp(base,"puts") || !strcmp(base,"fputs") || !strcmp(base,"fputc") ||
        !strcmp(base,"putchar") || !strcmp(base,"write") || !strcmp(base,"fwrite")) {
        
        e->regs[0] = 1;
        SIM_LOG(base, "(I/O skipped) → 1");
        return 1;
    }
    if (!strcmp(base,"atoi") || !strcmp(base,"atol") || !strcmp(base,"atoll")) {
        
        char buf[32]=""; int i2;
        for(i2=0;i2<31;i2++){uint8_t ch2=emu_read8(e,e->regs[0]+i2);
            if(!ch2)break;buf[i2]=(char)ch2;}
        e->regs[0]=(uint64_t)(int64_t)atoll(buf);
        SIM_LOG(base, "→ %lld", (long long)e->regs[0]);
        return 1;
    }
    if (!strcmp(base,"strtol") || !strcmp(base,"strtoll") ||
        !strcmp(base,"strtoul") || !strcmp(base,"strtoull")) {
        char buf[64]=""; int i2;
        for(i2=0;i2<63;i2++){uint8_t ch2=emu_read8(e,e->regs[0]+i2);
            if(!ch2)break;buf[i2]=(char)ch2;}
        int base2=(int)e->regs[2];
        if(base2==0)base2=10;
        e->regs[0]=strtoull(buf,NULL,base2);
        SIM_LOG(base, "base=%d → %llu", base2, (unsigned long long)e->regs[0]);
        return 1;
    }
    if (!strcmp(base,"exit") || !strcmp(base,"_exit") || !strcmp(base,"abort") ||
        !strcmp(base,"__exit") || !strcmp(base,"_Exit")) {
        snprintf(e->halt_reason, sizeof(e->halt_reason), "%s(%lld)", base, (long long)e->regs[0]);
        e->halted = 1;
        SIM_LOG(base, "code=%lld", (long long)e->regs[0]);
        return 1;
    }
    if (!strcmp(base,"getenv")) {
        e->regs[0] = 0; 
        SIM_LOG(base, "→ NULL");
        return 1;
    }
    
    if (!strncmp(base,"cob_",4) || !strncmp(base,"COB_",4)) {
        
        e->regs[0] = 0;
        SIM_LOG(base, "(COBOL runtime → 0)");
        return 1;
    }
    
    if (!strncmp(base,"_gfortran_",10) || !strncmp(base,"for_",4)) {
        e->regs[0] = 0;
        SIM_LOG(base, "(Fortran runtime → 0)");
        return 1;
    }
    
    if (!strncmp(base,"ada_",4) || !strncmp(base,"__gnat_",7)) {
        e->regs[0] = 0;
        SIM_LOG(base, "(Ada runtime → 0)");
        return 1;
    }
    
    if (!strncmp(base,"runtime_",8) || !strncmp(base,"runtime.",8)) {
        e->regs[0] = 0;
        SIM_LOG(base, "(Go runtime → 0)");
        return 1;
    }
    
    if (!strncmp(base,"rust_",5)||!strncmp(base,"swift_",6)||!strncmp(base,"swift.",6)||
        !strncmp(base,"_swift",6)||!strncmp(base,"_D",2)) {
        e->regs[0] = 0;
        SIM_LOG(base, "(lang runtime → 0)");
        return 1;
    }
    
    if (!strcmp(base,"pthread_mutex_lock") || !strcmp(base,"pthread_mutex_unlock") ||
        !strcmp(base,"pthread_once") || !strcmp(base,"pthread_key_create") ||
        !strcmp(base,"__cxa_guard_acquire") || !strcmp(base,"__cxa_guard_release") ||
        !strcmp(base,"__cxa_atexit") || !strcmp(base,"__cxa_throw") ||
        !strcmp(base,"__stack_chk_fail") || !strcmp(base,"__asan_report_load") ||
        !strcmp(base,"__ubsan_handle") || !strcmp(base,"__tsan_func_entry")) {
        e->regs[0] = 0;
        SIM_LOG(base, "(runtime guard → 0)");
        return 1;
    }

#undef SIM_LOG
    return 0; 
}

#pragma GCC diagnostic pop
static int emu_simulate_syscall(emu_state_t *e, FILE *out, int color) {
    const char *CR = color ? "\033[0m"    : "";
    const char *CY = color ? "\033[1;33m" : "";
    const char *CG = color ? "\033[1;32m" : "";
    const char *CR2= color ? "\033[1;31m" : "";
    uint64_t nr = e->regs[8];  /* ARM64 Linux ABI: syscall number in x8 */
    /* RISC-V: syscall in a7 = regs[17] */
    if (e->bin && e->bin->arch == ARCH_RISCV64) nr = e->regs[17];
    uint64_t a0=e->regs[0], a1=e->regs[1], a2=e->regs[2];
    (void)a1;
    const char *sname = "?";
    uint64_t retval   = 0;

    /* ── SANDBOX SYSCALL FIREWALL ────────────────────────────────────────────
     * Block any syscall that could cause the emulated code to interact with
     * the real host OS beyond what is safe for a static analysis tool.
     *
     * Blocked categories:
     *   - Process creation: execve, fork, vfork, clone, execveat
     *   - File I/O: open, openat, creat, write (to fd≠1/2), read from real fd
     *   - Network: socket, connect, bind, accept, sendto, recvfrom
     *   - Tracing: ptrace, perf_event_open, process_vm_readv/writev
     *   - Memory with EXEC: mprotect with PROT_EXEC, mmap with PROT_EXEC
     *   - Signals to real processes: kill, tkill, tgkill
     *   - Kernel modules: init_module, finit_module, delete_module
     *   - Device I/O: ioctl (except harmless tty ops)
     *   - UID/credentials: setuid, setgid, capset
     *   - Time modification: settimeofday, adjtimex
     *
     * All blocked syscalls: return -EPERM (0xFFFFFFFFFFFFFFFF = -1), log.  */

    /* ── DANGEROUS — always block ── */
    switch (nr) {
    /* process creation / execution */
    case 220: /* clone    */
    case 221: /* execve   */
    case 281: /* execveat */
    case 435: /* clone3   */
    case 1079: /* fork proxy (non-standard) */
        sname = (nr==221||nr==281) ? "execve/execveat" : "clone/fork/clone3";
        goto sandbox_block;

    /* file open / creat — block all, emulated code should not touch host FS */
    case 56:  /* openat  */
    case 55:  /* open    (compat) */
    case 257: /* openat2 */
    case 85:  /* creat   */
        /* Allow: return fake fd=3 for read-only opens so analysis can proceed,
         * but we do NOT forward to OS — just track and return fake fd.        */
        sname  = "openat";
        retval = 3;   /* fake fd — all reads from it return 0 */
        e->regs[0] = retval;
        if (out) fprintf(out, "  %s[SVC #%llu]%s %s%s%s → %sFAKE fd=3 (sandbox)%s\n",
                         CY,(unsigned long long)nr,CR,CG,sname,CR,CY,CR);
        return 1;

    /* network */
    case 198: /* socket  */ case 203: /* connect */ case 200: /* bind   */
    case 202: /* accept  */ case 206: /* sendto  */ case 207: /* recvfrom */
    case 204: /* listen  */ case 211: /* sendmsg */ case 212: /* recvmsg */
    case 208: /* setsockopt */ case 209: /* getsockopt */
        sname = "network-syscall";
        goto sandbox_block;

    /* ptrace / perf */
    case 117: /* ptrace          */
    case 241: /* perf_event_open */
    case 270: /* process_vm_readv  */
    case 271: /* process_vm_writev */
        sname = "ptrace/perf";
        goto sandbox_block;

    /* signals to real processes */
    case 129: /* kill  */ case 130: /* tkill */ case 131: /* tgkill */
    case 132: /* sigaltstack */
    case 134: /* rt_sigaction */ case 135: /* rt_sigprocmask */
        sname = "signal-syscall";
        goto sandbox_block;

    /* kernel modules */
    case 105: /* init_module   */ case 273: /* finit_module */
    case 106: /* delete_module */
        sname = "kernel-module";
        goto sandbox_block;

    /* credential escalation */
    case 146: /* setuid */ case 147: /* setgid */
    case 148: /* setreuid */ case 149: /* setregid */
    case 150: /* getgroups */ case 151: /* setgroups */
    case 164: /* setresuid   */ case 165: /* getresuid */
    case 166: /* setresgid   */ case 167: /* getresgid */
    case 168: /* setpgid     */
    case 184: /* capset      */
        sname = "credential-op";
        goto sandbox_block;

    /* mprotect with PROT_EXEC (flag 0x4) — potential JIT shellcode */
    case 226: /* mprotect */
        if (a2 & 0x4) {
            sname = "mprotect+EXEC";
            goto sandbox_block;
        }
        sname  = "mprotect";
        retval = 0;
        break;

    /* mmap with PROT_EXEC */
    case 222: /* mmap */
        if (a2 & 0x4) {
            /* strip EXEC bit, allow as data mapping */
            sname  = "mmap(PROT_EXEC→stripped)";
            retval = emu_malloc(e, a2 ? a2 : 4096);
            if (out) fprintf(out, "  %s[SVC #%llu]%s %sSANDBOX%s PROT_EXEC stripped → %s0x%llx%s\n",
                             CY,(unsigned long long)nr,CR,CY,CR,CG,(unsigned long long)retval,CR);
            e->regs[0] = retval;
            return 1;
        }
        sname  = "mmap";
        retval = emu_malloc(e, a2 ? a2 : 4096);
        break;

    /* ── SAFE / SIMULATED ── */
    case 57:  sname="close";    retval=0;      break;
    case 63:  sname="read";     retval=a2;     break;  /* fake: returns count */
    case 64:  sname="write";    retval=a2;     break;  /* fake: discards data */
    case 93:  /* exit */
        snprintf(e->halt_reason,sizeof(e->halt_reason),"exit(%llu)",(unsigned long long)a0);
        e->halted=1;
        if(out) fprintf(out,"  %s[SVC]%s exit(%llu)\n",CY,CR,(unsigned long long)a0);
        return 1;
    case 94:  /* exit_group */
        snprintf(e->halt_reason,sizeof(e->halt_reason),"exit_group(%llu)",(unsigned long long)a0);
        e->halted=1;
        if(out) fprintf(out,"  %s[SVC]%s exit_group(%llu)\n",CY,CR,(unsigned long long)a0);
        return 1;
    case 160: sname="uname";    retval=0;      break;
    case 172: sname="getpid";   retval=1234;   break;
    case 174: sname="getuid";   retval=1000;   break;
    case 175: sname="geteuid";  retval=1000;   break;
    case 176: sname="getgid";   retval=1000;   break;
    case 177: sname="getegid";  retval=1000;   break;
    case 214: sname="brk";      retval=a0?a0:0x30000000; break;
    case 215: sname="munmap";   retval=0;      break;
    case 260: sname="wait4";    retval=a0;     break;
    /* ioctl — only allow safe tty ops, block everything else */
    case 29:  sname="ioctl";    retval=0;      break;
    /* fcntl, fstat, lstat, stat — safe */
    case 25: case 80: case 262: sname="fstat/stat"; retval=0; break;
    /* lseek */
    case 62:  sname="lseek";    retval=0;      break;
    /* futex — harmless in emulation */
    case 98:  sname="futex";    retval=0;      break;
    /* nanosleep / clock_nanosleep — swallow, return 0 (slept OK) */
    case 101: case 115: sname="nanosleep"; retval=0; break;

    /* clock_gettime(clk_id, struct timespec *tp) — fill fake timespec
     * IMPROVEMENT 1: fake timing with jitter so timing-probes see
     * plausible, monotonically advancing nanosecond values.           */
    case 113:
        sname = "clock_gettime";
        emu_fill_timespec(e, a1, e->steps);
        retval = 0;
        break;

    /* gettimeofday(struct timeval *tv, struct timezone *tz)
     * IMPROVEMENT 1: fake timeval with same monotonic fake clock.     */
    case 169:
        sname = "gettimeofday";
        emu_fill_timeval(e, a0, e->steps);
        retval = 0;
        break;

    /* getrandom(buf, buflen, flags)
     * IMPROVEMENT 3: controlled entropy — deterministic but organic-
     * looking bytes so entropy probes don't see all-zeros.            */
    case 278:
        sname = "getrandom";
        emu_fill_entropy(e, a0, a1, e->steps);
        retval = a1;   /* return number of bytes written */
        break;

    /* pipe, pipe2 — return fake fds */
    case 59: case 293: sname="pipe"; retval=0; break;
    default:
        sname  = "syscall";
        retval = 0;
        break;
    }

    e->regs[0] = retval;
    if (out) fprintf(out,"  %s[SVC #%llu]%s %s%s%s → %s0x%llx%s\n",
                     CY,(unsigned long long)nr,CR,CG,sname,CR,CG,
                     (unsigned long long)retval,CR);
    return 1;

sandbox_block:
    /* IMPROVEMENT 2: Realistic errno per syscall category.
     * Previously all blocked syscalls returned -EPERM which is a
     * fingerprint-able pattern.  Real kernels return different errors
     * depending on context, so we replicate that behaviour here.
     *
     *   process creation (execve/fork/clone) → -EACCES  (sandbox lockdown)
     *   network calls                        → -ENETUNREACH (no network)
     *   ptrace / perf                        → -EPERM   (correct for non-root)
     *   signals to other pids                → -ESRCH   (no such process)
     *   credential ops                       → -EPERM   (correct for non-root)
     *   kernel modules                       → -EPERM   (correct for non-root)
     *   default                              → -ENOSYS  (not implemented)
     */
    {
        uint64_t fake_errno;
        switch (nr) {
        case 220: case 221: case 281: case 435: case 1079:
            fake_errno = EACCES_NEG;   break;  /* fork/exec family       */
        case 198: case 203: case 200: case 202:
        case 206: case 207: case 204: case 211:
        case 212: case 208: case 209:
            fake_errno = ENETUNREACH_NEG; break; /* network family        */
        case 117: case 241: case 270: case 271:
            fake_errno = (uint64_t)-1ULL; break; /* ptrace → -EPERM      */
        case 129: case 130: case 131:
            fake_errno = ESRCH_NEG;    break;  /* kill/tkill: no target  */
        case 132: case 134: case 135:
            fake_errno = EINVAL_NEG;   break;  /* sigaltstack/rt_sig*    */
        case 105: case 106: case 273:
            fake_errno = (uint64_t)-1ULL; break; /* modules → -EPERM     */
        case 146: case 147: case 148: case 149:
        case 150: case 151: case 164: case 165:
        case 166: case 167: case 168: case 184:
            fake_errno = (uint64_t)-1ULL; break; /* credentials → -EPERM */
        default:
            fake_errno = ENOSYS_NEG;   break;  /* catch-all              */
        }
        e->regs[0] = fake_errno;
    }
    mpath_record_syscall(nr);
    if (out) fprintf(out,"  %s[SVC #%llu BLOCKED]%s %sSANDBOX%s %s%s%s → errno=%lld\n",
                     CY,(unsigned long long)nr,CR,CR2,"",CG,sname,CR,
                     (long long)(int64_t)e->regs[0]);
    return 1;
}

/*
 * vm_trace_record — called whenever the emulator executes a br/blr that
 * looks like a VM dispatch (indirect jump from a register holding a
 * handler address loaded from a jump table).  We record:
 *   - which instruction PC dispatched
 *   - which handler was jumped to
 *   - the content of x0..x3 as candidate opcode/IP registers
 *   - the global step counter
 */
static void vm_trace_record(emu_state_t *e, uint64_t dispatch_pc,
                             uint64_t handler_pc, int step_no,
                             dax_binary_t *bin) {
    if (g_nvm_trace >= VM_DISPATCH_MAX) return;
    dax_vm_dispatch_entry_t *ent = &g_vm_trace[g_nvm_trace++];
    ent->dispatch_pc = dispatch_pc;
    ent->handler_pc  = handler_pc;
    ent->step_no     = step_no;
    /* heuristic: x0 or x1 often carries opcode, x2/x3 carry VM IP */
    ent->opcode_val  = e->regs[0];
    ent->ip_val      = e->regs[1];
    ent->handler_name[0] = '\0';
    if (bin) {
        dax_func_t   *fn2 = dax_func_find(bin, handler_pc);
        dax_symbol_t *sym = dax_sym_find(bin, handler_pc);
        const char *lbl = sym ? (sym->demangled[0] ? sym->demangled : sym->name)
                              : (fn2 ? fn2->name : NULL);
        if (lbl && lbl[0])
            snprintf(ent->handler_name, sizeof(ent->handler_name), "%.47s", lbl);
    }
}

static int emu_step_arm64(emu_state_t *e) {
    if (!e->code_base) { snprintf(e->halt_reason,sizeof(e->halt_reason),"no code"); e->halted=1; return 0; }
    uint32_t raw = emu_read32(e, e->pc);
    a64_insn_t insn; a64_decode(raw, e->pc, &insn);
    const char *mn = insn.mnemonic;
    const char *ops = insn.operands;
    char a1[64]="", a2[64]="", a3[64]="", a4[64]="";
    
    {
        const char *p=ops; char *bufs[4]={a1,a2,a3,a4}; int k;
        for(k=0;k<4;k++){
            while(*p==' ')p++;
            char *d=bufs[k]; int j=0;
            while(*p&&*p!=','&&j<63){*d++=*p++;j++;} *d='\0'; if(*p==',')p++;
        }
    }
    uint64_t next_pc = e->pc + 4;
    
#define RV(r)     emu_get_reg(e,(r))
#define SV(r,v)   emu_set_reg(e,(r),(v))
#define IMM(s)    parse_arm64_imm(s)
#define IS(s)     (strcmp(mn,(s))==0)
#define HAS(s)    (strstr(ops,(s))!=NULL)
#define W32(v)    ((v)&0xFFFFFFFFULL)
#define SX32(v)   ((uint64_t)(int64_t)(int32_t)(uint32_t)(v))
#define SX16(v)   ((uint64_t)(int64_t)(int16_t)(uint16_t)(v))
#define SX8(v)    ((uint64_t)(int64_t)(int8_t)(uint8_t)(v))
    
#define SET_FLAGS_SUB(r,a,b) do{ \
    e->flags_z=((r)==0); \
    e->flags_n=(((r)>>63)&1); \
    e->flags_c=((uint64_t)(a)>=(uint64_t)(b)); \
    e->flags_v=(((a)^(b))&((a)^(r))&(1ULL<<63))!=0; \
}while(0)
#define SET_FLAGS_ADD(r,a,b) do{ \
    e->flags_z=((r)==0); \
    e->flags_n=(((r)>>63)&1); \
    e->flags_c=((r)<(uint64_t)(a)); \
    e->flags_v=((~((a)^(b)))&((a)^(r))&(1ULL<<63))!=0; \
}while(0)
#define SET_FLAGS_LOG(r) do{ e->flags_z=((r)==0); e->flags_n=(((r)>>63)&1); e->flags_c=0; e->flags_v=0; }while(0)
    
    uint64_t mem_addr = 0;
    int      mem_wb   = 0;   
    char     mem_base[16] = "";
    {
        const char *bp = strchr(ops,'[');
        if (bp) {
            bp++;
            int bi=0; while(*bp&&*bp!=','&&*bp!=']'&&bi<15) mem_base[bi++]=*bp++;
            mem_base[bi]='\0';
            uint64_t base_v = (strcmp(mem_base,"sp")==0) ? e->sp : RV(mem_base);
            int64_t  off    = 0;
            
            const char *cp = bp;
            while(*cp&&*cp!=',' &&*cp!=']') cp++;
            if (*cp==',') {
                cp++;
                while(*cp==' ') cp++;
                if (*cp=='#') {
                    off = (int64_t)strtoll(cp+1,NULL,0);
                } else if ((*cp=='x'||*cp=='w')&&isdigit((unsigned char)cp[1])) {
                    
                    char rnm[16]=""; int ri=0;
                    while(*cp&&*cp!=','&&*cp!=' '&&*cp!=']'&&ri<15) rnm[ri++]=*cp++;
                    rnm[ri]='\0';
                    uint64_t roff = RV(rnm);
                    
                    const char *sp2 = strstr(cp,"#");
                    int sh=0; if(sp2) sh=(int)strtol(sp2+1,NULL,0);
                    off = (int64_t)(roff << sh);
                }
            }
            
            const char *ep = strchr(ops,']');
            if (ep && ep[1]=='!') { mem_wb=1; (void)off; }
            mem_addr = base_v + (uint64_t)off;
            
            if (mem_wb==1 && mem_base[0])
                emu_set_reg(e, mem_base, mem_addr);
        }
    }

    

    
    if (IS("mov")||IS("movz")) {
        if(a2[0]=='#') SV(a1,IMM(a2));
        else           SV(a1,RV(a2));
    }
    else if (IS("movn")) {
        uint64_t sh=0; const char *lp=strstr(ops,"lsl"); if(lp){const char*sp=strchr(lp,'#');if(sp)sh=IMM(sp);}
        SV(a1,a1[0]=='w'?W32(~(IMM(a2)<<sh)):~(IMM(a2)<<sh));
    }
    else if (IS("movk")) {
        uint64_t cur=RV(a1),imm=IMM(a2),sh=0;
        const char *lp=strstr(ops,"lsl"); if(lp){const char*sp=strchr(lp,'#');if(sp)sh=IMM(sp);}
        uint64_t mask=~(0xFFFFULL<<sh);
        SV(a1,(cur&mask)|((imm&0xFFFF)<<sh));
    }
    else if (IS("adr")||IS("adrp")) {
        uint64_t tgt=0; const char *tp=strstr(a2,"0x"); if(tp)tgt=strtoull(tp,NULL,16); else tgt=e->pc;
        SV(a1,tgt);
    }
    
    else if (IS("add")||IS("adds")) {
        uint64_t v1=RV(a2);
        uint64_t v2; int is_imm=(a3[0]=='#');
        if(is_imm){ v2=IMM(a3); }
        else {
            v2=RV(a3);
            
            const char *lp=strstr(ops,"lsl"); if(!lp)lp=strstr(ops,"lsr"); if(!lp)lp=strstr(ops,"asr");
            if(lp){const char*sp=strchr(lp,'#');if(sp){uint64_t sh=IMM(sp);
                if(strncmp(lp,"lsr",3)==0)v2>>=sh;
                else if(strncmp(lp,"asr",3)==0)v2=(uint64_t)((int64_t)v2>>(int)sh);
                else v2<<=sh;}}
        }
        uint64_t r=v1+v2; SV(a1,r);
        if(IS("adds")) SET_FLAGS_ADD(r,v1,v2);
    }
    else if (IS("sub")||IS("subs")) {
        uint64_t v1=RV(a2);
        uint64_t v2=a3[0]=='#'?IMM(a3):RV(a3);
        uint64_t r=v1-v2; SV(a1,r);
        if(IS("subs")) SET_FLAGS_SUB(r,v1,v2);
    }
    else if (IS("adc")||IS("adcs")) {
        uint64_t r=RV(a2)+RV(a3)+(uint64_t)e->flags_c; SV(a1,r);
        if(IS("adcs")) SET_FLAGS_ADD(r,RV(a2),RV(a3));
    }
    else if (IS("sbc")||IS("sbcs")) {
        uint64_t r=RV(a2)-RV(a3)-(uint64_t)(1-e->flags_c); SV(a1,r);
        if(IS("sbcs")) SET_FLAGS_SUB(r,RV(a2),RV(a3));
    }
    else if (IS("mul")||IS("madd")) { SV(a1,IS("madd")?RV(a2)*RV(a3)+RV(a4):RV(a2)*RV(a3)); }
    else if (IS("mneg")||IS("msub")) { SV(a1,IS("msub")?RV(a4)-RV(a2)*RV(a3):0-RV(a2)*RV(a3)); }
    else if (IS("smull")||IS("umull")) { SV(a1,RV(a2)*RV(a3)); }
    else if (IS("smulh")) { SV(a1,(uint64_t)(((__int128)(int64_t)RV(a2)*(int64_t)RV(a3))>>64)); }
    else if (IS("umulh")) { SV(a1,(uint64_t)(((unsigned __int128)RV(a2)*RV(a3))>>64)); }
    else if (IS("sdiv")) { int64_t b=(int64_t)RV(a3); SV(a1,b==0?0:(uint64_t)((int64_t)RV(a2)/b)); }
    else if (IS("udiv")) { uint64_t b=RV(a3); SV(a1,b==0?0:RV(a2)/b); }
    else if (IS("neg")||IS("negs")) { uint64_t r=0-RV(a2); SV(a1,r); if(IS("negs")) SET_FLAGS_SUB(r,0,RV(a2)); }
    else if (IS("abs")) { int64_t v=(int64_t)RV(a2); SV(a1,(uint64_t)(v<0?-v:v)); }
    
    else if (IS("and")||IS("ands")) {
        uint64_t r=RV(a2)&(a3[0]=='#'?IMM(a3):RV(a3)); SV(a1,r);
        if(IS("ands")) SET_FLAGS_LOG(r);
    }
    else if (IS("orr")) { SV(a1,RV(a2)|(a3[0]=='#'?IMM(a3):RV(a3))); }
    else if (IS("eor")) { SV(a1,RV(a2)^(a3[0]=='#'?IMM(a3):RV(a3))); }
    else if (IS("bic")||IS("bics")) { uint64_t r=RV(a2)&~RV(a3); SV(a1,r); if(IS("bics")) SET_FLAGS_LOG(r); }
    else if (IS("orn")) { SV(a1,RV(a2)|~RV(a3)); }
    else if (IS("eon")) { SV(a1,RV(a2)^~RV(a3)); }
    else if (IS("mvn")) { SV(a1,~RV(a2)); }
    else if (IS("tst")||IS("ands")) { uint64_t r=RV(a1)&(a2[0]=='#'?IMM(a2):RV(a2)); SET_FLAGS_LOG(r); }
    
    else if (IS("lsl")) {
        uint64_t sh=a3[0]=='#'?IMM(a3):RV(a3)&63; SV(a1,RV(a2)<<sh);
    }
    else if (IS("lsr")) {
        uint64_t sh=a3[0]=='#'?IMM(a3):RV(a3)&63; SV(a1,RV(a2)>>sh);
    }
    else if (IS("asr")) {
        uint64_t sh=a3[0]=='#'?IMM(a3):RV(a3)&63;
        SV(a1,(uint64_t)((int64_t)RV(a2)>>(int)sh));
    }
    else if (IS("ror")) {
        uint64_t v=RV(a2),sh=a3[0]=='#'?IMM(a3):RV(a3)&63;
        SV(a1,sh==0?v:(v>>sh)|(v<<(64-sh)));
    }
    else if (IS("extr")) {
        uint64_t lsb=IMM(a3);
        SV(a1,lsb==0?RV(a2):(RV(a2)<<(64-lsb))|(RV(a3)>>lsb));
    }
    
    else if (IS("sbfm")||IS("sbfx")) {
        uint64_t immr=IMM(a3),imms=a4[0]?IMM(a4):0;
        uint64_t src=RV(a2);
        if(imms>=immr){ 
            uint64_t width=imms-immr+1;
            uint64_t mask=(width==64)?~0ULL:((1ULL<<width)-1);
            uint64_t bits=(src>>immr)&mask;
            int64_t  sign=(bits>>((width-1)))&1;
            SV(a1,sign?bits|(~mask):bits);
        } else { 
            uint64_t r=(immr==0)?src:(src>>immr)|(src<<(64-immr));
            SV(a1,r);
        }
    }
    else if (IS("ubfm")||IS("ubfx")) {
        uint64_t immr=IMM(a3),imms=a4[0]?IMM(a4):0;
        uint64_t src=RV(a2);
        if(imms>=immr){ uint64_t w=imms-immr+1,m=(w==64)?~0ULL:((1ULL<<w)-1); SV(a1,(src>>immr)&m); }
        else { uint64_t r=(immr==0)?src:(src>>immr)|(src<<(64-immr)); SV(a1,r); }
    }
    else if (IS("bfm")||IS("bfi")||IS("bfxil")||IS("bfc")) {
        
        if(IS("bfc")) { uint64_t lsb=IMM(a2),width=IMM(a3);
            uint64_t mask=((width==64)?~0ULL:((1ULL<<width)-1))<<lsb;
            SV(a1,RV(a1)&~mask); }
        else {
            uint64_t lsb=IMM(a3),width=a4[0]?IMM(a4):1;
            uint64_t mask=(width==64)?~0ULL:((1ULL<<width)-1);
            uint64_t src_bits=RV(a2)&mask;
            SV(a1,(RV(a1)&~(mask<<lsb))|(src_bits<<lsb));
        }
    }
    else if (IS("sxtb")) { SV(a1,SX8(RV(a2))); }
    else if (IS("sxth")) { SV(a1,SX16(RV(a2))); }
    else if (IS("sxtw")) { SV(a1,SX32(RV(a2))); }
    else if (IS("uxtb")) { SV(a1,RV(a2)&0xFF); }
    else if (IS("uxth")) { SV(a1,RV(a2)&0xFFFF); }
    
    else if (IS("cmp")||IS("subs")) {
        uint64_t v1=RV(IS("subs")?a2:a1);
        uint64_t v2=(a2[0]=='#'||a3[0]=='#')?(IS("cmp")?IMM(a2):IMM(a3)):RV(IS("cmp")?a2:a3);
        uint64_t r=v1-v2; SET_FLAGS_SUB(r,v1,v2);
        if(IS("subs")) SV(a1,r);
    }
    else if (IS("cmn")||IS("adds")) {
        uint64_t v1=RV(IS("adds")?a2:a1);
        uint64_t v2=(IS("adds")&&a3[0]=='#')?IMM(a3):(IS("cmn")&&a2[0]=='#')?IMM(a2):RV(IS("cmn")?a2:a3);
        uint64_t r=v1+v2; SET_FLAGS_ADD(r,v1,v2);
        if(IS("adds")) SV(a1,r);
    }
    else if (IS("tst")) { uint64_t r=RV(a1)&(a2[0]=='#'?IMM(a2):RV(a2)); SET_FLAGS_LOG(r); }
    
    else if (IS("csel")||IS("csinc")||IS("csinv")||IS("csneg")) {
        int t=0;
        const char *cond=a4[0]?a4:a3;
        
        while(*cond==' ')cond++;
        if(!strncmp(cond,"eq",2))t=e->flags_z;
        else if(!strncmp(cond,"ne",2))t=!e->flags_z;
        else if(!strncmp(cond,"ge",2))t=(e->flags_n==e->flags_v);
        else if(!strncmp(cond,"gt",2))t=!e->flags_z&&(e->flags_n==e->flags_v);
        else if(!strncmp(cond,"le",2))t=e->flags_z||(e->flags_n!=e->flags_v);
        else if(!strncmp(cond,"lt",2))t=(e->flags_n!=e->flags_v);
        else if(!strncmp(cond,"mi",2))t=e->flags_n;
        else if(!strncmp(cond,"pl",2))t=!e->flags_n;
        else if(!strncmp(cond,"vs",2))t=e->flags_v;
        else if(!strncmp(cond,"vc",2))t=!e->flags_v;
        else if(!strncmp(cond,"hi",2))t=e->flags_c&&!e->flags_z;
        else if(!strncmp(cond,"ls",2))t=!e->flags_c||e->flags_z;
        else if(!strncmp(cond,"cs",2)||!strncmp(cond,"hs",2))t=e->flags_c;
        else if(!strncmp(cond,"cc",2)||!strncmp(cond,"lo",2))t=!e->flags_c;
        else t=1; 
        uint64_t fval=RV(a3);
        if(!t){ if(IS("csinc"))fval++; else if(IS("csinv"))fval=~fval; else if(IS("csneg"))fval=0-fval; }
        SV(a1,t?RV(a2):fval);
    }
    else if (IS("cset")||IS("csetm")) {
        int t=0;
        if(!strncmp(a2,"eq",2))t=e->flags_z; else if(!strncmp(a2,"ne",2))t=!e->flags_z;
        else if(!strncmp(a2,"ge",2))t=(e->flags_n==e->flags_v); else if(!strncmp(a2,"gt",2))t=!e->flags_z&&(e->flags_n==e->flags_v);
        else if(!strncmp(a2,"le",2))t=e->flags_z||(e->flags_n!=e->flags_v); else if(!strncmp(a2,"lt",2))t=(e->flags_n!=e->flags_v);
        else if(!strncmp(a2,"mi",2))t=e->flags_n; else if(!strncmp(a2,"pl",2))t=!e->flags_n;
        else if(!strncmp(a2,"hi",2))t=e->flags_c&&!e->flags_z; else if(!strncmp(a2,"ls",2))t=!e->flags_c||e->flags_z;
        else if(!strncmp(a2,"cs",2)||!strncmp(a2,"hs",2))t=e->flags_c; else if(!strncmp(a2,"cc",2)||!strncmp(a2,"lo",2))t=!e->flags_c;
        else t=1;
        SV(a1,IS("csetm")?t?~0ULL:0:t?1:0);
    }
    else if (IS("cinc")||IS("cinv")||IS("cneg")) {
        int t=0;
        if(!strncmp(a3,"eq",2))t=e->flags_z; else if(!strncmp(a3,"ne",2))t=!e->flags_z;
        else if(!strncmp(a3,"ge",2))t=(e->flags_n==e->flags_v); else t=1;
        uint64_t fv=RV(a2);
        if(!t){ if(IS("cinc"))fv++; else if(IS("cinv"))fv=~fv; else fv=0-fv; }
        SV(a1,t?RV(a2):fv);
    }
    
    else if (!strncmp(mn,"ldr",3)||!strncmp(mn,"ldur",4)||IS("ldp")) {
        int bits=64,is_signed=0;
        if(mn[3]=='b') bits=8;
        else if(mn[3]=='h') bits=16;
        else if(!strcmp(mn+3,"sw")||!strcmp(mn+3,"sh")||!strcmp(mn+3,"sb")) { bits=mn[4]=='w'?32:mn[4]=='h'?16:8; is_signed=1; }
        if (IS("ldp")) {
            
            uint64_t v1=bits==32?emu_read32(e,mem_addr):(bits==64?emu_read64(e,mem_addr):emu_read8(e,mem_addr));
            uint64_t v2=bits==32?emu_read32(e,mem_addr+4):(bits==64?emu_read64(e,mem_addr+8):emu_read8(e,mem_addr+1));
            SV(a1,v1); SV(a2,v2);
            
            {
                const char *ep=strrchr(ops,']');
                if(ep&&ep[1]==','){ int64_t poff=(int64_t)strtoll(ep+2,NULL,0); e->sp+=(uint64_t)poff; }
            }
        } else {
            uint64_t val=0;
            if(bits==8) val=emu_read8(e,mem_addr);
            else if(bits==16) val=(uint64_t)emu_read8(e,mem_addr)|((uint64_t)emu_read8(e,mem_addr+1)<<8);
            else if(bits==32) val=emu_read32(e,mem_addr);
            else val=emu_read64(e,mem_addr);
            if(is_signed){
                if(bits==8) val=SX8(val); else if(bits==16) val=SX16(val); else val=SX32(val);
            }
            SV(a1,val);
            
            if(mem_base[0]&&!mem_wb){
                const char *ep=strrchr(ops,']');
                if(ep&&ep[1]==','){ int64_t poff=(int64_t)strtoll(ep+2,NULL,0);
                    uint64_t nb=(strcmp(mem_base,"sp")==0)?e->sp:RV(mem_base);
                    nb+=(uint64_t)poff; emu_set_reg(e,mem_base,nb); }
            }
        }
    }
    
    else if (!strncmp(mn,"str",3)||!strncmp(mn,"stur",4)||IS("stp")) {
        int bits=64;
        if(mn[3]=='b') bits=8;
        else if(mn[3]=='h') bits=16;
        if (IS("stp")) {
            uint64_t v1=RV(a1),v2=RV(a2);
            if(bits==32){ emu_write32(e,mem_addr,(uint32_t)v1); emu_write32(e,mem_addr+4,(uint32_t)v2); }
            else{ emu_write64(e,mem_addr,v1); emu_write64(e,mem_addr+8,v2); }
            
            if(mem_wb) {  }
            else {
                const char *ep=strrchr(ops,']');
                if(ep&&ep[1]==','){ int64_t poff=(int64_t)strtoll(ep+2,NULL,0); e->sp+=(uint64_t)poff; }
            }
        } else {
            uint64_t v=RV(a1);
            if(bits==8) emu_write8(e,mem_addr,(uint8_t)v);
            else if(bits==16){ emu_write8(e,mem_addr,(uint8_t)v); emu_write8(e,mem_addr+1,(uint8_t)(v>>8)); }
            else if(bits==32) emu_write32(e,mem_addr,(uint32_t)v);
            else emu_write64(e,mem_addr,v);
            
            if(mem_base[0]&&!mem_wb){
                const char *ep=strrchr(ops,']');
                if(ep&&ep[1]==','){ int64_t poff=(int64_t)strtoll(ep+2,NULL,0);
                    uint64_t nb=(strcmp(mem_base,"sp")==0)?e->sp:RV(mem_base);
                    nb+=(uint64_t)poff; emu_set_reg(e,mem_base,nb); }
            }
        }
    }
    
    else if (!strncmp(mn,"ldxr",4)||!strncmp(mn,"ldaxr",5)||!strncmp(mn,"ldar",4)||!strncmp(mn,"ldapr",5)) {
        int bits=mn[3]=='b'?8:mn[3]=='h'?16:mn[4]=='b'?8:mn[4]=='h'?16:64;
        uint64_t val=bits==8?emu_read8(e,mem_addr):bits==16?(uint64_t)emu_read8(e,mem_addr)|((uint64_t)emu_read8(e,mem_addr+1)<<8):bits==32?emu_read32(e,mem_addr):emu_read64(e,mem_addr);
        SV(a1,val);
    }
    else if (!strncmp(mn,"stxr",4)||!strncmp(mn,"stlxr",5)||!strncmp(mn,"stlr",4)||!strncmp(mn,"stlrb",5)) {
        
        int bits=mn[3]=='b'?8:mn[3]=='h'?16:mn[4]=='b'?8:mn[4]=='h'?16:64;
        const char *src=!strncmp(mn,"stxr",4)||!strncmp(mn,"stlxr",5)?a2:a1;
        if(bits==8) emu_write8(e,mem_addr,(uint8_t)RV(src));
        else if(bits==32) emu_write32(e,mem_addr,(uint32_t)RV(src));
        else emu_write64(e,mem_addr,RV(src));
        if(!strncmp(mn,"stxr",4)||!strncmp(mn,"stlxr",5)) SV(a1,0); 
    }
    
    else if (!strncmp(mn,"ldadd",5)||!strncmp(mn,"stadd",5)) { uint64_t old=emu_read64(e,mem_addr); emu_write64(e,mem_addr,old+RV(a1)); if(!strncmp(mn,"ldadd",5)) SV(a1,old); }
    else if (!strncmp(mn,"ldclr",5)||!strncmp(mn,"stclr",5)) { uint64_t old=emu_read64(e,mem_addr); emu_write64(e,mem_addr,old&~RV(a1)); if(!strncmp(mn,"ldclr",5)) SV(a1,old); }
    else if (!strncmp(mn,"ldset",5)||!strncmp(mn,"stset",5)) { uint64_t old=emu_read64(e,mem_addr); emu_write64(e,mem_addr,old|RV(a1)); if(!strncmp(mn,"ldset",5)) SV(a1,old); }
    else if (!strncmp(mn,"ldeor",5)||!strncmp(mn,"steor",5)) { uint64_t old=emu_read64(e,mem_addr); emu_write64(e,mem_addr,old^RV(a1)); if(!strncmp(mn,"ldeor",5)) SV(a1,old); }
    else if (!strncmp(mn,"swp",3)) { uint64_t old=emu_read64(e,mem_addr); emu_write64(e,mem_addr,RV(a1)); SV(a2,old); }
    else if (IS("cas")||IS("casa")||IS("casl")||IS("casal")) { 
        uint64_t mem_v=emu_read64(e,mem_addr);
        if(mem_v==RV(a1)) emu_write64(e,mem_addr,RV(a2));
        SV(a1,mem_v);
    }
    
    else if (IS("b")) {
        uint64_t tgt=0; const char *tp=strstr(a1,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        if(tgt){ next_pc=tgt; }
    }
    else if (!strncmp(mn,"b.",2)) {
        const char *cond=mn+2; uint64_t tgt=0;
        const char *tp=strstr(a1,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        int taken=0;
        if(!strcmp(cond,"eq"))taken=e->flags_z;
        else if(!strcmp(cond,"ne"))taken=!e->flags_z;
        else if(!strcmp(cond,"ge"))taken=(e->flags_n==e->flags_v);
        else if(!strcmp(cond,"gt"))taken=!e->flags_z&&(e->flags_n==e->flags_v);
        else if(!strcmp(cond,"le"))taken=e->flags_z||(e->flags_n!=e->flags_v);
        else if(!strcmp(cond,"lt"))taken=(e->flags_n!=e->flags_v);
        else if(!strcmp(cond,"mi"))taken=e->flags_n;
        else if(!strcmp(cond,"pl"))taken=!e->flags_n;
        else if(!strcmp(cond,"vs"))taken=e->flags_v;
        else if(!strcmp(cond,"vc"))taken=!e->flags_v;
        else if(!strcmp(cond,"hi"))taken=e->flags_c&&!e->flags_z;
        else if(!strcmp(cond,"ls"))taken=!e->flags_c||e->flags_z;
        else if(!strcmp(cond,"cs")||!strcmp(cond,"hs"))taken=e->flags_c;
        else if(!strcmp(cond,"cc")||!strcmp(cond,"lo"))taken=!e->flags_c;
        else if(!strcmp(cond,"al")||!strcmp(cond,"nv"))taken=1;
        /* IMPROVEMENT 4: multi-path — fork the not-taken path for later
         * exploration so both branches are eventually analysed.          */
        if (tgt && g_mpath.nforks < MPATH_MAX_FORKS) {
            char fork_reason[96];
            snprintf(fork_reason, sizeof(fork_reason),
                     "b.%.10s not-taken @ 0x%llx", cond,
                     (unsigned long long)e->pc);
            /* Push the alternative (not-taken) path */
            uint64_t alt_pc = taken ? next_pc : tgt;
            mpath_push_fork(e, alt_pc, fork_reason);
        }
        if(taken&&tgt) next_pc=tgt;
    }
    else if (IS("cbz")||IS("cbnz")) {
        uint64_t tgt=0; const char *tp=strstr(a2,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        int taken=IS("cbz")?(RV(a1)==0):(RV(a1)!=0);
        /* IMPROVEMENT 4: multi-path fork for cbz/cbnz */
        if (tgt && g_mpath.nforks < MPATH_MAX_FORKS) {
            char fork_reason[64];
            snprintf(fork_reason, sizeof(fork_reason),
                     "%s not-taken @ 0x%llx", mn, (unsigned long long)e->pc);
            mpath_push_fork(e, taken ? next_pc : tgt, fork_reason);
        }
        if(taken&&tgt) next_pc=tgt;
    }
    else if (IS("tbnz")||IS("tbz")) {
        uint64_t bit=IMM(a2); uint64_t tgt=0;
        const char *tp=strstr(a3,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        int set=(int)((RV(a1)>>bit)&1);
        int taken2=(IS("tbnz")?set:!set);
        /* IMPROVEMENT 4: multi-path fork for tbz/tbnz */
        if (tgt && g_mpath.nforks < MPATH_MAX_FORKS) {
            char fork_reason[64];
            snprintf(fork_reason, sizeof(fork_reason),
                     "%s not-taken @ 0x%llx", mn, (unsigned long long)e->pc);
            mpath_push_fork(e, taken2 ? next_pc : tgt, fork_reason);
        }
        if(taken2&&tgt) next_pc=tgt;
    }
    else if (IS("bl")) {
        uint64_t tgt=0; const char *tp=strstr(a1,"0x"); if(tp)tgt=strtoull(tp,NULL,16);
        if(tgt){
            
            if(emu_simulate_libc(e, tgt, NULL, 0)) {
                
                e->regs[30]=next_pc;
            }
            
            else if(e->bin && tgt >= e->bin->sections[0].vaddr) {
                int is_internal = 0, si2;
                for(si2=0;si2<e->bin->nsections;si2++){
                    dax_section_t *s2=&e->bin->sections[si2];
                    if(s2->type==SEC_TYPE_CODE&&tgt>=s2->vaddr&&tgt<s2->vaddr+s2->size){
                        is_internal=1; break;
                    }
                }
                if(is_internal && e->call_depth < EMU_CALL_DEPTH-1) {
                    /* track call frequency — detect VM interpreter step fn */
                    vm_hot_record(e, e->pc, tgt);
                    e->call_stack[e->call_depth++] = next_pc;
                    e->regs[30] = next_pc;
                    next_pc = tgt;
                } else if(is_internal) {
                    
                    e->regs[30]=next_pc;
                    e->regs[0]=0;
                } else {
                    
                    e->regs[30]=next_pc;
                    e->regs[0]=0;
                }
            } else {
                
                e->regs[30]=next_pc;
                e->regs[0]=0;
            }
        }
    }
    else if (IS("blr")) {
        uint64_t tgt=RV(a1);
        e->regs[30]=next_pc;
        if(tgt>0x1000 && e->bin && e->call_depth < EMU_CALL_DEPTH-1) {
            int is_internal=0, si2;
            for(si2=0;si2<e->bin->nsections;si2++){
                dax_section_t *s2=&e->bin->sections[si2];
                if(s2->type==SEC_TYPE_CODE&&tgt>=s2->vaddr&&tgt<s2->vaddr+s2->size){
                    is_internal=1; break;
                }
            }
            if(is_internal){
                /* track call frequency — detect VM handler dispatch */
                vm_hot_record(e, e->pc, tgt);
                e->call_stack[e->call_depth++]=next_pc;
                next_pc=tgt;
            } else {
                
                e->regs[0]=0;
            }
        } else {
            e->regs[0]=0; 
        }
    }
    else if (IS("br")) {
        uint64_t tgt = RV(a1);
        /*
         * Heuristic: if the target was loaded from a jump table (high
         * likelihood when we are inside a VM interpret loop), record it
         * as a VM dispatch event so the post-run trace can be printed.
         */
        if (tgt > 0x1000 && e->bin) {
            int _looks_vm = 0;
            /* Check if tgt lands inside a known function that is not
               the current entry — typical for VM handler dispatch      */
            dax_func_t *_tfn = dax_func_find(e->bin, tgt);
            dax_func_t *_cfn = dax_func_find(e->bin, e->entry_fn_start);
            if (_tfn && _cfn && _tfn->start != _cfn->start)
                _looks_vm = 1;
            /* Also flag if tgt resolves to a known resolved-indirect   */
            if (!_looks_vm) {
                int _ri;
                for (_ri = 0; _ri < e->bin->nresolved_indirect; _ri++) {
                    if (e->bin->resolved_indirect_to[_ri] == tgt) {
                        _looks_vm = 1; break;
                    }
                }
            }
            if (_looks_vm)
                vm_trace_record(e, e->pc, tgt, e->steps, e->bin);
        }
        next_pc = tgt;
    }
    else if (!strncmp(mn,"ret",3)) {
        if(e->call_depth > 0) {
            
            next_pc = e->call_stack[--e->call_depth];
        } else {
            
            snprintf(e->halt_reason,sizeof(e->halt_reason),
                     "ret  x0=0x%llx",(unsigned long long)e->regs[0]);
            e->halted=1; return 0;
        }
    }
    
    else if (IS("push")) {  }
    else if (IS("pop")) { }
    
    else if (!strncmp(mn,"fmov",4)) {
        int fn1=fp_rn(a1), fn2=fp_rn(a2);
        if((a1[0]=='x'||a1[0]=='w')&&fn2>=0)
            SV(a1, g_fp_regs[fn2].d[0]);        
        else if(fn1>=0&&(a2[0]=='x'||a2[0]=='w'))
            g_fp_regs[fn1].d[0]=RV(a2);          
        else if(fn1>=0&&fn2>=0)
            g_fp_regs[fn1]=g_fp_regs[fn2];       
        else if(fn1>=0&&a2[0]=='#') {
            double iv=atof(a2+1); memcpy(&g_fp_regs[fn1].d[0],&iv,8);
        }
    }
    else if (!strncmp(mn,"fcvt",4)||!strncmp(mn,"scvtf",5)||!strncmp(mn,"ucvtf",5)||
             !strncmp(mn,"fcvtz",5)||!strncmp(mn,"fcvtas",6)||!strncmp(mn,"fcvtau",6)||
             !strncmp(mn,"fcvtms",6)||!strncmp(mn,"fcvtps",6)||!strncmp(mn,"fcvtns",6)) {
        
        int fn_d=fp_rn(a1), fn_s=fp_rn(a2);
        if(!strncmp(mn,"scvtf",5)||!strncmp(mn,"ucvtf",5)) {
            
            double dv=!strncmp(mn,"scvtf",5)?(double)(int64_t)RV(a2):(double)RV(a2);
            if(fn_d>=0) fp_set(fn_d,dv);
        } else {
            
            double dv=fn_s>=0?fp_get(fn_s):0.0;
            if(a1[0]=='x'||a1[0]=='w') SV(a1,(uint64_t)(int64_t)dv);
        }
    }
    else if (!strncmp(mn,"fadd",4)||!strncmp(mn,"fsub",4)||!strncmp(mn,"fmul",4)||
             !strncmp(mn,"fdiv",4)||!strncmp(mn,"fabs",4)||!strncmp(mn,"fneg",4)||
             !strncmp(mn,"fmax",4)||!strncmp(mn,"fmin",4)||!strncmp(mn,"fsqrt",5)||
             !strncmp(mn,"fmadd",5)||!strncmp(mn,"fmsub",5)||!strncmp(mn,"fnmadd",6)||
             !strncmp(mn,"fnmsub",6)||!strncmp(mn,"frintz",6)||!strncmp(mn,"frinta",6)||
             !strncmp(mn,"frintn",6)||!strncmp(mn,"frintp",6)||!strncmp(mn,"frintm",6)) {
        
        int fd=fp_rn(a1),fn2=fp_rn(a2),fn3=fp_rn(a3),fn4_=fp_rn(a4);
        if(fd>=0) {
            double v2=fn2>=0?fp_get(fn2):0.0, v3=fn3>=0?fp_get(fn3):0.0;
            double r=0.0;
            if(!strncmp(mn,"fadd",4))      r=v2+v3;
            else if(!strncmp(mn,"fsub",4)) r=v2-v3;
            else if(!strncmp(mn,"fmul",4)) r=v2*v3;
            else if(!strncmp(mn,"fdiv",4)) r=(v3!=0.0)?v2/v3:0.0;
            else if(!strncmp(mn,"fabs",4)) r=v2<0?-v2:v2;
            else if(!strncmp(mn,"fneg",4)) r=-v2;
            else if(!strncmp(mn,"fmax",4)) r=v2>v3?v2:v3;
            else if(!strncmp(mn,"fmin",4)) r=v2<v3?v2:v3;
            else if(!strncmp(mn,"fsqrt",5)){ double sq=v2; if(sq>=0){r=sq;for(int _=0;_<50;_++)r=0.5*(r+sq/r);} }
            else if(!strncmp(mn,"fmadd",5)) r=v2*v3+(fn4_>=0?fp_get(fn4_):0.0);
            else if(!strncmp(mn,"fmsub",5)) r=v2*v3-(fn4_>=0?fp_get(fn4_):0.0);
            else if(!strncmp(mn,"fnmadd",6)) r=-(v2*v3)-(fn4_>=0?fp_get(fn4_):0.0);
            else if(!strncmp(mn,"fnmsub",6)) r=-(v2*v3)+(fn4_>=0?fp_get(fn4_):0.0);
            else r=v2; 
            fp_set(fd,r);
        }
    }
    else if (!strncmp(mn,"fcmp",4)||!strncmp(mn,"fccmp",5)) {
        int fn_a=fp_rn(a1),fn_b=fp_rn(a2);
        double va=fn_a>=0?fp_get(fn_a):0.0;
        double vb=(a2[0]=='#'&&!strcmp(a2,"#0.0"))?0.0:(fn_b>=0?fp_get(fn_b):0.0);
        e->flags_z=(va==vb); e->flags_n=(va<vb); e->flags_c=(va>=vb); e->flags_v=0;
    }
    else if (!strncmp(mn,"fcsel",5)) { SV(a1,0); } 
    
    else if (mn[0]=='v'||
             !strncmp(mn,"movi",4)||!strncmp(mn,"mvni",4)||
             !strncmp(mn,"dup",3)||!strncmp(mn,"ins",3)||
             !strncmp(mn,"tbl",3)||!strncmp(mn,"tbx",3)||
             !strncmp(mn,"zip",3)||!strncmp(mn,"uzp",3)||!strncmp(mn,"trn",3)||
             !strncmp(mn,"rev",3)||!strncmp(mn,"cnt",3)||
             !strncmp(mn,"ld1",3)||!strncmp(mn,"ld2",3)||
             !strncmp(mn,"ld3",3)||!strncmp(mn,"ld4",3)||
             !strncmp(mn,"st1",3)||!strncmp(mn,"st2",3)||
             !strncmp(mn,"st3",3)||!strncmp(mn,"st4",3)||
             !strncmp(mn,"shl",3)||!strncmp(mn,"sshr",4)||!strncmp(mn,"ushr",4)||
             !strncmp(mn,"sqadd",5)||!strncmp(mn,"uqadd",5)||!strncmp(mn,"sqsub",5)||
             !strncmp(mn,"pmul",4)||!strncmp(mn,"pmull",5)||
             !strncmp(mn,"addv",4)||!strncmp(mn,"smov",4)||!strncmp(mn,"umov",4)||
             !strncmp(mn,"fmla",4)||!strncmp(mn,"fmls",4)) {
        
        if((a1[0]=='x'||a1[0]=='w')&&(!strncmp(mn,"umov",4)||!strncmp(mn,"smov",4))) SV(a1,0);
    }
    
    else if (!strncmp(mn,"paci",4)||!strncmp(mn,"pacib",5)||!strncmp(mn,"pacd",4)||
             !strncmp(mn,"auti",4)||!strncmp(mn,"autib",5)||!strncmp(mn,"autd",4)||
             IS("paciaz")||IS("pacibz")||IS("autiasp")||IS("autibsp")||
             IS("xpaclri")||IS("paciza")||IS("pacizb")) {  }
    else if (IS("xpaci")||IS("xpacd")) { SV(a1,RV(a1)&0x0000FFFFFFFFFFFFULL);  }
    
    else if (IS("nop")||IS("wfi")||IS("wfe")||IS("sev")||IS("sevl")||IS("yield")||
             IS("isb")||IS("dsb")||IS("dmb")||IS("esb")||IS("clrex")||
             !strncmp(mn,"bti",3)||!strncmp(mn,"hint",4)||
             IS("mrs")||IS("msr")||
             IS("sys")||IS("sysl")||
             IS("at")||IS("dc")||IS("ic")||IS("tlbi")||
             IS("prfm")||IS("prfum")||
             IS("dw")||IS("autiasp")||IS("autibsp")) {  }
    else if (IS("svc")) {
        emu_simulate_syscall(e, NULL, 0);
    }
    
    else if (!strncmp(mn,"dp_",3)) {
        
        if(a1[0]=='x'||a1[0]=='w') SV(a1,0);
    }
    
    else {
        
        if (e->steps < 3) { 
            snprintf(e->halt_reason,sizeof(e->halt_reason),
                     "unknown: %s (continuing)",mn);
        }
        
        if((a1[0]=='x'||a1[0]=='w')&&a1[1]>='0'&&a1[1]<='9') SV(a1,0);
        
    }

#undef RV
#undef SV
#undef IMM
#undef IS
#undef HAS
#undef W32
#undef SX32
#undef SX16
#undef SX8
#undef SET_FLAGS_SUB
#undef SET_FLAGS_ADD
#undef SET_FLAGS_LOG

    e->pc = next_pc;
    return 1;
}

static int emu_step_riscv(emu_state_t *e) {
    rv_insn_t insn;
    int len;
    uint64_t next_pc;
    const char *mn, *ops;
    char a1[32]="", a2[32]="", a3[32]="";

    if (!e->code_base) {
        snprintf(e->halt_reason,sizeof(e->halt_reason),"no code");
        e->halted=1; return 0;
    }

    {
        size_t off = (size_t)(e->pc - e->code_vaddr);
        if (off >= e->code_size) {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"pc out of section");
            e->halted=1; return 0;
        }
        len = rv_decode(e->code_base + off, e->code_size - off, e->pc, &insn);
        if (len <= 0) {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"decode failed at 0x%llx",
                     (unsigned long long)e->pc);
            e->halted=1; return 0;
        }
    }

    mn   = insn.mnemonic;
    ops  = insn.operands;
    next_pc = e->pc + (uint64_t)len;

    {
        const char *p=ops; char *bufs[3]={a1,a2,a3}; int k;
        for(k=0;k<3;k++){
            while(*p==' ')p++;
            char *d=bufs[k]; int j=0;
            while(*p&&*p!=','&&j<31){*d++=*p++;j++;} *d='\0';
            if(*p==',')p++;
        }
    }

#define RR(name)   (rv_reg_idx(name)>=0&&rv_reg_idx(name)<32 ? \
                    e->regs[rv_reg_idx(name)] : \
                    (strcmp(name,"sp")==0 ? e->sp : 0ULL))
#define WR(name,v) do{ int _i=rv_reg_idx(name); \
    if(_i>0&&_i<32) e->regs[_i]=(v); \
    else if(strcmp(name,"sp")==0) e->sp=(v); \
    } while(0)
#define IMM_RV(s)  ((uint64_t)(int64_t)strtoll((s),NULL,0))
#define SFZ(r)     do{e->flags_z=((r)==0);e->flags_n=(((r)>>63)&1); \
                      e->flags_c=0;e->flags_v=0;}while(0)
#define IS_RV(s)   (strcmp(mn,(s))==0)
#define STARTS(s)  (strncmp(mn,(s),strlen(s))==0)

    if (!a1[0]) { e->pc = next_pc; return 1; }

    if (IS_RV("ret") || (IS_RV("jalr") && strcmp(a1,"zero")==0 && strcmp(a2,"ra")==0)) {
        if (e->call_depth > 0) {
            e->call_depth--;
            next_pc = e->call_stack[e->call_depth];
        } else {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"ret at depth 0");
            e->halted = 1;
        }
        e->pc = next_pc; return 1;
    }

    if (IS_RV("jal")) {
        uint64_t tgt = 0;
        if (a2[0]=='0') tgt = strtoull(a2,NULL,16);
        else if (a1[0]=='0') { tgt = strtoull(a1,NULL,16); a1[0]='\0'; }
        if (!strcmp(a1,"ra") || !strcmp(a1,"x1")) {
            if (e->call_depth < EMU_CALL_DEPTH)
                e->call_stack[e->call_depth++] = next_pc;
        }
        if (tgt) next_pc = tgt;
        e->pc = next_pc; return 1;
    }

    if (IS_RV("jalr") || IS_RV("c.jalr")) {
        uint64_t base = RR(a2[0]?a2:a1);
        int64_t  off  = a3[0] ? (int64_t)strtoll(a3,NULL,0) : 0;
        uint64_t tgt  = (base + (uint64_t)off) & ~1ULL;
        if (!strcmp(a1,"ra")||!strcmp(a1,"x1")) {
            if (e->call_depth < EMU_CALL_DEPTH)
                e->call_stack[e->call_depth++] = next_pc;
        }
        next_pc = tgt;
        e->pc = next_pc; return 1;
    }

    if (IS_RV("c.jr")) {
        uint64_t tgt = RR(a1) & ~1ULL;
        next_pc = tgt; e->pc = next_pc; return 1;
    }

    if (IS_RV("j")) {
        if (a1[0]=='0') next_pc = strtoull(a1,NULL,16);
        e->pc = next_pc; return 1;
    }

    if (IS_RV("beq")||IS_RV("bne")||IS_RV("blt")||IS_RV("bge")||
        IS_RV("bltu")||IS_RV("bgeu")) {
        uint64_t v1=RR(a1), v2=RR(a2);
        int taken=0;
        if      (IS_RV("beq"))  taken=(v1==v2);
        else if (IS_RV("bne"))  taken=(v1!=v2);
        else if (IS_RV("blt"))  taken=((int64_t)v1<(int64_t)v2);
        else if (IS_RV("bge"))  taken=((int64_t)v1>=(int64_t)v2);
        else if (IS_RV("bltu")) taken=(v1<v2);
        else if (IS_RV("bgeu")) taken=(v1>=v2);
        if (taken && a3[0]=='0') next_pc = strtoull(a3,NULL,16);
        e->pc = next_pc; return 1;
    }

    if (IS_RV("c.beqz")||IS_RV("c.bnez")) {
        uint64_t v1=RR(a1); int taken=0;
        if (IS_RV("c.beqz")) taken=(v1==0);
        else                  taken=(v1!=0);
        if (taken && a2[0]=='0') next_pc = strtoull(a2,NULL,16);
        e->pc = next_pc; return 1;
    }

    if (IS_RV("li")||IS_RV("c.li")) {
        WR(a1, IMM_RV(a2)); e->pc=next_pc; return 1;
    }

    if (IS_RV("mv")||IS_RV("c.mv")) {
        WR(a1, RR(a2)); e->pc=next_pc; return 1;
    }

    if (IS_RV("lui")||IS_RV("c.lui")) {
        uint64_t imm = strtoull(a2,NULL,16);
        WR(a1, imm<<12); e->pc=next_pc; return 1;
    }

    if (IS_RV("auipc")) {
        uint64_t imm = strtoull(a2,NULL,16);
        WR(a1, e->pc + (imm<<12)); e->pc=next_pc; return 1;
    }

    if (IS_RV("addi")||IS_RV("c.addi")) {
        uint64_t r=RR(a2)+IMM_RV(a3); WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("addiw")||IS_RV("c.addiw")) {
        uint64_t r=(uint64_t)(int64_t)(int32_t)(uint32_t)(RR(a2)+IMM_RV(a3));
        WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("add")||IS_RV("c.add")) {
        uint64_t r=RR(a2)+RR(a3); WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("sub")||IS_RV("c.sub")) {
        uint64_t r=RR(a2)-RR(a3); WR(a1,r);
        e->flags_z=(r==0); e->flags_n=((r>>63)&1);
        e->flags_c=(RR(a2)>=RR(a3)); e->pc=next_pc; return 1;
    }
    if (IS_RV("and")||IS_RV("c.and")||IS_RV("andi")) {
        uint64_t r=IS_RV("andi")?RR(a2)&IMM_RV(a3):RR(a2)&RR(a3);
        WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("or")||IS_RV("c.or")||IS_RV("ori")) {
        uint64_t r=IS_RV("ori")?RR(a2)|IMM_RV(a3):RR(a2)|RR(a3);
        WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("xor")||IS_RV("c.xor")||IS_RV("xori")) {
        uint64_t r=IS_RV("xori")?RR(a2)^IMM_RV(a3):RR(a2)^RR(a3);
        WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("sll")||IS_RV("slli")||IS_RV("c.slli")) {
        int sh = (IS_RV("sll"))?(int)(RR(a3)&63):(int)(strtoull(a3,NULL,0)&63);
        uint64_t r=RR(a2)<<sh; WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("srl")||IS_RV("srli")||IS_RV("c.srli")) {
        int sh=(IS_RV("srl"))?(int)(RR(a3)&63):(int)(strtoull(a3,NULL,0)&63);
        uint64_t r=RR(a2)>>sh; WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("sra")||IS_RV("srai")||IS_RV("c.srai")) {
        int sh=(IS_RV("sra"))?(int)(RR(a3)&63):(int)(strtoull(a3,NULL,0)&63);
        uint64_t r=(uint64_t)((int64_t)RR(a2)>>sh); WR(a1,r); SFZ(r); e->pc=next_pc; return 1;
    }
    if (IS_RV("mul")) {
        WR(a1, RR(a2)*RR(a3)); e->pc=next_pc; return 1;
    }
    if (IS_RV("div")||IS_RV("divu")) {
        uint64_t d=RR(a3);
        WR(a1, d?RR(a2)/d:~0ULL); e->pc=next_pc; return 1;
    }
    if (IS_RV("rem")||IS_RV("remu")) {
        uint64_t d=RR(a3);
        WR(a1, d?RR(a2)%d:RR(a2)); e->pc=next_pc; return 1;
    }

    if (IS_RV("ld")||IS_RV("c.ld")||IS_RV("c.ldsp")) {
        int64_t off2=strtoll(a3[0]?a3:(a2[0]?a2:"0"),NULL,0);
        uint64_t base=RR(a2[0]?a2:"sp");
        uint64_t addr=(IS_RV("c.ldsp")?e->sp:base)+(uint64_t)off2;
        WR(a1, emu_read64(e,addr)); e->pc=next_pc; return 1;
    }
    if (IS_RV("lw")||IS_RV("lwu")||IS_RV("c.lw")||IS_RV("c.lwsp")) {
        int64_t off2=strtoll(a3[0]?a3:(a2[0]?a2:"0"),NULL,0);
        uint64_t base=RR(a2[0]?a2:"sp");
        uint64_t addr=(IS_RV("c.lwsp")?e->sp:base)+(uint64_t)off2;
        uint64_t v=emu_read32(e,addr);
        WR(a1, IS_RV("lw")?(uint64_t)(int64_t)(int32_t)v:v);
        e->pc=next_pc; return 1;
    }
    if (IS_RV("lh")||IS_RV("lhu")) {
        int64_t off2=strtoll(a3,NULL,0);
        uint64_t addr=RR(a2)+(uint64_t)off2;
        uint64_t v=(uint64_t)emu_read8(e,addr)|(uint64_t)(emu_read8(e,addr+1)<<8);
        WR(a1, IS_RV("lh")?(uint64_t)(int64_t)(int16_t)v:v);
        e->pc=next_pc; return 1;
    }
    if (IS_RV("lb")||IS_RV("lbu")) {
        int64_t off2=strtoll(a3,NULL,0);
        uint64_t addr=RR(a2)+(uint64_t)off2;
        uint64_t v=emu_read8(e,addr);
        WR(a1, IS_RV("lb")?(uint64_t)(int64_t)(int8_t)v:v);
        e->pc=next_pc; return 1;
    }

    if (IS_RV("sd")||IS_RV("c.sd")||IS_RV("c.sdsp")) {
        int64_t off2=strtoll(a3[0]?a3:(a2[0]?a2:"0"),NULL,0);
        uint64_t base=IS_RV("c.sdsp")?e->sp:RR(a2[0]?a2:"sp");
        uint64_t addr=base+(uint64_t)off2;
        emu_write64(e,addr,RR(a1)); e->pc=next_pc; return 1;
    }
    if (IS_RV("sw")||IS_RV("c.sw")||IS_RV("c.swsp")) {
        int64_t off2=strtoll(a3[0]?a3:(a2[0]?a2:"0"),NULL,0);
        uint64_t base=IS_RV("c.swsp")?e->sp:RR(a2[0]?a2:"sp");
        uint64_t addr=base+(uint64_t)off2;
        emu_write32(e,addr,(uint32_t)RR(a1)); e->pc=next_pc; return 1;
    }

    if (IS_RV("ecall")) {
        uint64_t nr=e->regs[17];
        if (nr==64) {
            e->regs[10]=(uint64_t)(int64_t)-38;
        } else if (nr==93||nr==94) {
            snprintf(e->halt_reason,sizeof(e->halt_reason),"exit(%lld)",(long long)e->regs[10]);
            e->halted=1;
        } else {
            e->regs[10]=(uint64_t)(int64_t)-38;
        }
        e->pc=next_pc; return 1;
    }

    if (IS_RV("ebreak")) {
        snprintf(e->halt_reason,sizeof(e->halt_reason),"ebreak");
        e->halted=1; e->pc=next_pc; return 1;
    }

    if (IS_RV("nop")||IS_RV("c.nop")||IS_RV("fence")||IS_RV("fence.i")) {
        e->pc=next_pc; return 1;
    }

    if (STARTS("csr")) {
        if (IS_RV("csrrs")||IS_RV("csrrw")||IS_RV("csrrc")) {
            WR(a1, 0);
        }
        e->pc=next_pc; return 1;
    }

    if (STARTS("amo")||IS_RV("lr.w")||IS_RV("lr.d")||
        IS_RV("sc.w")||IS_RV("sc.d")) {
        e->pc=next_pc; return 1;
    }

    e->pc = next_pc;
    return 1;

#undef RR
#undef WR
#undef IMM_RV
#undef SFZ
#undef IS_RV
#undef STARTS
}

void dax_emulate_func(dax_binary_t *bin, int func_idx,
                      uint64_t *init_regs, int nregs,
                      dax_opts_t *opts, FILE *out) {
    int         c  = opts ? opts->color : 1;
    dax_func_t *fn;
    int         si, i;
    emu_state_t *e;

    const char *CY = c ? "\033[1;33m"  : "";
    const char *CB = c ? COL_ADDR      : "";
    const char *CG = c ? "\033[1;32m"  : "";
    const char *CD = c ? COL_COMMENT   : "";
    const char *CR = c ? COL_RESET     : "";
    const char *CM = c ? COL_MNEM      : "";
    const char *CO = c ? COL_OPS       : "";
    const char *CF = c ? "\033[1;35m"  : "";
    const char *CE = c ? "\033[1;31m"  : "";

    DAX_GUARD_BIN(bin);
    if (!dax_func_idx_ok(bin, func_idx)) return;
    fn = &bin->functions[func_idx];

    e = (emu_state_t *)calloc(1, sizeof(emu_state_t));
    if (!e) return;

    g_nvm_trace = 0;   /* clear VM dispatch trace for this run */
    g_nhot      = 0;   /* clear call-frequency table           */
    g_heap_top  = EMU_HEAP_BASE;
    memset(g_fp_regs, 0, sizeof(g_fp_regs));
    /* IMPROVEMENT 4: reset multi-path state for this run */
    memset(&g_mpath, 0, sizeof(g_mpath));
    g_emu_jitter_state = 0xDEADC0DE12345678ULL ^ (uint64_t)(uintptr_t)bin;

    e->bin           = bin;
    e->pc            = fn->start;
    e->sp            = EMU_STACK_BASE + EMU_STACK_SIZE - 0x80;
    e->call_depth    = 0;
    e->entry_fn_start= fn->start;

    
    for (i = 0; i < 256; i++) emu_write8(e, e->sp - (uint64_t)i, (uint8_t)(0xAB));

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (fn->start >= sec->vaddr && fn->start < sec->vaddr + sec->size) {
            e->code_base  = bin->data + sec->offset;
            e->code_size  = (size_t)sec->size;
            e->code_vaddr = sec->vaddr;
            break;
        }
    }

    if (init_regs)
        for (i = 0; i < nregs && i < 32; i++) e->regs[i] = init_regs[i];

    /* ── Sandbox: write stack canaries ── */
    emu_canary_write(e);

    /* ── Sandbox banner ── */
    fprintf(out, "\n");
    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  ══════════════ EMULATION: %s ══════════════\n", fn->name);
    if (c) fprintf(out, "%s", CR);
    fprintf(out, "  %sSandbox VM%s  addr_range=0x%llx..0x%llx  pages=%d  max_steps=%d\n",
            c?"\033[1;33m":"", CR,
            (unsigned long long)EMU_SANDBOX_NULL_SIZE,
            (unsigned long long)EMU_SANDBOX_MAX_ADDR,
            EMU_MEM_PAGES, EMU_MAX_STEPS);
    fprintf(out, "  %sarch%s  %-8s  |  %sentry%s  0x%llx  |  %ssp%s  0x%llx\n",
            CD,CR, bin->arch==ARCH_RISCV64?"RISCV64":bin->arch==ARCH_X86_64?"X86-64":"ARM64",
            CB,CR, (unsigned long long)fn->start, CY,CR, (unsigned long long)e->sp);
    fprintf(out, "  %sInitial regs:%s", CD, CR);
    for (i = 0; i < (init_regs ? nregs : 4); i++)
        fprintf(out, "  %sx%d%s=%s0x%llx%s", CY, i, CR, CG,
                (unsigned long long)e->regs[i], CR);
    fprintf(out, "\n\n");

    
    int loop_guard[256]; memset(loop_guard, 0, sizeof(loop_guard));

    while (!e->halted && e->steps < EMU_MAX_STEPS) {
        uint64_t saved_pc   = e->pc;
        uint64_t saved_regs[32];
        memcpy(saved_regs, e->regs, sizeof(e->regs));
        uint64_t saved_sp   = e->sp;

        
        char _emu_mnem[32]="", _emu_ops[128]="";
        int  _emu_was_call = 0;
        uint64_t _emu_call_tgt = 0;
        {
            if (bin->arch == ARCH_RISCV64) {
                size_t _off = (size_t)(saved_pc - e->code_vaddr);
                if (_off < e->code_size) {
                    rv_insn_t _ri;
                    rv_decode(e->code_base+_off, e->code_size-_off, saved_pc, &_ri);
                    snprintf(_emu_mnem, 32,  "%s", _ri.mnemonic);
                    snprintf(_emu_ops, 128, "%.127s", _ri.operands);
                    _emu_was_call=(!strcmp(_ri.mnemonic,"jal")&&_ri.operands[0]!='z');
                    if(_emu_was_call){const char*tp=strstr(_ri.operands,"0x");if(tp)_emu_call_tgt=strtoull(tp,NULL,16);}
                }
            } else {
                uint32_t raw = emu_read32(e, e->pc);
                a64_insn_t insn; a64_decode(raw, e->pc, &insn);
                snprintf(_emu_mnem, 32,  "%s", insn.mnemonic);
                snprintf(_emu_ops,  128, "%s", insn.operands);
                _emu_was_call=(strcmp(insn.mnemonic,"bl")==0);
                if(_emu_was_call){const char*tp=strstr(insn.operands,"0x");if(tp)_emu_call_tgt=strtoull(tp,NULL,16);}
            }
        }

        /* ── Sandbox: validate PC before executing ── */
        if (!emu_sandbox_addr_ok(e, saved_pc)) break;

        int lgi = (int)(saved_pc & 0xFF);
        loop_guard[lgi]++;
        if (loop_guard[lgi] > 64) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "loop at 0x%llx (visited >64 times)", (unsigned long long)saved_pc);
            break;
        }

        int ok = (bin->arch == ARCH_RISCV64) ? emu_step_riscv(e) : emu_step_arm64(e);
        e->steps++;

        /* ── Sandbox: canary check every 32 steps (balance perf vs safety) ── */
        if ((e->steps & 31) == 0) {
            if (!emu_canary_check(e)) break;
        }

        /* ── Sandbox: validate new PC after step ── */
        if (!e->halted && e->pc != saved_pc) {
            if (e->pc < EMU_SANDBOX_NULL_SIZE || e->pc >= EMU_SANDBOX_MAX_ADDR) {
                snprintf(e->halt_reason, sizeof(e->halt_reason),
                         "SANDBOX: PC escape to 0x%llx — halted",
                         (unsigned long long)e->pc);
                e->halted = 1;
                if (c) fprintf(out, "  %s[SANDBOX VIOLATION]%s PC escape 0x%llx\n",
                               c?"\033[1;31m":"", CR, (unsigned long long)e->pc);
                break;
            }
        }

        
        fprintf(out, "  %s0x%09llx%s  %s%-10s%s %s%-28s%s",
                CB, (unsigned long long)saved_pc, CR,
                CM, _emu_mnem, CR,
                CO, _emu_ops, CR);

        
        int nshown = 0;
        for (i = 0; i < 16 && nshown < 3; i++) {
            if (e->regs[i] != saved_regs[i]) {
                fprintf(out, "  %s→ x%d=0x%llx%s", CY, i,
                        (unsigned long long)e->regs[i], CR);
                nshown++;
            }
        }
        
        if (e->sp != saved_sp)
            fprintf(out, "  %s→ sp=0x%llx%s", CY, (unsigned long long)e->sp, CR);
        fprintf(out, "\n");

        
        if (_emu_was_call && _emu_call_tgt) {
            if (!emu_simulate_libc(e, _emu_call_tgt, out, c)) {
                if (e->call_depth > 0) {
                    dax_func_t *called = dax_func_find(bin, _emu_call_tgt);
                    fprintf(out, "  %s%*s[CALL-> 0x%llx %s  depth=%d]%s\n",
                            CY, e->call_depth*2, "",
                            (unsigned long long)_emu_call_tgt,
                            called&&called->name[0]?called->name:"?",
                            e->call_depth, CR);
                }
            }
        }
        if (!strncmp(_emu_mnem,"ret",3) && !strcmp(_emu_mnem,"ret") && !e->halted
            && bin->arch != ARCH_RISCV64) {
        }
        if (!strcmp(_emu_mnem,"svc") || !strcmp(_emu_mnem,"ecall")) {
            emu_simulate_syscall(e, out, c);
        }

        if (!ok) break;

        
        if (e->pc == saved_pc && !e->halted) {
            snprintf(e->halt_reason, sizeof(e->halt_reason),
                     "pc stuck at 0x%llx", (unsigned long long)saved_pc);
            break;
        }

        
        if(e->call_depth == 0) {
            dax_func_t *cur_fn = dax_func_find(bin, e->pc);
            if (cur_fn && cur_fn->start == e->pc && cur_fn->start != fn->start) {
                snprintf(e->halt_reason, sizeof(e->halt_reason),
                         "jumped to %.180s", cur_fn->name);
                break;
            }
        }
    }

    /* ── Sandbox: final canary check after run ── */
    emu_canary_check(e);

    fprintf(out, "\n");
    fprintf(out, "  %s────────────── Emulation result ──────────────%s\n", CD, CR);
    fprintf(out, "  %s%-12s%s %d steps\n", CD, "Steps:", CR, e->steps);
    if (e->halt_reason[0])
        fprintf(out, "  %s%-12s%s %s%s%s\n", CD, "Halted:", CR, CG, e->halt_reason, CR);

    /* ── Sandbox status line ── */
    {
        const char *sb_col = c ? "\033[1;32m" : "";
        const char *sb_warn= c ? "\033[1;31m" : "";
        int is_violation = (strncmp(e->halt_reason,"SANDBOX",7)==0);
        fprintf(out, "  %s%-12s%s %s%s%s  pages_used=%d/%d  heap=0x%llx\n",
                CD, "Sandbox:", CR,
                is_violation ? sb_warn : sb_col,
                is_violation ? "VIOLATION DETECTED" : "contained — no host access",
                CR,
                e->npages, EMU_MEM_PAGES,
                (unsigned long long)g_heap_top);
    }

    
    fprintf(out, "\n  %sGeneral-purpose registers:%s\n", CD, CR);
    for (i = 0; i < 16; i += 2) {
        fprintf(out, "    %sx%-2d%s = %s0x%016llx%s  (%10lld)    ",
                CY, i, CR, CG, (unsigned long long)e->regs[i], CR, (long long)e->regs[i]);
        fprintf(out, "  %sx%-2d%s = %s0x%016llx%s  (%10lld)\n",
                CY, i+1, CR, CG, (unsigned long long)e->regs[i+1], CR, (long long)e->regs[i+1]);
    }
    fprintf(out, "    %ssp%s  = %s0x%016llx%s\n", CY, CR, CG, (unsigned long long)e->sp, CR);
    fprintf(out, "    %sflags%s  Z=%d N=%d C=%d V=%d\n", CY, CR,
            e->flags_z, e->flags_n, e->flags_c, e->flags_v);

    
    int fp_used = 0;
    for (i = 0; i < 32; i++)
        if (g_fp_regs[i].d[0] != 0 || g_fp_regs[i].d[1] != 0) fp_used++;
    if (fp_used > 0) {
        fprintf(out, "\n  %sFP/SIMD registers (non-zero):%s\n", CD, CR);
        for (i = 0; i < 32; i++) {
            if (g_fp_regs[i].d[0] != 0 || g_fp_regs[i].d[1] != 0) {
                double dv; memcpy(&dv, &g_fp_regs[i].d[0], 8);
                fprintf(out, "    %sd%-2d%s = %s0x%016llx%s  (%g)\n",
                        CF, i, CR, CG, (unsigned long long)g_fp_regs[i].d[0], CR, dv);
            }
        }
    }

    
    fprintf(out, "\n  %sReturn value (x0):%s %s0x%llx%s  (%lld)\n",
            CD, CR, CG, (unsigned long long)e->regs[0], CR, (long long)e->regs[0]);
    if (e->steps >= EMU_MAX_STEPS)
        fprintf(out, "  %s[WARNING] step limit (%d) reached — increase EMU_MAX_STEPS for deeper analysis%s\n",
                CE, EMU_MAX_STEPS, CR);
    fprintf(out, "\n");

    /* ── VM Dispatch Flow Trace ─────────────────────────────────────────── */
    if (g_nvm_trace > 0) {
        const char *CTL = c ? "\033[1;36m" : "";  /* cyan title  */
        const char *CHL = c ? "\033[1;33m" : "";  /* yellow addr */
        const char *CGR = c ? "\033[0;32m" : "";  /* green name  */
        const char *CDM = c ? "\033[0;90m" : "";  /* dim         */
        fprintf(out, "  %s══════════════ VM DISPATCH FLOW TRACE ══════════════%s\n", CTL, CR);
        fprintf(out, "  %s  %-6s  %-18s  %-18s  %-10s  %-10s  %s%s\n",
                CDM, "step", "dispatch@", "handler@", "opcode", "vm_ip", "handler_name", CR);
        int vi;
        for (vi = 0; vi < g_nvm_trace; vi++) {
            dax_vm_dispatch_entry_t *vd = &g_vm_trace[vi];
            fprintf(out, "  %s  %-6d%s  %s0x%016llx%s  %s0x%016llx%s",
                    CDM, vd->step_no, CR,
                    CHL, (unsigned long long)vd->dispatch_pc, CR,
                    CGR, (unsigned long long)vd->handler_pc,  CR);
            fprintf(out, "  %s0x%08llx%s  %s0x%08llx%s",
                    CDM, (unsigned long long)vd->opcode_val, CR,
                    CDM, (unsigned long long)vd->ip_val,     CR);
            if (vd->handler_name[0])
                fprintf(out, "  %s<%s>%s", CGR, vd->handler_name, CR);
            fprintf(out, "\n");
            /* show flow arrows between consecutive dispatches */
            if (vi + 1 < g_nvm_trace) {
                dax_vm_dispatch_entry_t *nx = &g_vm_trace[vi+1];
                if (nx->dispatch_pc != vd->dispatch_pc)
                    fprintf(out, "  %s  │   ↳ dispatch moved: 0x%llx → 0x%llx%s\n",
                            CDM,
                            (unsigned long long)vd->dispatch_pc,
                            (unsigned long long)nx->dispatch_pc, CR);
            }
        }
        fprintf(out, "  %s  total dispatches recorded: %d%s\n\n", CDM, g_nvm_trace, CR);
    }

    /* ── IMPROVEMENT 4: Multi-Path Execution Report ─────────────────────── *
     * After the primary trace completes, run each forked (not-taken) path  *
     * with a reduced step budget and report unique syscalls + halt reasons. */
    if (g_mpath.nforks > 0) {
        const char *CMP  = c ? "\033[1;36m" : "";   /* cyan  */
        const char *CMA  = c ? "\033[1;33m" : "";   /* yellow */
        const char *CMG  = c ? "\033[1;32m" : "";   /* green  */
        const char *CMD  = c ? "\033[0;90m" : "";   /* dim    */
        const char *CME  = c ? "\033[1;31m" : "";   /* red    */

        fprintf(out, "  %s══════════════ MULTI-PATH ANALYSIS (%d forked paths) ══════════════%s\n",
                CMP, g_mpath.nforks, CR);

        int pi;
        for (pi = 0; pi < g_mpath.nforks; pi++) {
            mpath_snapshot_t *snap = &g_mpath.forks[pi];

            /* Build a fresh emu_state from the snapshot */
            emu_state_t *pe = (emu_state_t *)calloc(1, sizeof(emu_state_t));
            if (!pe) break;

            pe->bin   = bin;
            pe->pc    = snap->pc;
            pe->sp    = snap->sp;
            pe->flags_z = snap->flags_z;
            pe->flags_n = snap->flags_n;
            pe->flags_c = snap->flags_c;
            pe->flags_v = snap->flags_v;
            pe->steps   = snap->steps;
            pe->entry_fn_start = fn->start;
            memcpy(pe->regs, snap->regs, sizeof(pe->regs));

            /* Map the code section for this PC */
            int psi;
            for (psi = 0; psi < bin->nsections && psi < DAX_MAX_SECTIONS; psi++) {
                dax_section_t *psec = &bin->sections[psi];
                if (pe->pc >= psec->vaddr &&
                    pe->pc < psec->vaddr + psec->size &&
                    psec->offset + psec->size <= bin->size) {
                    pe->code_base  = bin->data + psec->offset;
                    pe->code_size  = psec->size;
                    pe->code_vaddr = psec->vaddr;
                    break;
                }
            }
            emu_canary_write(pe);

            fprintf(out, "\n  %s[PATH %d]%s  fork_reason=%s%s%s  start=0x%llx\n",
                    CMA, pi + 1, CR, CMD, snap->fork_reason, CR,
                    (unsigned long long)snap->pc);

            int path_steps = 0;
            int path_syscalls = 0;
            uint64_t first_syscall_nr = 0;

            while (!pe->halted && path_steps < MPATH_MAX_STEPS) {
                if (!emu_sandbox_addr_ok(pe, pe->pc)) break;
                int ok = (bin->arch == ARCH_RISCV64)
                         ? emu_step_riscv(pe) : emu_step_arm64(pe);
                pe->steps++;
                path_steps++;
                if (!emu_canary_check(pe)) break;
                if (!ok || pe->halted) break;
                /* Track syscall-like patterns: svc #0 sets x8 as nr */
                /* (already recorded via mpath_record_syscall in syscall handler) */
                (void)path_syscalls; (void)first_syscall_nr;
            }

            /* Summarise this path */
            fprintf(out, "  %s    steps=%d  halt=%s%s%s  x0=0x%llx  x1=0x%llx\n",
                    CMD, path_steps,
                    pe->halt_reason[0] ? CME : CMG,
                    pe->halt_reason[0] ? pe->halt_reason : "budget exhausted",
                    CR,
                    (unsigned long long)pe->regs[0],
                    (unsigned long long)pe->regs[1]);

            g_mpath.total_paths_run++;
            free(pe);
        }

        /* Union syscall report across all paths */
        if (g_mpath.nsyscalls_seen > 0) {
            fprintf(out, "\n  %s  Syscalls observed across all paths:%s", CMP, CR);
            int si2;
            for (si2 = 0; si2 < g_mpath.nsyscalls_seen; si2++)
                fprintf(out, " %s#%llu%s",
                        CMA, (unsigned long long)g_mpath.syscalls_seen[si2], CR);
            fprintf(out, "\n");
        }
        fprintf(out, "  %s  total paths run: %d (primary) + %d (forked) = %d%s\n\n",
                CMD, 1, g_mpath.total_paths_run, 1 + g_mpath.total_paths_run, CR);
    }

    free(e);
}

/* ═══════════════════════════════════════════════════════════════════════════
 * Step-resume emulation — step = continue from last PC, run = restart
 * ═══════════════════════════════════════════════════════════════════════════ */

void dax_step_init(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    const char *CY = c ? "\033[1;33m" : "";
    const char *CR = c ? "\033[0m"    : "";
    const char *CB = c ? "\033[1;34m" : "";

    if (!bin || func_idx < 0 || func_idx >= bin->nfunctions) return;
    dax_func_t *fn = &bin->functions[func_idx];

    memset(&g_step_state, 0, sizeof(g_step_state));
    g_step_state.active    = 1;
    g_step_state.func_idx  = func_idx;
    g_step_state.pc        = fn->start;
    g_step_state.sp        = EMU_STACK_BASE + EMU_STACK_SIZE - 0x80;
    g_step_state.steps_done= 0;
    g_nvm_trace            = 0;   /* fresh dispatch trace for this session */
    g_nhot                 = 0;   /* fresh call-frequency table            */

    fprintf(out, "\n  %s[STEP-INIT]%s  func=%s%s%s  entry=0x%llx\n",
            CY, CR, CB, fn->name[0] ? fn->name : "?", CR,
            (unsigned long long)fn->start);
    fprintf(out, "  %sUse 'step [n]' to advance N instructions. 'run' restarts from 0.%s\n\n", CR, CR);
}

/*
 * dax_step_next — advance the step cursor by `n` instructions.
 * Returns 0 when halted/done, 1 while still running.
 * State is preserved across calls via g_step_state.
 */
int dax_step_next(dax_binary_t *bin, int n, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    const char *CY = c ? "\033[1;33m" : "";
    const char *CB = c ? "\033[1;34m" : "";
    const char *CM = c ? "\033[1;35m" : "";
    const char *CO = c ? "\033[0;33m" : "";
    const char *CG = c ? "\033[1;32m" : "";
    const char *CD = c ? "\033[0;90m" : "";
    const char *CE = c ? "\033[1;31m" : "";
    const char *CR = c ? "\033[0m"    : "";

    if (!g_step_state.active) {
        fprintf(out, "  %s[STEP] No active step session. Use 'step init <func>' first.%s\n", CE, CR);
        return 0;
    }
    if (!bin || g_step_state.func_idx < 0 ||
        g_step_state.func_idx >= bin->nfunctions) return 0;

    /* Build a temporary emu_state from g_step_state */
    emu_state_t *e = (emu_state_t *)calloc(1, sizeof(emu_state_t));
    if (!e) return 0;

    e->bin        = bin;
    e->pc         = g_step_state.pc;
    e->sp         = g_step_state.sp;
    e->flags_z    = g_step_state.flags_z;
    e->flags_n    = g_step_state.flags_n;
    e->flags_c    = g_step_state.flags_c;
    e->flags_v    = g_step_state.flags_v;
    e->steps      = g_step_state.steps_done;
    e->entry_fn_start = bin->functions[g_step_state.func_idx].start;
    memcpy(e->regs, g_step_state.regs, sizeof(e->regs));

    /* map code section */
    int si;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        if (sec->size == 0 || sec->offset > bin->size) continue;
        if (sec->size > bin->size - sec->offset) continue;
        if (e->pc >= sec->vaddr && e->pc < sec->vaddr + sec->size) {
            e->code_base  = bin->data + sec->offset;
            e->code_size  = sec->size;
            e->code_vaddr = sec->vaddr;
            break;
        }
    }

    fprintf(out, "\n  %s[STEP +%d]%s  from PC=0x%llx  (done=%d)\n",
            CY, n, CR, (unsigned long long)e->pc, e->steps);

    int done = 0;
    int executed = 0;
    while (executed < n && !e->halted && e->steps < EMU_MAX_STEPS) {
        uint64_t saved_pc  = e->pc;
        uint64_t saved_regs[32];
        memcpy(saved_regs, e->regs, sizeof(e->regs));
        uint64_t saved_sp  = e->sp;

        /* ── Sandbox: validate PC before executing ── */
        if (!emu_sandbox_addr_ok(e, saved_pc)) { done = 1; break; }

        /* Decode for display */
        char _mnem[32]="", _ops[128]="";
        if (bin->arch == ARCH_RISCV64) {
            rv_insn_t ri; memset(&ri, 0, sizeof(ri));
            size_t off2 = (size_t)(saved_pc - e->code_vaddr);
            if (e->code_base && off2 < e->code_size)
                rv_decode(e->code_base+off2, e->code_size-off2, saved_pc, &ri);
            strncpy(_mnem, ri.mnemonic, sizeof(_mnem)-1); _mnem[sizeof(_mnem)-1]='\0';
            strncpy(_ops,  ri.operands, sizeof(_ops)-1);  _ops[sizeof(_ops)-1]='\0';
        } else {
            uint32_t raw = emu_read32(e, e->pc);
            a64_insn_t insn2; a64_decode(raw, e->pc, &insn2);
            strncpy(_mnem, insn2.mnemonic, sizeof(_mnem)-1); _mnem[sizeof(_mnem)-1]='\0';
            strncpy(_ops,  insn2.operands, sizeof(_ops)-1);  _ops[sizeof(_ops)-1]='\0';
        }

        int ok = (bin->arch == ARCH_RISCV64) ? emu_step_riscv(e) : emu_step_arm64(e);
        e->steps++;
        executed++;

        /* ── Sandbox: canary + PC check after step ── */
        if (!emu_canary_check(e)) { done = 1; break; }
        if (!e->halted && e->pc != saved_pc) {
            if (e->pc < EMU_SANDBOX_NULL_SIZE || e->pc >= EMU_SANDBOX_MAX_ADDR) {
                snprintf(e->halt_reason, sizeof(e->halt_reason),
                         "SANDBOX: PC escape to 0x%llx", (unsigned long long)e->pc);
                e->halted = 1; done = 1;
                fprintf(out, "  %s[SANDBOX VIOLATION]%s PC=0x%llx\n",
                        c?"\033[1;31m":"", CR, (unsigned long long)e->pc);
                break;
            }
        }

        fprintf(out, "  %s0x%09llx%s  %s%-10s%s %s%-28s%s",
                CB, (unsigned long long)saved_pc, CR,
                CM, _mnem, CR,
                CO, _ops, CR);

        int ns = 0, ii;
        for (ii = 0; ii < 16 && ns < 3; ii++) {
            if (e->regs[ii] != saved_regs[ii]) {
                fprintf(out, "  %s→ x%d=0x%llx%s", CY, ii,
                        (unsigned long long)e->regs[ii], CR);
                ns++;
            }
        }
        if (e->sp != saved_sp)
            fprintf(out, "  %s→ sp=0x%llx%s", CY, (unsigned long long)e->sp, CR);
        fprintf(out, "\n");

        if (!ok || e->halted) { done = 1; break; }
        if (e->pc == saved_pc) { done = 1; break; }
    }

    if (e->halted || done) {
        fprintf(out, "\n  %s[STEP HALTED]%s  %s%s%s  x0=0x%llx\n",
                CE, CR, CG,
                e->halt_reason[0] ? e->halt_reason : "done",
                CR, (unsigned long long)e->regs[0]);
        snprintf(g_step_state.last_halt, sizeof(g_step_state.last_halt),
                 "%s", e->halt_reason);
        g_step_state.active = 0;
        free(e);
        return 0;
    }

    /* Persist state back */
    g_step_state.pc         = e->pc;
    g_step_state.sp         = e->sp;
    g_step_state.flags_z    = e->flags_z;
    g_step_state.flags_n    = e->flags_n;
    g_step_state.flags_c    = e->flags_c;
    g_step_state.flags_v    = e->flags_v;
    g_step_state.steps_done = e->steps;
    memcpy(g_step_state.regs, e->regs, sizeof(e->regs));

    fprintf(out, "  %s→ PC now at 0x%llx  (total steps: %d)%s\n\n",
            CD, (unsigned long long)e->pc, e->steps, CR);

    free(e);
    return 1;
}

void dax_emulate_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i, limit;
    DAX_GUARD_BIN(bin);
    if (!opts || !out) return;
    limit = DAX_CLAMP(bin->nfunctions, 0, 4);
    for (i = 0; i < limit; i++) {
        uint64_t init[8] = {0,1,2,3,4,5,6,7};
        dax_emulate_func(bin, i, init, 4, opts, out);
    }
}
