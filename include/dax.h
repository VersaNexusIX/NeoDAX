#ifndef DAX_H
#define DAX_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

#define DAX_VERSION "1.1.1"
#define DAX_MAX_INSN_LEN   15
#define DAX_MAX_MNEMONIC   32
#define DAX_MAX_OPERANDS   256
#define DAX_MAX_SECTIONS   128
#define DAX_BANNER_WIDTH   72
#define DAX_MAX_SYMBOLS    8192
#define DAX_MAX_XREFS      16384
#define DAX_MAX_FUNCTIONS  4096
#define DAX_SYM_NAME_LEN   512
#define DAX_MAX_BLOCKS     32768
#define DAX_MAX_EDGES      65536
#define DAX_MAX_COMMENTS   8192
#define DAX_COMMENT_LEN    512
#define DAX_DAXC_MAGIC     0x584F454EU
#define DAX_DAXC_VERSION   4
#define DAX_MAX_UNICODE_STR 512
#define DAX_MAX_USTRINGS   4096

typedef enum {
    ARCH_UNKNOWN = 0, ARCH_X86_64, ARCH_ARM64, ARCH_RISCV64
} dax_arch_t;

typedef enum {
    FMT_UNKNOWN = 0, FMT_ELF32, FMT_ELF64, FMT_PE32, FMT_PE64, FMT_RAW
} dax_fmt_t;

typedef enum {
    DAX_PLAT_UNKNOWN = 0, DAX_PLAT_LINUX, DAX_PLAT_ANDROID,
    DAX_PLAT_BSD, DAX_PLAT_UNIX, DAX_PLAT_WINDOWS
} dax_os_t;

typedef enum {
    SYM_UNKNOWN = 0, SYM_FUNC, SYM_OBJECT,
    SYM_IMPORT, SYM_EXPORT, SYM_WEAK, SYM_LOCAL
} dax_sym_type_t;

typedef enum {
    IGRP_UNKNOWN = 0, IGRP_PROLOGUE, IGRP_EPILOGUE,
    IGRP_CALL, IGRP_BRANCH, IGRP_RET, IGRP_SYSCALL,
    IGRP_ARITHMETIC, IGRP_LOGIC, IGRP_DATAMOV, IGRP_COMPARE,
    IGRP_STACK, IGRP_STRING, IGRP_FLOAT, IGRP_SIMD,
    IGRP_CRYPTO, IGRP_NOP, IGRP_PRIV
} dax_igrp_t;

typedef enum {
    SEC_TYPE_CODE, SEC_TYPE_DATA, SEC_TYPE_RODATA, SEC_TYPE_BSS,
    SEC_TYPE_PLT, SEC_TYPE_GOT, SEC_TYPE_DYNAMIC, SEC_TYPE_DEBUG, SEC_TYPE_OTHER
} dax_sec_type_t;

typedef enum {
    EDGE_FALL = 0,
    EDGE_JUMP,
    EDGE_COND_TRUE,
    EDGE_COND_FALSE,
    EDGE_CALL,
    EDGE_RET
} dax_edge_type_t;

typedef enum {
    STR_ENC_ASCII = 0,
    STR_ENC_UTF8,
    STR_ENC_UTF16LE,
    STR_ENC_UTF16BE
} dax_str_enc_t;

typedef struct {
    uint64_t    address;
    char        text[DAX_COMMENT_LEN];
} dax_comment_t;

typedef struct {
    uint64_t        address;
    char            name[DAX_SYM_NAME_LEN];
    char            demangled[DAX_SYM_NAME_LEN];
    dax_sym_type_t  type;
    uint64_t        size;
    int             is_entry;
} dax_symbol_t;

typedef struct {
    uint64_t    from;
    uint64_t    to;
    int         is_call;
} dax_xref_t;

typedef struct {
    uint64_t    start;
    uint64_t    end;
    char        name[DAX_SYM_NAME_LEN];
    int         sym_idx;
    uint32_t    insn_count;
    uint32_t    block_count;
    uint8_t     has_loops;
    uint8_t     has_calls;
} dax_func_t;

typedef struct {
    uint64_t        start;
    uint64_t        end;
    int             func_idx;
    int             id;
    int             succ[16];           /* expanded from 4 — poly dispatch tables need more */
    int             nsucc;
    int             pred[16];           /* expanded from 4 */
    int             npred;
    dax_edge_type_t edge_type[16];      /* parallel to succ[] */
    int             is_entry;
    int             is_exit;
    int             is_poly;            /* block is inside a polymorphic region  */
    int             is_smc;             /* block contains SMC-patched bytes      */
} dax_block_t;

typedef struct {
    uint64_t    address;
    uint8_t     bytes[DAX_MAX_INSN_LEN];
    uint8_t     length;
    char        mnemonic[DAX_MAX_MNEMONIC];
    char        operands[DAX_MAX_OPERANDS];
} dax_insn_t;

typedef struct {
    char            name[64];
    uint64_t        offset;
    uint64_t        vaddr;
    uint64_t        size;
    uint32_t        flags;
    dax_sec_type_t  type;
    uint32_t        insn_count;
    uint64_t        file_offset;
} dax_section_t;

typedef struct {
    uint64_t        address;
    char            value_utf8[DAX_MAX_UNICODE_STR];
    uint16_t        byte_length;
    dax_str_enc_t   encoding;
} dax_ustring_t;

/* ── Polymorphic obfuscation region ── */
#define DAX_POLY_MAX 128
typedef struct {
    uint64_t  start;          /* start vaddr of polymorphic region        */
    uint64_t  end;            /* end vaddr                                */
    int       mutation_score; /* 0-10 confidence                          */
    char      technique[64];  /* e.g. "junk insertion", "opcode subst"    */
    char      obfuscator[32]; /* e.g. "OLLVM", "Themida", "custom VM"     */
} dax_poly_region_t;

/* ── AIRE insight record ── */
#define DAX_AIRE_MAX 128
typedef struct {
    uint64_t  addr;
    char      category[32];   /* "vm-dispatch","poly","anti-debug", etc.  */
    char      insight[1024];  /* AIRE structured interpretation + action  */
    int       confidence;     /* 0-100                                    */
} dax_aire_insight_t;

/* ── AIRE memory: persists analysis context across sessions ── */
#define AIRE_MEMORY_MAX_ENTRIES  32
#define AIRE_MEMORY_FILE         ".aire_memory"

typedef struct {
    char     sha256[65];        /* binary fingerprint                       */
    char     filepath[256];     /* path to binary                           */
    char     category[32];      /* top insight category from last run       */
    char     summary[256];      /* short summary of last analysis           */
    char     last_cmd[64];      /* last interactive command run             */
    int      top_confidence;    /* confidence of top insight                */
    uint64_t top_addr;          /* address of top insight                   */
    int      run_count;         /* how many times AIRE ran on this binary   */
    char     timestamp[32];     /* ISO-8601 timestamp of last run           */
} aire_memory_entry_t;

typedef struct {
    aire_memory_entry_t entries[AIRE_MEMORY_MAX_ENTRIES];
    int                 count;
} aire_memory_t;

typedef struct {
    uint8_t         *data;
    size_t           size;
    dax_arch_t       arch;
    dax_fmt_t        fmt;
    dax_os_t         os;
    uint64_t         entry;
    uint64_t         base;
    uint64_t         image_size;
    dax_section_t    sections[DAX_MAX_SECTIONS];
    int              nsections;
    char             filepath[512];
    char             sha256[65];
    char             build_id[64];
    dax_symbol_t    *symbols;
    int              nsymbols;
    dax_xref_t      *xrefs;
    int              nxrefs;
    dax_func_t      *functions;
    int              nfunctions;
    dax_block_t     *blocks;
    int              nblocks;
    dax_comment_t   *comments;
    int              ncomments;
    dax_ustring_t   *ustrings;
    int              nustrings;
    uint32_t         total_insns;
    uint64_t         code_size;
    uint64_t         data_size;
    int              is_pie;
    int              is_stripped;
    int              has_debug;
    /* ── obfuscation analysis shared state ── */
    /* resolved indirect branch targets from symexec → feed to CFG */
    uint64_t  resolved_indirect_from[128]; /* br/blr instruction PC */
    uint64_t  resolved_indirect_to[128];   /* resolved target address */
    int       nresolved_indirect;
    /* SMC patches confirmed by symexec + emulator real-time tracking */
    uint64_t  smc_write_pc[128];
    uint64_t  smc_target_addr[128];
    uint32_t  smc_old_word[128];
    uint32_t  smc_new_word[128];
    int       nsmc_patches;
    /* SMC mutation chains: sequences of writes to the same target */
    uint64_t  smc_chain_addr[32];    /* addresses that were written >1 time */
    int       smc_chain_count[32];   /* how many times each was patched */
    int       nsmc_chains;
    /* emulator real-time SMC: writes captured during dax_emulate_all */
    uint64_t  emu_smc_write_pc[64];
    uint64_t  emu_smc_target[64];
    uint32_t  emu_smc_new_word[64];
    int       nemu_smc;
    /* obfuscation scoring (higher = more obfuscated) */
    int       obf_score_smc;
    int       obf_score_opaque;
    int       obf_score_indirect;
    int       obf_score_antidebug;

    /* ── polymorphic obfuscation map ── */
    dax_poly_region_t poly_regions[DAX_POLY_MAX];
    int               npoly_regions;

    /* ── AIRE: Assisted Intelligence Reverse Engineering ── */
    dax_aire_insight_t aire_insights[DAX_AIRE_MAX];
    int                naire_insights;
} dax_binary_t;

typedef struct {
    int      show_bytes;
    int      show_addr;
    int      color;
    int      verbose;
    int      symbols;
    int      xrefs;
    int      groups;
    int      strings;
    int      funcs;
    int      demangle;
    int      all_sections;
    int      cfg;
    int      loops;
    int      callgraph;
    int      switches;
    int      interactive;
    int      unicode;
    int      symexec;
    int      ssa;
    int      decompile;
    int      emulate;
    int      entropy;
    int      rda;
    int      ivf;
    char     section[64];
    char     output_daxc[512];
    char     plugin_dir[512];
    int      list_plugins;
    char     initial_shell_cmd[512];
    uint64_t start_addr;
    uint64_t end_addr;
    int      aire;        /* AIRE: Assisted Intelligence Reverse Engineering */
    int      poly_map;    /* polymorphic obfuscation mapping                */
    int      vm_trace;    /* detailed VM dispatch flow tracing              */
    int      dsa;         /* DSA — Dynamic Single Assignment (all funcs)   */
} dax_opts_t;

#pragma pack(push,1)
typedef struct {
    uint32_t  magic;
    uint32_t  version;
    uint32_t  arch;
    uint32_t  fmt;
    uint32_t  os;
    uint64_t  entry;
    uint64_t  base;
    uint64_t  image_size;
    char      filepath[512];
    char      sha256[65];
    char      build_id[64];
    uint32_t  nsections;
    uint32_t  nsymbols;
    uint32_t  nxrefs;
    uint32_t  nfunctions;
    uint32_t  nblocks;
    uint32_t  ncomments;
    uint32_t  nustrings;
    uint32_t  total_insns;
    uint64_t  code_size;
    uint64_t  data_size;
    uint8_t   is_pie;
    uint8_t   is_stripped;
    uint8_t   has_debug;
    uint8_t   pad[5];
    uint64_t  off_sections;
    uint64_t  off_symbols;
    uint64_t  off_xrefs;
    uint64_t  off_functions;
    uint64_t  off_blocks;
    uint64_t  off_comments;
    uint64_t  off_insns;
    uint64_t  ninsns;
    uint64_t  off_ustrings;
    uint8_t   reserved[32];
} daxc_header_t;
#pragma pack(pop)

int  dax_load_binary(const char *path, dax_binary_t *bin);
int  dax_parse_elf(dax_binary_t *bin);
int  dax_parse_pe(dax_binary_t *bin);
int  dax_disasm_x86_64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int  dax_disasm_arm64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
int  dax_disasm_riscv64(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts);
void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts);
void dax_free_binary(dax_binary_t *bin);

int           dax_sym_load(dax_binary_t *bin);
dax_symbol_t *dax_sym_find(dax_binary_t *bin, uint64_t addr);
const char   *dax_sym_name(dax_binary_t *bin, uint64_t addr);

int         dax_xref_build(dax_binary_t *bin);
int         dax_xref_find_to(dax_binary_t *bin, uint64_t addr, dax_xref_t *out, int max);

int         dax_func_detect(dax_binary_t *bin, uint8_t *code, size_t sz,
                             uint64_t base, dax_section_t *sec);
dax_func_t *dax_func_find(dax_binary_t *bin, uint64_t addr);

int         dax_demangle(const char *mangled, char *out, size_t outsz);

dax_igrp_t  dax_classify_x86(const char *mnem);
dax_igrp_t  dax_classify_arm64(const char *mnem);
dax_igrp_t  dax_classify_riscv(const char *mnem);
const char *dax_igrp_str(dax_igrp_t g);

dax_sec_type_t dax_sec_classify(const char *name, uint32_t flags);

int         dax_cfg_build(dax_binary_t *bin, uint8_t *code, size_t sz,
                           uint64_t base, int func_idx);
int         dax_cfg_print(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out);

int         dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path);
int         dax_daxc_read(const char *path, dax_binary_t *bin);
int         dax_daxc_to_asm(const char *daxc_path, const char *asm_path, int color);

void        dax_comment_add(dax_binary_t *bin, uint64_t addr, const char *text);
const char *dax_comment_get(dax_binary_t *bin, uint64_t addr);

int         dax_interactive(dax_binary_t *bin, dax_opts_t *opts);

int   dax_loop_detect(dax_binary_t *bin, int func_idx, FILE *out, int color);
void  dax_loop_print_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_callgraph_print(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_switch_detect(dax_binary_t *bin, dax_opts_t *opts,
                         uint8_t *code, size_t sz, uint64_t base, FILE *out);

void  dax_print_correction(int argc, char **argv, FILE *out);

void  dax_symexec_func(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out);
void  dax_symexec_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void  dax_symexec_prepass(dax_binary_t *bin); /* silent — populates resolved_indirect/smc fields */

void  dax_ssa_lift_func(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out);
void  dax_ssa_lift_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_decompile_func(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out);
void  dax_decompile_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_emulate_func(dax_binary_t *bin, int func_idx,
                       uint64_t *init_regs, int nregs,
                       dax_opts_t *opts, FILE *out);
void  dax_emulate_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_entropy_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_rda_section(dax_binary_t *bin, dax_section_t *sec,
                      uint64_t start_addr, dax_opts_t *opts, FILE *out);
void  dax_rda_all(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

void  dax_ivf_scan(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

/* ── AIRE: Assisted Intelligence Reverse Engineering ── */
/* ── DSA — Dynamic Single Assignment ─────────────────────────────────────── */
/* DSA opaque handle — 65536 bytes covers the full dsa_func_t struct.
 * Allocate on heap: void *df = calloc(1, DAX_DSA_FUNC_SIZE);
 * then cast to (dsa_func_t*) when calling dax_dsa_* APIs. */
#define DAX_DSA_FUNC_SIZE 65536
typedef struct dsa_func_t dsa_func_t;  /* opaque — full def in dsa.c */
void dax_dsa_build_func(dax_binary_t *bin, int func_idx,
                        struct dsa_func_t *out_df);
void dax_dsa_print(dax_binary_t *bin, int func_idx,
                   struct dsa_func_t *out_df,
                   dax_opts_t *opts, FILE *out);
/*
 * dax_dsa_aire_signals — lightweight DSA pass for AIRE rule integration.
 * Returns a bitmask:
 *   0x01  opaque-predicate (phi with zero-frequency arm)
 *   0x02  dispatch-index definition
 *   0x04  crypto constant
 *   0x08  SMC write definition
 *   0x10  loop induction variable
 *   0x20  key material
 *   0x40  loop counter
 */
int  dax_dsa_aire_signals(dax_binary_t *bin, int func_idx,
                          const char **out_crypto, int *out_ncrypto);

void  dax_aire_analyze(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

/* ── Polymorphic obfuscation map ── */
void  dax_poly_map(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

/* ── VM dispatch flow tracer ── */
void  dax_vm_trace(dax_binary_t *bin, dax_opts_t *opts, FILE *out);

/* ── VM dispatch trace buffer (defined in emulate.c, extern here) ── */
#define VM_DISPATCH_MAX 512
typedef struct {
    uint64_t dispatch_pc;
    uint64_t handler_pc;
    uint64_t opcode_val;
    uint64_t ip_val;
    int      step_no;
    char     handler_name[48];
} dax_vm_dispatch_entry_t;

extern dax_vm_dispatch_entry_t g_vm_trace[VM_DISPATCH_MAX];
extern int                     g_nvm_trace;

/* ── Step-resume emulation (interactive) ── */
typedef struct {
    int      active;
    int      func_idx;
    uint64_t pc;
    uint64_t regs[32];
    uint64_t sp;
    uint8_t  flags_z, flags_n, flags_c, flags_v;
    int      steps_done;
    char     last_halt[192];
} dax_step_state_t;

extern dax_step_state_t g_step_state;

void  dax_step_init(dax_binary_t *bin, int func_idx, dax_opts_t *opts, FILE *out);
int   dax_step_next(dax_binary_t *bin, int n, dax_opts_t *opts, FILE *out);

void  dax_scan_unicode(dax_binary_t *bin);
int   dax_utf8_decode(const uint8_t *buf, size_t len, uint32_t *codepoint, int *seq_len);
int   dax_utf16le_to_utf8(const uint8_t *src, size_t src_bytes, char *dst, size_t dst_max);
void  dax_print_unicode_strings(dax_binary_t *bin, dax_opts_t *opts, FILE *out);


void        dax_config_load(const char *path);
const char *dax_config_version(void);
const char *dax_config_name(void);
const char *dax_config_codename(void);
const char *dax_config_tagline(void);
const char *dax_config_logo(int line);
int         dax_config_loaded(void);
void  dax_compute_sha256(dax_binary_t *bin);

int   dax_harden_filesize(size_t sz, int color);
int   dax_harden_section_bounds(dax_binary_t *bin, int color);
int   dax_harden_symcount(int n, int color);
int   dax_harden_funccount(int n, int color);
int   dax_harden_blockcount(int n, int color);
int   dax_harden_xrefcount(int n, int color);
int   dax_harden_flat_binary(dax_binary_t *bin, int color);
int   dax_harden_daxc_magic(uint32_t magic, uint32_t version, int color);
int   dax_harden_string_field(const char *s, size_t maxlen, const char *field_name, int color);
int   dax_harden_address_range(uint64_t start, uint64_t end, const char *context, int color);
int   dax_harden_insn_length(uint8_t len, uint64_t addr, int color);
int   dax_harden_canary(int color);
int   dax_harden_alloc_size(size_t n, size_t elemsize, const char *what, int color);
int   dax_harden_elf_header(const uint8_t *data, size_t size, int color);
int   dax_harden_pe_header(const uint8_t *data, size_t size, int color);
void  dax_harden_all(dax_binary_t *bin, int color);

const char *dax_arch_str(dax_arch_t a);
const char *dax_fmt_str(dax_fmt_t f);
const char *dax_os_str(dax_os_t o);

#define COL_RESET     "\033[0m"
#define COL_ADDR      "\033[1;34m"
#define COL_BYTES     "\033[0;90m"
#define COL_MNEM      "\033[1;37m"
#define COL_OPS       "\033[0;36m"
#define COL_LABEL     "\033[1;33m"
#define COL_SECTION   "\033[1;32m"
#define COL_COMMENT   "\033[0;90m"
#define COL_SYM       "\033[1;35m"
#define COL_XREF      "\033[0;33m"
#define COL_FUNC      "\033[1;36m"
#define COL_STRING    "\033[0;32m"
#define COL_GRP_CALL  "\033[1;33m"
#define COL_GRP_BRNCH "\033[0;33m"
#define COL_GRP_RET   "\033[1;31m"
#define COL_GRP_ARITH "\033[0;37m"
#define COL_GRP_STACK "\033[0;35m"
#define COL_GRP_SYS   "\033[1;31m"
#define COL_GRP_NOP   "\033[0;90m"
#define COL_GRP_MOV   "\033[0;36m"
#define COL_SEC_CODE  "\033[1;34m"
#define COL_SEC_DATA  "\033[1;33m"
#define COL_SEC_RO    "\033[1;32m"
#define COL_SEC_BSS   "\033[0;90m"
#define COL_SEC_PLT   "\033[1;35m"
#define COL_SEC_GOT   "\033[0;35m"
#define COL_SEC_DBG   "\033[0;33m"
#define COL_ENTRY     "\033[1;31m"
#define COL_DEMANGLED "\033[0;32m"
#define COL_CFG_BLOCK "\033[0;34m"
#define COL_RISCV_C   "\033[0;33m"
#define COL_CFG_TRUE  "\033[0;32m"
#define COL_CFG_FALSE "\033[0;31m"
#define COL_CFG_CALL  "\033[0;33m"
#define COL_CFG_FALL  "\033[0;90m"
#define COL_HILIGHT   "\033[7m"
#define COL_STATUS    "\033[1;32m"
#define COL_INPUTBAR  "\033[0;37;44m"
#define COL_UNICODE   "\033[0;35m"
#define COL_PURPLE    "\033[0;35m"
#define COL_META      "\033[0;90m"

/* ── Plugin System ─────────────────────────────────────────────────────── */

#define DAX_PLUGIN_MAGIC   0x584F454EU
#define DAX_PLUGIN_VERSION 1
#define DAX_MAX_PLUGINS    64
#define DAX_PLUGIN_NAME_LEN 64

typedef enum {
    DAX_PLUGIN_HOOK_NONE      = 0,
    DAX_PLUGIN_HOOK_POST_LOAD = (1<<0),
    DAX_PLUGIN_HOOK_PRE_DISASM= (1<<1),
    DAX_PLUGIN_HOOK_POST_DISASM=(1<<2),
    DAX_PLUGIN_HOOK_IVF       = (1<<3),
    DAX_PLUGIN_HOOK_UI_PANEL  = (1<<4),
    DAX_PLUGIN_HOOK_BANNER    = (1<<5),
} dax_plugin_hook_t;

typedef struct {
    uint32_t          magic;
    uint32_t          version;
    char              name[DAX_PLUGIN_NAME_LEN];
    char              description[256];
    char              author[64];
    char              plugin_version[16];
    dax_plugin_hook_t hooks;
    void (*on_post_load)(dax_binary_t *bin, dax_opts_t *opts);
    void (*on_pre_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_post_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ivf)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ui_panel)(dax_binary_t *bin, FILE *out);
    void (*on_banner)(FILE *out, int color);
} dax_plugin_t;

typedef struct {
    dax_plugin_t *plugins[DAX_MAX_PLUGINS];
    int           count;
    char          load_errors[DAX_MAX_PLUGINS][256];
    int           nerrors;
} dax_plugin_registry_t;

int  dax_plugin_load_dir(dax_plugin_registry_t *reg, const char *dir);
void dax_plugin_run_post_load(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts);
void dax_plugin_run_pre_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_post_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_ivf(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_banner(dax_plugin_registry_t *reg, FILE *out, int color);
void dax_plugin_list(dax_plugin_registry_t *reg, FILE *out, int color);
void dax_plugin_free(dax_plugin_registry_t *reg);

#endif
