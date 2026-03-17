#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <ctype.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

extern const char *dax_igrp_color(dax_igrp_t g, int color);
extern const char *dax_sec_type_color(dax_sec_type_t t, int color);

static dax_section_t *find_section_by_name(dax_binary_t *bin, const char *name) {
    int i;
    for (i = 0; i < bin->nsections; i++)
        if (strcmp(bin->sections[i].name, name) == 0)
            return &bin->sections[i];
    return NULL;
}

static dax_section_t *find_exec_section(dax_binary_t *bin) {
    int i;
    for (i = 0; i < bin->nsections; i++) {
        const char *n = bin->sections[i].name;
        if (bin->sections[i].size > 0 &&
            (strcmp(n,".text")==0 || strcmp(n,"CODE")==0 || strcmp(n,".code")==0))
            return &bin->sections[i];
    }
    for (i = 0; i < bin->nsections; i++) {
        if (bin->sections[i].size > 0 &&
            (bin->sections[i].flags & 0x4 || bin->sections[i].flags & 0x20000000))
            return &bin->sections[i];
    }
    return bin->nsections > 0 ? &bin->sections[0] : NULL;
}

/* Resolve any address to a printable string in any data section.
   Returns pointer into bin->data, or NULL if not a string. */
static const char *dax_resolve_string(dax_binary_t *bin, uint64_t addr) {
    int i;
    size_t len, left;
    const char *p;
    uint64_t off;

    if (!addr) return NULL;

    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *sec = &bin->sections[i];
        /* Search ALL readable sections — rodata, data, text literals */
        if (addr < sec->vaddr || addr >= sec->vaddr + sec->size) continue;
        if (sec->offset + sec->size > bin->size)                 continue;
        off = sec->offset + (addr - sec->vaddr);
        if (off >= bin->size)                                    continue;

        p    = (const char *)(bin->data + off);
        left = (size_t)(bin->size - off);
        if (left == 0) continue;

        if (p[0] == '\0') continue;

        {
            unsigned char b0 = (unsigned char)p[0];
            int is_utf8_lead = (b0 >= 0xC2 && b0 <= 0xF4);
            if (!isprint(b0) && !is_utf8_lead && b0 != '\n' && b0 != '\t') continue;
        }

        len = 0;
        while (len < left && len < 512) {
            unsigned char ch = (unsigned char)p[len];
            if (ch == 0) break;
            if (isprint(ch) || ch == '\n' || ch == '\t' || ch == '\r') {
                len++;
            } else if (ch >= 0xC2 && ch <= 0xF4 && len + 1 < left) {
                uint32_t cp2 = 0;
                int      sl2 = 0;
                if (dax_utf8_decode((const uint8_t *)p + len, left - len, &cp2, &sl2) == 0 && sl2 >= 2)
                    len += (size_t)sl2;
                else
                    break;
            } else {
                break;
            }
        }

        if (len < 2)        continue;
        if (len >= left)    continue;
        if (p[len] != '\0') continue;

        return p;
    }
    return NULL;
}

/* Legacy name kept for callers */
static const char *find_rodata_string(dax_binary_t *bin, uint64_t addr) {
    return dax_resolve_string(bin, addr);
}

/* Format a raw string into a safe, escaped, quoted form.
   out_buf must be at least out_max bytes. Returns out_buf. */
static char *dax_format_string(const char *str, char *out_buf, size_t out_max) {
    size_t k = 0;
    size_t j = 0;
    if (!str || out_max < 6) { if (out_buf) out_buf[0]=0; return out_buf; }

    for (j = 0; str[j] && k < out_max - 5; j++) {
        unsigned char ch = (unsigned char)str[j];
        if      (ch == '\n') { out_buf[k++]='\\'; out_buf[k++]='n'; }
        else if (ch == '\t') { out_buf[k++]='\\'; out_buf[k++]='t'; }
        else if (ch == '\r') { out_buf[k++]='\\'; out_buf[k++]='r'; }
        else if (ch == '\\') { out_buf[k++]='\\'; out_buf[k++]='\\'; }
        else if (ch == '"')   { out_buf[k++]='\\'; out_buf[k++]='"'; }
        else if (isprint(ch))  { out_buf[k++]=(char)ch; }
        else {
            /* hex escape for non-printable */
            if (k + 5 < out_max) {
                out_buf[k++] = '\\';
                out_buf[k++] = 'x';
                out_buf[k++] = "0123456789abcdef"[ch >> 4];
                out_buf[k++] = "0123456789abcdef"[ch & 0xf];
            }
        }
    }

    /* Truncate indicator */
    if (str[j] && k + 4 < out_max) {
        out_buf[k++] = '.'; out_buf[k++] = '.'; out_buf[k++] = '.';
    }

    out_buf[k] = 0;
    return out_buf;
}

static void print_func_header(dax_binary_t *bin, uint64_t addr,
                               dax_opts_t *opts, FILE *out) {
    dax_func_t *fn;
    dax_symbol_t *sym;
    int c = opts->color;

    fn  = opts->funcs ? dax_func_find(bin, addr) : NULL;
    sym = opts->symbols ? dax_sym_find(bin, addr) : NULL;

    if (!sym && !fn) return;
    if (fn && fn->start != addr) return;
    if (sym && sym->address != addr) return;

    fprintf(out, "\n");

    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  ┌─────────────────────────────────────────\n");

    if (sym) {
        const char *display = sym->demangled[0] ? sym->demangled : sym->name;
        const char *typestr =
            sym->type == SYM_FUNC   ? "func"   :
            sym->type == SYM_IMPORT ? "import" :
            sym->type == SYM_EXPORT ? "export" :
            sym->type == SYM_WEAK   ? "weak"   :
            sym->type == SYM_LOCAL  ? "local"  : "sym";

        if (sym->is_entry) {
            if (c) fprintf(out, "%s", COL_ENTRY);
            fprintf(out, "  │ [ENTRY]  ");
            if (c) fprintf(out, "%s", COL_FUNC);
        } else {
            fprintf(out, "  │ [%s]  ", typestr);
        }

        if (c) fprintf(out, "%s", COL_SYM);
        fprintf(out, "%s", display);
        if (c) fprintf(out, "%s", COL_FUNC);

        if (sym->demangled[0] && strcmp(sym->demangled, sym->name) != 0) {
            if (c) fprintf(out, "%s", COL_COMMENT);
            fprintf(out, "  ; %s", sym->name);
        }
        fprintf(out, "\n");
    }

    if (fn && fn->start == addr) {
        if (c) fprintf(out, "%s", COL_FUNC);
        if (fn->end > fn->start)
            fprintf(out, "  │ size: %llu bytes\n",
                    (unsigned long long)(fn->end - fn->start));
        if (opts->xrefs) {
            dax_xref_t xrs[8];
            int nx = dax_xref_find_to(bin, addr, xrs, 8);
            if (nx > 0) {
                int j;
                fprintf(out, "  │ xrefs: ");
                for (j = 0; j < nx; j++) {
                    if (c) fprintf(out, "%s", COL_XREF);
                    fprintf(out, "0x%llx%s", (unsigned long long)xrs[j].from,
                            xrs[j].is_call ? "(call)" : "(jmp)");
                    if (c) fprintf(out, "%s", COL_FUNC);
                    if (j < nx-1) fprintf(out, ", ");
                }
                fprintf(out, "\n");
            }
        }
    }

    if (c) fprintf(out, "%s", COL_FUNC);
    fprintf(out, "  └─────────────────────────────────────────\n");
    if (c) fprintf(out, "%s", COL_RESET);
}

static void print_label(dax_binary_t *bin, uint64_t addr,
                        dax_opts_t *opts, FILE *out) {
    dax_symbol_t *sym;
    int c = opts->color;

    if (!opts->symbols) return;
    sym = dax_sym_find(bin, addr);
    if (!sym || sym->type == SYM_FUNC || sym->type == SYM_EXPORT) return;

    if (c) fprintf(out, "%s", COL_LABEL);
    fprintf(out, "  %s:\n", sym->demangled[0] ? sym->demangled : sym->name);
    if (c) fprintf(out, "%s", COL_RESET);
}

static void print_section_header(dax_section_t *sec, dax_opts_t *opts, FILE *out) {
    int c = opts->color;
    const char *scol = c ? dax_sec_type_color(sec->type, c) : "";

    fprintf(out, "\n");
    if (c) fprintf(out, "%s", scol);
    fprintf(out, "  ════ section %-20s  vaddr=0x%016llx  size=%llu ════\n",
            sec->name, (unsigned long long)sec->vaddr, (unsigned long long)sec->size);
    if (c) fprintf(out, "%s", COL_RESET);
}

/* ─────────────────────────────────────────────────────────────────
 * Resolve string/symbol address from an instruction operand string.
 * Handles:
 *   x86_64 : LEA/MOV direct addr, RIP-relative [rip+disp], imm addr
 *   ARM64  : ADR/ADRP absolute addr, LDR literal, MOV #imm
 * Returns resolved virtual address, or 0 if cannot resolve.
 * ───────────────────────────────────────────────────────────────── */
static uint64_t resolve_operand_addr(dax_binary_t *bin,
                                     const char *mnemonic,
                                     const char *operands,
                                     uint64_t    insn_addr,
                                     uint8_t     insn_len) {
    uint64_t target = 0;
    const char *p;
    (void)bin;

    if (!operands || !operands[0]) return 0;

    /* ── ARM64 patterns ─────────────────────────────────────────── */
    if (bin->arch == ARCH_ARM64) {
        /* adr / adrp / ldr literal: operand is "xN, 0xADDR" */
        if (!strncmp(mnemonic,"adr",3) ||
            !strncmp(mnemonic,"ldr",3)) {
            p = strchr(operands, ',');
            if (p) sscanf(p+1, " 0x%llx", (unsigned long long *)&target);
        }
        /* mov / movz: second operand is immediate = address
           e.g.  movz x0, #0x520  or  mov x0, #0x520 */
        else if (!strncmp(mnemonic,"mov",3)) {
            p = strchr(operands, ',');
            if (p) {
                /* skip '#' if present */
                const char *q = p + 1;
                while (*q == ' ' || *q == '\t') q++;
                if (*q == '#') q++;
                sscanf(q, "0x%llx", (unsigned long long *)&target);
            }
        }
        /* bl / b direct target - not a data address */
        return target;
    }

    /* ── x86_64 patterns ───────────────────────────────────────── */

    /* 1. RIP-relative: "PTR [rip+0xDISP]" or "PTR [rip-0xDISP]"
          Real EA = insn_addr + insn_len + signed_disp              */
    p = strstr(operands, "rip+");
    if (p) {
        uint64_t disp = 0;
        sscanf(p + 4, "0x%llx", (unsigned long long *)&disp);
        target = insn_addr + (uint64_t)insn_len + disp;
        return target;
    }
    p = strstr(operands, "rip-");
    if (p) {
        uint64_t disp = 0;
        sscanf(p + 4, "0x%llx", (unsigned long long *)&disp);
        target = insn_addr + (uint64_t)insn_len - disp;
        return target;
    }

    /* 2. Direct immediate in second operand after comma:
          "mov rdi, 0x402010"
          "lea rax, 0x400560"                                       */
    p = strchr(operands, ',');
    if (p) {
        const char *q = p + 1;
        while (*q == ' ' || *q == '\t') q++;
        if (*q == '0' && *(q+1) == 'x') {
            sscanf(q, "0x%llx", (unsigned long long *)&target);
            if (target > 0x1000) return target;
        }
    }

    /* 3. Single direct address as first/only operand:
          "call 0x4005a0"  "jmp 0x4005a0"
          For call/jmp we don't want string resolve, handled below  */
    if (operands[0] == '0' && operands[1] == 'x') {
        sscanf(operands, "0x%llx", (unsigned long long *)&target);
        return target;
    }

    return 0;
}

static void print_insn_comment(dax_binary_t *bin, const char *mnemonic,
                                const char *operands, uint64_t addr,
                                uint8_t insn_len,
                                dax_opts_t *opts, FILE *out) {
    int        c      = opts->color;
    int        printed = 0;

    if (!opts->strings && !opts->symbols && !opts->groups) return;

    /* ── group annotation ──────────────────────────────────────── */
    if (opts->groups) {
        dax_igrp_t  grp = (bin->arch == ARCH_X86_64)
                           ? dax_classify_x86(mnemonic)
                           : dax_classify_arm64(mnemonic);
        const char *gs  = dax_igrp_str(grp);
        if (gs && gs[0]) {
            if (c) fprintf(out, "%s", COL_COMMENT);
            fprintf(out, "  ; [%s]", gs);
            if (c) fprintf(out, "%s", COL_RESET);
            printed = 1;
        }
    }

    /* ── string / symbol resolve ───────────────────────────────── */
    if ((opts->strings || opts->symbols) && operands[0]) {
        uint64_t    target;
        const char *str    = NULL;
        const char *sym    = NULL;
        char        safe[128];
        int         is_branch_insn = 0;

        /* Don't try to resolve strings for branch/call targets */
        if (!strncmp(mnemonic,"call",4) || !strncmp(mnemonic,"jmp",3) ||
            !strncmp(mnemonic,"j",1)    || !strcmp(mnemonic,"bl")      ||
            !strcmp(mnemonic,"blr")     || !strcmp(mnemonic,"br")      ||
            (mnemonic[0]=='b' && mnemonic[1]=='.'))
            is_branch_insn = 1;

        target = resolve_operand_addr(bin, mnemonic, operands, addr, insn_len);

        if (target && target > 0xfff) {
            if (opts->strings && !is_branch_insn) {
                str = dax_resolve_string(bin, target);
                if (str) {
                    dax_format_string(str, safe, sizeof(safe));
                    if (!printed) fprintf(out, "  ;");
                    else          fprintf(out, " ");
                    if (c) fprintf(out, "%s", COL_STRING);
                    fprintf(out, " \"%s\"", safe);
                    if (c) fprintf(out, "%s", COL_RESET);
                    printed = 1;
                }
            }

            if (opts->symbols && !str) {
                sym = dax_sym_name(bin, target);
                if (sym) {
                    if (!printed) fprintf(out, "  ;");
                    else          fprintf(out, " ");
                    if (c) fprintf(out, "%s", COL_SYM);
                    fprintf(out, " <%s>", sym);
                    if (c) fprintf(out, "%s", COL_RESET);
                    printed = 1;
                }
            }
        }
    }

    (void)printed;
}

static int should_disasm_all(dax_opts_t *opts) {
    return opts->all_sections;
}

int dax_disasm_x86_64(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    dax_section_t *sec;
    uint8_t       *code;
    size_t         code_size;
    uint64_t       base_addr;
    size_t         off;
    x86_insn_t     insn;
    int            count = 0;
    int            c     = opts->color;
    int            first_sec = 1;

    if (should_disasm_all(opts)) {
        int i;
        for (i = 0; i < bin->nsections; i++) {
            dax_opts_t sub = *opts;
            sub.all_sections = 0;
            strncpy(sub.section, bin->sections[i].name, sizeof(sub.section)-1);
            if (bin->sections[i].type == SEC_TYPE_CODE ||
                bin->sections[i].type == SEC_TYPE_PLT) {
                count += dax_disasm_x86_64(bin, &sub, out);
            }
        }
        return count;
    }

    if (opts->section[0]) {
        sec = find_section_by_name(bin, opts->section);
        if (!sec) sec = find_exec_section(bin);
    } else {
        sec = find_exec_section(bin);
    }

    if (!sec || sec->offset + sec->size > bin->size) {
        fprintf(stderr, "neodax: section not found or out of bounds\n");
        return -1;
    }

    code      = bin->data + sec->offset;
    code_size = (size_t)sec->size;
    base_addr = sec->vaddr;

    if (opts->start_addr && opts->start_addr > base_addr) {
        size_t delta = (size_t)(opts->start_addr - base_addr);
        if (delta >= code_size) return -1;
        code      += delta;
        code_size -= delta;
        base_addr  = opts->start_addr;
    }

    if (opts->funcs)
        dax_func_detect(bin, code, code_size, base_addr, sec);

    print_section_header(sec, opts, out);
    (void)first_sec;

    off = 0;
    while (off < code_size) {
        int     len;
        int     i;
        char    bytestr[64] = "";
        char   *bp;
        uint8_t *ptr;
        uint64_t cur_addr = base_addr + off;

        if (opts->end_addr != (uint64_t)-1 && cur_addr >= opts->end_addr) break;

        ptr = code + off;
        len = x86_decode(ptr, code_size - off, cur_addr, &insn);
        if (len <= 0) { off++; continue; }

        if (opts->funcs || opts->symbols)
            print_func_header(bin, cur_addr, opts, out);
        else
            print_label(bin, cur_addr, opts, out);

        if (c) fprintf(out, "%s", COL_ADDR);
        fprintf(out, "  %016llx", (unsigned long long)cur_addr);
        if (c) fprintf(out, "%s", COL_RESET);
        fprintf(out, "  ");

        if (opts->show_bytes) {
            bp = bytestr;
            for (i = 0; i < len && i < DAX_MAX_INSN_LEN; i++)
                bp += sprintf(bp, "%02x ", (unsigned)ptr[i]);
            for (; i < 10; i++) bp += sprintf(bp, "   ");
            if (c) fprintf(out, "%s%-32s%s", COL_BYTES, bytestr, COL_RESET);
            else   fprintf(out, "%-32s", bytestr);
        }

        {
            dax_igrp_t grp  = dax_classify_x86(insn.mnemonic);
            const char *mcol = c ? dax_igrp_color(grp, 1) : "";
            const char *ocol = c ? COL_OPS : "";
            const char *rst  = c ? COL_RESET : "";

            fprintf(out, "%s%-10s%s", mcol, insn.mnemonic, rst);
            if (insn.ops[0]) fprintf(out, "%s%s%s", ocol, insn.ops, rst);
        }

        print_insn_comment(bin, insn.mnemonic, insn.ops, cur_addr, insn.length, opts, out);

        fprintf(out, "\n");
        off += (size_t)len;
        count++;
    }

    fprintf(out, "\n");
    if (opts->verbose)
        fprintf(out, "  [%d instructions decoded]\n\n", count);
    bin->total_insns += (uint32_t)count;
    return count;
}

int dax_disasm_arm64(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    dax_section_t *sec;
    uint8_t       *code;
    size_t         code_size;
    uint64_t       base_addr;
    size_t         off;
    a64_insn_t     insn;
    int            count = 0;
    int            c     = opts->color;

    if (should_disasm_all(opts)) {
        int i;
        for (i = 0; i < bin->nsections; i++) {
            dax_opts_t sub = *opts;
            sub.all_sections = 0;
            strncpy(sub.section, bin->sections[i].name, sizeof(sub.section)-1);
            if (bin->sections[i].type == SEC_TYPE_CODE ||
                bin->sections[i].type == SEC_TYPE_PLT) {
                count += dax_disasm_arm64(bin, &sub, out);
            }
        }
        return count;
    }

    if (opts->section[0]) {
        sec = find_section_by_name(bin, opts->section);
        if (!sec) sec = find_exec_section(bin);
    } else {
        sec = find_exec_section(bin);
    }

    if (!sec || sec->offset + sec->size > bin->size) {
        fprintf(stderr, "neodax: section not found or out of bounds\n");
        return -1;
    }

    code      = bin->data + sec->offset;
    code_size = (size_t)sec->size;
    if (code_size % 4) code_size -= code_size % 4;
    base_addr = sec->vaddr;

    if (opts->start_addr && opts->start_addr > base_addr) {
        size_t delta = (size_t)(opts->start_addr - base_addr);
        if (delta >= code_size) return -1;
        code      += delta;
        code_size -= delta;
        base_addr  = opts->start_addr;
    }

    if (opts->funcs)
        dax_func_detect(bin, code, code_size, base_addr, sec);

    print_section_header(sec, opts, out);

    {
    uint64_t adrp_base = 0;
    int      adrp_reg  = -1;
    off = 0;
    while (off + 4 <= code_size) {
        uint32_t raw;
        char     bytestr[24];
        uint64_t cur_addr = base_addr + off;
        uint64_t str_hint = 0;

        if (opts->end_addr != (uint64_t)-1 && cur_addr >= opts->end_addr) break;

        raw = (uint32_t)(code[off]) | (code[off+1]<<8) |
              (code[off+2]<<16)     | (code[off+3]<<24);

        a64_decode(raw, cur_addr, &insn);

        /* Track adrp+add/ldr pairs for string resolution */
        {
            char rn_tmp[8], rn2_tmp[8];
            uint64_t pg = 0;
            int64_t  off12 = 0;
            if (!strcmp(insn.mnemonic,"adrp") &&
                sscanf(insn.operands,"%7[^,], 0x%llx",rn_tmp,(unsigned long long*)&pg)==2) {
                adrp_base = pg;
                adrp_reg  = (rn_tmp[0]=='x') ? atoi(rn_tmp+1) : (rn_tmp[0]=='w') ? atoi(rn_tmp+1) : -1;
            } else if ((!strcmp(insn.mnemonic,"add") || !strcmp(insn.mnemonic,"ldr")) && adrp_reg>=0 &&
                       sscanf(insn.operands,"%7[^,], %7[^,], #%lli",rn_tmp,rn2_tmp,(long long*)&off12)==3) {
                int r2 = (rn2_tmp[0]=='x'||rn2_tmp[0]=='w') ? atoi(rn2_tmp+1) : -1;
                if (r2 == adrp_reg) {
                    str_hint  = (uint64_t)((int64_t)adrp_base + off12);
                    adrp_reg  = -1;
                }
            } else if (adrp_reg >= 0) {
                adrp_reg = -1;
            }
        }

        if (opts->funcs || opts->symbols)
            print_func_header(bin, cur_addr, opts, out);
        else
            print_label(bin, cur_addr, opts, out);

        if (c) fprintf(out, "%s", COL_ADDR);
        fprintf(out, "  %016llx", (unsigned long long)cur_addr);
        if (c) fprintf(out, "%s", COL_RESET);
        fprintf(out, "  ");

        if (opts->show_bytes) {
            snprintf(bytestr, sizeof(bytestr), "%02x %02x %02x %02x",
                     code[off], code[off+1], code[off+2], code[off+3]);
            if (c) fprintf(out, "%s%-16s%s", COL_BYTES, bytestr, COL_RESET);
            else   fprintf(out, "%-16s", bytestr);
        }

        {
            dax_igrp_t grp  = dax_classify_arm64(insn.mnemonic);
            const char *mcol = c ? dax_igrp_color(grp, 1) : "";
            const char *ocol = c ? COL_OPS : "";
            const char *rst  = c ? COL_RESET : "";

            fprintf(out, "%s%-10s%s", mcol, insn.mnemonic, rst);
            if (insn.operands[0]) fprintf(out, "%s%s%s", ocol, insn.operands, rst);
        }

        /* Use pair-resolved address if available, else use normal resolver */
        if (str_hint && opts->strings) {
            const char *pstr = dax_resolve_string(bin, str_hint);
            if (pstr) {
                char safe[128];
                dax_format_string(pstr, safe, sizeof(safe));
                if (c) fprintf(out, "%s", COL_STRING);
                fprintf(out, "  ; \"%s\"", safe);
                if (c) fprintf(out, "%s", COL_RESET);
            } else {
                print_insn_comment(bin, insn.mnemonic, insn.operands, cur_addr, 4, opts, out);
            }
        } else {
            print_insn_comment(bin, insn.mnemonic, insn.operands, cur_addr, 4, opts, out);
        }

        fprintf(out, "\n");
        off += 4;
        count++;
    }
    } /* adrp tracking block */

    fprintf(out, "\n");
    if (opts->verbose)
        fprintf(out, "  [%d instructions decoded]\n\n", count);
    bin->total_insns += (uint32_t)count;
    return count;
}

int dax_disasm_riscv64(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    dax_section_t *sec;
    uint8_t       *code;
    size_t         code_size;
    uint64_t       base_addr;
    size_t         off;
    rv_insn_t      insn;
    int            count = 0;
    int            c     = opts->color;

    /* Section selection */
    if (opts->section[0]) {
        sec = find_section_by_name(bin, opts->section);
        if (!sec) sec = find_exec_section(bin);
    } else {
        sec = find_exec_section(bin);
    }

    if (!sec || sec->offset + sec->size > bin->size) {
        fprintf(stderr, "neodax: section not found or out of bounds\n");
        return -1;
    }

    code      = bin->data + sec->offset;
    code_size = (size_t)sec->size;
    base_addr = sec->vaddr;

    if (opts->start_addr && opts->start_addr > base_addr) {
        size_t delta = (size_t)(opts->start_addr - base_addr);
        if (delta >= code_size) return -1;
        code      += delta;
        code_size -= delta;
        base_addr  = opts->start_addr;
    }

    if (opts->funcs)
        dax_func_detect(bin, code, code_size, base_addr, sec);

    print_section_header(sec, opts, out);

    off = 0;
    while (off < code_size) {
        uint64_t cur_addr = base_addr + off;
        int      len;
        char     bytestr[32];
        uint64_t str_hint  = 0;
        static uint64_t auipc_base = 0;
        static int      auipc_reg  = -1;

        if (opts->end_addr != (uint64_t)-1 && cur_addr >= opts->end_addr) break;

        len = rv_decode(code + off, code_size - off, cur_addr, &insn);
        if (len <= 0) { off++; continue; }

        /* auipc + addi/add pair for string resolution */
        if (!strcmp(insn.mnemonic,"auipc")) {
            char rn_s[8];
            uint64_t pg = 0;
            if (sscanf(insn.operands, "%7[^,], 0x%llx", rn_s, (unsigned long long*)&pg)==2) {
                auipc_reg  = (rn_s[0]=='a'||rn_s[0]=='s'||rn_s[0]=='t'||rn_s[0]=='r'||rn_s[0]=='z') ? 99 : -1;
                if (rn_s[0]=='a'||rn_s[0]=='s'||rn_s[0]=='t') {
                    auipc_base = pg;
                    auipc_reg  = 1; /* any nonzero */
                }
            }
        } else if ((!strcmp(insn.mnemonic,"addi")||!strcmp(insn.mnemonic,"add")) && auipc_reg>0) {
            char rd_s[8],rn_s[8];
            int64_t off12=0;
            if (sscanf(insn.operands,"%7[^,], %7[^,], %lld",rd_s,rn_s,(long long*)&off12)==3) {
                str_hint = (uint64_t)((int64_t)auipc_base + off12);
                auipc_reg = -1;
            }
        } else if (!strcmp(insn.mnemonic,"li") && auipc_reg<0) {
            /* li rd, 0xADDR — direct address load */
            char rd_s[8];
            uint64_t lit = 0;
            if (sscanf(insn.operands,"%7[^,], 0x%llx",rd_s,(unsigned long long*)&lit)==2)
                str_hint = lit;
        } else {
            auipc_reg = -1;
        }

        if (opts->funcs || opts->symbols)
            print_func_header(bin, cur_addr, opts, out);
        else
            print_label(bin, cur_addr, opts, out);

        /* Address */
        if (c) fprintf(out, "%s", COL_ADDR);
        fprintf(out, "  %016llx", (unsigned long long)cur_addr);
        if (c) fprintf(out, "%s", COL_RESET);
        fprintf(out, "  ");

        /* Hex bytes */
        if (opts->show_bytes) {
            if (insn.length == 2)
                snprintf(bytestr, sizeof(bytestr), "%02x %02x",
                         code[off], code[off+1]);
            else
                snprintf(bytestr, sizeof(bytestr), "%02x %02x %02x %02x",
                         code[off], code[off+1], code[off+2], code[off+3]);
            if (c) fprintf(out, "%s%-16s%s", COL_BYTES, bytestr, COL_RESET);
            else   fprintf(out, "%-16s", bytestr);
        }

        /* Mnemonic + operands — compressed in dimmer color */
        {
            dax_igrp_t  grp  = dax_classify_riscv(insn.mnemonic);
            const char *mcol;
            if (insn.length == 2 && c)
                mcol = COL_RISCV_C;
            else
                mcol = c ? dax_igrp_color(grp, 1) : "";
            const char *ocol = c ? COL_OPS   : "";
            const char *rst  = c ? COL_RESET : "";
            fprintf(out, "%s%-12s%s", mcol, insn.mnemonic, rst);
            if (insn.operands[0])
                fprintf(out, "%s%s%s", ocol, insn.operands, rst);
        }

        /* String annotation */
        if (opts->strings) {
            if (str_hint && str_hint > 0xfff) {
                const char *pstr = dax_resolve_string(bin, str_hint);
                if (pstr) {
                    char safe[128];
                    dax_format_string(pstr, safe, sizeof(safe));
                    if (c) fprintf(out, "%s", COL_STRING);
                    fprintf(out, "  ; \"%s\"", safe);
                    if (c) fprintf(out, "%s", COL_RESET);
                } else {
                    print_insn_comment(bin, insn.mnemonic, insn.operands,
                                       cur_addr, (uint8_t)insn.length, opts, out);
                }
            } else {
                print_insn_comment(bin, insn.mnemonic, insn.operands,
                                   cur_addr, (uint8_t)insn.length, opts, out);
            }
        } else {
            print_insn_comment(bin, insn.mnemonic, insn.operands,
                               cur_addr, (uint8_t)insn.length, opts, out);
        }

        fprintf(out, "\n");
        off  += (size_t)len;
        count++;
    }

    fprintf(out, "\n");
    if (opts->verbose)
        fprintf(out, "  [%d instructions decoded]\n\n", count);
    return count;
}
