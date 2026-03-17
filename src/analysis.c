#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"
#include "riscv.h"

dax_igrp_t dax_classify_x86(const char *m) {
    if (!m || !m[0]) return IGRP_UNKNOWN;

    if (!strcmp(m,"nop") || !strcmp(m,"endbr64") || !strcmp(m,"endbr32"))
        return IGRP_NOP;

    if (!strncmp(m,"call",4))
        return IGRP_CALL;

    if (!strncmp(m,"ret",3) || !strcmp(m,"iret") || !strcmp(m,"iretq"))
        return IGRP_RET;

    if (!strncmp(m,"jmp",3) || !strncmp(m,"j",1))
        return IGRP_BRANCH;

    if (!strcmp(m,"syscall") || !strcmp(m,"sysenter") || !strcmp(m,"int") ||
        !strcmp(m,"int3") || !strcmp(m,"int1"))
        return IGRP_SYSCALL;

    if (!strcmp(m,"push") || !strcmp(m,"pop") || !strcmp(m,"pushfq") ||
        !strcmp(m,"popfq") || !strcmp(m,"pushf") || !strcmp(m,"popf") ||
        !strcmp(m,"enter") || !strcmp(m,"leave"))
        return IGRP_STACK;

    if (!strcmp(m,"mov") || !strcmp(m,"movsx") || !strcmp(m,"movzx") ||
        !strcmp(m,"movabs") || !strcmp(m,"movsxd") || !strcmp(m,"movss") ||
        !strcmp(m,"movsd") || !strcmp(m,"movaps") || !strcmp(m,"movups") ||
        !strcmp(m,"movdqu") || !strcmp(m,"movq") || !strcmp(m,"lea") ||
        !strcmp(m,"xchg") || !strcmp(m,"cmpxchg") || !strcmp(m,"xadd") ||
        !strcmp(m,"bswap") || !strcmp(m,"cbw") || !strcmp(m,"cwde") ||
        !strcmp(m,"cdqe") || !strcmp(m,"cwd") || !strcmp(m,"cdq") || !strcmp(m,"cqo"))
        return IGRP_DATAMOV;

    if (!strcmp(m,"add") || !strcmp(m,"sub") || !strcmp(m,"mul") || !strcmp(m,"imul") ||
        !strcmp(m,"div") || !strcmp(m,"idiv") || !strcmp(m,"inc") || !strcmp(m,"dec") ||
        !strcmp(m,"neg") || !strcmp(m,"adc") || !strcmp(m,"sbb") ||
        !strcmp(m,"shl") || !strcmp(m,"shr") || !strcmp(m,"sar") || !strcmp(m,"rol") ||
        !strcmp(m,"ror") || !strcmp(m,"rcl") || !strcmp(m,"rcr") ||
        !strcmp(m,"shld") || !strcmp(m,"shrd"))
        return IGRP_ARITHMETIC;

    if (!strcmp(m,"and") || !strcmp(m,"or") || !strcmp(m,"xor") || !strcmp(m,"not") ||
        !strcmp(m,"bsf") || !strcmp(m,"bsr") || !strcmp(m,"bt") || !strcmp(m,"bts") ||
        !strcmp(m,"btr") || !strcmp(m,"btc") || !strcmp(m,"tzcnt") || !strcmp(m,"lzcnt") ||
        !strcmp(m,"popcnt") || !strcmp(m,"andn"))
        return IGRP_LOGIC;

    if (!strcmp(m,"cmp") || !strcmp(m,"test") || !strncmp(m,"set",3) ||
        !strncmp(m,"cmov",4) || !strcmp(m,"cmpxchg8b"))
        return IGRP_COMPARE;

    if (!strncmp(m,"rep",3) || !strcmp(m,"movsb") || !strcmp(m,"movsw") ||
        !strcmp(m,"movsd") || !strcmp(m,"movsq") || !strcmp(m,"stosb") ||
        !strcmp(m,"stosw") || !strcmp(m,"stosd") || !strcmp(m,"stosq") ||
        !strcmp(m,"scasb") || !strcmp(m,"scasw") || !strcmp(m,"scasd") ||
        !strcmp(m,"cmpsb") || !strcmp(m,"cmpsw") || !strcmp(m,"cmpsd") ||
        !strcmp(m,"lodsb") || !strcmp(m,"lodsw") || !strcmp(m,"lodsd"))
        return IGRP_STRING;

    if (!strncmp(m,"f",1) || !strncmp(m,"add",3) || !strncmp(m,"mul",3) ||
        !strncmp(m,"xorp",2) || !strncmp(m,"addp",4) || !strncmp(m,"subp",4))
        return IGRP_FLOAT;

    if (!strcmp(m,"cli") || !strcmp(m,"sti") || !strcmp(m,"clc") || !strcmp(m,"stc") ||
        !strcmp(m,"cld") || !strcmp(m,"std") || !strcmp(m,"hlt") || !strcmp(m,"ud2") ||
        !strcmp(m,"cpuid") || !strcmp(m,"rdtsc") || !strcmp(m,"rdmsr") ||
        !strcmp(m,"wrmsr") || !strcmp(m,"rdpmc") || !strcmp(m,"in") || !strcmp(m,"out"))
        return IGRP_PRIV;

    return IGRP_UNKNOWN;
}

dax_igrp_t dax_classify_arm64(const char *m) {
    if (!m || !m[0]) return IGRP_UNKNOWN;

    if (!strcmp(m,"nop") || !strcmp(m,"isb") || !strcmp(m,"dsb") || !strcmp(m,"dmb"))
        return IGRP_NOP;

    if (!strcmp(m,"bl") || !strcmp(m,"blr"))
        return IGRP_CALL;

    if (!strcmp(m,"ret"))
        return IGRP_RET;

    if (!strncmp(m,"b.",2) || !strcmp(m,"b") || !strcmp(m,"br") ||
        !strcmp(m,"cbz") || !strcmp(m,"cbnz") || !strcmp(m,"tbz") || !strcmp(m,"tbnz"))
        return IGRP_BRANCH;

    if (!strcmp(m,"svc") || !strcmp(m,"hvc") || !strcmp(m,"smc") || !strcmp(m,"brk"))
        return IGRP_SYSCALL;

    if (!strcmp(m,"stp") || !strcmp(m,"ldp") ||
        !strcmp(m,"str") || !strcmp(m,"strb") || !strcmp(m,"strh") ||
        !strcmp(m,"ldr") || !strcmp(m,"ldrb") || !strcmp(m,"ldrh") ||
        !strcmp(m,"ldrsb") || !strcmp(m,"ldrsh") || !strcmp(m,"ldrsw"))
        return IGRP_STACK;

    if (!strcmp(m,"mov") || !strcmp(m,"movz") || !strcmp(m,"movn") || !strcmp(m,"movk") ||
        !strcmp(m,"adr") || !strcmp(m,"adrp") || !strcmp(m,"fmov") ||
        !strcmp(m,"uxtb") || !strcmp(m,"uxth") || !strcmp(m,"sxtb") ||
        !strcmp(m,"sxth") || !strcmp(m,"sxtw") || !strcmp(m,"bfm") ||
        !strcmp(m,"ubfm") || !strcmp(m,"sbfm") || !strcmp(m,"extr"))
        return IGRP_DATAMOV;

    if (!strcmp(m,"add") || !strcmp(m,"adds") || !strcmp(m,"sub") || !strcmp(m,"subs") ||
        !strcmp(m,"mul") || !strcmp(m,"madd") || !strcmp(m,"msub") ||
        !strcmp(m,"mneg") || !strcmp(m,"udiv") || !strcmp(m,"sdiv") ||
        !strcmp(m,"lsl") || !strcmp(m,"lsr") || !strcmp(m,"asr") || !strcmp(m,"ror") ||
        !strcmp(m,"neg") || !strcmp(m,"negs") || !strcmp(m,"adc") || !strcmp(m,"sbc") ||
        !strcmp(m,"clz") || !strcmp(m,"cls") || !strcmp(m,"rbit") ||
        !strcmp(m,"rev") || !strcmp(m,"rev16") || !strcmp(m,"rev64"))
        return IGRP_ARITHMETIC;

    if (!strcmp(m,"and") || !strcmp(m,"ands") || !strcmp(m,"orr") || !strcmp(m,"orn") ||
        !strcmp(m,"eor") || !strcmp(m,"eon") || !strcmp(m,"bic") || !strcmp(m,"bics") ||
        !strcmp(m,"tst"))
        return IGRP_LOGIC;

    if (!strcmp(m,"cmp") || !strcmp(m,"cmn") || !strcmp(m,"csel") || !strcmp(m,"cset") ||
        !strncmp(m,"csinc",5) || !strncmp(m,"csneg",5) || !strncmp(m,"csinv",5) ||
        !strcmp(m,"ccmp") || !strcmp(m,"ccmn") || !strcmp(m,"cinc") ||
        !strcmp(m,"cinv") || !strcmp(m,"cneg"))
        return IGRP_COMPARE;

    if (!strcmp(m,"mrs") || !strcmp(m,"msr") || !strcmp(m,"eret") ||
        !strcmp(m,"clrex") || !strcmp(m,"sys"))
        return IGRP_PRIV;

    return IGRP_UNKNOWN;
}

const char *dax_igrp_str(dax_igrp_t g) {
    switch (g) {
        case IGRP_PROLOGUE:  return "prologue";
        case IGRP_EPILOGUE:  return "epilogue";
        case IGRP_CALL:      return "call";
        case IGRP_BRANCH:    return "branch";
        case IGRP_RET:       return "return";
        case IGRP_SYSCALL:   return "syscall";
        case IGRP_ARITHMETIC:return "arithmetic";
        case IGRP_LOGIC:     return "logic";
        case IGRP_DATAMOV:   return "data-move";
        case IGRP_COMPARE:   return "compare";
        case IGRP_STACK:     return "stack";
        case IGRP_STRING:    return "string";
        case IGRP_FLOAT:     return "float";
        case IGRP_SIMD:      return "simd";
        case IGRP_NOP:       return "nop";
        case IGRP_PRIV:      return "privileged";
        default:             return "";
    }
}

const char *dax_igrp_color(dax_igrp_t g, int color) {
    if (!color) return "";
    switch (g) {
        case IGRP_CALL:       return COL_GRP_CALL;
        case IGRP_BRANCH:     return COL_GRP_BRNCH;
        case IGRP_RET:        return COL_GRP_RET;
        case IGRP_SYSCALL:    return COL_GRP_SYS;
        case IGRP_STACK:      return COL_GRP_STACK;
        case IGRP_NOP:        return COL_GRP_NOP;
        case IGRP_DATAMOV:    return COL_GRP_MOV;
        case IGRP_ARITHMETIC:
        case IGRP_LOGIC:      return COL_GRP_ARITH;
        default:              return COL_MNEM;
    }
}

dax_sec_type_t dax_sec_classify(const char *name, uint32_t flags) {
    if (!name) return SEC_TYPE_OTHER;
    if (!strcmp(name,".text") || !strcmp(name,"CODE") || !strcmp(name,".code") ||
        !strcmp(name,".init") || !strcmp(name,".fini") || !strcmp(name,".plt") ||
        !strcmp(name,".plt.got") || !strcmp(name,".plt.sec"))
        return (!strcmp(name,".plt")||!strcmp(name,".plt.got")||!strcmp(name,".plt.sec"))
               ? SEC_TYPE_PLT : SEC_TYPE_CODE;

    if (!strcmp(name,".data") || !strcmp(name,".data.rel.ro") ||
        !strcmp(name,".init_array") || !strcmp(name,".fini_array"))
        return SEC_TYPE_DATA;

    if (!strcmp(name,".rodata") || !strcmp(name,".rdata") || !strcmp(name,".eh_frame"))
        return SEC_TYPE_RODATA;

    if (!strcmp(name,".bss") || !strcmp(name,".tbss"))
        return SEC_TYPE_BSS;

    if (!strcmp(name,".got") || !strcmp(name,".got.plt"))
        return SEC_TYPE_GOT;

    if (!strcmp(name,".dynamic") || !strcmp(name,".dynstr") ||
        !strcmp(name,".dynsym") || !strcmp(name,".rela.dyn") ||
        !strcmp(name,".rela.plt") || !strcmp(name,".gnu.version") ||
        !strcmp(name,".gnu.version_r") || !strcmp(name,".gnu.hash"))
        return SEC_TYPE_DYNAMIC;

    if (!strncmp(name,".debug",6) || !strcmp(name,".gnu_debuglink") ||
        !strcmp(name,".gnu_debugaltlink") || !strcmp(name,".eh_frame_hdr") ||
        !strcmp(name,".note.gnu.build-id") || !strcmp(name,".note.ABI-tag") ||
        !strcmp(name,".note.gnu.property") || !strcmp(name,".shstrtab") ||
        !strcmp(name,".strtab") || !strcmp(name,".symtab"))
        return SEC_TYPE_DEBUG;

    (void)flags;
    return SEC_TYPE_OTHER;
}

const char *dax_sec_type_color(dax_sec_type_t t, int color) {
    if (!color) return "";
    switch (t) {
        case SEC_TYPE_CODE:    return COL_SEC_CODE;
        case SEC_TYPE_DATA:    return COL_SEC_DATA;
        case SEC_TYPE_RODATA:  return COL_SEC_RO;
        case SEC_TYPE_BSS:     return COL_SEC_BSS;
        case SEC_TYPE_PLT:     return COL_SEC_PLT;
        case SEC_TYPE_GOT:     return COL_SEC_GOT;
        case SEC_TYPE_DYNAMIC: return COL_COMMENT;
        case SEC_TYPE_DEBUG:   return COL_SEC_DBG;
        default:               return COL_MNEM;
    }
}

int dax_xref_build(dax_binary_t *bin) {
    int i;
    if (!bin->xrefs) {
        bin->xrefs = (dax_xref_t *)calloc(DAX_MAX_XREFS, sizeof(dax_xref_t));
        if (!bin->xrefs) return -1;
    }
    bin->nxrefs = 0;

    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *sec = &bin->sections[i];
        uint8_t       *code;
        size_t         code_size;
        uint64_t       addr;
        size_t         off;

        if (sec->type != SEC_TYPE_CODE && sec->type != SEC_TYPE_PLT) continue;
        if (sec->offset + sec->size > bin->size) continue;

        code      = bin->data + sec->offset;
        code_size = (size_t)sec->size;
        addr      = sec->vaddr;
        off       = 0;

        if (bin->arch == ARCH_X86_64) {
            x86_insn_t insn;
            while (off < code_size) {
                int len = x86_decode(code + off, code_size - off, addr + off, &insn);
                if (len <= 0) { off++; continue; }
                {
                    dax_igrp_t grp = dax_classify_x86(insn.mnemonic);
                    if ((grp == IGRP_CALL || grp == IGRP_BRANCH) &&
                        insn.ops[0] && insn.ops[0] == '0') {
                        uint64_t target = 0;
                        sscanf(insn.ops, "0x%llx", (unsigned long long *)&target);
                        if (target && bin->nxrefs < DAX_MAX_XREFS) {
                            bin->xrefs[bin->nxrefs].from    = addr + off;
                            bin->xrefs[bin->nxrefs].to      = target;
                            bin->xrefs[bin->nxrefs].is_call = (grp == IGRP_CALL);
                            bin->nxrefs++;
                        }
                    }
                }
                off += (size_t)len;
            }
        } else if (bin->arch == ARCH_ARM64) {
            while (off + 4 <= code_size) {
                uint32_t raw2 = (uint32_t)(code[off])|(code[off+1]<<8)|
                                (code[off+2]<<16)|(code[off+3]<<24);
                a64_insn_t insn2;
                a64_decode(raw2, addr + off, &insn2);
                {
                    dax_igrp_t grp = dax_classify_arm64(insn2.mnemonic);
                    if ((grp == IGRP_CALL || grp == IGRP_BRANCH) &&
                        insn2.operands[0] == '0') {
                        uint64_t target = 0;
                        sscanf(insn2.operands, "0x%llx", (unsigned long long *)&target);
                        if (target && bin->nxrefs < DAX_MAX_XREFS) {
                            bin->xrefs[bin->nxrefs].from    = addr + off;
                            bin->xrefs[bin->nxrefs].to      = target;
                            bin->xrefs[bin->nxrefs].is_call = (grp == IGRP_CALL);
                            bin->nxrefs++;
                        }
                    }
                }
                off += 4;
            }
        }
    }
    return bin->nxrefs;
}

int dax_xref_find_to(dax_binary_t *bin, uint64_t addr, dax_xref_t *out, int max) {
    int i, found = 0;
    for (i = 0; i < bin->nxrefs && found < max; i++) {
        if (bin->xrefs[i].to == addr)
            out[found++] = bin->xrefs[i];
    }
    return found;
}

int dax_func_detect(dax_binary_t *bin, uint8_t *code, size_t code_size,
                    uint64_t base_addr, dax_section_t *sec) {
    size_t   off = 0;
    uint64_t cur_func_start = 0;
    int      in_func = 0;

    if (!bin->functions) {
        bin->functions = (dax_func_t *)calloc(DAX_MAX_FUNCTIONS, sizeof(dax_func_t));
        if (!bin->functions) return -1;
    }

    if (bin->arch == ARCH_X86_64) {
        x86_insn_t insn;
        while (off < code_size) {
            uint64_t cur_addr = base_addr + off;
            int      len;

            dax_symbol_t *sym = dax_sym_find(bin, cur_addr);
            if (sym && (sym->type==SYM_FUNC||sym->type==SYM_EXPORT||
                        sym->type==SYM_WEAK||sym->is_entry)) {
                if (in_func && cur_func_start && bin->nfunctions < DAX_MAX_FUNCTIONS)
                    bin->functions[bin->nfunctions-1].end = cur_addr;
                if (bin->nfunctions < DAX_MAX_FUNCTIONS) {
                    dax_func_t *fn = &bin->functions[bin->nfunctions++];
                    fn->start   = cur_addr;
                    fn->end     = 0;
                    fn->sym_idx = (int)(sym - bin->symbols);
                    strncpy(fn->name, sym->demangled[0]?sym->demangled:sym->name,
                            DAX_SYM_NAME_LEN-1);
                }
                cur_func_start = cur_addr;
                in_func = 1;
            }

            len = x86_decode(code+off, code_size-off, cur_addr, &insn);
            if (len <= 0) { off++; continue; }

            if (!in_func) {
                int is_push_rbp = (!strcmp(insn.mnemonic,"push") && strstr(insn.ops,"rbp"));
                int is_endbr    = (!strcmp(insn.mnemonic,"endbr64")||!strcmp(insn.mnemonic,"endbr32"));
                if (is_push_rbp || is_endbr) {
                    if (bin->nfunctions < DAX_MAX_FUNCTIONS) {
                        dax_func_t *fn = &bin->functions[bin->nfunctions++];
                        fn->start   = cur_addr;
                        fn->end     = 0;
                        fn->sym_idx = -1;
                        snprintf(fn->name, DAX_SYM_NAME_LEN, "sub_%llx",
                                 (unsigned long long)cur_addr);
                        cur_func_start = cur_addr;
                        in_func = 1;
                    }
                }
            }

            if (in_func && (!strncmp(insn.mnemonic,"ret",3)||!strcmp(insn.mnemonic,"iret")||
                            !strcmp(insn.mnemonic,"iretq"))) {
                if (bin->nfunctions > 0)
                    bin->functions[bin->nfunctions-1].end = cur_addr+(uint64_t)len;
                in_func = 0;
            }

            off += (size_t)len;
        }

    } else if (bin->arch == ARCH_ARM64) {
        /* First pass: mark bl targets as sub_ADDR */
        {
            size_t off2 = 0;
            while (off2 + 4 <= code_size) {
                uint32_t r2 = (uint32_t)(code[off2])|(code[off2+1]<<8)|
                              (code[off2+2]<<16)|(code[off2+3]<<24);
                a64_insn_t i2; a64_decode(r2, base_addr+off2, &i2);
                if (!strcmp(i2.mnemonic,"bl") && i2.operands[0]=='0') {
                    uint64_t tgt = 0;
                    sscanf(i2.operands,"0x%llx",(unsigned long long*)&tgt);
                    if (tgt >= base_addr && tgt < base_addr+code_size) {
                        int dup=0, fi2;
                        for (fi2=0;fi2<bin->nfunctions;fi2++)
                            if (bin->functions[fi2].start==tgt){dup=1;break;}
                        if (!dup && bin->nfunctions < DAX_MAX_FUNCTIONS) {
                            dax_func_t *fn=&bin->functions[bin->nfunctions++];
                            fn->start=tgt; fn->end=0; fn->sym_idx=-1;
                            snprintf(fn->name,DAX_SYM_NAME_LEN,"sub_%llx",
                                     (unsigned long long)tgt);
                        }
                    }
                }
                off2 += 4;
            }
        }

        while (off + 4 <= code_size) {
            uint64_t cur_addr = base_addr + off;
            uint32_t raw = (uint32_t)(code[off])|(code[off+1]<<8)|
                           (code[off+2]<<16)|(code[off+3]<<24);
            a64_insn_t insn; a64_decode(raw, cur_addr, &insn);

            dax_symbol_t *sym = dax_sym_find(bin, cur_addr);
            if (sym && (sym->type==SYM_FUNC||sym->type==SYM_EXPORT||sym->is_entry)) {
                if (in_func && bin->nfunctions > 0)
                    bin->functions[bin->nfunctions-1].end = cur_addr;
                { int fi2, fnd=0;
                  for (fi2=0;fi2<bin->nfunctions;fi2++)
                      if (bin->functions[fi2].start==cur_addr) {
                          bin->functions[fi2].sym_idx=(int)(sym-bin->symbols);
                          const char *sn=sym->demangled[0]?sym->demangled:sym->name;
                          strncpy(bin->functions[fi2].name,sn,DAX_SYM_NAME_LEN-1);
                          fnd=1; break;
                      }
                  if (!fnd && bin->nfunctions < DAX_MAX_FUNCTIONS) {
                      dax_func_t *fn=&bin->functions[bin->nfunctions++];
                      fn->start=cur_addr; fn->end=0;
                      fn->sym_idx=(int)(sym-bin->symbols);
                      strncpy(fn->name,sym->demangled[0]?sym->demangled:sym->name,
                              DAX_SYM_NAME_LEN-1);
                  }
                }
                cur_func_start = cur_addr; in_func = 1;
            }

            if (!in_func) {
                int is_bl_tgt=0, fi2;
                for (fi2=0;fi2<bin->nfunctions;fi2++)
                    if (bin->functions[fi2].start==cur_addr){is_bl_tgt=1;break;}
                if (is_bl_tgt) {
                    in_func=1; cur_func_start=cur_addr;
                } else {
                    int is_pro =
                        !strcmp(insn.mnemonic,"paciasp") ||
                        !strncmp(insn.mnemonic,"bti",3)  ||
                        (!strcmp(insn.mnemonic,"stp") && strstr(insn.operands,"x29,x30"));
                    if (is_pro && bin->nfunctions < DAX_MAX_FUNCTIONS) {
                        dax_func_t *fn=&bin->functions[bin->nfunctions++];
                        fn->start=cur_addr; fn->end=0; fn->sym_idx=-1;
                        snprintf(fn->name,DAX_SYM_NAME_LEN,"sub_%llx",
                                 (unsigned long long)cur_addr);
                        cur_func_start=cur_addr; in_func=1;
                    }
                }
            }

            if (in_func && (!strcmp(insn.mnemonic,"ret") ||
                            !strcmp(insn.mnemonic,"retaa") ||
                            !strcmp(insn.mnemonic,"retab"))) {
                if (bin->nfunctions > 0)
                    bin->functions[bin->nfunctions-1].end = cur_addr+4;
                in_func=0;
            }
            off += 4;
        }
    }

    if (in_func && bin->nfunctions > 0 && !bin->functions[bin->nfunctions-1].end)
        bin->functions[bin->nfunctions-1].end = base_addr + code_size;
    (void)sec; (void)cur_func_start;
    return bin->nfunctions;
}

dax_func_t *dax_func_find(dax_binary_t *bin, uint64_t addr) {
    int i;
    for (i = 0; i < bin->nfunctions; i++) {
        if (addr >= bin->functions[i].start &&
            (bin->functions[i].end == 0 || addr < bin->functions[i].end))
            return &bin->functions[i];
    }
    return NULL;
}

void dax_switch_detect(dax_binary_t *bin, dax_opts_t *opts,
                       uint8_t *code, size_t sz, uint64_t base, FILE *out) {
    int    c  = opts->color;
    size_t off = 0;
    int    nfound = 0;

    const char *C_SW  = c ? "\033[1;35m" : "";
    const char *C_ADR = c ? "\033[1;34m" : "";
    const char *C_CMT = c ? "\033[0;90m" : "";
    const char *C_RST = c ? "\033[0m"    : "";

    if (bin->arch != ARCH_X86_64) return;

    while (off < sz) {
        x86_insn_t cmp_insn, jmp_insn;
        int   l1, l2;
        uint64_t cur = base + off;
        size_t   next_off;
        char     dummy_mnem[32];
        char     dummy_ops[128];

        l1 = x86_decode(code + off, sz - off, cur, &cmp_insn);
        if (l1 <= 0) { off++; continue; }

        strncpy(dummy_mnem, cmp_insn.mnemonic, 31);
        strncpy(dummy_ops,  cmp_insn.ops,      127);

        next_off = off + (size_t)l1;
        if (next_off + 2 >= sz) { off += (size_t)l1; continue; }

        l2 = x86_decode(code + next_off, sz - next_off,
                        base + next_off, &jmp_insn);
        if (l2 <= 0) { off += (size_t)l1; continue; }

        {
            int is_cmp_imm =
                (strcmp(dummy_mnem, "cmp") == 0 ||
                 strcmp(dummy_mnem, "sub") == 0) &&
                strchr(dummy_ops, ',') != NULL;

            int is_ja_jb =
                (strncmp(jmp_insn.mnemonic, "ja",  2) == 0 ||
                 strncmp(jmp_insn.mnemonic, "jb",  2) == 0 ||
                 strncmp(jmp_insn.mnemonic, "jae", 3) == 0 ||
                 strncmp(jmp_insn.mnemonic, "jbe", 3) == 0);

            int is_jmp_mem =
                (strcmp(jmp_insn.mnemonic, "jmp") == 0 &&
                 (strstr(jmp_insn.ops, "PTR") != NULL ||
                  strstr(jmp_insn.ops, "[") != NULL));

            if (is_cmp_imm && (is_ja_jb || is_jmp_mem)) {
                long n_cases = 0;
                char *comma = strchr(dummy_ops, ',');
                if (comma) n_cases = strtol(comma + 1, NULL, 0) + 1;
                if (n_cases < 2) n_cases = 2;
                if (n_cases > 512) n_cases = 512;

                nfound++;
                fprintf(out, "\n  %sswitch #%d%s  %s0x%llx%s",
                        C_SW, nfound, C_RST, C_ADR,
                        (unsigned long long)cur, C_RST);
                fprintf(out, "  %s~%ld cases%s\n", C_CMT, n_cases, C_RST);

                fprintf(out, "  %s│%s  cmp   \033[0;36m%s\033[0m\n",
                        C_CMT, C_RST, dummy_ops);
                fprintf(out, "  %s│%s  %-6s \033[0;36m%s\033[0m  %s(default/out-of-range)%s\n",
                        C_CMT, C_RST, jmp_insn.mnemonic, jmp_insn.ops,
                        C_CMT, C_RST);
                if (is_jmp_mem)
                    fprintf(out, "  %s└─%s  jmp via jump table\n", C_CMT, C_RST);
            }
        }

        off += (size_t)l1;
    }

    if (nfound == 0) {
        fprintf(out, "%s  (no switch patterns detected)%s\n", C_CMT, C_RST);
    }
}

dax_igrp_t dax_classify_riscv(const char *m) {
    if (!m || !m[0]) return IGRP_UNKNOWN;
    /* compressed aliases */
    if (!strncmp(m,"c.j",3))   return IGRP_BRANCH;
    if (!strncmp(m,"c.b",3))   return IGRP_BRANCH;
    if (!strcmp(m,"c.jalr")||!strcmp(m,"c.jal")) return IGRP_CALL;
    if (!strcmp(m,"c.jr"))     return IGRP_BRANCH;
    if (!strcmp(m,"c.ebreak")) return IGRP_SYSCALL;
    if (!strncmp(m,"c.l",3)||!strncmp(m,"c.s",3)||!strncmp(m,"c.f",3)) return IGRP_STACK;
    if (!strncmp(m,"c.mv",4)||!strncmp(m,"c.li",4)||!strncmp(m,"c.lui",5)) return IGRP_DATAMOV;
    if (!strncmp(m,"c.",2))    return IGRP_ARITHMETIC;
    /* base ISA */
    if (!strcmp(m,"ret"))        return IGRP_RET;
    if (!strcmp(m,"jal")||!strcmp(m,"jalr")) {
        return (!strcmp(m,"jal")) ? IGRP_CALL : IGRP_BRANCH;
    }
    if (!strcmp(m,"j"))          return IGRP_BRANCH;
    if (!strncmp(m,"b",1) && strlen(m)>=3) return IGRP_BRANCH;
    if (!strcmp(m,"ecall")||!strcmp(m,"ebreak")) return IGRP_SYSCALL;
    if (!strcmp(m,"mret")||!strcmp(m,"sret")||
        !strcmp(m,"wfi") ||!strncmp(m,"csr",3)||
        !strcmp(m,"fence")||!strcmp(m,"fence.i")) return IGRP_PRIV;
    if (!strncmp(m,"ld",2)||!strncmp(m,"lw",2)||!strncmp(m,"lh",2)||!strncmp(m,"lb",2)||
        !strncmp(m,"sd",2)||!strncmp(m,"sw",2)||!strncmp(m,"sh",2)||!strncmp(m,"sb",2)||
        !strncmp(m,"fl",2)||!strncmp(m,"fs",2))  return IGRP_STACK;
    if (!strcmp(m,"lui")||!strcmp(m,"auipc")||
        !strcmp(m,"li") ||!strcmp(m,"mv")   ||
        !strncmp(m,"fmv",3)||!strncmp(m,"fcvt",4)) return IGRP_DATAMOV;
    if (!strncmp(m,"add",3)||!strncmp(m,"sub",3)||!strncmp(m,"mul",3)||
        !strncmp(m,"div",3)||!strncmp(m,"rem",3)||!strncmp(m,"sll",3)||
        !strncmp(m,"srl",3)||!strncmp(m,"sra",3)||!strncmp(m,"neg",3)||
        !strncmp(m,"fadd",4)||!strncmp(m,"fsub",4)||!strncmp(m,"fmul",4)||
        !strncmp(m,"fdiv",4)||!strncmp(m,"fsqrt",5)||!strncmp(m,"fma",3)) return IGRP_ARITHMETIC;
    if (!strncmp(m,"xor",3)||!strncmp(m,"or",2)||!strncmp(m,"and",3)||
        !strcmp(m,"not")||!strncmp(m,"slt",3)) return IGRP_LOGIC;
    if (!strncmp(m,"lr.",3)||!strncmp(m,"sc.",3)||!strncmp(m,"amo",3)) return IGRP_STRING;
    if (!strncmp(m,"feq",3)||!strncmp(m,"flt",3)||!strncmp(m,"fle",3)||
        !strncmp(m,"fclass",6)) return IGRP_COMPARE;
    return IGRP_UNKNOWN;
}
