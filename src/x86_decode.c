#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "x86.h"

const char *x86_reg_names_64[] = {
    "rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi",
    "r8","r9","r10","r11","r12","r13","r14","r15"
};
const char *x86_reg_names_32[] = {
    "eax","ecx","edx","ebx","esp","ebp","esi","edi",
    "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d"
};
const char *x86_reg_names_16[] = {
    "ax","cx","dx","bx","sp","bp","si","di",
    "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w"
};
const char *x86_reg_names_8l[] = {
    "al","cl","dl","bl","spl","bpl","sil","dil",
    "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b"
};
const char *x86_reg_names_8h[] = {
    "al","cl","dl","bl","ah","ch","dh","bh"
};
const char *x86_reg_names_xmm[] = {
    "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
    "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15"
};
static const char *x86_seg_names[] = { "es","cs","ss","ds","fs","gs" };

static const char *regname(int idx, int bits, int has_rex) {
    idx &= 15;
    if (bits == 64) return x86_reg_names_64[idx];
    if (bits == 32) return x86_reg_names_32[idx];
    if (bits == 16) return x86_reg_names_16[idx];
    if (bits == 8) {
        if (has_rex || idx >= 4) return x86_reg_names_8l[idx];
        return x86_reg_names_8h[idx];
    }
    return "?";
}

static int is_prefix(uint8_t b) {
    return b == 0xF0 || b == 0xF2 || b == 0xF3 ||
           b == 0x26 || b == 0x2E || b == 0x36 ||
           b == 0x3E || b == 0x64 || b == 0x65 ||
           b == 0x66 || b == 0x67;
}

static int seg_from_prefix(uint8_t b) {
    switch (b) {
        case 0x26: return 0;
        case 0x2E: return 1;
        case 0x36: return 2;
        case 0x3E: return 3;
        case 0x64: return 4;
        case 0x65: return 5;
    }
    return -1;
}

static void decode_modrm_mem(x86_insn_t *I, const uint8_t *buf, size_t avail,
                              int pos, int bits, int seg,
                              char *out, int *consumed) {
    uint8_t modrm = I->modrm;
    uint8_t mod   = (modrm >> 6) & 3;
    uint8_t rm    = modrm & 7;
    uint8_t rex_b = I->has_rex ? ((I->rex >> 0) & 1) : 0;
    int     use_sib = 0;
    int     disp_sz = 0;
    int64_t disp    = 0;
    char    inner[64];
    int     p = pos;

    if (mod == 3) {
        snprintf(out, 64, "%s", regname(rm | (rex_b << 3), bits, I->has_rex));
        *consumed = p;
        return;
    }

    if (rm == 4) {
        use_sib = 1;
        I->sib     = buf[p++];
        I->has_sib = 1;
    }

    if (mod == 0 && rm == 5) {
        disp_sz = 4;
    } else if (mod == 1) {
        disp_sz = 1;
    } else if (mod == 2) {
        disp_sz = 4;
    }

    if (disp_sz == 1) {
        disp = (int8_t)buf[p];
        p++;
    } else if (disp_sz == 4) {
        disp = (int32_t)(buf[p] | ((uint32_t)buf[p+1]<<8) |
                         ((uint32_t)buf[p+2]<<16) | ((uint32_t)buf[p+3]<<24));
        p += 4;
    }

    I->disp      = disp;
    I->disp_size = disp_sz;

    if (mod == 0 && rm == 5 && !use_sib) {
        if (disp >= 0) snprintf(inner, sizeof(inner), "rip+0x%llx", (unsigned long long)disp);
        else           snprintf(inner, sizeof(inner), "rip-0x%llx", (unsigned long long)-disp);
        disp = 0;
    } else if (use_sib) {
        uint8_t sib   = I->sib;
        uint8_t ss    = (sib >> 6) & 3;
        uint8_t idx   = (sib >> 3) & 7;
        uint8_t base  = sib & 7;
        int     rex_x = I->has_rex ? ((I->rex >> 1) & 1) : 0;
        int     scale = 1 << ss;
        int     efbase;

        efbase = base | (rex_b << 3);

        if (base == 5 && mod == 0) {
            if (idx == 4) {
                if (disp >= 0) snprintf(inner, sizeof(inner), "0x%llx", (unsigned long long)disp);
                else           snprintf(inner, sizeof(inner), "-0x%llx", (unsigned long long)-disp);
                disp = 0;
            } else {
                if (disp >= 0) snprintf(inner, sizeof(inner), "%s*%d+0x%llx",
                    regname(idx|(rex_x<<3),64,I->has_rex), scale, (unsigned long long)disp);
                else snprintf(inner, sizeof(inner), "%s*%d-0x%llx",
                    regname(idx|(rex_x<<3),64,I->has_rex), scale, (unsigned long long)-disp);
                disp = 0;
            }
        } else {
            if (idx == 4) {
                snprintf(inner, sizeof(inner), "%s", regname(efbase,64,I->has_rex));
            } else if (scale == 1) {
                snprintf(inner, sizeof(inner), "%s+%s",
                    regname(efbase,64,I->has_rex),
                    regname(idx|(rex_x<<3),64,I->has_rex));
            } else {
                snprintf(inner, sizeof(inner), "%s+%s*%d",
                    regname(efbase,64,I->has_rex),
                    regname(idx|(rex_x<<3),64,I->has_rex), scale);
            }
        }
    } else {
        snprintf(inner, sizeof(inner), "%s", regname(rm|(rex_b<<3), 64, I->has_rex));
    }

    {
        const char *sz_pfx;
        char disp_str[32] = "";
        char seg_str[8]   = "";

        switch (bits) {
            case 8:  sz_pfx = "BYTE PTR ";  break;
            case 16: sz_pfx = "WORD PTR ";  break;
            case 32: sz_pfx = "DWORD PTR "; break;
            case 64: sz_pfx = "QWORD PTR "; break;
            default: sz_pfx = "";
        }

        if (seg >= 0 && seg < 6) {
            snprintf(seg_str, sizeof(seg_str), "%s:", x86_seg_names[seg]);
        }

        if (disp > 0)  snprintf(disp_str, sizeof(disp_str), "+0x%llx", (unsigned long long)disp);
        else if (disp < 0) snprintf(disp_str, sizeof(disp_str), "-0x%llx", (unsigned long long)-disp);

        snprintf(out, 80, "%s%s[%s%s]", sz_pfx, seg_str, inner, disp_str);
    }

    *consumed = p;
}

static uint64_t read_imm(const uint8_t *buf, int sz) {
    if (sz == 1) return buf[0];
    if (sz == 2) return buf[0] | ((uint16_t)buf[1]<<8);
    if (sz == 4) return buf[0]|((uint32_t)buf[1]<<8)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<24);
    if (sz == 8) {
        uint64_t lo = buf[0]|((uint32_t)buf[1]<<8)|((uint32_t)buf[2]<<16)|((uint32_t)buf[3]<<24);
        uint64_t hi = buf[4]|((uint32_t)buf[5]<<8)|((uint32_t)buf[6]<<16)|((uint32_t)buf[7]<<24);
        return lo | (hi << 32);
    }
    return 0;
}

#define MAX_BUF 15

int x86_decode(const uint8_t *buf, size_t len, uint64_t addr, x86_insn_t *insn) {
    int     p = 0;
    int     opsz = 32;
    int     addrsz = 64;
    uint8_t rex = 0;
    int     has_rex = 0;
    int     seg = -1;
    int     rep = 0, repne = 0, lock = 0;
    uint8_t op;
    int     rex_r, rex_b, rex_w, rex_x;

    memset(insn, 0, sizeof(*insn));
    insn->address = addr;
    insn->is64    = 1;

    if (len == 0) return -1;

    while (p < MAX_BUF && p < (int)len && is_prefix(buf[p])) {
        uint8_t pf = buf[p];
        if (pf == 0x66) { opsz = 16; }
        else if (pf == 0x67) { addrsz = 32; }
        else if (pf == 0xF2) { repne = 1; }
        else if (pf == 0xF3) { rep = 1; }
        else if (pf == 0xF0) { lock = 1; }
        else { int s = seg_from_prefix(pf); if (s >= 0) seg = s; }
        insn->prefixes[insn->nprefixes++] = pf;
        p++;
    }

    if (p < (int)len && (buf[p] & 0xF0) == 0x40) {
        rex     = buf[p];
        has_rex = 1;
        insn->rex     = rex;
        insn->has_rex = 1;
        p++;
        if (rex & 0x08) opsz = 64;
    }

    rex_w = has_rex ? ((rex >> 3) & 1) : 0;
    rex_r = has_rex ? ((rex >> 2) & 1) : 0;
    rex_x = has_rex ? ((rex >> 1) & 1) : 0;
    rex_b = has_rex ? ((rex >> 0) & 1) : 0;

    if (rex_w) opsz = 64;
    (void)rex_x;
    (void)addrsz;

    if (p >= (int)len) return -1;
    op = buf[p++];

    insn->opcode[0]  = op;
    insn->opcode_len = 1;

    {
        char ops[256]  = "";
        char mnem[32]  = "???";
        char tmp1[80]  = "";
        char tmp2[80]  = "";
        int  consumed  = p;
        int  ok        = 1;

#define NEED(n) if (p + (n) > (int)len) { ok = 0; goto done; }
#define REG_OP(idx, bits) regname((idx)|((rex_r)<<3), bits, has_rex)
#define RM_REG(idx, bits) regname((idx)|((rex_b)<<3), bits, has_rex)
#define MODRM_REG(bits) \
    do { \
        NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1; \
        decode_modrm_mem(insn, buf, len, p+1, bits, seg, tmp1, &consumed); \
        snprintf(tmp2, sizeof(tmp2), "%s", REG_OP((insn->modrm>>3)&7, bits)); \
    } while(0)

        switch (op) {
            case 0x00: case 0x01: case 0x02: case 0x03:
            case 0x08: case 0x09: case 0x0A: case 0x0B:
            case 0x10: case 0x11: case 0x12: case 0x13:
            case 0x18: case 0x19: case 0x1A: case 0x1B:
            case 0x20: case 0x21: case 0x22: case 0x23:
            case 0x28: case 0x29: case 0x2A: case 0x2B:
            case 0x30: case 0x31: case 0x32: case 0x33:
            case 0x38: case 0x39: case 0x3A: case 0x3B: {
                const char *mnems[] = {"add","add","add","add",
                                       "or","or","or","or",
                                       "adc","adc","adc","adc",
                                       "sbb","sbb","sbb","sbb",
                                       "and","and","and","and",
                                       "sub","sub","sub","sub",
                                       "xor","xor","xor","xor",
                                       "cmp","cmp","cmp","cmp"};
                int idx  = (op & 0x38) >> 3;
                int bits = (op & 1) ? opsz : 8;
                int dir  = (op & 2);
                MODRM_REG(bits);
                strncpy(mnem, mnems[idx*4], sizeof(mnem)-1);
                if (dir) snprintf(ops, sizeof(ops), "%s, %s", tmp2, tmp1);
                else     snprintf(ops, sizeof(ops), "%s, %s", tmp1, tmp2);
                p = consumed;
                break;
            }
            case 0x04: NEED(1); strncpy(mnem,"add",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"al, 0x%02x",buf[p++]); break;
            case 0x05: {
                int isz = (opsz==16)?2:4; NEED(isz);
                strncpy(mnem,"add",sizeof(mnem)-1);
                if (opsz==16) snprintf(ops,sizeof(ops),"ax, 0x%04llx",(unsigned long long)read_imm(buf+p,2));
                else if (opsz==64) snprintf(ops,sizeof(ops),"rax, 0x%08llx",(unsigned long long)(int32_t)read_imm(buf+p,4));
                else snprintf(ops,sizeof(ops),"eax, 0x%08llx",(unsigned long long)read_imm(buf+p,4));
                p += isz; break;
            }
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
                strncpy(mnem,"push",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s",RM_REG(op&7,64)); break;
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                strncpy(mnem,"pop",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s",RM_REG(op&7,64)); break;
            case 0x63: {
                int bits = opsz;
                MODRM_REG(32);
                strncpy(mnem,(rex_w)?"movsxd":"arpl",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, %s",
                    regname(((insn->modrm>>3)&7)|(rex_r<<3),(rex_w?64:bits),has_rex), tmp1);
                p = consumed; break;
            }
            case 0x68: { int isz=(opsz==16)?2:4; NEED(isz);
                strncpy(mnem,"push",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%llx",(unsigned long long)read_imm(buf+p,isz)); p+=isz; break; }
            case 0x6A: NEED(1); strncpy(mnem,"push",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%02x",(int8_t)buf[p++]); break;
            case 0x70: case 0x71: case 0x72: case 0x73:
            case 0x74: case 0x75: case 0x76: case 0x77:
            case 0x78: case 0x79: case 0x7A: case 0x7B:
            case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
                const char *jcc[] = {"jo","jno","jb","jnb","je","jne","jbe","ja",
                                     "js","jns","jp","jnp","jl","jge","jle","jg"};
                int8_t rel; NEED(1); rel = (int8_t)buf[p++];
                strncpy(mnem,jcc[op&0xF],sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)p+(int64_t)rel));
                break;
            }
            case 0x80: case 0x81: case 0x83: {
                const char *grp[] = {"add","or","adc","sbb","and","sub","xor","cmp"};
                int bits  = (op==0x80)?8:opsz;
                int isz;
                NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,bits,seg,tmp1,&consumed);
                p = consumed;
                if (op==0x81) isz=(opsz==16)?2:4; else isz=1;
                NEED(isz);
                int64_t imm = (op==0x83)?(int8_t)read_imm(buf+p,1):(int64_t)read_imm(buf+p,isz);
                p += isz;
                strncpy(mnem,grp[(insn->modrm>>3)&7],sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, 0x%llx",tmp1,(unsigned long long)(uint64_t)imm);
                break;
            }
            case 0x84: case 0x85: {
                int bits = (op==0x84)?8:opsz;
                MODRM_REG(bits);
                strncpy(mnem,"test",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break;
            }
            case 0x86: case 0x87: {
                int bits = (op==0x86)?8:opsz;
                MODRM_REG(bits);
                strncpy(mnem,"xchg",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break;
            }
            case 0x88: case 0x89: case 0x8A: case 0x8B: {
                int bits = (op&1)?opsz:8;
                int dir  = (op&2);
                MODRM_REG(bits);
                strncpy(mnem,"mov",sizeof(mnem)-1);
                if (dir) snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1);
                else     snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2);
                p=consumed; break;
            }
            case 0x8D: {
                MODRM_REG(opsz);
                strncpy(mnem,"lea",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break;
            }
            case 0x90: strncpy(mnem,"nop",sizeof(mnem)-1); break;
            case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97:
                strncpy(mnem,"xchg",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"rax, %s",RM_REG(op&7,64)); break;
            case 0x98: strncpy(mnem,(opsz==64)?"cdqe":(opsz==16)?"cbw":"cwde",sizeof(mnem)-1); break;
            case 0x99: strncpy(mnem,(opsz==64)?"cqo":(opsz==16)?"cwd":"cdq",sizeof(mnem)-1); break;
            case 0x9C: strncpy(mnem,"pushfq",sizeof(mnem)-1); break;
            case 0x9D: strncpy(mnem,"popfq",sizeof(mnem)-1); break;
            case 0xA4: strncpy(mnem,(rep)?"rep movsb":"movsb",sizeof(mnem)-1); break;
            case 0xA5: strncpy(mnem,(rep)?"rep movsq":"movsq",sizeof(mnem)-1); break;
            case 0xAA: strncpy(mnem,(rep)?"rep stosb":"stosb",sizeof(mnem)-1); break;
            case 0xAB: strncpy(mnem,(rep)?"rep stosq":"stosq",sizeof(mnem)-1); break;
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                NEED(1); strncpy(mnem,"mov",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, 0x%02x",RM_REG(op&7,8),(unsigned)buf[p++]); break;
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
                int isz = (opsz==64)?8:(opsz==16)?2:4;
                NEED(isz);
                uint64_t imm = read_imm(buf+p, isz); p += isz;
                strncpy(mnem,"mov",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, 0x%llx",RM_REG(op&7,opsz),(unsigned long long)imm);
                break;
            }
            case 0xC0: case 0xC1: {
                const char *sgrp[]= {"rol","ror","rcl","rcr","shl","shr","sal","sar"};
                int bits = (op==0xC0)?8:opsz;
                NEED(2); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,bits,seg,tmp1,&consumed);
                p = consumed;
                NEED(1); uint8_t cnt = buf[p++];
                strncpy(mnem,sgrp[(insn->modrm>>3)&7],sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, %u",tmp1,(unsigned)cnt); break;
            }
            case 0xC2: NEED(2); strncpy(mnem,"ret",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%04x",(unsigned)read_imm(buf+p,2)); p+=2; break;
            case 0xC3: strncpy(mnem,"ret",sizeof(mnem)-1); break;
            case 0xC6: case 0xC7: {
                int bits = (op==0xC6)?8:opsz;
                int isz  = (op==0xC6)?1:(opsz==16)?2:4;
                NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,bits,seg,tmp1,&consumed);
                p = consumed; NEED(isz);
                uint64_t imm = read_imm(buf+p,isz); p+=isz;
                strncpy(mnem,"mov",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s, 0x%llx",tmp1,(unsigned long long)imm); break;
            }
            case 0xC9: strncpy(mnem,"leave",sizeof(mnem)-1); break;
            case 0xCC: strncpy(mnem,"int3",sizeof(mnem)-1); break;
            case 0xCD: NEED(1); strncpy(mnem,"int",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%02x",(unsigned)buf[p++]); break;
            case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
                const char *sgrp[]= {"rol","ror","rcl","rcr","shl","shr","sal","sar"};
                int bits = (op==0xD0||op==0xD2)?8:opsz;
                int bycl = (op==0xD2||op==0xD3);
                NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,bits,seg,tmp1,&consumed);
                p = consumed;
                strncpy(mnem,sgrp[(insn->modrm>>3)&7],sizeof(mnem)-1);
                if (bycl) snprintf(ops,sizeof(ops),"%s, cl",tmp1);
                else      snprintf(ops,sizeof(ops),"%s, 1",tmp1);
                break;
            }
            case 0xE8: { NEED(4);
                int32_t rel = (int32_t)read_imm(buf+p,4); p+=4;
                strncpy(mnem,"call",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)p+(int64_t)rel));
                break;
            }
            case 0xE9: { NEED(4);
                int32_t rel = (int32_t)read_imm(buf+p,4); p+=4;
                strncpy(mnem,"jmp",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)p+(int64_t)rel));
                break;
            }
            case 0xEB: { NEED(1);
                int8_t rel = (int8_t)buf[p++];
                strncpy(mnem,"jmp",sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)p+(int64_t)rel));
                break;
            }
            case 0xF6: case 0xF7: {
                const char *ug[]= {"test","test","not","neg","mul","imul","div","idiv"};
                int bits = (op==0xF6)?8:opsz;
                NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,bits,seg,tmp1,&consumed);
                p = consumed;
                int gidx = (insn->modrm>>3)&7;
                strncpy(mnem,ug[gidx],sizeof(mnem)-1);
                if (gidx == 0 || gidx == 1) {
                    int isz=(op==0xF6)?1:(opsz==16)?2:4; NEED(isz);
                    uint64_t imm=read_imm(buf+p,isz); p+=isz;
                    snprintf(ops,sizeof(ops),"%s, 0x%llx",tmp1,(unsigned long long)imm);
                } else {
                    snprintf(ops,sizeof(ops),"%s",tmp1);
                }
                break;
            }
            case 0xF8: strncpy(mnem,"clc",sizeof(mnem)-1); break;
            case 0xF9: strncpy(mnem,"stc",sizeof(mnem)-1); break;
            case 0xFA: strncpy(mnem,"cli",sizeof(mnem)-1); break;
            case 0xFB: strncpy(mnem,"sti",sizeof(mnem)-1); break;
            case 0xFC: strncpy(mnem,"cld",sizeof(mnem)-1); break;
            case 0xFD: strncpy(mnem,"std",sizeof(mnem)-1); break;
            case 0xFE: case 0xFF: {
                const char *fg[] = {"inc","dec","call","callf","jmp","jmpf","push","???"};
                int bits = (op==0xFE)?8:opsz;
                NEED(1); insn->modrm = buf[p]; insn->has_modrm = 1;
                decode_modrm_mem(insn,buf,len,p+1,(op==0xFF)?64:bits,seg,tmp1,&consumed);
                p = consumed;
                strncpy(mnem,fg[(insn->modrm>>3)&7],sizeof(mnem)-1);
                snprintf(ops,sizeof(ops),"%s",tmp1); break;
            }
            case 0x0F: {
                if (p >= (int)len) { ok=0; goto done; }
                uint8_t op2 = buf[p++];
                insn->opcode[1] = op2;
                insn->opcode_len = 2;
                switch (op2) {
                    case 0x05: strncpy(mnem,"syscall",sizeof(mnem)-1); break;
                    case 0x06: strncpy(mnem,"clts",sizeof(mnem)-1); break;
                    case 0x0B: strncpy(mnem,"ud2",sizeof(mnem)-1); break;
                    case 0x1E: {
                        if (rep && p < (int)len) {
                            uint8_t mod = buf[p];
                            if (mod == 0xFA) { p++; strncpy(mnem,"endbr64",sizeof(mnem)-1); rep=0; break; }
                            if (mod == 0xFB) { p++; strncpy(mnem,"endbr32",sizeof(mnem)-1); rep=0; break; }
                        }
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,opsz,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,"nop",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s",tmp1); break;
                    }
                    case 0x1F: {
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,opsz,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,"nop",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s",tmp1); break;
                    }
                    case 0x20: { NEED(1);
                        int cr = (buf[p]>>3)&7; int rm_ = buf[p]&7; p++;
                        snprintf(mnem,sizeof(mnem),"mov");
                        snprintf(ops,sizeof(ops),"%s, cr%d", x86_reg_names_64[rm_], cr); break;
                    }
                    case 0x22: { NEED(1);
                        int cr = (buf[p]>>3)&7; int rm_ = buf[p]&7; p++;
                        snprintf(mnem,sizeof(mnem),"mov");
                        snprintf(ops,sizeof(ops),"cr%d, %s", cr, x86_reg_names_64[rm_]); break;
                    }
                    case 0x31: strncpy(mnem,"rdtsc",sizeof(mnem)-1); break;
                    case 0x32: strncpy(mnem,"rdmsr",sizeof(mnem)-1); break;
                    case 0x33: strncpy(mnem,"rdpmc",sizeof(mnem)-1); break;
                    case 0x34: strncpy(mnem,"sysenter",sizeof(mnem)-1); break;
                    case 0x35: strncpy(mnem,"sysexit",sizeof(mnem)-1); break;
                    case 0x40: case 0x41: case 0x42: case 0x43:
                    case 0x44: case 0x45: case 0x46: case 0x47:
                    case 0x48: case 0x49: case 0x4A: case 0x4B:
                    case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
                        const char *cmv[]={"cmovo","cmovno","cmovb","cmovnb","cmove","cmovne",
                                           "cmovbe","cmova","cmovs","cmovns","cmovp","cmovnp",
                                           "cmovl","cmovge","cmovle","cmovg"};
                        MODRM_REG(opsz);
                        strncpy(mnem,cmv[op2&0xF],sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break;
                    }
                    case 0x80: case 0x81: case 0x82: case 0x83:
                    case 0x84: case 0x85: case 0x86: case 0x87:
                    case 0x88: case 0x89: case 0x8A: case 0x8B:
                    case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
                        const char *jcc2[]={"jo","jno","jb","jnb","je","jne","jbe","ja",
                                            "js","jns","jp","jnp","jl","jge","jle","jg"};
                        NEED(4); int32_t rel=(int32_t)read_imm(buf+p,4); p+=4;
                        strncpy(mnem,jcc2[op2&0xF],sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)p+(int64_t)rel));
                        break;
                    }
                    case 0x90: case 0x91: case 0x92: case 0x93:
                    case 0x94: case 0x95: case 0x96: case 0x97:
                    case 0x98: case 0x99: case 0x9A: case 0x9B:
                    case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
                        const char *setcc[]={"seto","setno","setb","setnb","sete","setne",
                                             "setbe","seta","sets","setns","setp","setnp",
                                             "setl","setge","setle","setg"};
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,8,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,setcc[op2&0xF],sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s",tmp1); break;
                    }
                    case 0xA2: strncpy(mnem,"cpuid",sizeof(mnem)-1); break;
                    case 0xAB: { MODRM_REG(opsz);
                        strncpy(mnem,"bts",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break; }
                    case 0xAC: { NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,opsz,seg,tmp1,&consumed);
                        p=consumed; NEED(1);
                        strncpy(mnem,"shrd",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s, %d",tmp1,
                            regname(((insn->modrm>>3)&7)|(rex_r<<3),opsz,has_rex),(int)buf[p++]); break; }
                    case 0xAD: { MODRM_REG(opsz);
                        strncpy(mnem,"shrd",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s, cl",tmp1,tmp2); p=consumed; break; }
                    case 0xBC: { MODRM_REG(opsz);
                        strncpy(mnem,"bsf",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break; }
                    case 0xBD: { MODRM_REG(opsz);
                        strncpy(mnem,"bsr",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break; }
                    case 0xC0: case 0xC1: {
                        int bits2=(op2==0xC0)?8:opsz;
                        MODRM_REG(bits2);
                        strncpy(mnem,"xadd",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break;
                    }
                    case 0xC7: { NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,64,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,"cmpxchg8b",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s",tmp1); break;
                    }
                    case 0xC8: case 0xC9: case 0xCA: case 0xCB:
                    case 0xCC: case 0xCD: case 0xCE: case 0xCF:
                        strncpy(mnem,"bswap",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s",RM_REG(op2&7,opsz)); break;
                    case 0x10: case 0x11: {
                        int dir2=(op2&1);
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem, rep?"movss":(repne?"movsd":"movups"),sizeof(mnem)-1);
                        snprintf(tmp2,sizeof(tmp2),"%s%d", rep||repne?"xmm":"xmm",
                            ((insn->modrm>>3)&7)|(rex_r<<3));
                        if (dir2) snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2);
                        else      snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1);
                        rep=repne=0; break;
                    }
                    case 0x28: case 0x29: {
                        int dir2=(op2&1);
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        int xidx = ((insn->modrm>>3)&7)|(rex_r<<3);
                        snprintf(tmp2,sizeof(tmp2),"xmm%d",xidx);
                        strncpy(mnem,"movaps",sizeof(mnem)-1);
                        if (dir2) snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2);
                        else      snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1);
                        break;
                    }
                    case 0x57: {
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        int xidx = ((insn->modrm>>3)&7)|(rex_r<<3);
                        snprintf(tmp2,sizeof(tmp2),"xmm%d",xidx);
                        strncpy(mnem,"xorps",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); break;
                    }
                    case 0x58: case 0x59: case 0x5C: case 0x5E: {
                        const char *ssemn[]={"addps","mulps","???","???","subps","???","divps"};
                        const char *nm = (op2==0x58)?"addps":(op2==0x59)?"mulps":
                                         (op2==0x5C)?"subps":"divps";
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        int xidx=((insn->modrm>>3)&7)|(rex_r<<3);
                        snprintf(tmp2,sizeof(tmp2),"xmm%d",xidx);
                        strncpy(mnem, rep ? (nm[2]=='d'?"addss":"mulss") : nm, sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1);
                        (void)ssemn; rep=0; break;
                    }
                    case 0x6F: {
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        int xidx=((insn->modrm>>3)&7)|(rex_r<<3);
                        snprintf(tmp2,sizeof(tmp2),"xmm%d",xidx);
                        strncpy(mnem, rep?"movdqu":"movq",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); rep=0; break;
                    }
                    case 0x7F: {
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,128,seg,tmp1,&consumed);
                        p=consumed;
                        int xidx=((insn->modrm>>3)&7)|(rex_r<<3);
                        snprintf(tmp2,sizeof(tmp2),"xmm%d",xidx);
                        strncpy(mnem, rep?"movdqu":"movq",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); rep=0; break;
                    }
                    case 0xA3: { MODRM_REG(opsz);
                        strncpy(mnem,"bt",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break; }
                    case 0xAF: { MODRM_REG(opsz);
                        strncpy(mnem,"imul",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp2,tmp1); p=consumed; break; }
                    case 0xB0: case 0xB1: {
                        int bits=(op2==0xB0)?8:opsz;
                        MODRM_REG(bits);
                        strncpy(mnem,"cmpxchg",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break;
                    }
                    case 0xB3: { MODRM_REG(opsz);
                        strncpy(mnem,"btr",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",tmp1,tmp2); p=consumed; break; }
                    case 0xB6: case 0xB7: {
                        int src_bits=(op2==0xB6)?8:16;
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,src_bits,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,"movzx",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",
                            regname(((insn->modrm>>3)&7)|(rex_r<<3),opsz,has_rex), tmp1); break;
                    }
                    case 0xBE: case 0xBF: {
                        int src_bits=(op2==0xBE)?8:16;
                        NEED(1); insn->modrm=buf[p]; insn->has_modrm=1;
                        decode_modrm_mem(insn,buf,len,p+1,src_bits,seg,tmp1,&consumed);
                        p=consumed;
                        strncpy(mnem,"movsx",sizeof(mnem)-1);
                        snprintf(ops,sizeof(ops),"%s, %s",
                            regname(((insn->modrm>>3)&7)|(rex_r<<3),opsz,has_rex), tmp1); break;
                    }
                    default:
                        snprintf(mnem, sizeof(mnem), "db 0x0f,0x%02x", op2);
                        break;
                }
                break;
            }
            default:
                if (lock) snprintf(mnem,sizeof(mnem),"lock");
                else snprintf(mnem,sizeof(mnem),"db 0x%02x",(unsigned)op);
                break;
        }

done:
        if (!ok) { p = 1; snprintf(mnem,sizeof(mnem),"db 0x%02x",(unsigned)op); ops[0]=0; }
        if (lock && mnem[0] != 'l') {
            char tmp_m[32]; snprintf(tmp_m,sizeof(tmp_m),"lock %s",mnem);
            strncpy(mnem,tmp_m,sizeof(mnem)-1);
        }
        if (repne && mnem[0] != 'r') {
            char tmp_m[32]; snprintf(tmp_m,sizeof(tmp_m),"repne %s",mnem);
            strncpy(mnem,tmp_m,sizeof(mnem)-1);
        }
        strncpy(insn->mnemonic, mnem, sizeof(insn->mnemonic)-1);
        strncpy(insn->ops, ops, sizeof(insn->ops)-1);
    }

    insn->length = (uint8_t)p;
    if (insn->length == 0) insn->length = 1;
    return (int)insn->length;
}

void x86_format(x86_insn_t *insn, char *mnem_out, char *ops_out) {
    strncpy(mnem_out, insn->mnemonic, DAX_MAX_MNEMONIC-1);
    strncpy(ops_out,  insn->ops,      DAX_MAX_OPERANDS-1);
}
