#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "arm64.h"

const char *a64_cond_str[] = {
    "eq","ne","cs","cc","mi","pl","vs","vc",
    "hi","ls","ge","lt","gt","le","al","nv"
};

void a64_reg_name(a64_reg_t r, int is32, char *out) {
    int n = (int)r & 31;
    if (n == 31) { strcpy(out, is32 ? "wzr" : "xzr"); return; }
    if (is32) snprintf(out, 8, "w%d", n);
    else      snprintf(out, 8, "x%d", n);
}

static void xreg(int n, char *out) {
    if (n == 31) { strcpy(out, "sp"); return; }
    snprintf(out, 8, "x%d", n);
}

static void xreg_zr(int n, char *out) {
    if (n == 31) { strcpy(out, "xzr"); return; }
    snprintf(out, 8, "x%d", n);
}

static void wreg(int n, char *out) {
    if (n == 31) { strcpy(out, "wsp"); return; }
    snprintf(out, 8, "w%d", n);
}

static void wreg_zr(int n, char *out) {
    if (n == 31) { strcpy(out, "wzr"); return; }
    snprintf(out, 8, "w%d", n);
}

static const char *shift_name(int s) {
    switch (s) {
        case 0: return "lsl";
        case 1: return "lsr";
        case 2: return "asr";
        case 3: return "ror";
    }
    return "?";
}

static const char *ext_name(int e) {
    const char *t[] = {"uxtb","uxth","uxtw","uxtx","sxtb","sxth","sxtw","sxtx"};
    return (e >= 0 && e < 8) ? t[e] : "?";
}

#define BIT(v,n)    (((uint32_t)(v)>>(n))&1u)
#define BITS(v,h,l) (((uint32_t)(v)>>(l)) & ((1u<<((h)-(l)+1))-1u))

static int64_t sext(uint64_t val, int bits) {
    int64_t s = (int64_t)(val << (64 - bits));
    return s >> (64 - bits);
}

int a64_decode(uint32_t raw, uint64_t addr, a64_insn_t *insn) {
    char ops[128] = "";
    char mnem[32] = "???";
    char ra[8], rb[8], rc[8];
    int  sf, opc, rn, rm, rd, rt, rt2, imm6, imm7, imm12, imm16;

    insn->raw     = raw;
    insn->address = addr;

    if (raw == 0xD503201F) { strcpy(mnem,"nop"); goto done; }
    if (raw == 0xD5033FDF) { strcpy(mnem,"isb"); goto done; }
    if (raw == 0xD5033F9F) { strcpy(mnem,"dsb"); strcpy(ops,"sy"); goto done; }
    if (raw == 0xD5033BBF) { strcpy(mnem,"dmb"); strcpy(ops,"ish"); goto done; }
    if (raw == 0xD69F03E0) { strcpy(mnem,"eret"); goto done; }
    if (raw == 0xD503305F) { strcpy(mnem,"clrex"); goto done; }

    /* BTI (Branch Target Identification) */
    if ((raw & 0xFFFFFF1F) == 0xD503241F) {
        int targets = (raw>>6)&3;
        const char *t[] = {"bti","bti c","bti j","bti jc"};
        strcpy(mnem, t[targets]); goto done;
    }

    /* PAC / AUT / XPAC instructions */
    if (raw == 0xD503233F) { strcpy(mnem,"paciaz");   goto done; }
    if (raw == 0xD503237F) { strcpy(mnem,"pacibz");   goto done; }
    if (raw == 0xD50323BF) { strcpy(mnem,"autiasp");  goto done; }
    if (raw == 0xD50323FF) { strcpy(mnem,"autibsp");  goto done; }
    if (raw == 0xD503227F) { strcpy(mnem,"paciasp");  goto done; }
    if (raw == 0xD50322FF) { strcpy(mnem,"pacibsp");  goto done; }
    if (raw == 0xD503203F) { strcpy(mnem,"xpaclri");  goto done; }
    if ((raw & 0xFFFFFFE0) == 0xDAC143E0) { strcpy(mnem,"xpaci"); xreg_zr(raw&31,ra); snprintf(ops,sizeof(ops),"%s",ra); goto done; }
    if ((raw & 0xFFFFFFE0) == 0xDAC147E0) { strcpy(mnem,"xpacib"); xreg_zr(raw&31,ra); snprintf(ops,sizeof(ops),"%s",ra); goto done; }

    /* PACI/AUTIA/AUTIB key variants */
    if ((raw & 0xFFFFF800) == 0xDAC10000) {
        int Z  = BIT(raw,13);
        int M  = BIT(raw,12);
        int op = BITS(raw,11,10);
        xreg_zr(raw&31, ra);
        const char *pops[] = {"pacia","pacib","autia","autib"};
        strcpy(mnem, pops[op]);
        if (Z) strcat(mnem, "z");
        else { xreg_zr(BITS(raw,9,5), rb); snprintf(ops,sizeof(ops),"%s, %s", ra, rb); }
        (void)M;
        goto done;
    }

    /* HINT space (D503 20XX) — catch-all for unrecognised hints */
    if ((raw & 0xFFFFF01F) == 0xD503201F) {
        int crm = BITS(raw,11,8);
        int op2 = BITS(raw,7,5);
        snprintf(mnem,sizeof(mnem),"hint #%d", (crm<<3)|op2);
        goto done;
    }

    if ((raw & 0xFFFFFC1F) == 0xD65F0000) {
        rn = BITS(raw,9,5); xreg(rn, ra);
        strcpy(mnem,"ret"); snprintf(ops,sizeof(ops),"%s",ra); goto done;
    }
    if ((raw & 0xFFFFFC1F) == 0xD61F0000) {
        rn = BITS(raw,9,5); xreg(rn, ra);
        strcpy(mnem,"br"); snprintf(ops,sizeof(ops),"%s",ra); goto done;
    }
    if ((raw & 0xFFFFFC1F) == 0xD63F0000) {
        rn = BITS(raw,9,5); xreg(rn, ra);
        strcpy(mnem,"blr"); snprintf(ops,sizeof(ops),"%s",ra); goto done;
    }

    if ((raw & 0xFF000000) == 0xD4000000) {
        uint16_t imm = (uint16_t)BITS(raw,20,5);
        int type = BITS(raw,4,0);
        if (type == 1) { strcpy(mnem,"svc"); }
        else if (type == 2) { strcpy(mnem,"hvc"); }
        else if (type == 3) { strcpy(mnem,"smc"); }
        else { strcpy(mnem,"brk"); }
        snprintf(ops,sizeof(ops),"#0x%x",imm);
        goto done;
    }

    if ((raw & 0x7C000000) == 0x14000000) {
        int64_t imm26 = sext((uint64_t)BITS(raw,25,0) << 2, 28);
        uint64_t target = addr + (uint64_t)imm26;
        strcpy(mnem, BIT(raw,31) ? "bl" : "b");
        snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)target);
        goto done;
    }

    if ((raw & 0xFF000010) == 0x54000000) {
        int cond_  = BITS(raw,3,0);
        int64_t r  = sext((uint64_t)BITS(raw,23,5) << 2, 21);
        snprintf(mnem,sizeof(mnem),"b.%s", a64_cond_str[cond_]);
        snprintf(ops,sizeof(ops),"0x%016llx",(unsigned long long)(addr+(uint64_t)r));
        goto done;
    }

    if ((raw & 0x7E000000) == 0x34000000) {
        sf = BIT(raw,31); rt = BITS(raw,4,0);
        int64_t r = sext((uint64_t)BITS(raw,23,5) << 2, 21);
        strcpy(mnem, BIT(raw,24) ? "cbnz" : "cbz");
        if (sf) xreg_zr(rt,ra); else wreg_zr(rt,ra);
        snprintf(ops,sizeof(ops),"%s, 0x%016llx",ra,(unsigned long long)(addr+(uint64_t)r));
        goto done;
    }

    if ((raw & 0x7E000000) == 0x36000000) {
        sf = BIT(raw,31); rt = BITS(raw,4,0);
        int bit = (int)(BIT(raw,31)<<5) | (int)BITS(raw,23,19);
        int64_t r  = sext((uint64_t)BITS(raw,18,5) << 2, 16);
        strcpy(mnem, BIT(raw,24) ? "tbnz" : "tbz");
        if (sf) xreg_zr(rt,ra); else wreg_zr(rt,ra);
        snprintf(ops,sizeof(ops),"%s, #%d, 0x%016llx",ra,bit,(unsigned long long)(addr+(uint64_t)r));
        goto done;
    }

    if ((raw & 0x1F000000) == 0x10000000) {
        sf = BIT(raw,31); rd = BITS(raw,4,0);
        int64_t imm = sext(((int64_t)BITS(raw,23,5)<<2)|BITS(raw,30,29), 21);
        uint64_t target;
        xreg_zr(rd, ra);
        if (sf) { target = (addr & ~0xFFFULL)+((uint64_t)imm<<12); strcpy(mnem,"adrp"); }
        else    { target = addr + (uint64_t)imm; strcpy(mnem,"adr"); }
        snprintf(ops,sizeof(ops),"%s, 0x%016llx",ra,(unsigned long long)target);
        goto done;
    }

    if ((raw & 0x1F000000) == 0x0A000000) {
        sf   = BIT(raw,31);
        opc  = BITS(raw,30,29);
        int N    = BIT(raw,21);
        int shft = BITS(raw,23,22);
        rm   = BITS(raw,20,16);
        imm6 = BITS(raw,15,10);
        rn   = BITS(raw,9,5);
        rd   = BITS(raw,4,0);
        const char *lmn[] = {"and","orr","eor","ands"};
        const char *nmn[] = {"bic","orn","eon","bics"};
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); xreg_zr(rm,rc); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); wreg_zr(rm,rc); }
        if (!N && opc == 1 && rn == 31) {
            strcpy(mnem,"mov");
            if (imm6) snprintf(ops,sizeof(ops),"%s, %s, %s #%d",ra,rc,shift_name(shft),imm6);
            else      snprintf(ops,sizeof(ops),"%s, %s",ra,rc);
        } else if (!N && opc == 3 && rd == 31) {
            strcpy(mnem,"tst");
            if (imm6) snprintf(ops,sizeof(ops),"%s, %s, %s #%d",rb,rc,shift_name(shft),imm6);
            else      snprintf(ops,sizeof(ops),"%s, %s",rb,rc);
        } else {
            strcpy(mnem, N ? nmn[opc] : lmn[opc]);
            if (imm6) snprintf(ops,sizeof(ops),"%s, %s, %s, %s #%d",ra,rb,rc,shift_name(shft),imm6);
            else      snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc);
        }
        goto done;
    }

    if ((raw & 0x1F000000) == 0x0B000000) {
        sf   = BIT(raw,31);
        opc  = BITS(raw,30,29);
        int S    = BIT(raw,29);
        int shft = BITS(raw,23,22);
        int ext_ = BIT(raw,21);
        rm   = BITS(raw,20,16);
        imm6 = BITS(raw,15,10);
        int ext3 = BITS(raw,15,13);
        int imm3 = BITS(raw,12,10);
        rn   = BITS(raw,9,5);
        rd   = BITS(raw,4,0);
        const char *mn[] = {"add","adds","sub","subs"};
        strcpy(mnem, mn[opc]);
        if (S && rd == 31) strcpy(mnem, (opc>=2) ? "cmp" : "cmn");
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); xreg_zr(rm,rc); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); wreg_zr(rm,rc); }
        if (ext_) {
            if (imm3) snprintf(ops,sizeof(ops),"%s, %s, %s, %s #%d",ra,rb,rc,ext_name(ext3),imm3);
            else      snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,ext_name(ext3));
        } else {
            if (S && rd == 31) {
                if (imm6) snprintf(ops,sizeof(ops),"%s, %s, %s #%d",rb,rc,shift_name(shft),imm6);
                else      snprintf(ops,sizeof(ops),"%s, %s",rb,rc);
            } else {
                if (imm6) snprintf(ops,sizeof(ops),"%s, %s, %s, %s #%d",ra,rb,rc,shift_name(shft),imm6);
                else      snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc);
            }
        }
        goto done;
    }

    if ((raw & 0x1F800000) == 0x11000000) {
        sf    = BIT(raw,31);
        opc   = BITS(raw,30,29);
        int sh    = BIT(raw,22);
        imm12 = BITS(raw,21,10);
        rn    = BITS(raw,9,5);
        rd    = BITS(raw,4,0);
        int S = BIT(raw,29);
        const char *mn[] = {"add","adds","sub","subs"};
        strcpy(mnem, mn[opc]);
        if (S && rd == 31) strcpy(mnem, (opc>=2) ? "cmp" : "cmn");
        if (sf) { xreg(rd,ra); xreg(rn,rb); }
        else    { wreg(rd,ra); wreg(rn,rb); }
        uint32_t immv = sh ? ((uint32_t)imm12 << 12) : (uint32_t)imm12;
        if (S && rd == 31) snprintf(ops,sizeof(ops),"%s, #0x%x",rb,immv);
        else               snprintf(ops,sizeof(ops),"%s, %s, #0x%x",ra,rb,immv);
        goto done;
    }

    if ((raw & 0x3F800000) == 0x12000000 || (raw & 0x3F800000) == 0x32000000) {
        sf    = BIT(raw,31);
        opc   = BITS(raw,30,29);
        int immr  = BITS(raw,21,16);
        int imms  = BITS(raw,15,10);
        rn    = BITS(raw,9,5);
        rd    = BITS(raw,4,0);
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); }
        int maxbit = sf ? 63 : 31;
        if (opc == 0) {
            if (imms == maxbit) { strcpy(mnem,"asr"); snprintf(ops,sizeof(ops),"%s, %s, #%d",ra,rb,immr); }
            else if (imms+1 == immr) { strcpy(mnem,"lsl"); snprintf(ops,sizeof(ops),"%s, %s, #%d",ra,rb,(sf?64:32)-immr); }
            else { strcpy(mnem,"sbfm"); snprintf(ops,sizeof(ops),"%s, %s, #%d, #%d",ra,rb,immr,imms); }
        } else if (opc == 1) {
            strcpy(mnem,"bfm"); snprintf(ops,sizeof(ops),"%s, %s, #%d, #%d",ra,rb,immr,imms);
        } else {
            if (imms == maxbit) { strcpy(mnem,"lsr"); snprintf(ops,sizeof(ops),"%s, %s, #%d",ra,rb,immr); }
            else if (immr==0&&imms==7)  { strcpy(mnem,"uxtb"); snprintf(ops,sizeof(ops),"%s, %s",ra,rb); }
            else if (immr==0&&imms==15) { strcpy(mnem,"uxth"); snprintf(ops,sizeof(ops),"%s, %s",ra,rb); }
            else { strcpy(mnem,"ubfm"); snprintf(ops,sizeof(ops),"%s, %s, #%d, #%d",ra,rb,immr,imms); }
        }
        goto done;
    }

    if ((raw & 0x3F800000) == 0x13000000) {
        sf    = BIT(raw,31);
        int immr  = BITS(raw,21,16);
        int imms  = BITS(raw,15,10);
        rn    = BITS(raw,9,5);
        rd    = BITS(raw,4,0);
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); }
        if (!sf && immr==0 && imms==31) { strcpy(mnem,"sxtw"); snprintf(ops,sizeof(ops),"%s, %s",ra,rb); }
        else if (imms+1 == immr) { strcpy(mnem,"ror"); snprintf(ops,sizeof(ops),"%s, %s, #%d",ra,rb,immr); }
        else {
            rm = BITS(raw,20,16);
            xreg_zr(rm,rc);
            strcpy(mnem,"extr"); snprintf(ops,sizeof(ops),"%s, %s, %s, #%d",ra,rb,rc,imms);
        }
        goto done;
    }

    if ((raw & 0xFF800000) == 0x52800000 || (raw & 0xFF800000) == 0x72800000 ||
        (raw & 0xFF800000) == 0x92800000 || (raw & 0xFF800000) == 0xD2800000) {
        sf    = BIT(raw,31);
        opc   = BITS(raw,30,29);
        int hw    = BITS(raw,22,21);
        imm16 = BITS(raw,20,5);
        rd    = BITS(raw,4,0);
        const char *mn4[] = {"movn","???","movz","movk"};
        strcpy(mnem, mn4[opc]);
        if (sf) xreg_zr(rd,ra); else wreg_zr(rd,ra);
        if (hw) snprintf(ops,sizeof(ops),"%s, #0x%x, lsl #%d",ra,imm16,hw*16);
        else    snprintf(ops,sizeof(ops),"%s, #0x%x",ra,imm16);
        goto done;
    }

    if ((raw & 0x3A000000) == 0x28000000) {
        sf   = BIT(raw,31);
        int V    = BIT(raw,26);
        int L    = BIT(raw,22);
        int op_  = BITS(raw,24,23);
        imm7 = BITS(raw,21,15);
        rt2  = BITS(raw,14,10);
        rn   = BITS(raw,9,5);
        rt   = BITS(raw,4,0);
        int64_t offset = sext(imm7, 7) * (sf ? 8 : 4);
        if (!V) {
            if (sf) { xreg_zr(rt,ra); xreg_zr(rt2,rb); xreg(rn,rc); }
            else    { wreg_zr(rt,ra); wreg_zr(rt2,rb); wreg(rn,rc); }
            strcpy(mnem, L ? "ldp" : "stp");
            if (op_ == 1)
                snprintf(ops,sizeof(ops),"%s, %s, [%s], #%lld",ra,rb,rc,(long long)offset);
            else if (op_ == 3)
                snprintf(ops,sizeof(ops),"%s, %s, [%s, #%lld]!",ra,rb,rc,(long long)offset);
            else if (offset)
                snprintf(ops,sizeof(ops),"%s, %s, [%s, #%lld]",ra,rb,rc,(long long)offset);
            else
                snprintf(ops,sizeof(ops),"%s, %s, [%s]",ra,rb,rc);
        } else {
            /* SIMD/FP register pair: Sn, Dn, or Qn */
            int opc_sz2 = BIT(raw,31)*2 + sf;
            const char *fsuf = (opc_sz2==2) ? "q" : (opc_sz2==1) ? "d" : "s";
            int scale2  = (opc_sz2==2) ? 16 : (opc_sz2==1) ? 8 : 4;
            int64_t offset2 = sext(imm7, 7) * scale2;
            char va[8], vb[8];
            snprintf(va, sizeof(va), "%s%d", fsuf, rt);
            snprintf(vb, sizeof(vb), "%s%d", fsuf, rt2);
            xreg(rn, rc);
            strcpy(mnem, L ? "ldp" : "stp");
            if (op_ == 1)
                snprintf(ops,sizeof(ops),"%s, %s, [%s], #%lld",va,vb,rc,(long long)offset2);
            else if (op_ == 3)
                snprintf(ops,sizeof(ops),"%s, %s, [%s, #%lld]!",va,vb,rc,(long long)offset2);
            else if (offset2)
                snprintf(ops,sizeof(ops),"%s, %s, [%s, #%lld]",va,vb,rc,(long long)offset2);
            else
                snprintf(ops,sizeof(ops),"%s, %s, [%s]",va,vb,rc);
        }
        goto done;
    }

    /* SIMD/FP load-store (V=1): STR/LDR Qn, Dn, Sn, Hn, Bn */
    if ((raw & 0x3A000000) == 0x3C000000 || (raw & 0x3A000000) == 0x38000000) {
        int sz   = BITS(raw,31,30);
        int V    = BIT(raw,26);
        int opc  = BITS(raw,23,22);
        int is_load = (opc & 1);
        rn   = BITS(raw,9,5);
        rt   = BITS(raw,4,0);
        if (V) {
            /* FP/SIMD register: Qn (128), Dn (64), Sn (32), Hn (16), Bn (8) */
            const char *fsz[] = {"b","h","s","d"};
            const char *qsz   = (sz==0 && opc>=2) ? "q" : fsz[sz];
            xreg(rn, rb);
            snprintf(ra, sizeof(ra), "%s%d", qsz, rt);
            strcpy(mnem, is_load ? "ldr" : "str");
            if (BIT(raw,24)) {
                int off = (int)BITS(raw,21,10) * (1<<sz);
                if (off) snprintf(ops,sizeof(ops),"%s, [%s, #%d]",ra,rb,off);
                else     snprintf(ops,sizeof(ops),"%s, [%s]",ra,rb);
            } else {
                int imm9 = (int)(((int32_t)(BITS(raw,20,12)<<23))>>23);
                int mode = BITS(raw,11,10);
                if (mode==1)      snprintf(ops,sizeof(ops),"%s, [%s], #%d",ra,rb,imm9);
                else if (mode==3) snprintf(ops,sizeof(ops),"%s, [%s, #%d]!",ra,rb,imm9);
                else              snprintf(ops,sizeof(ops),"%s, [%s, #%d]",ra,rb,imm9?imm9:0);
            }
            goto done;
        }
    }

    /* SIMD STP/LDP Qn/Dn/Sn */
    if ((raw & 0x3E000000) == 0x2C000000 || (raw & 0x3E000000) == 0x6C000000) {
        int V = BIT(raw,26);
        int L = BIT(raw,22);
        int opc_sz = BITS(raw,31,30);
        if (V) {
            int op_ = BITS(raw,24,23);
            int imm7 = BITS(raw,21,15);
            int rt2_ = BITS(raw,14,10);
            rn = BITS(raw,9,5);
            rt = BITS(raw,4,0);
            const char *fsz2[] = {"s","d","q"};
            const char *qn2    = (opc_sz < 3) ? fsz2[opc_sz] : "q";
            int scale = opc_sz==2?16:(opc_sz==1?8:4);
            int offset = (int)(((int8_t)(imm7<<1))>>1) * scale;
            char r1[8], r2[8];
            snprintf(r1,sizeof(r1),"%s%d",qn2,rt);
            snprintf(r2,sizeof(r2),"%s%d",qn2,rt2_);
            xreg(rn,rb);
            strcpy(mnem, L?"ldp":"stp");
            if (op_==1) snprintf(ops,sizeof(ops),"%s, %s, [%s], #%d",r1,r2,rb,offset);
            else if (op_==3) snprintf(ops,sizeof(ops),"%s, %s, [%s, #%d]!",r1,r2,rb,offset);
            else if (offset) snprintf(ops,sizeof(ops),"%s, %s, [%s, #%d]",r1,r2,rb,offset);
            else snprintf(ops,sizeof(ops),"%s, %s, [%s]",r1,r2,rb);
            goto done;
        }
    }

    /* SIMD data-processing: MOVI, ORR imm, etc. */
    if ((raw & 0x9F800400) == 0x0F000400 || (raw & 0x9F800400) == 0x0F001400) {
        /* Modified immediate: MOVI / MVNI / ORR / BIC */
        int Q    = BIT(raw,30);
        int op_  = BIT(raw,29);
        int cmode= BITS(raw,15,12);
        int abcdefgh = (BITS(raw,20,16)<<5)|BITS(raw,9,5);
        rd = BITS(raw,4,0);
        uint64_t imm64 = 0;
        (void)Q; (void)cmode; (void)op_;
        /* Build immediate from abcdefgh */
        { int b; for(b=0;b<8;b++) if((abcdefgh>>b)&1) imm64|=(0xFFULL<<(b*8)); }
        if (!op_ && cmode>=14) strcpy(mnem,"movi");
        else if (op_ && cmode>=14) strcpy(mnem,"mvni");
        else strcpy(mnem,"movi");
        snprintf(ops,sizeof(ops),"v%d.%s, #0x%llx", rd,
                 Q?"2d":"d", (unsigned long long)imm64);
        goto done;
    }

    /* SIMD three-register: ADD/SUB/MUL/AND/ORR/EOR v regs */
    if ((raw & 0x1E000000) == 0x0E000000 && BIT(raw,28)==0) {
        int Q    = BIT(raw,30);
        int U    = BIT(raw,29);
        int size = BITS(raw,23,22);
        rm   = BITS(raw,20,16);
        int opcode5 = BITS(raw,15,11);
        rn   = BITS(raw,9,5);
        rd   = BITS(raw,4,0);
        const char *vsizes[] = {"8b","16b","4h","8h","2s","4s","?","2d"};
        const char *vsz = Q ? vsizes[(size<<1)|1] : vsizes[size<<1];
        char vd[8],vn[8],vm_[8];
        snprintf(vd,sizeof(vd),"v%d.%s",rd,vsz);
        snprintf(vn,sizeof(vn),"v%d.%s",rn,vsz);
        snprintf(vm_,sizeof(vm_),"v%d.%s",rm,vsz);
        if (opcode5==0x10 && !U) { strcpy(mnem,"add"); }
        else if (opcode5==0x10 && U) { strcpy(mnem,"sub"); }
        else if (opcode5==0x09 && U) { strcpy(mnem,"mul"); }
        else if (opcode5==0x01 && !U && size==0) { strcpy(mnem,"and"); snprintf(vd,8,"v%d.16b",rd); snprintf(vn,8,"v%d.16b",rn); snprintf(vm_,8,"v%d.16b",rm); }
        else if (opcode5==0x01 && !U && size==2) { strcpy(mnem,"orr"); snprintf(vd,8,"v%d.16b",rd); snprintf(vn,8,"v%d.16b",rn); snprintf(vm_,8,"v%d.16b",rm); }
        else if (opcode5==0x01 && U)  { strcpy(mnem,"eor"); snprintf(vd,8,"v%d.16b",rd); snprintf(vn,8,"v%d.16b",rn); snprintf(vm_,8,"v%d.16b",rm); }
        else if (opcode5==0x0F && !U) { strcpy(mnem,"smax"); }
        else if (opcode5==0x0F && U)  { strcpy(mnem,"umax"); }
        else if (opcode5==0x06 && !U) { strcpy(mnem,"cmgt"); }
        else if (opcode5==0x06 && U)  { strcpy(mnem,"cmhi"); }
        else {
            snprintf(mnem,sizeof(mnem),"v_%x",opcode5);
        }
        snprintf(ops,sizeof(ops),"%s, %s, %s",vd,vn,vm_);
        goto done;
    }

    if ((raw & 0x3A000000) == 0x38000000) {
        int sz   = BITS(raw,31,30);
        int V    = BIT(raw,26);
        int opc2 = BITS(raw,23,22);
        rn   = BITS(raw,9,5);
        rt   = BITS(raw,4,0);
        const char *lmn[] = {"ldrb","ldrh","ldr","ldr"};
        const char *smn[] = {"strb","strh","str","str"};
        const char *sln[] = {"ldrsb","ldrsh","ldrsw","???"};
        int is_load = (opc2 & 1);
        int is_sign = (opc2 >= 2);
        if (!V) {
            if (sz == 3) xreg_zr(rt,ra); else if (sz==2 && !is_sign) wreg_zr(rt,ra);
            else if (is_sign) xreg_zr(rt,ra);
            else wreg_zr(rt,ra);
            xreg(rn,rb);
            if (is_sign && sz <= 2) strcpy(mnem, sln[sz]);
            else strcpy(mnem, is_load ? lmn[sz] : smn[sz]);
            int mode = BITS(raw,11,10);
            if (BIT(raw,21)) {
                rm = BITS(raw,20,16);
                int opt = BITS(raw,15,13);
                int S2  = BIT(raw,12);
                xreg_zr(rm,rc);
                if (S2) snprintf(ops,sizeof(ops),"%s, [%s, %s, %s #%d]",ra,rb,rc,ext_name(opt),sz);
                else    snprintf(ops,sizeof(ops),"%s, [%s, %s, %s]",ra,rb,rc,ext_name(opt));
            } else if (BIT(raw,24)) {
                int off = (int)BITS(raw,21,10) * (1<<sz);
                if (off) snprintf(ops,sizeof(ops),"%s, [%s, #%d]",ra,rb,off);
                else     snprintf(ops,sizeof(ops),"%s, [%s]",ra,rb);
            } else {
                int32_t imm9 = (int32_t)sext(BITS(raw,20,12),9);
                if (mode == 1)      snprintf(ops,sizeof(ops),"%s, [%s], #%d",ra,rb,(int)imm9);
                else if (mode == 3) snprintf(ops,sizeof(ops),"%s, [%s, #%d]!",ra,rb,(int)imm9);
                else                snprintf(ops,sizeof(ops),"%s, [%s, #%d]",ra,rb,(int)imm9);
            }
            goto done;
        }
    }

    if ((raw & 0xBF000000) == 0x18000000) {
        opc  = BITS(raw,31,30);
        rt   = BITS(raw,4,0);
        int64_t r = sext((uint64_t)BITS(raw,23,5)<<2, 21);
        if (opc==0) { strcpy(mnem,"ldr"); wreg_zr(rt,ra); }
        else if (opc==1) { strcpy(mnem,"ldr"); xreg_zr(rt,ra); }
        else if (opc==2) { strcpy(mnem,"ldrsw"); xreg_zr(rt,ra); }
        else { strcpy(mnem,"prfm"); snprintf(ra,sizeof(ra),"#%d",rt); }
        snprintf(ops,sizeof(ops),"%s, 0x%016llx",ra,(unsigned long long)(addr+(uint64_t)r));
        goto done;
    }

    if ((raw & 0x1F000000) == 0x1A000000) {
        sf   = BIT(raw,31);
        int op1  = BITS(raw,30,21);
        rm   = BITS(raw,20,16);
        int op2_ = BITS(raw,15,10);
        rn   = BITS(raw,9,5);
        rd   = BITS(raw,4,0);
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); xreg_zr(rm,rc); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); wreg_zr(rm,rc); }
        /* Use op2_ (bits 15:10) for div/shift, op1 for csel family */
        if      (op2_==0x2)  { strcpy(mnem,"udiv"); snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if (op2_==0x3)  { strcpy(mnem,"sdiv"); snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if (op2_==0x8)  { strcpy(mnem,"lsl");  snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if (op2_==0x9)  { strcpy(mnem,"lsr");  snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if (op2_==0xA)  { strcpy(mnem,"asr");  snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if (op2_==0xB)  { strcpy(mnem,"ror");  snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
        else if ((op1&~1)==0) {
            int cond_  = BITS(raw,15,12);
            int op2c   = BITS(raw,11,10);
            int neg    = BIT(raw,30);
            if (op2c==0) {
                strcpy(mnem,"csel");
                snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,a64_cond_str[cond_]);
            } else if (op2c==1) {
                if (rn==rm && rn==31) {
                    strcpy(mnem, neg ? "cneg" : "cinc");
                    snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,a64_cond_str[cond_^1]);
                } else {
                    strcpy(mnem, neg ? "csneg" : "csinc");
                    snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,a64_cond_str[cond_]);
                }
            } else if (op2c==3) {
                if (rn==rm && rn==31) {
                    strcpy(mnem, neg ? "cinv" : "cset");
                    snprintf(ops,sizeof(ops),"%s, %s",ra,a64_cond_str[cond_^1]);
                } else {
                    strcpy(mnem, neg ? "csinv" : "csinv");
                    snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,a64_cond_str[cond_]);
                }
            }
        } else {
            snprintf(mnem,sizeof(mnem),"dp_%03x",op1);
            snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc);
        }
        (void)op2_;
        goto done;
    }

    if ((raw & 0x7FC00000) == 0x1AC00000) {
        sf  = BIT(raw,31);
        rn  = BITS(raw,9,5);
        rd  = BITS(raw,4,0);
        int opc2_ = BITS(raw,15,10);
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); }
        if (opc2_==0)  { strcpy(mnem,"rbit");  snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
        if (opc2_==1)  { strcpy(mnem,"rev16"); snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
        if (opc2_==2)  { strcpy(mnem,"rev");   snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
        if (opc2_==3)  { strcpy(mnem,"rev64"); snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
        if (opc2_==4)  { strcpy(mnem,"clz");   snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
        if (opc2_==5)  { strcpy(mnem,"cls");   snprintf(ops,sizeof(ops),"%s, %s",ra,rb); goto done; }
    }

    if ((raw & 0x1FE00000) == 0x1B000000) {
        sf   = BIT(raw,31);
        int o0   = BIT(raw,15);
        rm   = BITS(raw,20,16);
        int ra_  = BITS(raw,14,10);
        rn   = BITS(raw,9,5);
        rd   = BITS(raw,4,0);
        char rx[8];
        if (sf) { xreg_zr(rd,ra); xreg_zr(rn,rb); xreg_zr(rm,rc); xreg_zr(ra_,rx); }
        else    { wreg_zr(rd,ra); wreg_zr(rn,rb); wreg_zr(rm,rc); wreg_zr(ra_,rx); }
        if (!o0) {
            if (ra_==31) { strcpy(mnem,"mul");  snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
            else         { strcpy(mnem,"madd"); snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,rx); }
        } else {
            if (ra_==31) { strcpy(mnem,"mneg"); snprintf(ops,sizeof(ops),"%s, %s, %s",ra,rb,rc); }
            else         { strcpy(mnem,"msub"); snprintf(ops,sizeof(ops),"%s, %s, %s, %s",ra,rb,rc,rx); }
        }
        goto done;
    }

    if ((raw & 0xFF000000) == 0xD5000000) {
        int L    = BIT(raw,21);
        int op0_ = BITS(raw,20,19);
        int CRn  = BITS(raw,15,12);
        int CRm  = BITS(raw,11,8);
        int op2_ = BITS(raw,7,5);
        rt  = BITS(raw,4,0);
        xreg_zr(rt, ra);
        strcpy(mnem, L ? "mrs" : "msr");
        snprintf(ops,sizeof(ops),"%s, S%d_%d_C%d_C%d_%d",
            ra,(int)BIT(raw,20),op0_&3,CRn,CRm,op2_);
        goto done;
    }

    snprintf(mnem,sizeof(mnem),"dw");
    snprintf(ops,sizeof(ops),"0x%08x",raw);

done:
    strncpy(insn->mnemonic, mnem, sizeof(insn->mnemonic)-1);
    strncpy(insn->operands, ops,  sizeof(insn->operands)-1);
    return 4;
}
