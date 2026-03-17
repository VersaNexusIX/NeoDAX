#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "riscv.h"

const char *rv_reg_names[] = {
    "zero","ra","sp","gp","tp","t0","t1","t2",
    "s0",  "s1","a0","a1","a2","a3","a4","a5",
    "a6",  "a7","s2","s3","s4","s5","s6","s7",
    "s8",  "s9","s10","s11","t3","t4","t5","t6"
};

const char *rv_freg_names[] = {
    "ft0","ft1","ft2","ft3","ft4","ft5","ft6","ft7",
    "fs0","fs1","fa0","fa1","fa2","fa3","fa4","fa5",
    "fa6","fa7","fs2","fs3","fs4","fs5","fs6","fs7",
    "fs8","fs9","fs10","fs11","ft8","ft9","ft10","ft11"
};

const char *rv_cond_str[] = {
    "eq","ne","lt","ge","ltu","geu"
};

void rv_reg_name(int r, int is_float, char *out) {
    r &= 31;
    if (is_float) { strncpy(out, rv_freg_names[r], 7); }
    else          { strncpy(out, rv_reg_names[r],  7); }
}

#define BITS(v,h,l) (((uint32_t)(v)>>(l)) & ((1u<<((h)-(l)+1))-1u))
#define BIT(v,n)    (((uint32_t)(v)>>(n))&1u)

static int64_t sext32(uint32_t v, int bits) {
    int64_t s = (int64_t)((uint64_t)v << (64-bits));
    return s >> (64-bits);
}

static const char *rn(int r)  { return rv_reg_names[r&31]; }
static const char *frn(int r) { return rv_freg_names[r&31]; }

/* ── RV32C / RV64C  (compressed 16-bit) ──────────────────────── */
static int rv_decode_c(uint16_t hw, uint64_t addr, rv_insn_t *insn) {
    char *m = insn->mnemonic;
    char *o = insn->operands;
    int   op  = hw & 3;
    int   fn3 = (hw >> 13) & 7;
    int   rs1, rs2, rd, imm;

    insn->length = 2;

    switch (op) {
    case 0: /* Quadrant 0 */
        switch (fn3) {
        case 0: { /* C.ADDI4SPN */
            int nzuimm = BITS(hw,10,7)<<6|BITS(hw,12,11)<<4|BIT(hw,5)<<3|BIT(hw,6)<<2;
            rd = 8 + BITS(hw,4,2);
            if (!nzuimm) { strcpy(m,"c.illegal"); o[0]=0; break; }
            strcpy(m,"c.addi4spn");
            snprintf(o,DAX_MAX_OPERANDS,"%s, sp, %d", rn(rd), nzuimm);
            break; }
        case 1: /* C.FLD */
            rd  = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BITS(hw,6,5)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.fld");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", frn(rd), imm, rn(rs1)); break;
        case 2: /* C.LW */
            rd  = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BIT(hw,5)<<6|BITS(hw,12,10)<<3|BIT(hw,6)<<2;
            strcpy(m,"c.lw");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", rn(rd), imm, rn(rs1)); break;
        case 3: /* C.LD (RV64) */
            rd  = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BITS(hw,6,5)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.ld");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", rn(rd), imm, rn(rs1)); break;
        case 5: /* C.FSD */
            rs2 = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BITS(hw,6,5)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.fsd");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", frn(rs2), imm, rn(rs1)); break;
        case 6: /* C.SW */
            rs2 = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BIT(hw,5)<<6|BITS(hw,12,10)<<3|BIT(hw,6)<<2;
            strcpy(m,"c.sw");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", rn(rs2), imm, rn(rs1)); break;
        case 7: /* C.SD (RV64) */
            rs2 = 8+BITS(hw,4,2); rs1 = 8+BITS(hw,9,7);
            imm = BITS(hw,6,5)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.sd");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(%s)", rn(rs2), imm, rn(rs1)); break;
        default: strcpy(m,"c.?q0"); o[0]=0; break;
        }
        break;

    case 1: /* Quadrant 1 */
        switch (fn3) {
        case 0: /* C.NOP / C.ADDI */
            rd  = BITS(hw,11,7);
            imm = (int)(int8_t)((BIT(hw,12)<<7)|(BITS(hw,6,2)<<2));
            imm >>= 2;
            if (rd==0) { strcpy(m,"c.nop"); o[0]=0; }
            else {
                strcpy(m,"c.addi");
                snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), imm);
            }
            break;
        case 1: /* C.ADDIW (RV64) */
            rd  = BITS(hw,11,7);
            imm = (int)(int8_t)((BIT(hw,12)<<7)|(BITS(hw,6,2)<<2));
            imm >>= 2;
            strcpy(m,"c.addiw");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), imm); break;
        case 2: /* C.LI */
            rd  = BITS(hw,11,7);
            imm = (int)(int8_t)((BIT(hw,12)<<7)|(BITS(hw,6,2)<<2));
            imm >>= 2;
            strcpy(m,"c.li");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), imm); break;
        case 3: {
            rd = BITS(hw,11,7);
            if (rd==2) { /* C.ADDI16SP */
                imm = (int)(int16_t)((BIT(hw,12)<<10)|(BITS(hw,4,3)<<8)|
                      (BIT(hw,5)<<7)|(BIT(hw,2)<<6)|(BIT(hw,6)<<5));
                imm >>= 5;
                strcpy(m,"c.addi16sp");
                snprintf(o,DAX_MAX_OPERANDS,"sp, %d", imm);
            } else { /* C.LUI */
                imm = (int)(int32_t)((BIT(hw,12)<<18)|(BITS(hw,6,2)<<13));
                imm >>= 13;
                strcpy(m,"c.lui");
                snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%x", rn(rd), (unsigned)(imm & 0xFFFFF));
            }
            break; }
        case 4: { /* C.SRLI / C.SRAI / C.ANDI / C.SUB etc */
            int fn2 = BITS(hw,11,10);
            rd = 8+BITS(hw,9,7);
            if (fn2 <= 1) {
                int shamt = BIT(hw,12)<<5|BITS(hw,6,2);
                strcpy(m, fn2==0?"c.srli":"c.srai");
                snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), shamt);
            } else if (fn2==2) {
                imm = (int)(int8_t)((BIT(hw,12)<<7)|(BITS(hw,6,2)<<2));
                imm >>= 2;
                strcpy(m,"c.andi");
                snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), imm);
            } else {
                rs2 = 8+BITS(hw,4,2);
                int fn3b = (BIT(hw,12)<<2)|BITS(hw,6,5);
                const char *ops2[] = {"c.sub","c.xor","c.or","c.and",
                                      "c.subw","c.addw","c.?","c.?"};
                strcpy(m, ops2[fn3b]);
                snprintf(o,DAX_MAX_OPERANDS,"%s, %s", rn(rd), rn(rs2));
            }
            break; }
        case 5: { /* C.J */
            int j = (int16_t)((BIT(hw,12)<<12)|(BIT(hw,11)<<11)|(BITS(hw,10,9)<<9)|
                    (BIT(hw,8)<<8)|(BIT(hw,7)<<7)|(BIT(hw,6)<<6)|(BIT(hw,2)<<5)|
                    (BIT(hw,11)<<4)|(BITS(hw,5,3)<<1));
            j = (int)(int16_t)(j<<4)>>4;
            strcpy(m,"c.j");
            snprintf(o,DAX_MAX_OPERANDS,"0x%016llx",(unsigned long long)(addr+(int64_t)j)); break; }
        case 6: case 7: { /* C.BEQZ / C.BNEZ */
            rs1 = 8+BITS(hw,9,7);
            int b = (int16_t)((BIT(hw,12)<<8)|(BITS(hw,6,5)<<6)|(BIT(hw,2)<<5)|
                    (BITS(hw,11,10)<<3)|(BITS(hw,4,3)<<1));
            b = (int)(int16_t)(b<<7)>>7;
            strcpy(m, fn3==6?"c.beqz":"c.bnez");
            snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%016llx",rn(rs1),(unsigned long long)(addr+(int64_t)b)); break; }
        default: strcpy(m,"c.?q1"); o[0]=0; break;
        }
        break;

    case 2: /* Quadrant 2 */
        switch (fn3) {
        case 0: { /* C.SLLI */
            rd = BITS(hw,11,7);
            int shamt = BIT(hw,12)<<5|BITS(hw,6,2);
            strcpy(m,"c.slli");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d", rn(rd), shamt); break; }
        case 1: { /* C.FLDSP */
            rd = BITS(hw,11,7);
            imm = BIT(hw,4)<<8|BIT(hw,12)<<5|BITS(hw,6,5)<<3;
            strcpy(m,"c.fldsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", frn(rd), imm); break; }
        case 2: { /* C.LWSP */
            rd = BITS(hw,11,7);
            imm = BITS(hw,3,2)<<6|BIT(hw,12)<<5|BITS(hw,6,4)<<2;
            strcpy(m,"c.lwsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", rn(rd), imm); break; }
        case 3: { /* C.LDSP */
            rd = BITS(hw,11,7);
            imm = BITS(hw,4,2)<<6|BIT(hw,12)<<5|BITS(hw,6,5)<<3;
            strcpy(m,"c.ldsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", rn(rd), imm); break; }
        case 4: {
            rd = BITS(hw,11,7); rs2 = BITS(hw,6,2);
            if (!BIT(hw,12)) {
                if (!rs2) { strcpy(m,"c.jr"); snprintf(o,DAX_MAX_OPERANDS,"%s",rn(rd)); }
                else       { strcpy(m,"c.mv"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),rn(rs2)); }
            } else {
                if (!rd && !rs2) { strcpy(m,"c.ebreak"); o[0]=0; }
                else if (!rs2)   { strcpy(m,"c.jalr"); snprintf(o,DAX_MAX_OPERANDS,"%s",rn(rd)); }
                else             { strcpy(m,"c.add");  snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),rn(rs2)); }
            }
            break; }
        case 5: { /* C.FSDSP */
            rs2 = BITS(hw,6,2);
            imm = BITS(hw,9,7)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.fsdsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", frn(rs2), imm); break; }
        case 6: { /* C.SWSP */
            rs2 = BITS(hw,6,2);
            imm = BITS(hw,8,7)<<6|BITS(hw,12,9)<<2;
            strcpy(m,"c.swsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", rn(rs2), imm); break; }
        case 7: { /* C.SDSP */
            rs2 = BITS(hw,6,2);
            imm = BITS(hw,9,7)<<6|BITS(hw,12,10)<<3;
            strcpy(m,"c.sdsp");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %d(sp)", rn(rs2), imm); break; }
        default: strcpy(m,"c.?q2"); o[0]=0; break;
        }
        break;

    default:
        strcpy(m,"c.?"); o[0]=0;
        break;
    }
    return 2;
}

/* ── RV32I / RV64I base + extensions ─────────────────────────── */
int rv_decode(const uint8_t *buf, size_t len, uint64_t addr, rv_insn_t *insn) {
    uint32_t raw;
    int      op7, fn3, fn7, rd, rs1, rs2;
    int64_t  imm;
    char    *m = insn->mnemonic;
    char    *o = insn->operands;

    memset(insn, 0, sizeof(*insn));
    insn->address = addr;

    if (len < 2) return -1;

    /* Check for compressed (C extension) 16-bit instruction */
    {
        uint16_t hw = (uint16_t)(buf[0]) | ((uint16_t)(buf[1])<<8);
        if ((hw & 3) != 3) {
            insn->raw = hw;
            return rv_decode_c(hw, addr, insn);
        }
    }

    if (len < 4) return -1;
    raw = (uint32_t)(buf[0]) | ((uint32_t)buf[1]<<8) |
          ((uint32_t)buf[2]<<16) | ((uint32_t)buf[3]<<24);

    insn->raw    = raw;
    insn->length = 4;

    op7 = raw & 0x7F;
    rd   = BITS(raw,11,7);
    fn3  = BITS(raw,14,12);
    rs1  = BITS(raw,19,15);
    rs2  = BITS(raw,24,20);
    fn7  = BITS(raw,31,25);

    switch (op7) {

    /* LUI */
    case 0x37:
        imm = (int64_t)(int32_t)(raw & 0xFFFFF000);
        strcpy(m,"lui");
        snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%llx", rn(rd), (unsigned long long)(imm>>12)&0xFFFFF);
        break;

    /* AUIPC */
    case 0x17:
        imm = (int64_t)(int32_t)(raw & 0xFFFFF000);
        strcpy(m,"auipc");
        snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%016llx", rn(rd),
                 (unsigned long long)(uint64_t)(addr + (uint64_t)imm));
        break;

    /* JAL */
    case 0x6F: {
        int64_t joff = sext32(
            (BITS(raw,30,21)<<1) | (BIT(raw,20)<<11) |
            (BITS(raw,19,12)<<12) | (BIT(raw,31)<<20), 21);
        strcpy(m, rd==0 ? "j" : "jal");
        if (rd==0)
            snprintf(o,DAX_MAX_OPERANDS,"0x%016llx",(unsigned long long)(addr+(uint64_t)joff));
        else
            snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%016llx",rn(rd),(unsigned long long)(addr+(uint64_t)joff));
        break; }

    /* JALR */
    case 0x67:
        imm = sext32(BITS(raw,31,20), 12);
        strcpy(m, (rd==0&&rs1==1&&!imm) ? "ret" : (rd==1?"jalr":"jalr"));
        if (rd==0 && rs1==1 && !imm) { o[0]=0; }
        else if (!imm) snprintf(o,DAX_MAX_OPERANDS,"%s, %s", rn(rd), rn(rs1));
        else           snprintf(o,DAX_MAX_OPERANDS,"%s, %lld(%s)", rn(rd), (long long)imm, rn(rs1));
        break;

    /* BRANCH */
    case 0x63: {
        int64_t boff = sext32(
            (BIT(raw,8)<<1)|(BITS(raw,30,25)<<5)|
            (BITS(raw,11,9)<<9)|(BIT(raw,31)<<12), 13);
        const char *bcond[] = {"beq","bne","?","?","blt","bge","bltu","bgeu"};
        strcpy(m, bcond[fn3]);
        snprintf(o,DAX_MAX_OPERANDS,"%s, %s, 0x%016llx",
                 rn(rs1), rn(rs2), (unsigned long long)(addr+(uint64_t)boff));
        break; }

    /* LOAD */
    case 0x03: {
        const char *lmn[] = {"lb","lh","lw","ld","lbu","lhu","lwu","?"};
        imm = sext32(BITS(raw,31,20), 12);
        strcpy(m, lmn[fn3]);
        snprintf(o,DAX_MAX_OPERANDS,"%s, %lld(%s)", rn(rd), (long long)imm, rn(rs1));
        break; }

    /* STORE */
    case 0x23: {
        const char *smn[] = {"sb","sh","sw","sd","?","?","?","?"};
        imm = sext32((BITS(raw,31,25)<<5)|BITS(raw,11,7), 12);
        strcpy(m, smn[fn3]);
        snprintf(o,DAX_MAX_OPERANDS,"%s, %lld(%s)", rn(rs2), (long long)imm, rn(rs1));
        break; }

    /* OP-IMM (I-type arithmetic) */
    case 0x13: {
        static const char *iop[] = {"addi","slli","slti","sltiu","xori","srli","ori","andi"};
        imm = sext32(BITS(raw,31,20), 12);
        if (fn3==5 && fn7==0x20) {
            strcpy(m,"srai");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %d", rn(rd), rn(rs1), (int)BITS(raw,25,20));
        } else if (fn3==1 || fn3==5) {
            strcpy(m, iop[fn3]);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %d", rn(rd), rn(rs1), (int)BITS(raw,25,20));
        } else if (fn3==0 && rs1==0) {
            strcpy(m,"li");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %lld", rn(rd), (long long)imm);
        } else if (fn3==0 && imm==0) {
            strcpy(m,"mv");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s", rn(rd), rn(rs1));
        } else {
            strcpy(m, iop[fn3]);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %lld", rn(rd), rn(rs1), (long long)imm);
        }
        break; }

    /* OP-IMM-32 (RV64 W variants) */
    case 0x1B: {
        imm = sext32(BITS(raw,31,20), 12);
        if (fn3==0)      { strcpy(m,"addiw"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %lld",rn(rd),rn(rs1),(long long)imm); }
        else if (fn3==1) { strcpy(m,"slliw"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %d",rn(rd),rn(rs1),(int)BITS(raw,24,20)); }
        else if (fn3==5 && fn7==0)    { strcpy(m,"srliw"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %d",rn(rd),rn(rs1),(int)BITS(raw,24,20)); }
        else if (fn3==5 && fn7==0x20) { strcpy(m,"sraiw"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %d",rn(rd),rn(rs1),(int)BITS(raw,24,20)); }
        else { strcpy(m,"?iw"); o[0]=0; }
        break; }

    /* OP (R-type) */
    case 0x33: {
        static const char *rop[2][8] = {
            {"add","sll","slt","sltu","xor","srl","or","and"},
            {"sub","?",  "?",  "?",   "?",  "sra","?","?"}
        };
        static const char *mop[8] = {"mul","mulh","mulhsu","mulhu","div","divu","rem","remu"};
        if (fn7==1) {
            strcpy(m, mop[fn3]);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s", rn(rd), rn(rs1), rn(rs2));
        } else {
            int sub = (fn7==0x20) ? 1 : 0;
            strcpy(m, rop[sub][fn3]);
            if (fn3==0 && !sub && rs1==0) { strcpy(m,"mv"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),rn(rs2)); }
            else if (fn3==0 && !sub && rs2==0) { strcpy(m,"mv"); snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),rn(rs1)); }
            else snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s", rn(rd), rn(rs1), rn(rs2));
        }
        break; }

    /* OP-32 (RV64 W variants) */
    case 0x3B: {
        static const char *r32op[2][8] = {
            {"addw","sllw","?","?","?","srlw","?","?"},
            {"subw","?",   "?","?","?","sraw","?","?"}
        };
        static const char *m32op[8] = {"mulw","?","?","?","divw","divuw","remw","remuw"};
        if (fn7==1) {
            strcpy(m, m32op[fn3]);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s", rn(rd), rn(rs1), rn(rs2));
        } else {
            int sub = (fn7==0x20) ? 1 : 0;
            strcpy(m, r32op[sub][fn3]);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s", rn(rd), rn(rs1), rn(rs2));
        }
        break; }

    /* MISC-MEM (fence) */
    case 0x0F:
        strcpy(m, fn3==0 ? "fence" : "fence.i");
        o[0]=0;
        break;

    /* SYSTEM */
    case 0x73: {
        uint32_t csr = BITS(raw,31,20);
        if (!fn3) {
            if (!raw>>7) { strcpy(m,"ecall");  o[0]=0; }
            else if (csr==1) { strcpy(m,"ebreak"); o[0]=0; }
            else if (csr==0x102) { strcpy(m,"sret"); o[0]=0; }
            else if (csr==0x302) { strcpy(m,"mret"); o[0]=0; }
            else if (csr==0x105) { strcpy(m,"wfi");  o[0]=0; }
            else { strcpy(m,"system"); snprintf(o,DAX_MAX_OPERANDS,"0x%x",csr); }
        } else {
            static const char *csrop[8] = {"?","csrrw","csrrs","csrrc","?","csrrwi","csrrsi","csrrci"};
            strcpy(m, csrop[fn3]);
            if (csr==0xC00) snprintf(o,DAX_MAX_OPERANDS,"%s, cycle, %s",   rn(rd),rn(rs1));
            else if(csr==0xC01) snprintf(o,DAX_MAX_OPERANDS,"%s, time, %s",rn(rd),rn(rs1));
            else if(csr==0xC02) snprintf(o,DAX_MAX_OPERANDS,"%s, instret, %s",rn(rd),rn(rs1));
            else snprintf(o,DAX_MAX_OPERANDS,"%s, 0x%x, %s", rn(rd), csr, rn(rs1));
        }
        break; }

    /* ATOMIC (A extension) */
    case 0x2F: {
        int funct5 = BITS(raw,31,27);
        int aq = BIT(raw,26), rl = BIT(raw,25);
        char suffix[8] = "";
        if (aq&&rl) strcpy(suffix,".aqrl"); else if (aq) strcpy(suffix,".aq"); else if (rl) strcpy(suffix,".rl");
        const char *wsuf = fn3==2 ? "w" : "d";
        static const char *amop[32] = {
            "amoadd","amoxor","amoor","amoand","amomin","amomax","amominu","amomaxu",
            "amoswap","?","?","?","?","?","?","?",
            "lr","?","?","?","?","?","?","?",
            "sc","?","?","?","?","?","?","?"
        };
        if (funct5==0x02) {
            snprintf(m,DAX_MAX_MNEMONIC,"lr.%s%s",wsuf,suffix);
            snprintf(o,DAX_MAX_OPERANDS,"%s, (%s)", rn(rd), rn(rs1));
        } else if (funct5==0x03) {
            snprintf(m,DAX_MAX_MNEMONIC,"sc.%s%s",wsuf,suffix);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, (%s)", rn(rd), rn(rs2), rn(rs1));
        } else {
            snprintf(m,DAX_MAX_MNEMONIC,"%s.%s%s",amop[funct5&31],wsuf,suffix);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, (%s)", rn(rd), rn(rs2), rn(rs1));
        }
        break; }

    /* LOAD-FP */
    case 0x07: {
        imm = sext32(BITS(raw,31,20), 12);
        strcpy(m, fn3==2?"flw":"fld");
        snprintf(o,DAX_MAX_OPERANDS,"%s, %lld(%s)", frn(rd), (long long)imm, rn(rs1));
        break; }

    /* STORE-FP */
    case 0x27: {
        imm = sext32((BITS(raw,31,25)<<5)|BITS(raw,11,7), 12);
        strcpy(m, fn3==2?"fsw":"fsd");
        snprintf(o,DAX_MAX_OPERANDS,"%s, %lld(%s)", frn(rs2), (long long)imm, rn(rs1));
        break; }

    /* MADD/MSUB/NMSUB/NMADD (F/D extension) */
    case 0x43: case 0x47: case 0x4B: case 0x4F: {
        const char *fmaop[] = {"fmadd","fmsub","fnmsub","fnmadd"};
        int    fmt = BITS(raw,26,25);
        const char *suf = fmt==0?"s":"d";
        snprintf(m,DAX_MAX_MNEMONIC,"%s.%s",fmaop[(op7>>2)&3],suf);
        snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s, %s", frn(rd),frn(rs1),frn(rs2),frn(BITS(raw,31,27)));
        break; }

    /* OP-FP */
    case 0x53: {
        int   fmt   = BITS(raw,26,25);
        const char *suf = fmt==0?"s":"d";
        static const char *fop[] = {
            "fadd","fsub","fmul","fdiv","fsqrt","?","?","?",
            "fmin","fmax","?","?","fcvt.w","?","?","?",
            "?","?","?","?","?","?","?","?","fsgn","?","?","?","fmv.x.w","?","feq","flt","fle","fclass","?"
        };
        if (fn7==0x00) { snprintf(m,DAX_MAX_MNEMONIC,"fadd.%s",suf); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",frn(rd),frn(rs1),frn(rs2)); }
        else if (fn7==0x04) { snprintf(m,DAX_MAX_MNEMONIC,"fsub.%s",suf); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",frn(rd),frn(rs1),frn(rs2)); }
        else if (fn7==0x08) { snprintf(m,DAX_MAX_MNEMONIC,"fmul.%s",suf); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",frn(rd),frn(rs1),frn(rs2)); }
        else if (fn7==0x0C) { snprintf(m,DAX_MAX_MNEMONIC,"fdiv.%s",suf); snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",frn(rd),frn(rs1),frn(rs2)); }
        else if (fn7==0x2C) { snprintf(m,DAX_MAX_MNEMONIC,"fsqrt.%s",suf); snprintf(o,DAX_MAX_OPERANDS,"%s, %s",frn(rd),frn(rs1)); }
        else if (fn7==0x50) {
            const char *fcmp[]={"fle","flt","feq"};
            snprintf(m,DAX_MAX_MNEMONIC,"%s.%s",fcmp[fn3<3?fn3:0],suf);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",rn(rd),frn(rs1),frn(rs2));
        }
        else if (fn7==0x10 || fn7==0x14) {
            const char *sgn[]={"fsgnj","fsgnjn","fsgnjx"};
            snprintf(m,DAX_MAX_MNEMONIC,"%s.%s",sgn[fn3<3?fn3:0],suf);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s, %s",frn(rd),frn(rs1),frn(rs2));
        }
        else if (fn7==0x60) {
            snprintf(m,DAX_MAX_MNEMONIC,"fcvt.w%s.%s",rs2==1?"u":"",suf);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),frn(rs1));
        }
        else if (fn7==0x68) {
            snprintf(m,DAX_MAX_MNEMONIC,"fcvt.%s.w%s",suf,rs2==1?"u":"");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s",frn(rd),rn(rs1));
        }
        else if (fn7==0x70 && fn3==0) {
            snprintf(m,DAX_MAX_MNEMONIC,"fmv.x.%s",suf);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s",rn(rd),frn(rs1));
        }
        else if (fn7==0x78) {
            snprintf(m,DAX_MAX_MNEMONIC,"fmv.%s.x",suf);
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s",frn(rd),rn(rs1));
        }
        else if (fn7==0x20) {
            snprintf(m,DAX_MAX_MNEMONIC,"fcvt.%s.%s",fmt==1?"s":"d",fmt==0?"d":"s");
            snprintf(o,DAX_MAX_OPERANDS,"%s, %s",frn(rd),frn(rs1));
        }
        else {
            snprintf(m,DAX_MAX_MNEMONIC,"fop.%s",suf);
            snprintf(o,DAX_MAX_OPERANDS,"0x%x",fn7);
        }
        (void)fop;
        break; }

    default:
        snprintf(m,DAX_MAX_MNEMONIC,"dw");
        snprintf(o,DAX_MAX_OPERANDS,"0x%08x", raw);
        break;
    }

    return 4;
}
