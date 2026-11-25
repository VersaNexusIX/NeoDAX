#ifndef DAX_RISCV_H
#define DAX_RISCV_H

#include <stdint.h>
#include "dax.h"

typedef struct {
    uint32_t raw;
    uint64_t address;
    char     mnemonic[DAX_MAX_MNEMONIC];
    char     operands[DAX_MAX_OPERANDS];
    int      length;    /* 2 (compressed) or 4 (standard) */
} rv_insn_t;

extern const char *rv_cond_str[];
extern const char *rv_reg_names[];
extern const char *rv_freg_names[];

int  rv_decode(const uint8_t *buf, size_t len, uint64_t addr, rv_insn_t *insn);
void rv_reg_name(int r, int is_float, char *out);

#endif
