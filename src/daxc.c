#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

extern dax_igrp_t dax_classify_x86(const char *m);
extern dax_igrp_t dax_classify_arm64(const char *m);
extern const char *dax_igrp_color(dax_igrp_t g, int color);

#pragma pack(push,1)
typedef struct {
    uint64_t  address;
    char      mnemonic[DAX_MAX_MNEMONIC];
    char      operands[DAX_MAX_OPERANDS];
    uint8_t   bytes[DAX_MAX_INSN_LEN];
    uint8_t   length;
    uint8_t   grp;
    uint8_t   _pad[2];
} daxc_insn_t;
#pragma pack(pop)

void dax_comment_add(dax_binary_t *bin, uint64_t addr, const char *text) {
    int i;
    if (!bin->comments) {
        bin->comments = (dax_comment_t *)calloc(DAX_MAX_COMMENTS, sizeof(dax_comment_t));
        if (!bin->comments) return;
    }
    for (i = 0; i < bin->ncomments; i++) {
        if (bin->comments[i].address == addr) {
            strncpy(bin->comments[i].text, text, DAX_COMMENT_LEN - 1);
            return;
        }
    }
    if (bin->ncomments >= DAX_MAX_COMMENTS) return;
    bin->comments[bin->ncomments].address = addr;
    strncpy(bin->comments[bin->ncomments].text, text, DAX_COMMENT_LEN - 1);
    bin->ncomments++;
}

const char *dax_comment_get(dax_binary_t *bin, uint64_t addr) {
    int i;
    if (!bin->comments) return NULL;
    for (i = 0; i < bin->ncomments; i++)
        if (bin->comments[i].address == addr)
            return bin->comments[i].text;
    return NULL;
}

static uint64_t collect_insns(dax_binary_t *bin, daxc_insn_t **out) {
    uint64_t      total = 0;
    uint64_t      cap   = 65536;
    daxc_insn_t  *arr;
    int           si;

    arr = (daxc_insn_t *)calloc((size_t)cap, sizeof(daxc_insn_t));
    if (!arr) { *out = NULL; return 0; }

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        uint8_t       *code;
        size_t         sz;
        uint64_t       base;
        size_t         off;

        if (sec->type != SEC_TYPE_CODE && sec->type != SEC_TYPE_PLT) continue;
        if (sec->offset + sec->size > bin->size) continue;

        code = bin->data + sec->offset;
        sz   = (size_t)sec->size;
        base = sec->vaddr;
        off  = 0;

        if (bin->arch == ARCH_X86_64) {
            while (off < sz) {
                x86_insn_t insn;
                int l = x86_decode(code + off, sz - off, base + off, &insn);
                if (l <= 0) { off++; continue; }
                if (total >= cap) {
                    cap *= 2;
                    arr  = (daxc_insn_t *)realloc(arr, (size_t)cap * sizeof(daxc_insn_t));
                    if (!arr) { *out = NULL; return 0; }
                }
                arr[total].address = base + off;
                strncpy(arr[total].mnemonic, insn.mnemonic, DAX_MAX_MNEMONIC - 1);
                strncpy(arr[total].operands, insn.ops,      DAX_MAX_OPERANDS - 1);
                memcpy(arr[total].bytes, code + off, l < DAX_MAX_INSN_LEN ? (size_t)l : DAX_MAX_INSN_LEN);
                arr[total].length = (uint8_t)l;
                arr[total].grp    = (uint8_t)dax_classify_x86(insn.mnemonic);
                total++;
                off += (size_t)l;
            }
        } else {
            while (off + 4 <= sz) {
                uint32_t   raw = (uint32_t)(code[off]) | ((uint32_t)code[off+1]<<8) |
                                 ((uint32_t)code[off+2]<<16) | ((uint32_t)code[off+3]<<24);
                a64_insn_t insn;
                a64_decode(raw, base + off, &insn);
                if (total >= cap) {
                    cap *= 2;
                    arr  = (daxc_insn_t *)realloc(arr, (size_t)cap * sizeof(daxc_insn_t));
                    if (!arr) { *out = NULL; return 0; }
                }
                arr[total].address = base + off;
                strncpy(arr[total].mnemonic, insn.mnemonic, DAX_MAX_MNEMONIC - 1);
                strncpy(arr[total].operands, insn.operands, DAX_MAX_OPERANDS - 1);
                memcpy(arr[total].bytes, code + off, 4);
                arr[total].length = 4;
                arr[total].grp    = (uint8_t)dax_classify_arm64(insn.mnemonic);
                total++;
                off += 4;
            }
        }
    }

    *out = arr;
    return total;
}

static void escape_str(const char *src, char *dst, size_t dsz) {
    size_t wi = 0;
    while (*src && wi + 2 < dsz)
        dst[wi++] = (*src == '"' || *src == '\\') ? '_' : *src++;
    dst[wi] = '\0';
}

int dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path) {
    FILE        *fp;
    uint64_t     i, j;
    daxc_insn_t *insns = NULL;
    uint64_t     ninsns;
    const char  *arch_str;
    const char  *ver;

    (void)opts;

    fp = fopen(path, "w");
    if (!fp) { perror("neodax: cannot create .daxc"); return -1; }

    ninsns   = collect_insns(bin, &insns);
    arch_str = bin->arch == ARCH_X86_64 ? "x86_64" :
               bin->arch == ARCH_ARM64  ? "aarch64" : "riscv64";
    ver      = dax_config_version();
    if (!ver || !ver[0]) ver = DAX_VERSION;

    fprintf(fp, "#include <stdio.h>\n");
    fprintf(fp, "#include <stdint.h>\n");
    fprintf(fp, "#include <string.h>\n");
    fprintf(fp, "#include <stdlib.h>\n\n");

    fprintf(fp, "#define DAXC_MAGIC     \"NEOX\"\n");
    fprintf(fp, "#define DAXC_VERSION   %d\n",     DAX_DAXC_VERSION);
    fprintf(fp, "#define DAXC_ARCH      %d\n",     (int)bin->arch);
    fprintf(fp, "#define DAXC_FMT       %d\n",     (int)bin->fmt);
    fprintf(fp, "#define DAXC_OS        %d\n",     (int)bin->os);
    fprintf(fp, "#define DAXC_ENTRY     0x%016llxULL\n", (unsigned long long)bin->entry);
    fprintf(fp, "#define DAXC_BASE      0x%016llxULL\n", (unsigned long long)bin->base);
    fprintf(fp, "#define DAXC_PIE       %d\n",     bin->is_pie);
    fprintf(fp, "#define DAXC_STRIPPED  %d\n",     bin->is_stripped);
    fprintf(fp, "#define DAXC_NSYMS     %d\n",     bin->nsymbols);
    fprintf(fp, "#define DAXC_NFUNCS    %d\n",     bin->nfunctions);
    fprintf(fp, "#define DAXC_NINSNS    %llu\n\n", (unsigned long long)ninsns);

    fprintf(fp, "static const char daxc_neodax_version[] = \"%s\";\n", ver);
    fprintf(fp, "static const char daxc_arch[]     = \"%s\";\n", arch_str);
    fprintf(fp, "static const char daxc_filepath[] = \"%s\";\n", bin->filepath);
    fprintf(fp, "static const char daxc_sha256[]   = \"%s\";\n\n", bin->sha256);

    fprintf(fp, "typedef struct { uint64_t address; char mnem[32]; char ops[128]; uint8_t bytes[16]; uint8_t len; uint8_t grp; } daxc_insn_t;\n");
    fprintf(fp, "typedef struct { char name[512]; uint64_t start; uint64_t end; } daxc_func_t;\n");
    fprintf(fp, "typedef struct { uint64_t addr; char text[256]; } daxc_comment_t;\n\n");

    fprintf(fp, "static const daxc_func_t daxc_functions[%d] = {\n", bin->nfunctions > 0 ? bin->nfunctions : 1);
    for (i = 0; i < (uint64_t)bin->nfunctions; i++) {
        char safe[512];
        escape_str(bin->functions[i].name, safe, sizeof(safe));
        fprintf(fp, "    { \"%s\", 0x%016llxULL, 0x%016llxULL }%s\n",
                safe,
                (unsigned long long)bin->functions[i].start,
                (unsigned long long)bin->functions[i].end,
                i + 1 < (uint64_t)bin->nfunctions ? "," : "");
    }
    if (bin->nfunctions == 0) fprintf(fp, "    { \"\", 0ULL, 0ULL }\n");
    fprintf(fp, "};\n\n");

    if (bin->ncomments > 0 && bin->comments) {
        fprintf(fp, "static const daxc_comment_t daxc_comments[%d] = {\n", bin->ncomments);
        for (i = 0; i < (uint64_t)bin->ncomments; i++) {
            char st[256];
            escape_str(bin->comments[i].text, st, sizeof(st));
            fprintf(fp, "    { 0x%016llxULL, \"%s\" }%s\n",
                    (unsigned long long)bin->comments[i].address, st,
                    i + 1 < (uint64_t)bin->ncomments ? "," : "");
        }
        fprintf(fp, "};\nstatic const int daxc_ncomments = %d;\n\n", bin->ncomments);
    } else {
        fprintf(fp, "static const daxc_comment_t daxc_comments[1] = { { 0ULL, \"\" } };\n");
        fprintf(fp, "static const int daxc_ncomments = 0;\n\n");
    }

    fprintf(fp, "static const daxc_insn_t daxc_insns[DAXC_NINSNS > 0 ? DAXC_NINSNS : 1] = {\n");
    for (i = 0; i < ninsns; i++) {
        daxc_insn_t *ins = &insns[i];
        char sm[64], so[256];
        escape_str(ins->mnemonic, sm, sizeof(sm));
        escape_str(ins->operands, so, sizeof(so));
        fprintf(fp, "    { 0x%016llxULL, \"%s\", \"%s\", {",
                (unsigned long long)ins->address, sm, so);
        for (j = 0; j < ins->length && j < 16; j++)
            fprintf(fp, "%d%s", ins->bytes[j], j + 1 < ins->length ? "," : "");
        fprintf(fp, "}, %d, %d }%s\n", ins->length, ins->grp, i + 1 < ninsns ? "," : "");
    }
    if (ninsns == 0) fprintf(fp, "    { 0ULL, \"\", \"\", {0}, 0, 0 }\n");
    fprintf(fp, "};\n\n");

    fprintf(fp, "static void daxc_print_insn(const daxc_insn_t *ins, int color) {\n");
    fprintf(fp, "    const char *R  = color ? \"\\033[0m\"    : \"\";\n");
    fprintf(fp, "    const char *CB = color ? \"\\033[1;34m\" : \"\";\n");
    fprintf(fp, "    const char *CM = color ? \"\\033[1;37m\" : \"\";\n");
    fprintf(fp, "    const char *CO = color ? \"\\033[0;36m\" : \"\";\n");
    fprintf(fp, "    printf(\"  %%s0x%%016llx%%s  %%s%%-10s%%s %%s%%s%%s\\n\",\n");
    fprintf(fp, "           CB,(unsigned long long)ins->address,R,CM,ins->mnem,R,CO,ins->ops,R);\n");
    fprintf(fp, "}\n\n");

    fprintf(fp, "static void daxc_header(int color) {\n");
    fprintf(fp, "    int k;\n");
    fprintf(fp, "    const char *R  = color ? \"\\033[0m\"    : \"\";\n");
    fprintf(fp, "    const char *CY = color ? \"\\033[1;33m\" : \"\";\n");
    fprintf(fp, "    const char *CG = color ? \"\\033[0;90m\" : \"\";\n");
    fprintf(fp, "    const char *CW = color ? \"\\033[1;37m\" : \"\";\n");
    fprintf(fp, "    const char *CB = color ? \"\\033[1;34m\" : \"\";\n");
    fprintf(fp, "    const char *GN = color ? \"\\033[1;32m\" : \"\";\n");
    fprintf(fp, "    printf(\"\\n\");\n");
    fprintf(fp, "    if (color) printf(\"%%s\", GN);\n");
    fprintf(fp, "    for(k=0;k<72;k++) printf(\"-\");\n");
    fprintf(fp, "    if (color) printf(\"%%s\", R);\n");
    fprintf(fp, "    printf(\"\\n\");\n");
    fprintf(fp, "    printf(\"  %%sNEODAX SNAPSHOT%%s  magic=%%s%s%%s  version=%%s%d%%s\\n\", CW,R,CG,R,CG,R);\n",
            "NEOX", DAX_DAXC_VERSION);
    fprintf(fp, "    printf(\"  neodax %%s%%s%%s  arch=%%s%%s%%s\\n\", CG,daxc_neodax_version,R,CB,daxc_arch,R);\n");
    fprintf(fp, "    printf(\"  file    %%s%%s%%s\\n\", CG,daxc_filepath,R);\n");
    fprintf(fp, "    printf(\"  sha256  %%s%%s%%s\\n\", CG,daxc_sha256,R);\n");
    fprintf(fp, "    printf(\"  entry   %%s0x%%016llx%%s  base %%s0x%%016llx%%s\\n\",\n");
    fprintf(fp, "           CB,(unsigned long long)DAXC_ENTRY,R,CB,(unsigned long long)DAXC_BASE,R);\n");
    fprintf(fp, "    printf(\"  pie=%%d  stripped=%%d  syms=%%d  funcs=%%d  insns=%%llu\\n\",\n");
    fprintf(fp, "           DAXC_PIE,DAXC_STRIPPED,DAXC_NSYMS,DAXC_NFUNCS,(unsigned long long)DAXC_NINSNS);\n");
    fprintf(fp, "    if (color) printf(\"%%s\", GN);\n");
    fprintf(fp, "    for(k=0;k<72;k++) printf(\"-\");\n");
    fprintf(fp, "    if (color) printf(\"%%s\", R);\n");
    fprintf(fp, "    printf(\"\\n\\n\");\n");
    fprintf(fp, "    printf(\"%%sFunctions (%d):%%s\\n\", CY, R);\n", bin->nfunctions);
    fprintf(fp, "    for (k=0;k<%d;k++)\n", bin->nfunctions);
    fprintf(fp, "        printf(\"  %%s%%4d%%s  %%s0x%%016llx%%s  %%s%%s%%s\\n\",\n");
    fprintf(fp, "               CG,k,R,CB,(unsigned long long)daxc_functions[k].start,R,CW,daxc_functions[k].name,R);\n");
    fprintf(fp, "    printf(\"\\n\");\n");
    fprintf(fp, "}\n\n");

    fprintf(fp, "int main(int argc, char **argv) {\n");
    fprintf(fp, "    uint64_t i;\n");
    fprintf(fp, "    int color = 1, funcs_only = 0, j;\n");
    fprintf(fp, "    for (j=1;j<argc;j++) {\n");
    fprintf(fp, "        if (!strcmp(argv[j],\"-n\")) color=0;\n");
    fprintf(fp, "        if (!strcmp(argv[j],\"-f\")) funcs_only=1;\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    const char *R  = color ? \"\\033[0m\"    : \"\";\n");
    fprintf(fp, "    const char *CB = color ? \"\\033[1;34m\" : \"\";\n");
    fprintf(fp, "    const char *CY = color ? \"\\033[1;33m\" : \"\";\n");
    fprintf(fp, "    const char *CG = color ? \"\\033[0;90m\" : \"\";\n");
    fprintf(fp, "    const char *CZ = color ? \"\\033[1;35m\" : \"\";\n");
    fprintf(fp, "    (void)R; (void)CB; (void)CY; (void)CG; (void)CZ;\n");
    fprintf(fp, "    daxc_header(color);\n");
    fprintf(fp, "    if (funcs_only) return 0;\n");
    fprintf(fp, "    if (daxc_ncomments > 0) {\n");
    fprintf(fp, "        printf(\"%%sComments:%%s\\n\", CZ, R);\n");
    fprintf(fp, "        for (i=0;i<(uint64_t)daxc_ncomments;i++)\n");
    fprintf(fp, "            printf(\"  %%s0x%%016llx%%s  %%s%%s%%s\\n\",\n");
    fprintf(fp, "                   CB,(unsigned long long)daxc_comments[i].addr,R,CG,daxc_comments[i].text,R);\n");
    fprintf(fp, "        printf(\"\\n\");\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    printf(\"%%sDisassembly (%llu insns):%%s\\n\", CY, R);\n",
            (unsigned long long)ninsns);
    fprintf(fp, "    for (i=0;i<DAXC_NINSNS;i++) {\n");
    fprintf(fp, "        int k;\n");
    fprintf(fp, "        for (k=0;k<%d;k++) {\n", bin->nfunctions);
    fprintf(fp, "            if (daxc_functions[k].start == daxc_insns[i].address) {\n");
    fprintf(fp, "                printf(\"\\n%%s[%%s]%%s\\n\",CY,daxc_functions[k].name,R);\n");
    fprintf(fp, "                break;\n");
    fprintf(fp, "            }\n");
    fprintf(fp, "        }\n");
    fprintf(fp, "        daxc_print_insn(&daxc_insns[i], color);\n");
    fprintf(fp, "    }\n");
    fprintf(fp, "    printf(\"\\n\");\n");
    fprintf(fp, "    return 0;\n");
    fprintf(fp, "}\n");

    fclose(fp);
    free(insns);

    fprintf(stdout, "  [DAXC] Written : %s\n",   path);
    fprintf(stdout, "  [DAXC] Insns   : %llu\n", (unsigned long long)ninsns);
    fprintf(stdout, "  [DAXC] Funcs   : %d\n",   bin->nfunctions);
    fprintf(stdout, "  [DAXC] Format  : NEOX v%d (AOT C source)\n", DAX_DAXC_VERSION);
    fprintf(stdout, "  [DAXC] Compile : clang -O2 -o snapshot %s\n", path);
    fprintf(stdout, "  [DAXC] Run     : ./snapshot  [-n no-color]  [-f funcs-only]\n");
    fprintf(stdout, "  [DAXC] Load    : neodax %s\n", path);
    return 0;
}

int dax_daxc_read(const char *path, dax_binary_t *bin) {
    FILE *fp = fopen(path, "r");
    char  line[2048];

    if (!fp) { perror("neodax: cannot open .daxc"); return -1; }
    memset(bin, 0, sizeof(*bin));

    while (fgets(line, sizeof(line), fp)) {
        char *l = line;
        while (*l == ' ' || *l == '\t') l++;

        if (!strncmp(l, "#define DAXC_ARCH",     17)) sscanf(l+17, " %d",      (int*)&bin->arch);
        if (!strncmp(l, "#define DAXC_FMT",      16)) sscanf(l+16, " %d",      (int*)&bin->fmt);
        if (!strncmp(l, "#define DAXC_OS",       15)) sscanf(l+15, " %d",      (int*)&bin->os);
        if (!strncmp(l, "#define DAXC_ENTRY",    18)) sscanf(l+18, " 0x%llx",  (unsigned long long*)&bin->entry);
        if (!strncmp(l, "#define DAXC_BASE",     17)) sscanf(l+17, " 0x%llx",  (unsigned long long*)&bin->base);
        if (!strncmp(l, "#define DAXC_PIE",      16)) sscanf(l+16, " %d",      &bin->is_pie);
        if (!strncmp(l, "#define DAXC_STRIPPED", 21)) sscanf(l+21, " %d",      &bin->is_stripped);
        if (!strncmp(l, "#define DAXC_NSYMS",    18)) sscanf(l+18, " %d",      &bin->nsymbols);
        if (!strncmp(l, "#define DAXC_NFUNCS",   19)) sscanf(l+19, " %d",      &bin->nfunctions);

        if (!strncmp(l, "static const char daxc_filepath[]", 33)) {
            char *q1 = strchr(l, '"'), *q2 = q1 ? strchr(q1+1, '"') : NULL;
            if (q1 && q2) { *q2 = '\0'; strncpy(bin->filepath, q1+1, 511); }
        }
        if (!strncmp(l, "static const char daxc_sha256[]", 31)) {
            char *q1 = strchr(l, '"'), *q2 = q1 ? strchr(q1+1, '"') : NULL;
            if (q1 && q2) { *q2 = '\0'; strncpy(bin->sha256, q1+1, 64); }
        }

        if (!strncmp(l, "static const daxc_func_t daxc_functions[", 40)) {
            int nf = bin->nfunctions, fi = 0;
            if (nf > 0) {
                bin->functions = (dax_func_t *)calloc((size_t)nf, sizeof(dax_func_t));
                if (!bin->functions) { fclose(fp); return -1; }
                while (fi < nf && fgets(line, sizeof(line), fp)) {
                    char name[512] = "";
                    unsigned long long fs = 0, fe = 0;
                    if (sscanf(line, " { \"%511[^\"]\", 0x%llxULL, 0x%llxULL", name, &fs, &fe) >= 2) {
                        strncpy(bin->functions[fi].name, name, 511);
                        bin->functions[fi].start = (uint64_t)fs;
                        bin->functions[fi].end   = (uint64_t)fe;
                        fi++;
                    }
                }
                bin->nfunctions = fi;
            }
        }

        if (!strncmp(l, "static const daxc_comment_t daxc_comments[", 43)) {
            int nc = 0, ci = 0;
            sscanf(l, "static const daxc_comment_t daxc_comments[%d]", &nc);
            if (nc > 0) {
                bin->comments = (dax_comment_t *)calloc((size_t)nc, sizeof(dax_comment_t));
                if (!bin->comments) { fclose(fp); return -1; }
                while (ci < nc && fgets(line, sizeof(line), fp)) {
                    unsigned long long addr = 0;
                    char text[256] = "";
                    if (sscanf(line, " { 0x%llxULL, \"%255[^\"]\"", &addr, text) >= 1) {
                        bin->comments[ci].address = (uint64_t)addr;
                        strncpy(bin->comments[ci].text, text, DAX_COMMENT_LEN - 1);
                        ci++;
                    }
                }
                bin->ncomments = ci;
            }
        }
    }

    fclose(fp);
    bin->nblocks = 0;
    return 0;
}

int dax_daxc_to_asm(const char *daxc_path, const char *asm_path, int color) {
    dax_binary_t  bin;
    FILE         *out;
    FILE         *src;
    char          line[2048];
    uint64_t      ni = 0, insn_count = 0;
    daxc_insn_t  *insns = NULL;
    uint64_t      i;
    uint64_t      prev_func = (uint64_t)-1;
    int           c;

    if (dax_daxc_read(daxc_path, &bin) != 0) return -1;

    c   = color && (asm_path == NULL);
    out = asm_path ? fopen(asm_path, "w") : stdout;
    if (asm_path && !out) { perror("neodax: cannot create .S"); dax_free_binary(&bin); return -1; }

    src = fopen(daxc_path, "r");
    if (!src) { if (asm_path) fclose(out); dax_free_binary(&bin); return -1; }
    while (fgets(line, sizeof(line), src)) {
        char *l = line;
        while (*l == ' ' || *l == '\t') l++;
        if (!strncmp(l, "#define DAXC_NINSNS", 19)) {
            sscanf(l + 19, " %llu", (unsigned long long*)&insn_count);
            break;
        }
    }
    fclose(src);

    if (insn_count > 0) {
        insns = (daxc_insn_t *)calloc((size_t)insn_count, sizeof(daxc_insn_t));
        if (!insns) { if (asm_path) fclose(out); dax_free_binary(&bin); return -1; }
    }

    src = fopen(daxc_path, "r");
    if (src && insns) {
        int in_insns = 0;
        while (ni < insn_count && fgets(line, sizeof(line), src)) {
            char *l = line;
            while (*l == ' ' || *l == '\t') l++;
            if (!in_insns && !strncmp(l, "static const daxc_insn_t", 24)) { in_insns = 1; continue; }
            if (!in_insns) continue;
            if (l[0] == '}') break;
            {
                unsigned long long addr = 0;
                char mnem[64] = "", ops[256] = "";
                if (sscanf(l, " { 0x%llxULL, \"%63[^\"]\", \"%255[^\"]\"", &addr, mnem, ops) >= 2) {
                    insns[ni].address = (uint64_t)addr;
                    strncpy(insns[ni].mnemonic, mnem, DAX_MAX_MNEMONIC - 1);
                    strncpy(insns[ni].operands,  ops,  DAX_MAX_OPERANDS  - 1);
                    ni++;
                }
            }
        }
        fclose(src);
    }

    fprintf(out, "%s.file \"%s\"%s\n",
            c ? COL_COMMENT : "", bin.filepath, c ? COL_RESET : "");
    fprintf(out, "%s.arch %s%s\n",
            c ? COL_COMMENT : "", dax_arch_str(bin.arch), c ? COL_RESET : "");
    fprintf(out, "%s.neodax_ver \"%s\"%s\n\n",
            c ? COL_COMMENT : "", DAX_VERSION, c ? COL_RESET : "");

    for (i = 0; i < ni; i++) {
        daxc_insn_t  *ins = &insns[i];
        dax_symbol_t *sym = dax_sym_find(&bin, ins->address);
        const char   *cmt = dax_comment_get(&bin, ins->address);
        dax_func_t   *fn  = dax_func_find(&bin, ins->address);

        if (fn && fn->start == ins->address && fn->start != prev_func) {
            prev_func = fn->start;
            fprintf(out, "\n%s.global %s%s\n",
                    c ? COL_SECTION : "", fn->name, c ? COL_RESET : "");
            fprintf(out, "%s.type %s, @function%s\n",
                    c ? COL_COMMENT : "", fn->name, c ? COL_RESET : "");
        }
        if (sym) {
            const char *lbl = sym->demangled[0] ? sym->demangled : sym->name;
            fprintf(out, "%s%s:%s\n", c ? COL_LABEL : "", lbl, c ? COL_RESET : "");
        }
        if (cmt)
            fprintf(out, "%s    /* %s */%s\n", c ? COL_STRING : "", cmt, c ? COL_RESET : "");

        {
            const char *mcol = c ? dax_igrp_color((dax_igrp_t)ins->grp, 1) : "";
            const char *rst  = c ? COL_RESET : "";
            fprintf(out, "    %s%-10s%s %-30s /* 0x%016llx */\n",
                    mcol, ins->mnemonic, rst, ins->operands,
                    (unsigned long long)ins->address);
        }
    }

    free(insns);
    dax_free_binary(&bin);

    if (asm_path) {
        fclose(out);
        fprintf(stdout, "  [DAX] Written: %s  (%llu insns)\n",
                asm_path, (unsigned long long)ni);
    }
    return 0;
}
