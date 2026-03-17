#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "x86.h"
#include "arm64.h"

#ifdef __GNUC__
#  define FREAD_IGNORE(ptr, sz, n, fp)     do { size_t _r = fread((ptr),(sz),(n),(fp)); (void)_r; } while(0)
#else
#  define FREAD_IGNORE(ptr, sz, n, fp)     do { (void)fread((ptr),(sz),(n),(fp)); } while(0)
#endif



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

    for (si = 0; si < bin->nsections; si++) {
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
                strncpy(arr[total].operands, insn.ops, DAX_MAX_OPERANDS - 1);
                memcpy(arr[total].bytes, insn.mnemonic, 0);
                memcpy(arr[total].bytes, code + off, l < DAX_MAX_INSN_LEN ? (size_t)l : DAX_MAX_INSN_LEN);
                arr[total].length = (uint8_t)l;
                arr[total].grp    = (uint8_t)dax_classify_x86(insn.mnemonic);
                total++;
                off += (size_t)l;
            }
        } else {
            while (off + 4 <= sz) {
                uint32_t   raw = (uint32_t)(code[off]) | (code[off+1]<<8) |
                                 (code[off+2]<<16)     | (code[off+3]<<24);
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

int dax_daxc_write(dax_binary_t *bin, dax_opts_t *opts, const char *path) {
    FILE         *fp;
    daxc_header_t hdr;
    daxc_insn_t  *insns = NULL;
    uint64_t      ninsns;
    uint64_t      pos;

    fp = fopen(path, "wb");
    if (!fp) { perror("neodax: cannot create .daxc"); return -1; }

    memset(&hdr, 0, sizeof(hdr));
    hdr.magic       = DAX_DAXC_MAGIC;
    hdr.version     = DAX_DAXC_VERSION;
    hdr.arch        = (uint32_t)bin->arch;
    hdr.fmt         = (uint32_t)bin->fmt;
    hdr.os          = (uint32_t)bin->os;
    hdr.entry       = bin->entry;
    hdr.base        = bin->base;
    hdr.image_size  = bin->image_size;
    hdr.code_size   = bin->code_size;
    hdr.data_size   = bin->data_size;
    hdr.total_insns = bin->total_insns;
    hdr.is_pie      = (uint8_t)bin->is_pie;
    hdr.is_stripped = (uint8_t)bin->is_stripped;
    hdr.has_debug   = (uint8_t)bin->has_debug;
    hdr.nustrings   = (uint32_t)bin->nustrings;
    strncpy(hdr.filepath, bin->filepath, 511);
    strncpy(hdr.sha256,   bin->sha256,   64);
    strncpy(hdr.build_id, bin->build_id, 63);
    hdr.nsections  = (uint32_t)bin->nsections;
    hdr.nsymbols   = (uint32_t)bin->nsymbols;
    hdr.nxrefs     = (uint32_t)bin->nxrefs;
    hdr.nfunctions = (uint32_t)bin->nfunctions;
    hdr.nblocks    = (uint32_t)bin->nblocks;
    hdr.ncomments  = (uint32_t)bin->ncomments;

    fwrite(&hdr, sizeof(hdr), 1, fp);
    pos = sizeof(hdr);

    hdr.off_sections = pos;
    fwrite(bin->sections, sizeof(dax_section_t), (size_t)bin->nsections, fp);
    pos += sizeof(dax_section_t) * (uint64_t)bin->nsections;

    hdr.off_symbols = pos;
    if (bin->nsymbols > 0)
        fwrite(bin->symbols, sizeof(dax_symbol_t), (size_t)bin->nsymbols, fp);
    pos += sizeof(dax_symbol_t) * (uint64_t)bin->nsymbols;

    hdr.off_xrefs = pos;
    if (bin->nxrefs > 0)
        fwrite(bin->xrefs, sizeof(dax_xref_t), (size_t)bin->nxrefs, fp);
    pos += sizeof(dax_xref_t) * (uint64_t)bin->nxrefs;

    hdr.off_functions = pos;
    if (bin->nfunctions > 0)
        fwrite(bin->functions, sizeof(dax_func_t), (size_t)bin->nfunctions, fp);
    pos += sizeof(dax_func_t) * (uint64_t)bin->nfunctions;

    hdr.off_blocks = pos;
    if (bin->nblocks > 0)
        fwrite(bin->blocks, sizeof(dax_block_t), (size_t)bin->nblocks, fp);
    pos += sizeof(dax_block_t) * (uint64_t)bin->nblocks;

    hdr.off_comments = pos;
    if (bin->ncomments > 0 && bin->comments)
        fwrite(bin->comments, sizeof(dax_comment_t), (size_t)bin->ncomments, fp);
    pos += sizeof(dax_comment_t) * (uint64_t)bin->ncomments;

    ninsns = collect_insns(bin, &insns);
    hdr.off_insns = pos;
    hdr.ninsns    = ninsns;
    if (insns && ninsns > 0)
        fwrite(insns, sizeof(daxc_insn_t), (size_t)ninsns, fp);
    pos += sizeof(daxc_insn_t) * ninsns;
    free(insns);

    hdr.off_ustrings = pos;
    if (bin->nustrings > 0 && bin->ustrings)
        fwrite(bin->ustrings, sizeof(dax_ustring_t), (size_t)bin->nustrings, fp);

    fseek(fp, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, fp);
    fclose(fp);

    if (opts && opts->verbose)
        fprintf(stdout, "  [NEODAX] Written: %s  (insns=%llu syms=%d funcs=%d ustrings=%d)\n",
                path, (unsigned long long)ninsns, bin->nsymbols, bin->nfunctions, bin->nustrings);
    return 0;
}

int dax_daxc_read(const char *path, dax_binary_t *bin) {
    FILE         *fp;
    daxc_header_t hdr;

    fp = fopen(path, "rb");
    if (!fp) { perror("neodax: cannot open .daxc"); return -1; }

    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) { fclose(fp); return -1; }
    if (hdr.magic != DAX_DAXC_MAGIC) {
        fprintf(stderr, "neodax: not a .daxc file\n");
        fclose(fp);
        return -1;
    }

    memset(bin, 0, sizeof(*bin));
    bin->arch       = (dax_arch_t)hdr.arch;
    bin->fmt        = (dax_fmt_t)hdr.fmt;
    bin->os         = (dax_os_t)hdr.os;
    bin->entry      = hdr.entry;
    bin->base       = hdr.base;
    bin->image_size = hdr.image_size;
    bin->code_size  = hdr.code_size;
    bin->data_size  = hdr.data_size;
    bin->total_insns= hdr.total_insns;
    bin->is_pie     = hdr.is_pie;
    bin->is_stripped= hdr.is_stripped;
    bin->has_debug  = hdr.has_debug;
    strncpy(bin->filepath, hdr.filepath, 511);
    strncpy(bin->sha256,   hdr.sha256,   64);
    strncpy(bin->build_id, hdr.build_id, 63);

    bin->nsections = (int)hdr.nsections;
    if (hdr.nsections > 0) {
        fseek(fp, (long)hdr.off_sections, SEEK_SET);
        FREAD_IGNORE(bin->sections, sizeof(dax_section_t), hdr.nsections, fp);
    }

    if (hdr.nsymbols > 0) {
        bin->symbols  = (dax_symbol_t *)calloc(hdr.nsymbols, sizeof(dax_symbol_t));
        bin->nsymbols = (int)hdr.nsymbols;
        fseek(fp, (long)hdr.off_symbols, SEEK_SET);
        FREAD_IGNORE(bin->symbols, sizeof(dax_symbol_t), hdr.nsymbols, fp);
    }

    if (hdr.nxrefs > 0) {
        bin->xrefs  = (dax_xref_t *)calloc(hdr.nxrefs, sizeof(dax_xref_t));
        bin->nxrefs = (int)hdr.nxrefs;
        fseek(fp, (long)hdr.off_xrefs, SEEK_SET);
        FREAD_IGNORE(bin->xrefs, sizeof(dax_xref_t), hdr.nxrefs, fp);
    }

    if (hdr.nfunctions > 0) {
        bin->functions  = (dax_func_t *)calloc(hdr.nfunctions, sizeof(dax_func_t));
        bin->nfunctions = (int)hdr.nfunctions;
        fseek(fp, (long)hdr.off_functions, SEEK_SET);
        FREAD_IGNORE(bin->functions, sizeof(dax_func_t), hdr.nfunctions, fp);
    }

    if (hdr.nblocks > 0) {
        bin->blocks  = (dax_block_t *)calloc(hdr.nblocks, sizeof(dax_block_t));
        bin->nblocks = (int)hdr.nblocks;
        fseek(fp, (long)hdr.off_blocks, SEEK_SET);
        FREAD_IGNORE(bin->blocks, sizeof(dax_block_t), hdr.nblocks, fp);
    }

    if (hdr.ncomments > 0) {
        bin->comments  = (dax_comment_t *)calloc(hdr.ncomments, sizeof(dax_comment_t));
        bin->ncomments = (int)hdr.ncomments;
        fseek(fp, (long)hdr.off_comments, SEEK_SET);
        FREAD_IGNORE(bin->comments, sizeof(dax_comment_t), hdr.ncomments, fp);
    }

    if (hdr.nustrings > 0 && hdr.off_ustrings > 0) {
        bin->ustrings  = (dax_ustring_t *)calloc(hdr.nustrings, sizeof(dax_ustring_t));
        bin->nustrings = (int)hdr.nustrings;
        fseek(fp, (long)hdr.off_ustrings, SEEK_SET);
        FREAD_IGNORE(bin->ustrings, sizeof(dax_ustring_t), hdr.nustrings, fp);
    }

    fclose(fp);
    return 0;
}

int dax_daxc_to_asm(const char *daxc_path, const char *asm_path, int color) {
    FILE          *fp;
    FILE          *out;
    daxc_header_t  hdr;
    daxc_insn_t   *insns = NULL;
    dax_binary_t   bin;
    uint64_t       i;
    uint64_t       prev_func = (uint64_t)-1;
    int            c = color && (asm_path == NULL);

    fp = fopen(daxc_path, "rb");
    if (!fp) { perror("neodax: cannot open .daxc"); return -1; }
    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) { fclose(fp); return -1; }
    if (hdr.magic != DAX_DAXC_MAGIC) { fclose(fp); return -1; }

    memset(&bin, 0, sizeof(bin));
    dax_daxc_read(daxc_path, &bin);

    if (asm_path) {
        out = fopen(asm_path, "w");
        if (!out) { perror("neodax: cannot create .S"); fclose(fp); return -1; }
        c = 0;
    } else {
        out = stdout;
    }

    if (hdr.ninsns == 0) {
        fclose(fp);
        if (asm_path) fclose(out);
        return 0;
    }

    insns = (daxc_insn_t *)calloc((size_t)hdr.ninsns, sizeof(daxc_insn_t));
    if (!insns) { fclose(fp); if (asm_path) fclose(out); return -1; }
    fseek(fp, (long)hdr.off_insns, SEEK_SET);
    FREAD_IGNORE(insns, sizeof(daxc_insn_t), (size_t)hdr.ninsns, fp);
    fclose(fp);

    fprintf(out, "%s.file \"%s\"%s\n",
            c ? COL_COMMENT : "", hdr.filepath, c ? COL_RESET : "");
    fprintf(out, "%s.arch %s%s\n",
            c ? COL_COMMENT : "",
            hdr.arch == ARCH_X86_64 ? "x86_64" : "aarch64",
            c ? COL_RESET : "");
    fprintf(out, "\n");

    for (i = 0; i < hdr.ninsns; i++) {
        daxc_insn_t  *ins  = &insns[i];
        dax_symbol_t *sym  = dax_sym_find(&bin, ins->address);
        const char   *cmt  = dax_comment_get(&bin, ins->address);
        dax_func_t   *fn   = dax_func_find(&bin, ins->address);

        if (fn && fn->start == ins->address &&
            fn->start != prev_func) {
            prev_func = fn->start;
            fprintf(out, "\n");
            fprintf(out, "%s.global %s%s\n",
                    c ? COL_SECTION : "", fn->name, c ? COL_RESET : "");
            fprintf(out, "%s.type %s, @function%s\n",
                    c ? COL_COMMENT : "", fn->name, c ? COL_RESET : "");
        }

        if (sym) {
            const char *label = sym->demangled[0] ? sym->demangled : sym->name;
            fprintf(out, "%s%s:%s\n",
                    c ? COL_LABEL : "", label, c ? COL_RESET : "");
        }

        if (cmt) {
            fprintf(out, "%s    /* %s */%s\n",
                    c ? COL_STRING : "", cmt, c ? COL_RESET : "");
        }

        {
            const char *mcol = c ? dax_igrp_color((dax_igrp_t)ins->grp, 1) : "";
            const char *ocol = c ? COL_OPS : "";
            const char *rst  = c ? COL_RESET : "";
            const char *acol = c ? COL_ADDR : "";

            fprintf(out, "    %s%-10s%s %-30s%s /* 0x%016llx */\n",
                    mcol, ins->mnemonic, rst,
                    ins->operands, rst,
                    (unsigned long long)ins->address);
            (void)acol;
        }
    }

    free(insns);
    dax_free_binary(&bin);
    if (asm_path) {
        fclose(out);
        fprintf(stdout, "  [DAX] Written: %s  (%llu instructions)\n",
                asm_path, (unsigned long long)hdr.ninsns);
    }
    return 0;
}
