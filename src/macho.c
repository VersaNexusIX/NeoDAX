#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "dax.h"
#include "macho.h"

/* ── byte-swap helpers ─────────────────────────────────────────── */
static uint32_t bswap32(uint32_t v){
    return ((v&0xFF)<<24)|((v&0xFF00)<<8)|((v&0xFF0000)>>8)|(v>>24);
}
static uint64_t bswap64(uint64_t v){
    return ((uint64_t)bswap32((uint32_t)(v&0xFFFFFFFF))<<32)|
            (uint64_t)bswap32((uint32_t)(v>>32));
}

/* ── find best slice in FAT binary ──────────────────────────────── */
static int fat_find_slice(const uint8_t *data, size_t sz,
                           uint32_t want_cpu,
                           uint32_t *out_off, uint32_t *out_size)
{
    if (sz < sizeof(macho_fat_header_t)) return -1;
    const macho_fat_header_t *fh = (const macho_fat_header_t *)data;
    uint32_t narch = bswap32(fh->nfat_arch);
    if (narch > 64) return -1;

    size_t base = sizeof(macho_fat_header_t);
    for (uint32_t i = 0; i < narch; i++) {
        if (base + sizeof(macho_fat_arch_t) > sz) break;
        const macho_fat_arch_t *fa = (const macho_fat_arch_t *)(data + base);
        uint32_t cpu  = bswap32(fa->cputype);
        uint32_t off  = bswap32(fa->offset);
        uint32_t fsz  = bswap32(fa->size);
        if (cpu == want_cpu && off + fsz <= sz) {
            *out_off  = off;
            *out_size = fsz;
            return 0;
        }
        base += sizeof(macho_fat_arch_t);
    }
    /* fallback: take the first valid slice */
    base = sizeof(macho_fat_header_t);
    for (uint32_t i = 0; i < narch; i++) {
        if (base + sizeof(macho_fat_arch_t) > sz) break;
        const macho_fat_arch_t *fa = (const macho_fat_arch_t *)(data + base);
        uint32_t off = bswap32(fa->offset);
        uint32_t fsz = bswap32(fa->size);
        if (off + fsz <= sz) { *out_off = off; *out_size = fsz; return 0; }
        base += sizeof(macho_fat_arch_t);
    }
    return -1;
}

/* ── main parser ─────────────────────────────────────────────────── */
int dax_parse_macho(dax_binary_t *bin)
{
    const uint8_t *data = bin->data;
    size_t         sz   = bin->size;
    int            swap = 0;   /* big-endian swap needed? */

    /* --- Handle FAT / universal binary --- */
    uint32_t fat_magic = *(const uint32_t *)data;
    if (fat_magic == MACHO_FAT_MAGIC || fat_magic == MACHO_FAT_MAGIC_LE) {
        /* FAT header is always big-endian */
        uint32_t off = 0, slice_sz = 0;
        /* prefer native CPU — try ARM64 then x86-64 */
        if (fat_find_slice(data, sz, MACHO_CPU_ARM64,  &off, &slice_sz) != 0)
            fat_find_slice(data, sz, MACHO_CPU_X86_64, &off, &slice_sz);
        if (off == 0 || off + slice_sz > sz) {
            fprintf(stderr, "neodax: FAT binary: no usable slice found\n");
            return -1;
        }
        /* Parse the selected slice in-place (data offset from start) */
        data = bin->data + off;
        sz   = slice_sz;
    }

    if (sz < sizeof(macho_header64_t)) {
        fprintf(stderr, "neodax: Mach-O too small\n");
        return -1;
    }

    uint32_t magic = *(const uint32_t *)data;
    int is64 = 0;

    if      (magic == MACHO_MAGIC_64_LE) { is64 = 1; swap = 0; }
    else if (magic == MACHO_MAGIC_64)    { is64 = 1; swap = 1; }
    else if (magic == MACHO_MAGIC_32_LE) { is64 = 0; swap = 0; }
    else if (magic == MACHO_MAGIC_32)    { is64 = 0; swap = 1; }
    else {
        fprintf(stderr, "neodax: unrecognised Mach-O magic 0x%08X\n", magic);
        return -1;
    }

#define LE32(v) (swap ? bswap32(v) : (v))
#define LE64(v) (swap ? bswap64(v) : (v))

    /* --- Header --- */
    const macho_header64_t *hdr = (const macho_header64_t *)data;
    uint32_t cputype  = LE32(hdr->cputype);
    uint32_t filetype = LE32(hdr->filetype);
    uint32_t ncmds    = LE32(hdr->ncmds);
    uint32_t hdr_size = is64 ? sizeof(macho_header64_t) : sizeof(macho_header32_t);

    /* Arch */
    switch (cputype) {
        case MACHO_CPU_ARM64:
        case MACHO_CPU_ARM64_32: bin->arch = ARCH_ARM64;  break;
        case MACHO_CPU_X86_64:   bin->arch = ARCH_X86_64; break;
        default:                 bin->arch = ARCH_UNKNOWN; break;
    }

    bin->fmt  = is64 ? FMT_ELF64 : FMT_ELF32; /* reuse ELF enum — Mach-O 64/32 */
    bin->os   = DAX_PLAT_BSD;                  /* macOS is a BSD derivative */

    /* PIE = MH_EXECUTE with ASLR flag, or MH_DYLIB */
    bin->is_pie = (filetype == MACHO_MH_DYLIB) ? 1 : 0;

    /* --- Walk load commands --- */
    size_t   cmd_off     = hdr_size;
    uint64_t text_vmbase = 0;
    uint64_t entry_off   = 0;
    int      got_entry   = 0;
    uint64_t total_code  = 0;
    uint64_t total_data  = 0;
    uint64_t image_end   = 0;

    for (uint32_t ci = 0; ci < ncmds; ci++) {
        if (cmd_off + sizeof(macho_load_cmd_t) > sz) break;
        const macho_load_cmd_t *lc = (const macho_load_cmd_t *)(data + cmd_off);
        uint32_t cmd     = LE32(lc->cmd);
        uint32_t cmdsize = LE32(lc->cmdsize);
        if (cmdsize < 8 || cmd_off + cmdsize > sz) break;

        /* LC_SEGMENT_64 */
        if (cmd == MACHO_LC_SEGMENT_64 && is64) {
            const macho_segment64_t *seg = (const macho_segment64_t *)(data + cmd_off);
            uint64_t vm  = LE64(seg->vmaddr);
            uint64_t vsz = LE64(seg->vmsize);
            uint32_t ns  = LE32(seg->nsects);
            uint32_t ip  = LE32(seg->initprot);

            if (strncmp(seg->segname, "__TEXT", 6) == 0)
                text_vmbase = vm;

            if (vm + vsz > image_end) image_end = vm + vsz;

            /* iterate sections inside this segment */
            size_t sec_off = cmd_off + sizeof(macho_segment64_t);
            for (uint32_t si = 0; si < ns && si < (uint32_t)DAX_MAX_SECTIONS; si++) {
                if (sec_off + sizeof(macho_section64_t) > sz) break;
                const macho_section64_t *sec =
                    (const macho_section64_t *)(data + sec_off);

                if (bin->nsections >= DAX_MAX_SECTIONS) break;

                dax_section_t *ds = &bin->sections[bin->nsections++];

                /* Build combined name: segname,sectname  e.g. ".text" */
                char sname[64];
                char seg_s[17] = {0};
                char sec_s[17] = {0};
                strncpy(seg_s, sec->segname,  16);
                strncpy(sec_s, sec->sectname, 16);
                snprintf(sname, sizeof(sname), "%s", sec_s);
                /* strip leading underscore pairs: __text → .text */
                if (sname[0]=='_' && sname[1]=='_') {
                    snprintf(sname, sizeof(sname), ".%s", sec_s+2);
                }
                strncpy(ds->name, sname, sizeof(ds->name)-1);

                ds->vaddr  = LE64(sec->addr);
                ds->size   = LE64(sec->size);
                ds->offset = (uint64_t)LE32(sec->offset);
                ds->flags  = LE32(sec->flags);

                /* classify */
                uint32_t stype = ds->flags & 0xFF;
                int exec = (ip & 4) != 0;  /* VM_PROT_EXECUTE */
                if (exec || stype == 0 /* S_REGULAR in __TEXT */) {
                    if (strncmp(seg->segname, "__TEXT", 6) == 0 && exec)
                        ds->type = SEC_TYPE_CODE;
                    else if (strstr(ds->name, "data") || strstr(ds->name, "bss"))
                        ds->type = SEC_TYPE_DATA;
                    else
                        ds->type = SEC_TYPE_OTHER;
                } else {
                    ds->type = SEC_TYPE_DATA;
                }
                if (strstr(ds->name, "rodata") || strstr(ds->name, "cstring") ||
                    strstr(ds->name, "const"))
                    ds->type = SEC_TYPE_RODATA;
                if (strstr(ds->name, "got") || strstr(ds->name, "la_symbol_ptr"))
                    ds->type = SEC_TYPE_GOT;
                if (strstr(ds->name, "stubs") || strstr(ds->name, "plt"))
                    ds->type = SEC_TYPE_PLT;

                /* accumulate sizes */
                if (ds->type == SEC_TYPE_CODE)  total_code += ds->size;
                else                             total_data += ds->size;

                sec_off += sizeof(macho_section64_t);
            }
        }

        /* LC_MAIN — modern macOS entry point */
        else if (cmd == MACHO_LC_MAIN) {
            const macho_entry_cmd_t *ec = (const macho_entry_cmd_t *)(data + cmd_off);
            entry_off  = LE64(ec->entryoff);
            got_entry  = 1;
        }

        /* LC_SYMTAB — symbol table */
        else if (cmd == MACHO_LC_SYMTAB && is64) {
            const macho_symtab_cmd_t *st = (const macho_symtab_cmd_t *)(data + cmd_off);
            uint32_t symoff  = LE32(st->symoff);
            uint32_t nsyms   = LE32(st->nsyms);
            uint32_t stroff  = LE32(st->stroff);
            uint32_t strsz   = LE32(st->strsize);

            /* Adjust offsets relative to slice start (data - bin->data) */
            size_t slice_base = (size_t)(data - bin->data);
            symoff += (uint32_t)slice_base;
            stroff += (uint32_t)slice_base;

            if (nsyms > 0 && nsyms < DAX_MAX_SYMBOLS &&
                symoff + nsyms * sizeof(macho_nlist64_t) <= bin->size &&
                stroff + strsz <= bin->size) {

                bin->is_stripped = 0;
                uint32_t count = 0;
                bin->symbols = (dax_symbol_t *)calloc(nsyms + 1, sizeof(dax_symbol_t));
                if (!bin->symbols) goto sym_done;

                for (uint32_t si = 0; si < nsyms && count < DAX_MAX_SYMBOLS; si++) {
                    const macho_nlist64_t *nl = (const macho_nlist64_t *)
                        (bin->data + symoff + si * sizeof(macho_nlist64_t));
                    uint32_t strx  = LE32(nl->n_strx);
                    uint8_t  ntype = nl->n_type;
                    uint64_t nval  = LE64(nl->n_value);

                    /* skip debug/stab entries (type 0xE0 mask) and undefined */
                    if ((ntype & 0xE0) != 0) continue;  /* stab */
                    if (nval == 0)           continue;   /* undefined */
                    if (strx >= strsz)       continue;

                    const char *name = (const char *)(bin->data + stroff + strx);
                    /* strip leading underscore (macOS convention) */
                    if (name[0] == '_') name++;

                    dax_symbol_t *sym = &bin->symbols[count++];
                    strncpy(sym->name, name, sizeof(sym->name)-1);
                    sym->address = nval;
                    sym->type    = ((ntype & 0x0E) == 0x0E) ? SYM_FUNC : SYM_OBJECT;
                }
                bin->nsymbols = (int)count;
            } else {
                bin->is_stripped = 1;
            }
            sym_done:;
        }

        cmd_off += cmdsize;
    }

    /* --- entry point --- */
    if (got_entry && text_vmbase > 0)
        bin->entry = text_vmbase + entry_off;
    else if (text_vmbase > 0)
        bin->entry = text_vmbase;   /* fallback: start of __TEXT */

    /* --- binary metadata --- */
    bin->image_size = (image_end > 0) ? image_end : (uint64_t)sz;
    bin->code_size  = total_code;
    bin->data_size  = total_data;
    bin->base       = text_vmbase;

    if (!bin->symbols) bin->is_stripped = 1;

    /* SHA-256 already computed by caller */
    return 0;

#undef LE32
#undef LE64
}
