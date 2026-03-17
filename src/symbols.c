#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "elf.h"
#include "pe.h"

static int sym_cmp(const void *a, const void *b) {
    const dax_symbol_t *sa = (const dax_symbol_t *)a;
    const dax_symbol_t *sb = (const dax_symbol_t *)b;
    if (sa->address < sb->address) return -1;
    if (sa->address > sb->address) return  1;
    return 0;
}

static void add_symbol(dax_binary_t *bin, uint64_t addr, const char *name,
                       dax_sym_type_t type, uint64_t size) {
    dax_symbol_t *sym;
    int i;

    if (bin->nsymbols >= DAX_MAX_SYMBOLS) return;
    if (!name || !name[0]) return;
    /* Filter ARM64 mapping symbols ($x, $d, $t) — not real functions */
    if (name[0]=='$' && (name[1]=='x'||name[1]=='d'||name[1]=='t'||name[1]=='a') &&
        (name[2]=='\0'||name[2]=='.')) return;

    for (i = 0; i < bin->nsymbols; i++) {
        if (bin->symbols[i].address == addr &&
            strcmp(bin->symbols[i].name, name) == 0) return;
    }

    sym = &bin->symbols[bin->nsymbols++];
    memset(sym, 0, sizeof(*sym));
    sym->address = addr;
    strncpy(sym->name, name, DAX_SYM_NAME_LEN - 1);
    sym->type    = type;
    sym->size    = size;
    sym->is_entry = (addr == bin->entry);

    dax_demangle(name, sym->demangled, DAX_SYM_NAME_LEN);
}

static int load_elf64_symbols(dax_binary_t *bin) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)bin->data;
    Elf64_Shdr *sh;
    char       *shstr = NULL;
    int         i;

    if (bin->size < sizeof(Elf64_Ehdr)) return -1;
    if (eh->e_shoff == 0 || eh->e_shnum == 0) return 0;
    if (eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > bin->size) return -1;

    sh = (Elf64_Shdr *)(bin->data + eh->e_shoff);

    if (eh->e_shstrndx && eh->e_shstrndx < eh->e_shnum) {
        uint64_t off = sh[eh->e_shstrndx].sh_offset;
        if (off + sh[eh->e_shstrndx].sh_size <= bin->size)
            shstr = (char *)(bin->data + off);
    }

    for (i = 0; i < eh->e_shnum; i++) {
        Elf64_Shdr *s = &sh[i];
        const char *sname = (shstr && s->sh_name) ? shstr + s->sh_name : "";

        if (s->sh_type == 2 || s->sh_type == 11) {
            uint64_t symoff  = s->sh_offset;
            uint64_t symsize = s->sh_size;
            uint64_t entsize = s->sh_entsize ? s->sh_entsize : sizeof(Elf64_Sym);
            uint32_t strlink = s->sh_link;
            char    *strtab  = NULL;
            uint64_t nent;
            uint64_t j;

            if (symoff + symsize > bin->size) continue;
            if (strlink && strlink < (uint32_t)eh->e_shnum) {
                uint64_t stroff = sh[strlink].sh_offset;
                if (stroff + sh[strlink].sh_size <= bin->size)
                    strtab = (char *)(bin->data + stroff);
            }

            nent = symsize / entsize;
            for (j = 1; j < nent; j++) {
                Elf64_Sym *sym = (Elf64_Sym *)(bin->data + symoff + j * entsize);
                uint8_t   stt  = sym->st_info & 0xf;
                uint8_t   stb  = (sym->st_info >> 4) & 0xf;
                const char *name = "";
                dax_sym_type_t type;
                uint64_t addr;

                if (!strtab || sym->st_name == 0) continue;
                name = strtab + sym->st_name;
                if (!name[0]) continue;

                addr = sym->st_value;
                if (addr == 0 && stt != 6) continue;

                if (stt == 2)      type = SYM_FUNC;
                else if (stt == 1) type = SYM_OBJECT;
                else if (stt == 6) type = SYM_IMPORT;
                else if (stb == 2) type = SYM_WEAK;
                else if (stb == 0) type = SYM_LOCAL;
                else               type = SYM_UNKNOWN;

                if (s->sh_type == 11 && stt == 0) type = SYM_IMPORT;

                add_symbol(bin, addr, name, type, sym->st_size);
            }
            (void)sname;
        }
    }
    return 0;
}

static int load_elf32_symbols(dax_binary_t *bin) {
    Elf32_Ehdr *eh = (Elf32_Ehdr *)bin->data;
    Elf32_Shdr *sh;
    char       *shstr = NULL;
    int         i;

    if (bin->size < sizeof(Elf32_Ehdr)) return -1;
    if (eh->e_shoff == 0 || eh->e_shnum == 0) return 0;

    sh = (Elf32_Shdr *)(bin->data + eh->e_shoff);

    if (eh->e_shstrndx && eh->e_shstrndx < eh->e_shnum) {
        shstr = (char *)(bin->data + sh[eh->e_shstrndx].sh_offset);
    }

    for (i = 0; i < eh->e_shnum; i++) {
        Elf32_Shdr *s = &sh[i];
        if (s->sh_type == 2 || s->sh_type == 11) {
            uint32_t symoff  = s->sh_offset;
            uint32_t symsize = s->sh_size;
            uint32_t entsize = s->sh_entsize ? s->sh_entsize : sizeof(Elf32_Sym);
            uint32_t strlink = s->sh_link;
            char    *strtab  = NULL;
            uint32_t nent, j;

            if (symoff + symsize > (uint32_t)bin->size) continue;
            if (strlink && strlink < (uint32_t)eh->e_shnum) {
                strtab = (char *)(bin->data + sh[strlink].sh_offset);
            }

            nent = symsize / entsize;
            for (j = 1; j < nent; j++) {
                Elf32_Sym *sym = (Elf32_Sym *)(bin->data + symoff + j * entsize);
                uint8_t    stt = sym->st_info & 0xf;
                uint8_t    stb = (sym->st_info >> 4) & 0xf;
                const char *name = "";
                dax_sym_type_t type;
                uint64_t addr;

                if (!strtab || sym->st_name == 0) continue;
                name = strtab + sym->st_name;
                if (!name[0]) continue;

                addr = sym->st_value;
                if (addr == 0 && stt != 6) continue;

                if (stt == 2)      type = SYM_FUNC;
                else if (stt == 1) type = SYM_OBJECT;
                else if (stt == 6) type = SYM_IMPORT;
                else if (stb == 2) type = SYM_WEAK;
                else if (stb == 0) type = SYM_LOCAL;
                else               type = SYM_UNKNOWN;

                add_symbol(bin, addr, name, type, sym->st_size);
            }
            (void)shstr;
        }
    }
    return 0;
}

static int load_pe_exports(dax_binary_t *bin) {
    IMAGE_DOS_HEADER   *dos;
    IMAGE_NT_HEADERS64 *nt;
    uint32_t            nt_off;
    uint32_t            exp_rva, exp_sz;
    uint32_t           *funcs, *names;
    uint16_t           *ords;
    uint32_t            i, nnames, nfuncs;
    uint8_t            *data = bin->data;

    if (bin->size < sizeof(IMAGE_DOS_HEADER)) return -1;
    dos    = (IMAGE_DOS_HEADER *)data;
    nt_off = (uint32_t)dos->e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > bin->size) return -1;
    nt = (IMAGE_NT_HEADERS64 *)(data + nt_off);

    if (nt->OptionalHeader.NumberOfRvaAndSizes < 1) return 0;
    exp_rva = (uint32_t)nt->OptionalHeader.SizeOfHeapReserve;
    exp_sz  = (uint32_t)nt->OptionalHeader.SizeOfHeapCommit;

    {
        uint32_t dir0_rva = 0, dir0_sz = 0;
        uint8_t *optr = (uint8_t *)&nt->OptionalHeader;
        uint32_t optsize = nt->FileHeader.SizeOfOptionalHeader;
        if (optsize >= 112) {
            dir0_rva = *(uint32_t *)(optr + optsize - 128);
            dir0_sz  = *(uint32_t *)(optr + optsize - 124);
        }
        exp_rva = dir0_rva;
        exp_sz  = dir0_sz;
    }

    if (!exp_rva) return 0;

    {
        IMAGE_SECTION_HEADER *secs = (IMAGE_SECTION_HEADER *)(
            (uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader);
        uint32_t ns = nt->FileHeader.NumberOfSections;
        uint32_t exp_off = 0;
        uint32_t j;

        for (j = 0; j < ns; j++) {
            uint32_t va  = secs[j].VirtualAddress;
            uint32_t rsz = secs[j].SizeOfRawData;
            uint32_t raw = secs[j].PointerToRawData;
            if (exp_rva >= va && exp_rva < va + rsz) {
                exp_off = raw + (exp_rva - va);
                break;
            }
        }
        if (!exp_off || exp_off + 40 > bin->size) return 0;

        nfuncs = *(uint32_t *)(data + exp_off + 20);
        nnames = *(uint32_t *)(data + exp_off + 24);
        uint32_t funcs_rva = *(uint32_t *)(data + exp_off + 28);
        uint32_t names_rva = *(uint32_t *)(data + exp_off + 32);
        uint32_t ords_rva  = *(uint32_t *)(data + exp_off + 36);

        uint32_t funcs_off = 0, names_off = 0, ords_off = 0;
        for (j = 0; j < ns; j++) {
            uint32_t va  = secs[j].VirtualAddress;
            uint32_t rsz = secs[j].SizeOfRawData;
            uint32_t raw = secs[j].PointerToRawData;
            if (funcs_rva >= va && funcs_rva < va+rsz && !funcs_off) funcs_off = raw+(funcs_rva-va);
            if (names_rva >= va && names_rva < va+rsz && !names_off) names_off = raw+(names_rva-va);
            if (ords_rva  >= va && ords_rva  < va+rsz && !ords_off)  ords_off  = raw+(ords_rva-va);
        }

        if (!funcs_off || !names_off || !ords_off) return 0;
        if (funcs_off + nfuncs * 4 > bin->size) return 0;
        if (names_off + nnames * 4 > bin->size) return 0;
        if (ords_off  + nnames * 2 > bin->size) return 0;

        funcs = (uint32_t *)(data + funcs_off);
        names = (uint32_t *)(data + names_off);
        ords  = (uint16_t *)(data + ords_off);

        for (i = 0; i < nnames; i++) {
            uint32_t name_rva = names[i];
            uint16_t ord      = ords[i];
            uint32_t func_rva;
            uint32_t name_off = 0;
            const char *name;
            uint64_t addr;

            if (ord >= nfuncs) continue;
            func_rva = funcs[ord];
            if (!func_rva) continue;

            for (j = 0; j < ns; j++) {
                uint32_t va  = secs[j].VirtualAddress;
                uint32_t rsz = secs[j].SizeOfRawData;
                uint32_t raw = secs[j].PointerToRawData;
                if (name_rva >= va && name_rva < va+rsz) { name_off = raw+(name_rva-va); break; }
            }
            if (!name_off || name_off >= bin->size) continue;
            name = (const char *)(data + name_off);
            addr = bin->base + func_rva;
            add_symbol(bin, addr, name, SYM_EXPORT, 0);
        }
    }
    (void)exp_sz;
    return 0;
}

int dax_sym_load(dax_binary_t *bin) {
    if (!bin->symbols) {
        bin->symbols = (dax_symbol_t *)calloc(DAX_MAX_SYMBOLS, sizeof(dax_symbol_t));
        if (!bin->symbols) return -1;
    }
    bin->nsymbols = 0;

    if (bin->entry) {
        add_symbol(bin, bin->entry, "_start", SYM_FUNC, 0);
        bin->symbols[bin->nsymbols - 1].is_entry = 1;
    }

    if (bin->fmt == FMT_ELF64) {
        load_elf64_symbols(bin);
    } else if (bin->fmt == FMT_ELF32) {
        load_elf32_symbols(bin);
    } else if (bin->fmt == FMT_PE32 || bin->fmt == FMT_PE64) {
        load_pe_exports(bin);
    }

    if (bin->nsymbols > 1) {
        qsort(bin->symbols, bin->nsymbols, sizeof(dax_symbol_t), sym_cmp);
    }
    return bin->nsymbols;
}

dax_symbol_t *dax_sym_find(dax_binary_t *bin, uint64_t addr) {
    int lo = 0, hi = bin->nsymbols - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (bin->symbols[mid].address == addr) return &bin->symbols[mid];
        if (bin->symbols[mid].address < addr)  lo = mid + 1;
        else                                    hi = mid - 1;
    }
    return NULL;
}

const char *dax_sym_name(dax_binary_t *bin, uint64_t addr) {
    dax_symbol_t *s = dax_sym_find(bin, addr);
    if (!s) return NULL;
    if (s->demangled[0]) return s->demangled;
    return s->name;
}
