#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dax.h"
#include "macho.h"
#include "elf.h"
#include "pe.h"

static void elf64_compute_meta(dax_binary_t *bin, Elf64_Ehdr *eh) {
    int i;

    bin->is_pie      = (eh->e_type == 3) ? 1 : 0;
    bin->is_stripped = 1;
    bin->has_debug   = 0;
    bin->image_size  = 0;
    bin->code_size   = 0;
    bin->data_size   = 0;

    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s = &bin->sections[i];
        uint64_t       sec_end;

        if (s->type == SEC_TYPE_CODE || s->type == SEC_TYPE_PLT)
            bin->code_size += s->size;
        else if (s->type == SEC_TYPE_DATA || s->type == SEC_TYPE_RODATA ||
                 s->type == SEC_TYPE_BSS)
            bin->data_size += s->size;

        if (strcmp(s->name, ".symtab") == 0 || strcmp(s->name, ".strtab") == 0)
            bin->is_stripped = 0;

        if (strncmp(s->name, ".debug", 6) == 0 || strcmp(s->name, ".eh_frame") == 0)
            bin->has_debug = 1;

        if (s->vaddr && s->size) {
            sec_end = s->vaddr + s->size;
            if (sec_end > bin->image_size) bin->image_size = sec_end;
        }
    }

    if (bin->image_size > bin->base && bin->base)
        bin->image_size -= bin->base;
}
static void elf64_extract_build_id(dax_binary_t *bin) {
    int i;
    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s = &bin->sections[i];
        if (strcmp(s->name, ".note.gnu.build-id") == 0 ||
            strcmp(s->name, ".note.gnu.property") == 0) {
            if (s->offset + s->size <= bin->size && s->size >= 16) {
                uint8_t *nd = bin->data + s->offset;
                uint32_t namesz = *(uint32_t *)(nd + 0);
                uint32_t descsz = *(uint32_t *)(nd + 4);
                uint32_t off2   = 12 + ((namesz + 3) & ~3u);
                if (off2 + descsz <= s->size && descsz <= 32) {
                    uint32_t j;
                    for (j = 0; j < descsz && j < 32; j++)
                        snprintf(bin->build_id + j*2, 3, "%02x", nd[off2 + j]);
                    bin->build_id[descsz * 2] = '\0';
                    break;
                }
            }
        }
    }
}

int dax_load_binary(const char *path, dax_binary_t *bin) {
    FILE  *fp;
    size_t n;

    strncpy(bin->filepath, path, sizeof(bin->filepath) - 1);

    fp = fopen(path, "rb");
    if (!fp) {
        perror("fopen");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    bin->size = (size_t)ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (bin->size < 4) {
        fclose(fp);
        fprintf(stderr, "neodax: file too small\n");
        return -1;
    }

    bin->data = (uint8_t *)malloc(bin->size);
    if (!bin->data) {
        fclose(fp);
        fprintf(stderr, "neodax: out of memory\n");
        return -1;
    }

    n = fread(bin->data, 1, bin->size, fp);
    fclose(fp);

    if (n != bin->size) {
        free(bin->data);
        bin->data = NULL;
        fprintf(stderr, "neodax: read error\n");
        return -1;
    }

    {
        uint32_t magic32 = *(uint32_t *)bin->data;
        uint16_t magic16 = *(uint16_t *)bin->data;

        if (magic32 == 0x464C457F) {
            return dax_parse_elf(bin);
        } else if (magic16 == PE_DOS_MAGIC) {
            return dax_parse_pe(bin);
        } else if (magic32 == MACHO_MAGIC_64_LE || magic32 == MACHO_MAGIC_64    ||
                   magic32 == MACHO_MAGIC_32_LE || magic32 == MACHO_MAGIC_32    ||
                   magic32 == MACHO_FAT_MAGIC   || magic32 == MACHO_FAT_MAGIC_LE) {
            dax_compute_sha256(bin);
            return dax_parse_macho(bin);
        } else {
            bin->fmt  = FMT_RAW;
            bin->arch = ARCH_UNKNOWN;
            bin->os   = DAX_PLAT_UNKNOWN;
            fprintf(stderr, "neodax: unknown format, treating as raw binary\n");
            return 0;
        }
    }
}

int dax_parse_elf(dax_binary_t *bin) {
    uint8_t eclass;
    uint8_t osabi;

    eclass = bin->data[4];
    osabi  = bin->data[7];

    switch (osabi) {
        case ELFOSABI_NONE:
        case 3:  bin->os = DAX_PLAT_LINUX; break;
        case 9:  bin->os = DAX_PLAT_BSD;   break;
        case 2:  bin->os = DAX_PLAT_BSD;   break;
        case 12: bin->os = DAX_PLAT_BSD;   break;
        default: bin->os = DAX_PLAT_UNIX;  break;
    }

    if (eclass == ELFCLASS64) {
        Elf64_Ehdr *eh;
        Elf64_Shdr *sh;
        char       *shstrtab;
        uint16_t    i;

        if (bin->size < sizeof(Elf64_Ehdr)) return -1;
        eh = (Elf64_Ehdr *)bin->data;
        bin->fmt   = FMT_ELF64;
        bin->entry = eh->e_entry;
        bin->base  = 0;

        switch (eh->e_machine) {
            case EM_X86_64:  bin->arch = ARCH_X86_64;  break;
            case EM_AARCH64: bin->arch = ARCH_ARM64;   break;
            case EM_RISCV:   bin->arch = ARCH_RISCV64; break;
            default:
                fprintf(stderr, "neodax: unsupported ELF machine type: 0x%x\n", eh->e_machine);
                return -1;
        }

        if (eh->e_shoff == 0 || eh->e_shnum == 0) return 0;
        if (eh->e_shoff + (uint64_t)eh->e_shnum * sizeof(Elf64_Shdr) > bin->size) return -1;

        sh = (Elf64_Shdr *)(bin->data + eh->e_shoff);

        if (eh->e_shstrndx != 0 && eh->e_shstrndx < eh->e_shnum) {
            Elf64_Shdr *strs = &sh[eh->e_shstrndx];
            if (strs->sh_offset + strs->sh_size <= bin->size)
                shstrtab = (char *)(bin->data + strs->sh_offset);
            else
                shstrtab = NULL;
        } else {
            shstrtab = NULL;
        }

        bin->nsections = 0;
        for (i = 0; i < eh->e_shnum && bin->nsections < DAX_MAX_SECTIONS; i++) {
            Elf64_Shdr    *s   = &sh[i];
            dax_section_t *sec = &bin->sections[bin->nsections];

            if (s->sh_type == SHT_NULL) continue;

            if (shstrtab && s->sh_name)
                strncpy(sec->name, shstrtab + s->sh_name, sizeof(sec->name) - 1);
            else
                snprintf(sec->name, sizeof(sec->name), ".sect%d", i);

            sec->vaddr       = s->sh_addr;
            sec->offset      = s->sh_offset;
            sec->file_offset = s->sh_offset;
            sec->size        = s->sh_size;
            sec->flags       = (uint32_t)s->sh_flags;
            sec->type        = dax_sec_classify(sec->name, sec->flags);
            sec->insn_count  = 0;
            bin->nsections++;
        }

        if (bin->os == DAX_PLAT_LINUX || bin->os == DAX_PLAT_UNIX) {
            int j;
            for (j = 0; j < bin->nsections; j++) {
                if (strstr(bin->sections[j].name, "android") ||
                    strstr(bin->sections[j].name, ".dynstr")) {
                    uint8_t *ds = bin->data + bin->sections[j].offset;
                    if (bin->sections[j].offset + bin->sections[j].size <= bin->size) {
                        if (memmem(ds, (size_t)bin->sections[j].size, "Android", 7)) {
                            bin->os = DAX_PLAT_ANDROID;
                            break;
                        }
                    }
                }
            }
        }

        elf64_compute_meta(bin, eh);
        elf64_extract_build_id(bin);
        return 0;

    } else if (eclass == ELFCLASS32) {
        Elf32_Ehdr *eh;
        Elf32_Shdr *sh;
        char       *shstrtab;
        uint16_t    i;

        if (bin->size < sizeof(Elf32_Ehdr)) return -1;
        eh = (Elf32_Ehdr *)bin->data;
        bin->fmt   = FMT_ELF32;
        bin->entry = eh->e_entry;
        bin->base  = 0;

        switch (eh->e_machine) {
            case EM_X86_64:  bin->arch = ARCH_X86_64;  break;
            case EM_AARCH64: bin->arch = ARCH_ARM64;   break;
            case EM_RISCV:   bin->arch = ARCH_RISCV64; break;
            default:
                fprintf(stderr, "neodax: unsupported ELF32 machine: 0x%x\n", eh->e_machine);
                return -1;
        }

        if (eh->e_shoff == 0 || eh->e_shnum == 0) return 0;

        sh = (Elf32_Shdr *)(bin->data + eh->e_shoff);

        if (eh->e_shstrndx != 0 && eh->e_shstrndx < eh->e_shnum) {
            Elf32_Shdr *strs = &sh[eh->e_shstrndx];
            shstrtab = (char *)(bin->data + strs->sh_offset);
        } else {
            shstrtab = NULL;
        }

        bin->nsections = 0;
        bin->is_stripped = 1;
        bin->has_debug   = 0;
        bin->code_size   = 0;
        bin->data_size   = 0;

        for (i = 0; i < eh->e_shnum && bin->nsections < DAX_MAX_SECTIONS; i++) {
            Elf32_Shdr    *s   = &sh[i];
            dax_section_t *sec = &bin->sections[bin->nsections];

            if (s->sh_type == SHT_NULL) continue;

            if (shstrtab && s->sh_name)
                strncpy(sec->name, shstrtab + s->sh_name, sizeof(sec->name) - 1);
            else
                snprintf(sec->name, sizeof(sec->name), ".sect%d", i);

            sec->vaddr       = s->sh_addr;
            sec->offset      = s->sh_offset;
            sec->file_offset = s->sh_offset;
            sec->size        = s->sh_size;
            sec->flags       = s->sh_flags;
            sec->type        = dax_sec_classify(sec->name, sec->flags);
            sec->insn_count  = 0;

            if (sec->type == SEC_TYPE_CODE || sec->type == SEC_TYPE_PLT)
                bin->code_size += sec->size;
            else if (sec->type == SEC_TYPE_DATA || sec->type == SEC_TYPE_RODATA ||
                     sec->type == SEC_TYPE_BSS)
                bin->data_size += sec->size;
            if (strcmp(sec->name, ".symtab") == 0)
                bin->is_stripped = 0;
            if (strncmp(sec->name, ".debug", 6) == 0)
                bin->has_debug = 1;

            bin->nsections++;
        }

        bin->is_pie = (eh->e_type == 3) ? 1 : 0;
        return 0;
    }

    fprintf(stderr, "neodax: unknown ELF class\n");
    return -1;
}

int dax_parse_pe(dax_binary_t *bin) {
    IMAGE_DOS_HEADER     *dos;
    IMAGE_NT_HEADERS64   *nt;
    IMAGE_SECTION_HEADER *secs;
    int      i;
    uint32_t nt_off;

    if (bin->size < sizeof(IMAGE_DOS_HEADER)) return -1;
    dos    = (IMAGE_DOS_HEADER *)bin->data;
    nt_off = (uint32_t)dos->e_lfanew;

    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > bin->size) return -1;
    nt = (IMAGE_NT_HEADERS64 *)(bin->data + nt_off);

    if (nt->Signature != PE_NT_MAGIC) return -1;

    bin->os          = DAX_PLAT_WINDOWS;
    bin->is_stripped = 1;
    bin->has_debug   = 0;
    bin->code_size   = 0;
    bin->data_size   = 0;

    switch (nt->FileHeader.Machine) {
        case PE_MACHINE_X64:   bin->arch = ARCH_X86_64; break;
        case PE_MACHINE_ARM64: bin->arch = ARCH_ARM64;  break;
        default:
            fprintf(stderr, "neodax: unsupported PE machine: 0x%x\n", nt->FileHeader.Machine);
            return -1;
    }

    if (nt->OptionalHeader.Magic == PE_OPT64_MAGIC) {
        bin->fmt        = FMT_PE64;
        bin->entry      = nt->OptionalHeader.ImageBase + nt->OptionalHeader.AddressOfEntryPoint;
        bin->base       = nt->OptionalHeader.ImageBase;
        bin->image_size = nt->OptionalHeader.SizeOfImage;
        bin->is_pie     = (nt->OptionalHeader.DllCharacteristics & 0x0040) ? 1 : 0;
    } else {
        bin->fmt        = FMT_PE32;
        bin->entry      = nt->OptionalHeader.AddressOfEntryPoint;
        bin->base       = 0;
        bin->image_size = nt->OptionalHeader.SizeOfImage;
        bin->is_pie     = 0;
    }

    if (nt->FileHeader.PointerToSymbolTable != 0 && nt->FileHeader.NumberOfSymbols != 0)
        bin->is_stripped = 0;

    secs = (IMAGE_SECTION_HEADER *)(
        (uint8_t *)&nt->OptionalHeader + nt->FileHeader.SizeOfOptionalHeader
    );

    bin->nsections = 0;
    for (i = 0; i < nt->FileHeader.NumberOfSections && bin->nsections < DAX_MAX_SECTIONS; i++) {
        IMAGE_SECTION_HEADER *ps  = &secs[i];
        dax_section_t        *sec = &bin->sections[bin->nsections];

        memset(sec->name, 0, sizeof(sec->name));
        memcpy(sec->name, ps->Name, 8);

        sec->vaddr       = bin->base + ps->VirtualAddress;
        sec->offset      = ps->PointerToRawData;
        sec->file_offset = ps->PointerToRawData;
        sec->size        = ps->SizeOfRawData;
        sec->flags       = ps->Characteristics;
        sec->type        = dax_sec_classify(sec->name, sec->flags);
        sec->insn_count  = 0;

        if (sec->type == SEC_TYPE_CODE || sec->type == SEC_TYPE_PLT)
            bin->code_size += sec->size;
        else if (sec->type == SEC_TYPE_DATA || sec->type == SEC_TYPE_RODATA ||
                 sec->type == SEC_TYPE_BSS)
            bin->data_size += sec->size;

        if (strcmp(sec->name, ".pdb") == 0 || strcmp(sec->name, ".debug") == 0)
            bin->has_debug = 1;

        bin->nsections++;
    }

    return 0;
}

void dax_free_binary(dax_binary_t *bin) {
    if (bin->data)      { free(bin->data);      bin->data      = NULL; }
    if (bin->symbols)   { free(bin->symbols);   bin->symbols   = NULL; }
    if (bin->xrefs)     { free(bin->xrefs);     bin->xrefs     = NULL; }
    if (bin->functions) { free(bin->functions); bin->functions = NULL; }
    if (bin->blocks)    { free(bin->blocks);    bin->blocks    = NULL; }
    if (bin->comments)  { free(bin->comments);  bin->comments  = NULL; }
    if (bin->ustrings)  { free(bin->ustrings);  bin->ustrings  = NULL; }
    bin->size = 0;
}

void dax_free_binary_full(dax_binary_t *bin) {
    dax_free_binary(bin);
}
