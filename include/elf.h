#ifndef DAX_ELF_H
#define DAX_ELF_H

#include <stdint.h>

#define ELF_MAGIC       0x464C457F

#define ELFCLASS32      1
#define ELFCLASS64      2
#define ELFDATA2LSB     1
#define ELFDATA2MSB     2

#define ET_NONE         0
#define ET_REL          1
#define ET_EXEC         2
#define ET_DYN          3
#define ET_CORE         4

#define EM_X86_64       62
#define EM_AARCH64      183
#define EM_RISCV        243

#define ELFOSABI_NONE       0
#define ELFOSABI_LINUX      3
#define ELFOSABI_FREEBSD    9
#define ELFOSABI_OPENBSD    12
#define ELFOSABI_NETBSD     2

#define SHT_NULL        0
#define SHT_PROGBITS    1
#define SHT_STRTAB      3
#define SHF_EXECINSTR   0x4

#pragma pack(push, 1)

typedef struct {
    uint8_t     e_ident[16];
    uint16_t    e_type;
    uint16_t    e_machine;
    uint32_t    e_version;
    uint32_t    e_entry;
    uint32_t    e_phoff;
    uint32_t    e_shoff;
    uint32_t    e_flags;
    uint16_t    e_ehsize;
    uint16_t    e_phentsize;
    uint16_t    e_phnum;
    uint16_t    e_shentsize;
    uint16_t    e_shnum;
    uint16_t    e_shstrndx;
} Elf32_Ehdr;

typedef struct {
    uint8_t     e_ident[16];
    uint16_t    e_type;
    uint16_t    e_machine;
    uint32_t    e_version;
    uint64_t    e_entry;
    uint64_t    e_phoff;
    uint64_t    e_shoff;
    uint32_t    e_flags;
    uint16_t    e_ehsize;
    uint16_t    e_phentsize;
    uint16_t    e_phnum;
    uint16_t    e_shentsize;
    uint16_t    e_shnum;
    uint16_t    e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t    sh_name;
    uint32_t    sh_type;
    uint32_t    sh_flags;
    uint32_t    sh_addr;
    uint32_t    sh_offset;
    uint32_t    sh_size;
    uint32_t    sh_link;
    uint32_t    sh_info;
    uint32_t    sh_addralign;
    uint32_t    sh_entsize;
} Elf32_Shdr;

typedef struct {
    uint32_t    sh_name;
    uint32_t    sh_type;
    uint64_t    sh_flags;
    uint64_t    sh_addr;
    uint64_t    sh_offset;
    uint64_t    sh_size;
    uint32_t    sh_link;
    uint32_t    sh_info;
    uint64_t    sh_addralign;
    uint64_t    sh_entsize;
} Elf64_Shdr;

#pragma pack(pop)

#endif

typedef struct {
    uint32_t    st_name;
    uint8_t     st_info;
    uint8_t     st_other;
    uint16_t    st_shndx;
    uint64_t    st_value;
    uint64_t    st_size;
} Elf64_Sym;

typedef struct {
    uint32_t    st_name;
    uint32_t    st_value;
    uint32_t    st_size;
    uint8_t     st_info;
    uint8_t     st_other;
    uint16_t    st_shndx;
} Elf32_Sym;

#define SHT_SYMTAB  2
#define SHT_DYNSYM  11
