#ifndef DAX_MACHO_H
#define DAX_MACHO_H

#include <stdint.h>

/* Mach-O magic numbers */
#define MACHO_MAGIC_32      0xFEEDFACEU   /* 32-bit big-endian    */
#define MACHO_MAGIC_32_LE   0xCEFAEDFEU   /* 32-bit little-endian */
#define MACHO_MAGIC_64      0xFEEDFACFU   /* 64-bit big-endian    */
#define MACHO_MAGIC_64_LE   0xCFFAEDFEU   /* 64-bit little-endian */
#define MACHO_FAT_MAGIC     0xBEBAFECAU   /* FAT big-endian       */
#define MACHO_FAT_MAGIC_LE  0xCAFEBABEU   /* FAT little-endian    */

/* CPU types */
#define MACHO_CPU_X86_64    0x01000007
#define MACHO_CPU_ARM64     0x0100000C
#define MACHO_CPU_ARM64_32  0x0200000C
#define MACHO_CPU_X86       0x00000007
#define MACHO_CPU_ARM       0x0000000C

/* File types */
#define MACHO_MH_EXECUTE    0x2
#define MACHO_MH_DYLIB      0x6
#define MACHO_MH_BUNDLE     0x8
#define MACHO_MH_DYLINKER   0x7

/* Load command types */
#define MACHO_LC_SEGMENT_64     0x19
#define MACHO_LC_SEGMENT        0x1
#define MACHO_LC_SYMTAB         0x2
#define MACHO_LC_DYSYMTAB       0xB
#define MACHO_LC_MAIN           0x80000028
#define MACHO_LC_UNIXTHREAD     0x5
#define MACHO_LC_UUID           0x1B
#define MACHO_LC_BUILD_VERSION  0x32

#pragma pack(push, 1)

typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;   /* 64-bit only */
} macho_header64_t;

typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
} macho_header32_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
} macho_load_cmd_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    char     segname[16];
    uint64_t vmaddr;
    uint64_t vmsize;
    uint64_t fileoff;
    uint64_t filesize;
    uint32_t maxprot;
    uint32_t initprot;
    uint32_t nsects;
    uint32_t flags;
} macho_segment64_t;

typedef struct {
    char     sectname[16];
    char     segname[16];
    uint64_t addr;
    uint64_t size;
    uint32_t offset;
    uint32_t align;
    uint32_t reloff;
    uint32_t nreloc;
    uint32_t flags;
    uint32_t reserved1;
    uint32_t reserved2;
    uint32_t reserved3;
} macho_section64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint64_t entryoff;   /* offset from __TEXT base to entry point */
    uint64_t stacksize;
} macho_entry_cmd_t;

/* FAT header */
typedef struct {
    uint32_t magic;
    uint32_t nfat_arch;
} macho_fat_header_t;

typedef struct {
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t offset;
    uint32_t size;
    uint32_t align;
} macho_fat_arch_t;

/* nlist_64 for symbol table */
typedef struct {
    uint32_t n_strx;
    uint8_t  n_type;
    uint8_t  n_sect;
    uint16_t n_desc;
    uint64_t n_value;
} macho_nlist64_t;

typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t symoff;
    uint32_t nsyms;
    uint32_t stroff;
    uint32_t strsize;
} macho_symtab_cmd_t;

#pragma pack(pop)

int dax_parse_macho(dax_binary_t *bin);

#endif /* DAX_MACHO_H */
