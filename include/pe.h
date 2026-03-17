#ifndef DAX_PE_H
#define DAX_PE_H

#include <stdint.h>

#define PE_DOS_MAGIC    0x5A4D
#define PE_NT_MAGIC     0x00004550
#define PE_OPT32_MAGIC  0x010B
#define PE_OPT64_MAGIC  0x020B

#define PE_MACHINE_X64  0x8664
#define PE_MACHINE_ARM64 0xAA64

#define PE_SCN_CNT_CODE         0x00000020
#define PE_SCN_MEM_EXECUTE      0x20000000

#pragma pack(push, 1)

typedef struct {
    uint16_t    e_magic;
    uint16_t    e_cblp;
    uint16_t    e_cp;
    uint16_t    e_crlc;
    uint16_t    e_cparhdr;
    uint16_t    e_minalloc;
    uint16_t    e_maxalloc;
    uint16_t    e_ss;
    uint16_t    e_sp;
    uint16_t    e_csum;
    uint16_t    e_ip;
    uint16_t    e_cs;
    uint16_t    e_lfarlc;
    uint16_t    e_ovno;
    uint16_t    e_res[4];
    uint16_t    e_oemid;
    uint16_t    e_oeminfo;
    uint16_t    e_res2[10];
    int32_t     e_lfanew;
} IMAGE_DOS_HEADER;

typedef struct {
    uint16_t    Machine;
    uint16_t    NumberOfSections;
    uint32_t    TimeDateStamp;
    uint32_t    PointerToSymbolTable;
    uint32_t    NumberOfSymbols;
    uint16_t    SizeOfOptionalHeader;
    uint16_t    Characteristics;
} IMAGE_FILE_HEADER;

typedef struct {
    uint16_t    Magic;
    uint8_t     MajorLinkerVersion;
    uint8_t     MinorLinkerVersion;
    uint32_t    SizeOfCode;
    uint32_t    SizeOfInitializedData;
    uint32_t    SizeOfUninitializedData;
    uint32_t    AddressOfEntryPoint;
    uint32_t    BaseOfCode;
    uint64_t    ImageBase;
    uint32_t    SectionAlignment;
    uint32_t    FileAlignment;
    uint16_t    MajorOSVersion;
    uint16_t    MinorOSVersion;
    uint16_t    MajorImageVersion;
    uint16_t    MinorImageVersion;
    uint16_t    MajorSubsystemVersion;
    uint16_t    MinorSubsystemVersion;
    uint32_t    Win32VersionValue;
    uint32_t    SizeOfImage;
    uint32_t    SizeOfHeaders;
    uint32_t    CheckSum;
    uint16_t    Subsystem;
    uint16_t    DllCharacteristics;
    uint64_t    SizeOfStackReserve;
    uint64_t    SizeOfStackCommit;
    uint64_t    SizeOfHeapReserve;
    uint64_t    SizeOfHeapCommit;
    uint32_t    LoaderFlags;
    uint32_t    NumberOfRvaAndSizes;
} IMAGE_OPTIONAL_HEADER64;

typedef struct {
    uint32_t            Signature;
    IMAGE_FILE_HEADER   FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct {
    char        Name[8];
    uint32_t    VirtualSize;
    uint32_t    VirtualAddress;
    uint32_t    SizeOfRawData;
    uint32_t    PointerToRawData;
    uint32_t    PointerToRelocations;
    uint32_t    PointerToLinenumbers;
    uint16_t    NumberOfRelocations;
    uint16_t    NumberOfLinenumbers;
    uint32_t    Characteristics;
} IMAGE_SECTION_HEADER;

#pragma pack(pop)

#endif
