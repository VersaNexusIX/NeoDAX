export type Arch   = 'x86_64' | 'AArch64 (ARM64)' | 'RISC-V RV64GC' | 'unknown';
export type Format = 'ELF32' | 'ELF64' | 'PE32' | 'PE64+' | 'Raw' | 'unknown';
export type OS     = 'Linux' | 'Android' | 'BSD/macOS' | 'UNIX/SysV' | 'Windows' | 'unknown';
export type SectionType  = 'code'|'data'|'rodata'|'bss'|'plt'|'got'|'dynamic'|'debug'|'other';
export type SymbolType   = 'function'|'object'|'import'|'export'|'weak'|'local'|'unknown';
export type InsnGroup    = 'call'|'branch'|'return'|'syscall'|'arithmetic'|'logic'|'data-move'|'compare'|'stack'|'string'|'float'|'simd'|'nop'|'privileged'|'prologue'|'epilogue'|'unknown';
export type StringEnc    = 'ascii'|'utf-8'|'utf-16le'|'utf-16be';
export type EdgeType     = 'fall'|'jump'|'cond_true'|'cond_false'|'call'|'ret';

export interface BinaryInfo {
    readonly file:        string;
    readonly format:      Format;
    readonly arch:        Arch;
    readonly os:          OS;
    readonly entry:       bigint;
    readonly base:        bigint;
    readonly imageSize:   bigint;
    readonly codeSize:    bigint;
    readonly dataSize:    bigint;
    readonly totalInsns:  number;
    readonly nsections:   number;
    readonly nsymbols:    number;
    readonly nfunctions:  number;
    readonly nxrefs:      number;
    readonly nblocks:     number;
    readonly ncomments:   number;
    readonly nustrings:   number;
    readonly isPie:       boolean;
    readonly isStripped:  boolean;
    readonly hasDebug:    boolean;
    readonly sha256:      string;
    readonly buildId:     string;
    readonly version:     string;
}

export interface Section {
    readonly name:         string;
    readonly type:         SectionType;
    readonly vaddr:        bigint;
    readonly offset:       bigint;
    readonly size:         bigint;
    readonly flags:        number;
    readonly insnCount:    number;
    readonly isExecutable: boolean;
    readonly isWritable:   boolean;
    readonly isReadable:   boolean;
}

export interface Symbol {
    readonly name:       string;
    readonly demangled:  string;
    readonly address:    bigint;
    readonly size:       bigint;
    readonly type:       SymbolType;
    readonly isEntry:    boolean;
}

export interface Function {
    readonly name:        string;
    readonly start:       bigint;
    readonly end:         bigint;
    readonly size:        bigint;
    readonly insnCount:   number;
    readonly blockCount:  number;
    readonly hasLoops:    boolean;
    readonly hasCalls:    boolean;
    readonly symIndex:    number;
}

export interface Block {
    readonly start:    bigint;
    readonly end:      bigint;
    readonly id:       number;
    readonly funcIdx:  number;
    readonly isEntry:  boolean;
    readonly isExit:   boolean;
    readonly nsucc:    number;
    readonly npred:    number;
}

export interface Xref {
    readonly from:    bigint;
    readonly to:      bigint;
    readonly isCall:  boolean;
}

export interface Instruction {
    readonly address:   bigint;
    readonly mnemonic:  string;
    readonly operands:  string;
    readonly size:      number;
    readonly bytes:     number[];
    readonly symbol:    string | null;
    readonly group:     InsnGroup;
}

export interface UnicodeString {
    readonly address:     bigint;
    readonly value:       string;
    readonly byteLength:  number;
    readonly encoding:    StringEnc;
}

export interface AsciiString {
    readonly address: bigint;
    readonly value:   string;
    readonly length:  number;
}

export interface HottestFunction {
    readonly function:   Function;
    readonly callCount:  number;
}

export interface DisasmOptions {
    limit?:   number;
    offset?:  number;
}

export interface AnalysisResult {
    readonly info:            BinaryInfo;
    readonly symbols:         Symbol[];
    readonly functions:       Function[];
    readonly xrefs:           Xref[];
    readonly blocks:          Block[];
    readonly unicodeStrings:  UnicodeString[];
    readonly analysisTimeMs:  number;
}

export declare class NeoDAXBinary {
    readonly info:        BinaryInfo;
    readonly arch:        Arch;
    readonly format:      Format;
    readonly os:          OS;
    readonly entry:       bigint;
    readonly sha256:      string;
    readonly buildId:     string;
    readonly isPie:       boolean;
    readonly isStripped:  boolean;
    readonly hasDebug:    boolean;
    readonly file:        string;
    readonly loadTimeMs:  number;

    sections():                             Section[];
    symbols():                              Symbol[];
    functions():                            Function[];
    xrefs():                                Xref[];
    xrefsTo(address: bigint | number):      Xref[];
    xrefsFrom(address: bigint | number):    Xref[];
    blocks():                               Block[];
    unicodeStrings():                       UnicodeString[];
    strings():                              AsciiString[];

    symAt(address: bigint | number):             Symbol   | null;
    funcAt(address: bigint | number):            Function | null;
    sectionByName(name: string):                 Section  | null;
    sectionAt(address: bigint | number):         Section  | null;
    readBytes(address: bigint | number, length: number): Uint8Array | null;
    hottestFunctions(n?: number):                HottestFunction[];

    disasm(section?: string):                          string;
    disasmJson(section?: string, opts?: DisasmOptions): Instruction[];

    analyze(): AnalysisResult;

    symexec(funcIdx?: number):   string;
    ssa(funcIdx?: number):       string;
    decompile(funcIdx?: number): string;
    emulate(funcIdx?: number, initRegs?: Record<string, bigint | number>): string;

    entropy(): string;
    rda(section?: string): string;
    ivf(): string;

    close(): void;
    [Symbol.dispose](): void;
}

export declare function load(filePath: string): NeoDAXBinary;
export declare function version(): string;

export declare function withBinary<T>(
    filePath: string,
    callback: (bin: NeoDAXBinary) => T
): T;

export declare function withBinaryAsync<T>(
    filePath: string,
    callback: (bin: NeoDAXBinary) => Promise<T>
): Promise<T>;
