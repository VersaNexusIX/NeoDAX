/** NeoDAX v1.1.1 — TypeScript definitions
   Apache 2.0 License — https://github.com/VersaNexusIX/NeoDAX */

export type Arch        = 'x86_64' | 'AArch64 (ARM64)' | 'RISC-V RV64GC' | 'unknown';
export type Format      = 'ELF32' | 'ELF64' | 'PE32' | 'PE64+' | 'Mach-O' | 'Raw' | 'unknown';
export type OS          = 'Linux' | 'Android' | 'BSD/macOS' | 'UNIX/SysV' | 'Windows' | 'unknown';
export type SectionType = 'code'|'data'|'rodata'|'bss'|'plt'|'got'|'dynamic'|'debug'|'other';
export type SymbolType  = 'function'|'object'|'import'|'export'|'weak'|'local'|'unknown';
export type InsnGroup   = 'call'|'branch'|'return'|'syscall'|'arithmetic'|'logic'|
                          'data-move'|'compare'|'stack'|'string'|'float'|'simd'|
                          'nop'|'privileged'|'prologue'|'epilogue'|'pointer-auth'|'unknown';
export type StringEnc   = 'ascii'|'utf-8'|'utf-16le'|'utf-16be';
export type EdgeType    = 'fall'|'jump'|'cond_true'|'cond_false'|'call'|'ret'|'indirect';
export type ObfLevel    = 'CLEAN'|'LOW'|'MEDIUM'|'HIGH'|'EXTREME';

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
    readonly start:     bigint;
    readonly end:       bigint;
    readonly id:        number;
    readonly funcIdx:   number;
    readonly isEntry:   boolean;
    readonly isExit:    boolean;
    readonly isPoly:    boolean;   /* block is inside a polymorphic region  */
    readonly isSmc:     boolean;   /* block contains SMC-patched bytes      */
    readonly nsucc:     number;
    readonly npred:     number;
    readonly succ:      number[];  /* successor block IDs                   */
    readonly edgeType:  EdgeType[];/* parallel to succ[]                    */
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

/** A polymorphic / obfuscated region detected by --poly */
export interface PolyRegion {
    readonly start:          bigint;
    readonly end:            bigint;
    readonly size:           bigint;
    readonly mutationScore:  number;   /* 0-10 */
    readonly technique:      string;   /* e.g. "junk insertion", "opaque-predicate" */
    readonly obfuscator:     string;   /* e.g. "OLLVM", "Themida", "custom VM" */
}

/** A single AIRE insight */
export interface AireInsight {
    readonly addr:        bigint;
    readonly category:    string;   /* vm-dispatch | smc | poly | anti-debug | packer | func-purpose | arch-oddity */
    readonly insight:     string;   /* human-readable explanation */
    readonly confidence:  number;   /* 0-100 */
}

/** Callgraph node */
export interface CallgraphNode {
    readonly name:   string;
    readonly start:  bigint;
    readonly idx:    number;
}

/** Callgraph edge */
export interface CallgraphEdge {
    readonly from:  number;   /* function index */
    readonly to:    number;   /* function index */
    readonly addr:  bigint;   /* call site address */
}

/** Result of callgraphJson() */
export interface CallgraphResult {
    readonly nodes:  CallgraphNode[];
    readonly edges:  CallgraphEdge[];
}

/** Result of vmDetect() — one entry per detected VM interpreter */
export interface VmDetectResult {
    readonly funcName:    string;
    readonly score:       number;   /* 0-6 — ≥4 = VM_DISPATCH */
    readonly dispatchPc:  bigint;
    readonly tableBase:   bigint;
    readonly handlers:    bigint[]; /* resolved handler addresses */
}

/** Summary obfuscation score returned by obfuscationScore() */
export interface ObfuscationScore {
    readonly smc:       number;
    readonly opaque:    number;
    readonly indirect:  number;
    readonly antidebug: number;
    readonly total:     number;
    readonly level:     ObfLevel;
}

/** Register initial values for emulate() */
export type InitRegs = Partial<Record<
    'x0'|'x1'|'x2'|'x3'|'x4'|'x5'|'x6'|'x7'|\
    'x8'|'x9'|'x10'|'x11'|'x12'|'x13'|'x14'|'x15'|\
    'x16'|'x17'|'x18'|'x19'|'x20'|'x21'|'x22'|'x23'|\
    'x24'|'x25'|'x26'|'x27'|'x28'|'x29'|'x30'|'sp',
    bigint | number
>>;

export declare class NeoDAXBinary {
    readonly info:        BinaryInfo;
    readonly arch:        Arch;
    readonly format:      Format;
    readonly os:          OS;
    readonly entry:       bigint;
    readonly base:        bigint;
    readonly sha256:      string;
    readonly buildId:     string;
    readonly isPie:       boolean;
    readonly isStripped:  boolean;
    readonly hasDebug:    boolean;
    readonly file:        string;
    readonly loadTimeMs:  number;

    /* ── core structures ── */
    sections():                                          Section[];
    symbols():                                           Symbol[];
    functions():                                         Function[];
    xrefs():                                             Xref[];
    xrefsTo(address: bigint | number):                   Xref[];
    xrefsFrom(address: bigint | number):                 Xref[];
    blocks():                                            Block[];
    unicodeStrings():                                    UnicodeString[];
    strings():                                           AsciiString[];
    symAt(address: bigint | number):                     Symbol   | null;
    funcAt(address: bigint | number):                    Function | null;
    sectionByName(name: string):                         Section  | null;
    sectionAt(address: bigint | number):                 Section  | null;
    readBytes(address: bigint | number, len: number):    Uint8Array | null;
    hottestFunctions(n?: number):                        HottestFunction[];

    /* ── disassembly ── */
    disasm(section?: string):                              string;
    disasmRange(addr: bigint | number, nInsns?: number):   string;
    disasmJson(section?: string, opts?: DisasmOptions):    Instruction[];
    disasmFunc(funcIdx?: number):                          string;

    /* ── full analysis ── */
    analyze():                                             AnalysisResult;

    /* ── CFG / graphs ── */
    cfg(funcIdx?: number):                                 string;
    cfgJson(funcIdx?: number):                             Block[];
    loops(funcIdx?: number):                               string;
    callgraph():                                           string;
    callgraphJson():                                       CallgraphResult;
    switchDetect(section?: string):                        string;

    /* ── obfuscation ── */
    poly():                                                string;
    polyJson():                                            PolyRegion[];
    aire():                                                string;
    aireJson():                                            AireInsight[];
    vmTrace():                                             string;
    obfuscationScore():                                    ObfuscationScore;
    vmDetect():                                            VmDetectResult[];

    /* ── advanced analysis ── */
    symexec(funcIdx?: number):                             string;
    ssa(funcIdx?: number):                                 string;
    decompile(funcIdx?: number):                           string;

    /* ── emulation ── */
    emulate(funcIdx?: number, initRegs?: InitRegs):        string;
    emulateByName(name: string, initRegs?: InitRegs):      string;
    emulateAt(addr: bigint | number, initRegs?: InitRegs): string;

    /* ── entropy / scan ── */
    entropy():                                             string;
    rda(section?: string):                                 string;
    ivf():                                                 string;

    /* ── snapshot / annotations ── */
    saveDaxc(outPath: string):                             boolean;
    addComment(addr: bigint | number, text: string):       void;

    /* ── lifecycle ── */
    close():            void;
    [Symbol.dispose](): void;
    toString():         string;
}

/** Load a binary file and return a NeoDAXBinary instance. */
export declare function load(filePath: string): NeoDAXBinary;

/** Returns the NeoDAX native engine version string. */
export declare function version(): string;

/** Load binary, run callback, auto-close. */
export declare function withBinary<T>(
    filePath: string,
    callback: (bin: NeoDAXBinary) => T
): T;

/** Async load binary, run callback, auto-close. */
export declare function withBinaryAsync<T>(
    filePath: string,
    callback: (bin: NeoDAXBinary) => Promise<T>
): Promise<T>;
