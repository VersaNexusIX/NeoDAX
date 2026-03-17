#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dax.h"

static void print_usage(void) {
    const char *R  = "\033[0m";
    const char *Y  = "\033[1;33m";
    const char *W  = "\033[1;37m";
    const char *G  = "\033[1;32m";
    const char *C  = "\033[1;36m";
    const char *M  = "\033[1;35m";
    const char *B  = "\033[1;34m";
    const char *DG = "\033[0;90m";
    const char *RD = "\033[1;31m";
    FILE *o = stderr;

    fprintf(o, "\n");
    fprintf(o, "%s ███╗   ██╗███████╗ ██████╗ %s\n", Y, R);
    fprintf(o, "%s ████╗  ██║██╔════╝██╔═══██╗%s\n", Y, R);
    fprintf(o, "%s ██╔██╗ ██║█████╗  ██║   ██║%s  %sv%s%s\n", Y, R, DG, DAX_VERSION, R);
    fprintf(o, "%s ██║╚██╗██║██╔══╝  ██║   ██║%s  %sBinary Analysis & RE Tool%s\n", Y, R, DG, R);
    fprintf(o, "%s ██║ ╚████║███████╗╚██████╔╝%s\n", Y, R);
    fprintf(o, "%s ╚═╝  ╚═══╝╚══════╝ ╚═════╝ %s\n", Y, R);
    fprintf(o, "\n");

    fprintf(o, "%s  Usage%s  neodax %s[options]%s %s<binary>%s | neodax %s[options]%s %s<file.daxc>%s\n",
            W, R, DG, R, G, R, DG, R, C, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", B, R);
    fprintf(o, "%s║  DISASSEMBLY         ║%s\n", B, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", B, R);
    fprintf(o, "  %s-a%s              %sshow hex bytes alongside each instruction%s\n", W, R, DG, R);
    fprintf(o, "  %s-s%s %s<section>%s    %sdisassemble a specific section%s  %s(default: .text)%s\n", W, R, C, R, DG, R, DG, R);
    fprintf(o, "  %s-S%s              %sdisassemble ALL executable sections%s\n", W, R, DG, R);
    fprintf(o, "  %s-A%s %s<addr>%s       %sstart address in hex%s\n", W, R, C, R, DG, R);
    fprintf(o, "  %s-E%s %s<addr>%s       %send address in hex%s\n", W, R, C, R, DG, R);
    fprintf(o, "  %s-l%s              %slist all sections with full metadata%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", G, R);
    fprintf(o, "%s║  ANALYSIS            ║%s\n", G, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", G, R);
    fprintf(o, "  %s-y%s              %sresolve symbols from symtab / dynsym / PE exports%s\n", W, R, DG, R);
    fprintf(o, "  %s-d%s              %sdemangle C++ Itanium ABI symbols%s\n", W, R, DG, R);
    fprintf(o, "  %s-f%s              %sdetect function boundaries & sizes%s\n", W, R, DG, R);
    fprintf(o, "  %s-g%s              %sinstruction group coloring%s  %s(call/branch/ret/arith...)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-r%s              %scross-reference annotations%s  %s(who calls what)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-t%s              %sannotate string references (ASCII + UTF-8 + UTF-16)%s\n", W, R, DG, R);
    fprintf(o, "  %s-C%s              %scontrol flow graph%s  %s(basic blocks + edges)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-L%s              %sloop detection%s  %s(natural loops via dominators)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-G%s              %scall graph%s  %s(who calls who, tree view)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-W%s              %sswitch detection%s  %s(jump table patterns)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-u%s              %sscan & display Unicode strings%s  %s(UTF-8, UTF-16LE/BE)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "\n");
    fprintf(o, "%s╔══════════════════════╗%s\n", Y, R);
    fprintf(o, "%s║  ADVANCED ANALYSIS   ║%s\n", Y, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", Y, R);
    fprintf(o, "  %s-P%s              %ssymbolic execution%s  %s(track symbolic register state)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-Q%s              %sSSA lifting%s  %s(Static Single Assignment IR)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-D%s              %sdecompile%s  %s(pseudo-C from SSA IR)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-I%s              %semulate%s  %s(concrete execution engine)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-e%s              %sentropy analysis%s  %s(detect packed/encrypted regions)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-R%s              %srecursive descent disassembly%s  %s(follow control flow, mark dead bytes)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-V%s              %sinstruction validity filter%s  %s(invalid, privileged, dead, NOP-runs)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-x%s              %senable all standard analysis%s  %s(-y -d -f -g -r -t -u -C -L -G -W)%s\n", RD, R, DG, R, DG, R);
    fprintf(o, "  %s-X%s              %senable EVERYTHING%s  %s(adds -P -Q -D -I -e -R -V)%s\n", RD, R, DG, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", C, R);
    fprintf(o, "%s║  OUTPUT / FILES      ║%s\n", C, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", C, R);
    fprintf(o, "  %s-o%s %s<file.daxc>%s  %ssave full analysis snapshot%s  %s(symbols, CFG, xrefs, comments)%s\n", W, R, C, R, DG, R, DG, R);
    fprintf(o, "  %s-c%s              %sconvert .daxc → annotated .S assembly file%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s╔══════════════════════╗%s\n", DG, R);
    fprintf(o, "%s║  MISC                ║%s\n", DG, R);
    fprintf(o, "%s╚══════════════════════╝%s\n", DG, R);
    fprintf(o, "  %s-n%s              %sno color output%s  %s(for piping / logging)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-v%s              %sverbose mode%s  %s(instruction count, section info)%s\n", W, R, DG, R, DG, R);
    fprintf(o, "  %s-h%s              %sthis help page%s\n", W, R, DG, R);
    fprintf(o, "\n");

    fprintf(o, "%s  Examples%s\n", W, R);
    fprintf(o, "  %s──────────────────────────────────────────────────────%s\n", DG, R);
    fprintf(o, "  %s$%s neodax %s./binary%s\n", G, R, G, R);
    fprintf(o, "  %s$%s neodax %s-x%s %s./binary%s\n", G, R, Y, R, G, R);
    fprintf(o, "  %s$%s neodax %s-x -u -o%s %sanalysis.daxc%s %s./binary%s\n", G, R, Y, R, C, R, G, R);
    fprintf(o, "  %s$%s neodax %s-c%s %sanalysis.daxc%s                %s→ analysis.S%s\n", G, R, Y, R, C, R, DG, R);
    fprintf(o, "  %s$%s neodax %s-s .plt -a%s %s./binary%s              %s→ .plt with bytes%s\n", G, R, Y, R, G, R, DG, R);
    fprintf(o, "\n");
}

static void neodax_header_line(int use_color, int width) {
    int i;
    if (use_color) printf("%s", COL_SECTION);
    for (i = 0; i < width; i++) printf("─");
    if (use_color) printf("%s", COL_RESET);
    printf("\n");
}

void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts) {
    int color = opts ? opts->color : 1;
    const char *C  = color ? COL_LABEL   : "";
    const char *R  = color ? COL_RESET   : "";
    const char *DG = color ? COL_COMMENT : "";
    const char *W  = color ? COL_MNEM    : "";
    const char *GN = color ? COL_SECTION : "";
    const char *AD = color ? COL_ADDR    : "";
    const char *EN = color ? COL_ENTRY   : "";
    const char *MT = color ? COL_META    : "";
    int bw = DAX_BANNER_WIDTH;

    printf("\n");
    neodax_header_line(color, bw);
    printf("%s"
        " ███╗   ██╗███████╗ ██████╗ \n"
        " ████╗  ██║██╔════╝██╔═══██╗\n"
        " ██╔██╗ ██║█████╗  ██║   ██║\n"
        " ██║╚██╗██║██╔══╝  ██║   ██║\n"
        " ██║ ╚████║███████╗╚██████╔╝\n"
        " ╚═╝  ╚═══╝╚══════╝ ╚═════╝ \n"
        "%s", C, R);
    printf("%s  NeoDAX v%s  —  Binary Analysis & Disassembler%s\n", DG, DAX_VERSION, R);
    neodax_header_line(color, bw);

    printf(" %sFile%s          : %s\n",       W, R, bin->filepath);
    printf(" %sFormat%s        : %s\n",       W, R, dax_fmt_str(bin->fmt));
    printf(" %sArch%s          : %s\n",       W, R, dax_arch_str(bin->arch));
    printf(" %sOS/ABI%s        : %s\n",       W, R, dax_os_str(bin->os));
    printf(" %sEntry%s         : %s0x%016llx%s\n",
           W, R, EN, (unsigned long long)bin->entry, R);
    printf(" %sBase%s          : %s0x%016llx%s\n",
           W, R, AD, (unsigned long long)bin->base, R);
    if (bin->image_size)
        printf(" %sImage Size%s    : %s%llu bytes%s\n",
               W, R, MT, (unsigned long long)bin->image_size, R);
    printf(" %sSections%s      : %s%d%s\n",   W, R, GN, bin->nsections, R);
    if (bin->code_size)
        printf(" %sCode Size%s     : %s%llu bytes%s\n",
               W, R, AD, (unsigned long long)bin->code_size, R);
    if (bin->data_size)
        printf(" %sData Size%s     : %s%llu bytes%s\n",
               W, R, DG, (unsigned long long)bin->data_size, R);
    if (bin->total_insns)
        printf(" %sInstructions%s  : %s%u%s\n",
               W, R, MT, bin->total_insns, R);
    if (bin->nsymbols)
        printf(" %sSymbols%s       : %s%d%s\n",   W, R, C, bin->nsymbols, R);
    if (bin->nfunctions)
        printf(" %sFunctions%s     : %s%d%s\n",   W, R, C, bin->nfunctions, R);
    if (bin->nblocks)
        printf(" %sCFG Blocks%s    : %s%d%s\n",   W, R, DG, bin->nblocks, R);
    if (bin->nxrefs)
        printf(" %sXrefs%s         : %s%d%s\n",   W, R, DG, bin->nxrefs, R);
    if (bin->nustrings)
        printf(" %sUnicode Strs%s  : %s%d%s\n",   W, R, DG, bin->nustrings, R);
    if (bin->ncomments)
        printf(" %sComments%s      : %s%d%s\n",   W, R, DG, bin->ncomments, R);

    printf(" %sPIE%s           : %s%s%s\n",
           W, R, MT, bin->is_pie ? "yes" : "no", R);
    printf(" %sStripped%s      : %s%s%s\n",
           W, R, MT, bin->is_stripped ? "yes" : "no", R);
    printf(" %sDebug Info%s    : %s%s%s\n",
           W, R, MT, bin->has_debug ? "yes" : "no", R);
    if (bin->build_id[0])
        printf(" %sBuild-ID%s      : %s%s%s\n",   W, R, DG, bin->build_id, R);
    if (bin->sha256[0])
        printf(" %sSHA-256%s       : %s%s%s\n",   W, R, MT, bin->sha256, R);

    neodax_header_line(color, bw);
    printf("\n");
}

void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts) {
    int c = opts ? opts->color : 1;
    int i;
    static const char *stlabel[] = {
        "code","data","rodata","bss","plt","got","dyn","dbg","other"
    };
    extern const char *dax_sec_type_color(dax_sec_type_t t, int color);

    printf("\n");
    if (c) printf("%s", COL_MNEM);
    printf("  %-28s %-8s %-18s %-12s %-14s %-8s %s\n",
           "Section","Type","VirtAddr","FileOffset","Size","Flags","Insns");
    if (c) printf("%s", COL_RESET);
    if (c) printf("%s", COL_COMMENT);
    { int j; for(j=0;j<110;j++) printf("─"); }
    if (c) printf("%s", COL_RESET);
    printf("\n");

    for (i = 0; i < bin->nsections; i++) {
        dax_section_t *s  = &bin->sections[i];
        const char    *tc = c ? dax_sec_type_color(s->type, 1) : "";
        const char    *rc = c ? COL_RESET : "";
        const char    *ac = c ? COL_ADDR  : "";
        const char    *mc = c ? COL_META  : "";

        printf("  %s%-28s%s %s%-8s%s %s0x%016llx%s  0x%010llx  %-14llu",
               tc, s->name, rc,
               tc, stlabel[s->type], rc,
               ac, (unsigned long long)s->vaddr, rc,
               (unsigned long long)s->offset,
               (unsigned long long)s->size);

        if (s->flags) {
            if (c) printf("%s", COL_COMMENT);
            printf("  [%s%s%s] ",
                   (s->flags & 0x4 || s->flags & 0x20000000) ? "x" : "-",
                   (s->flags & 0x2)                           ? "w" : "-",
                   (s->flags & 0x1)                           ? "r" : "-");
            if (c) printf("%s", COL_RESET);
        } else {
            printf("       ");
        }

        if (s->insn_count)
            printf(" %s%u insns%s", mc, s->insn_count, rc);

        printf("\n");
    }
    printf("\n");
}

const char *dax_arch_str(dax_arch_t a) {
    switch(a) {
        case ARCH_X86_64:  return "x86_64";
        case ARCH_ARM64:   return "AArch64 (ARM64)";
        case ARCH_RISCV64: return "RISC-V RV64GC";
        default:           return "unknown";
    }
}

const char *dax_fmt_str(dax_fmt_t f) {
    switch(f) {
        case FMT_ELF32: return "ELF32";
        case FMT_ELF64: return "ELF64";
        case FMT_PE32:  return "PE32";
        case FMT_PE64:  return "PE64+";
        case FMT_RAW:   return "Raw";
        default:        return "unknown";
    }
}

const char *dax_os_str(dax_os_t o) {
    switch(o) {
        case DAX_PLAT_LINUX:   return "Linux";
        case DAX_PLAT_ANDROID: return "Android";
        case DAX_PLAT_BSD:     return "BSD/macOS";
        case DAX_PLAT_UNIX:    return "UNIX/SysV";
        case DAX_PLAT_WINDOWS: return "Windows";
        default:               return "unknown";
    }
}

int main(int argc, char **argv) {
    dax_binary_t bin;
    dax_opts_t   opts;
    int          list_only  = 0;
    int          to_asm     = 0;
    int          is_daxc    = 0;
    int          i;
    const char  *filepath   = NULL;
    struct timespec ts_start, ts_end;

    dax_print_correction(argc, argv, stderr);

    memset(&bin,  0, sizeof(bin));
    memset(&opts, 0, sizeof(opts));
    opts.show_addr  = 1;
    opts.color      = 1;
    opts.start_addr = 0;
    opts.end_addr   = (uint64_t)-1;
    strncpy(opts.section, ".text", sizeof(opts.section)-1);

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            switch (argv[i][1]) {
                case 'a': opts.show_bytes   = 1; break;
                case 'n': opts.color        = 0; break;
                case 'v': opts.verbose      = 1; break;
                case 'l': list_only         = 1; break;
                case 'S': opts.all_sections = 1; break;
                case 'y': opts.symbols      = 1; break;
                case 'd': opts.demangle     = 1; break;
                case 'f': opts.funcs        = 1; break;
                case 'g': opts.groups       = 1; break;
                case 'r': opts.xrefs        = 1; break;
                case 't': opts.strings      = 1; break;
                case 'C': opts.cfg          = 1; break;
                case 'L': opts.loops        = 1; break;
                case 'G': opts.callgraph    = 1; break;
                case 'W': opts.switches     = 1; break;
                case 'u': opts.unicode      = 1; break;
                case 'P': opts.symexec     = 1; break;
                case 'Q': opts.ssa         = 1; break;
                case 'D': opts.decompile   = 1; break;
                case 'I': opts.emulate     = 1; break;
                case 'e': opts.entropy     = 1; break;
                case 'R': opts.rda         = 1; break;
                case 'V': opts.ivf         = 1; break;
                case 'c': to_asm            = 1; break;
                case 'x':
                    opts.symbols = opts.demangle = opts.funcs = 1;
                    opts.groups  = opts.xrefs = opts.strings = opts.cfg = 1;
                    opts.loops   = opts.callgraph = opts.switches = 1;
                    opts.unicode = 1;
                    break;
                case 'X':
                    opts.symbols = opts.demangle = opts.funcs = 1;
                    opts.groups  = opts.xrefs = opts.strings = opts.cfg = 1;
                    opts.loops   = opts.callgraph = opts.switches = 1;
                    opts.unicode = 1;
                    opts.symexec = opts.ssa = opts.decompile = opts.emulate = 1;
                    opts.entropy = opts.rda = opts.ivf = 1;
                    break;
                case 'h': print_usage(); return 0;
                case 's':
                    if (i+1 < argc) strncpy(opts.section, argv[++i], sizeof(opts.section)-1);
                    break;
                case 'A':
                    if (i+1 < argc) opts.start_addr = (uint64_t)strtoull(argv[++i],NULL,16);
                    break;
                case 'E':
                    if (i+1 < argc) opts.end_addr = (uint64_t)strtoull(argv[++i],NULL,16);
                    break;
                case 'o':
                    if (i+1 < argc) strncpy(opts.output_daxc, argv[++i], 511);
                    break;
                default:
                    fprintf(stderr, "neodax: unknown option '-%c'\n", argv[i][1]);
                    print_usage(); return 1;
            }
        } else {
            filepath = argv[i];
        }
    }

    if (!filepath) {
        fprintf(stderr, "neodax: no input file\n");
        print_usage(); return 1;
    }

    {
        size_t flen = strlen(filepath);
        if (flen > 5 && strcmp(filepath + flen - 5, ".daxc") == 0)
            is_daxc = 1;
    }

    if (is_daxc && to_asm) {
        char asm_path[520];
        size_t flen = strlen(filepath);
        strncpy(asm_path, filepath, 514);
        asm_path[flen - 5] = 0;
        strcat(asm_path, ".S");
        return dax_daxc_to_asm(filepath, asm_path, opts.color);
    }

    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    if (is_daxc) {
        if (dax_daxc_read(filepath, &bin) != 0) {
            fprintf(stderr, "neodax: failed to read '%s'\n", filepath);
            return 1;
        }
        dax_print_banner(&bin, &opts);
        if (list_only) { dax_print_sections(&bin, &opts); dax_free_binary(&bin); return 0; }
        if (bin.arch == ARCH_X86_64)
            dax_disasm_x86_64(&bin, &opts, stdout);
        else if (bin.arch == ARCH_ARM64)
            dax_disasm_arm64(&bin, &opts, stdout);
        else if (bin.arch == ARCH_RISCV64)
            dax_disasm_riscv64(&bin, &opts, stdout);

        if (opts.unicode)
            dax_print_unicode_strings(&bin, &opts, stdout);

        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        {
            double elapsed = (ts_end.tv_sec - ts_start.tv_sec) +
                             (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
            if (opts.color) printf("%s", COL_COMMENT);
            printf("\n  Analysis completed in %.3f seconds.\n", elapsed);
            if (opts.color) printf("%s", COL_RESET);
        }

        dax_free_binary(&bin);
        return 0;
    }

    if (dax_load_binary(filepath, &bin) != 0) {
        fprintf(stderr, "neodax: failed to load '%s'\n", filepath);
        return 1;
    }

    dax_compute_sha256(&bin);

    if (opts.callgraph) opts.xrefs = 1;
    if (opts.loops)     opts.cfg   = 1;
    if (opts.symexec || opts.ssa || opts.decompile || opts.emulate) {
        opts.funcs   = 1;
        opts.symbols = 1;
        opts.cfg     = 1;
    }

    if (opts.symbols || opts.funcs || opts.xrefs || opts.strings || opts.cfg) {
        dax_sym_load(&bin);
        if (opts.xrefs || opts.cfg)
            dax_xref_build(&bin);
    }

    if (opts.unicode)
        dax_scan_unicode(&bin);

    if ((opts.cfg || opts.loops)) {
        int si, fi;
        for (si = 0; si < bin.nsections; si++) {
            if (bin.sections[si].type == SEC_TYPE_CODE && bin.sections[si].size > 0) {
                uint8_t *code = bin.data + bin.sections[si].offset;
                size_t   sz   = (size_t)bin.sections[si].size;
                uint64_t base = bin.sections[si].vaddr;
                dax_func_detect(&bin, code, sz, base, &bin.sections[si]);
            }
        }
        for (fi = 0; fi < bin.nfunctions; fi++) {
            dax_func_t *fn = &bin.functions[fi];
            int si2;
            for (si2 = 0; si2 < bin.nsections; si2++) {
                dax_section_t *sec = &bin.sections[si2];
                if (fn->start >= sec->vaddr && fn->start < sec->vaddr + sec->size &&
                    sec->offset + sec->size <= bin.size) {
                    uint8_t *code = bin.data + sec->offset;
                    size_t   sz   = (size_t)sec->size;
                    uint64_t base = sec->vaddr;
                    dax_cfg_build(&bin, code, sz, base, fi);
                    break;
                }
            }
        }
    }

    dax_print_banner(&bin, &opts);

    if (list_only) {
        dax_print_sections(&bin, &opts);
        if (opts.output_daxc[0]) dax_daxc_write(&bin, &opts, opts.output_daxc);
        dax_free_binary(&bin);

        clock_gettime(CLOCK_MONOTONIC, &ts_end);
        {
            double elapsed = (ts_end.tv_sec - ts_start.tv_sec) +
                             (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
            if (opts.color) printf("%s", COL_COMMENT);
            printf("  Analysis completed in %.3f seconds.\n", elapsed);
            if (opts.color) printf("%s", COL_RESET);
        }
        return 0;
    }

    if (bin.arch == ARCH_X86_64)
        dax_disasm_x86_64(&bin, &opts, stdout);
    else if (bin.arch == ARCH_ARM64)
        dax_disasm_arm64(&bin, &opts, stdout);
    else if (bin.arch == ARCH_RISCV64)
        dax_disasm_riscv64(&bin, &opts, stdout);
    else {
        fprintf(stderr, "neodax: unsupported architecture\n");
        dax_free_binary(&bin); return 1;
    }

    if (opts.cfg) {
        int fi;
        printf("\n");
        if (opts.color) printf("%s", COL_FUNC);
        printf("  ══════════════ CONTROL FLOW GRAPHS ══════════════\n");
        if (opts.color) printf("%s", COL_RESET);
        for (fi = 0; fi < bin.nfunctions; fi++)
            dax_cfg_print(&bin, fi, &opts, stdout);
    }

    if (opts.loops)
        dax_loop_print_all(&bin, &opts, stdout);

    if (opts.callgraph)
        dax_callgraph_print(&bin, &opts, stdout);

    if (opts.switches) {
        int si;
        int col = opts.color;
        printf("\n");
        if (col) printf("%s", COL_FUNC);
        printf("  ══════════════ SWITCH DETECTION ══════════════\n");
        if (col) printf("%s", COL_RESET);
        for (si = 0; si < bin.nsections; si++) {
            if (bin.sections[si].type == SEC_TYPE_CODE &&
                bin.sections[si].size > 0 &&
                bin.sections[si].offset + bin.sections[si].size <= bin.size) {
                uint8_t *code = bin.data + bin.sections[si].offset;
                size_t   sz   = (size_t)bin.sections[si].size;
                uint64_t base = bin.sections[si].vaddr;
                if (col) printf("%s  [%s]%s\n", COL_SECTION, bin.sections[si].name, COL_RESET);
                dax_switch_detect(&bin, &opts, code, sz, base, stdout);
            }
        }
        printf("\n");
    }

    if (opts.unicode)
        dax_print_unicode_strings(&bin, &opts, stdout);

    if (opts.symexec)
        dax_symexec_all(&bin, &opts, stdout);

    if (opts.ssa)
        dax_ssa_lift_all(&bin, &opts, stdout);

    if (opts.decompile)
        dax_decompile_all(&bin, &opts, stdout);

    if (opts.emulate)
        dax_emulate_all(&bin, &opts, stdout);

    if (opts.entropy)
        dax_entropy_scan(&bin, &opts, stdout);

    if (opts.rda)
        dax_rda_all(&bin, &opts, stdout);

    if (opts.ivf)
        dax_ivf_scan(&bin, &opts, stdout);

    if (opts.output_daxc[0])
        dax_daxc_write(&bin, &opts, opts.output_daxc);

    dax_free_binary(&bin);

    clock_gettime(CLOCK_MONOTONIC, &ts_end);
    {
        double elapsed = (ts_end.tv_sec - ts_start.tv_sec) +
                         (ts_end.tv_nsec - ts_start.tv_nsec) / 1e9;
        if (opts.color) printf("%s", COL_COMMENT);
        printf("\n  Analysis completed in %.3f seconds.\n", elapsed);
        if (opts.color) printf("%s", COL_RESET);
    }

    return 0;
}
