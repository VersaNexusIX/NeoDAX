#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <signal.h>
#include "dax.h"
#include "dax_guard.h"
#include "arm64.h"
#include "x86.h"

#define T_RST   "\033[0m"
#define T_BOLD  "\033[1m"
#define T_RED   "\033[1;31m"
#define T_GRN   "\033[1;32m"
#define T_YEL   "\033[1;33m"
#define T_BLU   "\033[1;34m"
#define T_MAG   "\033[1;35m"
#define T_CYN   "\033[0;36m"
#define T_WHT   "\033[1;37m"
#define T_GRY   "\033[0;90m"
#define T_DRED  "\033[0;31m"
#define T_DGRN  "\033[0;32m"
#define T_DYEL  "\033[0;33m"
#define T_DBLU  "\033[0;34m"
#define T_DCYN  "\033[0;36m"

#define BOX_H   "\u2500"
#define BOX_V   "\u2502"
#define BOX_LM  "\u251c"
#define BOX_RM  "\u2524"
#define BOX_DH  "\u2550"
#define BOX_DTL "\u2554"
#define BOX_DTR "\u2557"
#define BOX_DBL "\u255a"
#define BOX_DBR "\u255d"
#define BOX_DV  "\u2551"
#define SYM_OK  "\u2714"
#define SYM_ERR "\u2718"
#define SYM_ARR "\u2192"
#define SYM_DOT "\u25cf"
#define SYM_TRI "\u25b6"

static int tui_width(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 40)
        return (int)w.ws_col;
    return 80;
}

static void tui_panel_header(int color, const char *title, int width) {
    int tlen = (int)strlen(title);
    int pad  = width - 4 - tlen;
    int i;
    const char *C = color ? T_GRY : "";
    const char *Y = color ? T_YEL : "";
    const char *R = color ? T_RST : "";
    if (pad < 0) pad = 0;
    fprintf(stdout, "\n");
    fprintf(stdout, "  %s" BOX_DTL, C);
    fprintf(stdout, " %s%s%s ", Y, title, C);
    for (i = 0; i < pad; i++) fprintf(stdout, BOX_DH);
    fprintf(stdout, BOX_DTR "%s\n", R);
}

static void tui_panel_footer(int color, int width) {
    int i;
    const char *C = color ? T_GRY : "";
    const char *R = color ? T_RST : "";
    fprintf(stdout, "  %s" BOX_DBL, C);
    for (i = 0; i < width - 2; i++) fprintf(stdout, BOX_DH);
    fprintf(stdout, BOX_DBR "%s\n\n", R);
}

static void tui_psec(int color, const char *label, int width) {
    int i;
    const char *C = color ? T_GRY : "";
    const char *Y = color ? T_YEL : "";
    const char *R = color ? T_RST : "";
    int pad = width - 6 - (int)strlen(label);
    if (pad < 0) pad = 0;
    fprintf(stdout, "  %s" BOX_LM BOX_DH " %s%s%s ", C, Y, label, C);
    for (i = 0; i < pad; i++) fprintf(stdout, BOX_DH);
    fprintf(stdout, BOX_RM "%s\n", R);
}

static void tui_status(int color, dax_binary_t *bin, uint64_t cursor) {
    int w = tui_width();
    int i;
    const char *C = color ? T_GRY  : "";
    const char *Y = color ? T_YEL  : "";
    const char *G = color ? T_DGRN : "";
    const char *B = color ? T_DBLU : "";
    const char *W = color ? T_WHT  : "";
    const char *R = color ? T_RST  : "";
    const char *arch_s = "?";

    if (bin) {
        switch (bin->arch) {
            case ARCH_ARM64:   arch_s = "arm64";   break;
            case ARCH_X86_64:  arch_s = "x86_64";  break;
            case ARCH_RISCV64: arch_s = "riscv64"; break;
            default: break;
        }
    }

    fprintf(stdout, "\n  %s", C);
    for (i = 0; i < w - 4; i++) fprintf(stdout, BOX_H);
    fprintf(stdout, "%s\n", R);

    fprintf(stdout, "  %s* %s", G, R);
    if (bin && bin->filepath[0]) {
        const char *fname = strrchr(bin->filepath, '/');
        fname = fname ? fname + 1 : bin->filepath;
        fprintf(stdout, "%s%-20s%s", W, fname, R);
    } else {
        fprintf(stdout, "%s%-20s%s", C, "(no binary)", R);
    }
    fprintf(stdout, "  %s-> %s%s%s", C, Y, arch_s, R);
    if (bin)
        fprintf(stdout, "  %sfuncs=%s%d%s  syms=%s%d%s",
                C, B, bin->nfunctions, R, C, bin->nsymbols, R);
    fprintf(stdout, "  %scursor=%s0x%016llx%s\n",
            C, B, (unsigned long long)cursor, R);

    fprintf(stdout, "  %s", C);
    for (i = 0; i < w - 4; i++) fprintf(stdout, BOX_H);
    fprintf(stdout, "%s\n", R);
}

static uint64_t parse_addr(dax_binary_t *bin, const char *s) {
    int i;
    if (!s || !s[0]) return 0;
    if (s[0] == '0' && s[1] == 'x') return strtoull(s, NULL, 16);
    if (isdigit((unsigned char)s[0])) return strtoull(s, NULL, 0);
    if (bin) {
        for (i = 0; i < bin->nsymbols && i < DAX_MAX_SYMBOLS; i++)
            if (!strcmp(bin->symbols[i].name, s) ||
                !strcmp(bin->symbols[i].demangled, s))
                return bin->symbols[i].address;
        for (i = 0; i < bin->nfunctions; i++)
            if (!strcmp(bin->functions[i].name, s))
                return bin->functions[i].start;
    }
    return 0;
}

static int find_func(dax_binary_t *bin, const char *s) {
    int i;
    uint64_t addr = parse_addr(bin, s);
    for (i = 0; i < bin->nfunctions; i++) {
        char tmp[32];
        if (addr && bin->functions[i].start == addr) return i;
        if (!strcmp(bin->functions[i].name, s)) return i;
        snprintf(tmp, 32, "sub_%llx", (unsigned long long)bin->functions[i].start);
        if (!strcmp(tmp, s)) return i;
    }
    return -1;
}

static void hexdump(dax_binary_t *bin, uint64_t addr, int nbytes, int color) {
    int si;
    const char *CR = color ? T_RST  : "";
    const char *CA = color ? T_BLU  : "";
    const char *CH = color ? T_DGRN : "";
    const char *CX = color ? T_GRY  : "";

    if (!bin) return;
    if (addr == 0) { fprintf(stdout, "  address is 0\n"); return; }
    if (nbytes <= 0) nbytes = 256;
    if (nbytes > 65536) { fprintf(stdout, "  capped at 65536\n"); nbytes = 65536; }

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        size_t off;
        uint8_t *data;
        size_t avail;
        int row;
        if (addr < sec->vaddr || addr >= sec->vaddr + sec->size) continue;
        if (sec->offset + sec->size > bin->size) continue;
        off   = (size_t)(addr - sec->vaddr);
        data  = bin->data + sec->offset + off;
        avail = sec->size - off;
        if ((size_t)nbytes > avail) nbytes = (int)avail;
        for (row = 0; row < nbytes; row += 16) {
            int col;
            fprintf(stdout, "  %s0x%016llx%s  ",
                    CA, (unsigned long long)(addr + (uint64_t)row), CR);
            for (col = 0; col < 16; col++) {
                if (row + col < nbytes)
                    fprintf(stdout, "%s%02x%s ", CH, data[row + col], CR);
                else fprintf(stdout, "   ");
                if (col == 7) fprintf(stdout, " ");
            }
            fprintf(stdout, " %s|%s", CX, CR);
            for (col = 0; col < 16 && row + col < nbytes; col++) {
                unsigned char ch = data[row + col];
                fprintf(stdout, "%s%c%s", CX,
                        (ch >= 0x20 && ch < 0x7f) ? (char)ch : '.', CR);
            }
            fprintf(stdout, "%s|%s\n", CX, CR);
        }
        return;
    }
    fprintf(stdout, "  %sx 0x%llx not in any section%s\n",
            color ? T_DYEL : "", (unsigned long long)addr, color ? T_RST : "");
}

static void disasm_range(dax_binary_t *bin, uint64_t addr, int ninsns, dax_opts_t *opts) {
    dax_opts_t o;
    int si;
    if (!bin || !opts) return;
    if (addr == 0) {
        fprintf(stdout, "  %sx address is 0  --  use seek first%s\n",
                opts->color ? T_DYEL : "", opts->color ? T_RST : "");
        return;
    }
    if (ninsns <= 0 || ninsns > 4096) ninsns = 32;
    o = *opts;
    o.start_addr = addr;
    o.end_addr   = 0;
    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        uint64_t est;
        if (addr < sec->vaddr || addr >= sec->vaddr + sec->size) continue;
        est = addr + (uint64_t)(ninsns * (bin->arch == ARCH_X86_64 ? 15 : 4));
        if (est > sec->vaddr + sec->size) est = sec->vaddr + sec->size;
        o.end_addr = est;
        break;
    }
    if (o.end_addr == 0) o.end_addr = addr + (uint64_t)(ninsns * 4);
    if (bin->arch == ARCH_X86_64)    dax_disasm_x86_64(bin, &o, stdout);
    else if (bin->arch == ARCH_ARM64) dax_disasm_arm64(bin, &o, stdout);
}

static void cmd_run(dax_binary_t *bin, dax_opts_t *opts, const char *arg) {
    int fi = -1;
    int i;
    if (!bin || bin->nfunctions == 0) {
        fprintf(stdout, "  %sx no binary loaded or no functions%s\n",
                opts && opts->color ? T_DRED : "", opts && opts->color ? T_RST : "");
        return;
    }
    if (arg && arg[0]) {
        fi = find_func(bin, arg);
        if (fi < 0) {
            fprintf(stdout, "  %sx function '%s' not found%s\n",
                    opts && opts->color ? T_DRED : "", arg,
                    opts && opts->color ? T_RST : "");
            return;
        }
    }
    if (fi < 0) {
        for (i = 0; i < bin->nfunctions; i++) {
            if (!strcmp(bin->functions[i].name, "main") ||
                !strcmp(bin->functions[i].name, "_start")) { fi = i; break; }
        }
        if (fi < 0 && bin->nfunctions > 0) fi = 0;
    }
    if (fi < 0) { fprintf(stdout, "  no functions found\n"); return; }
    fprintf(stdout, "\n  %s> emulating %s%s\n\n",
            opts && opts->color ? T_GRN : "",
            bin->functions[fi].name,
            opts && opts->color ? T_RST : "");
    dax_emulate_func(bin, fi, NULL, 0, opts, stdout);
}

static void print_help(int color) {
    int w = tui_width();
    const char *Y = color ? T_YEL  : "";
    const char *G = color ? T_DGRN : "";
    const char *B = color ? T_DCYN : "";
    const char *W = color ? T_WHT  : "";
    const char *M = color ? T_MAG  : "";
    const char *R = color ? T_RST  : "";

#define PCMD(cmd,args,desc) \
    do { \
        fprintf(stdout,"  |  %s%-22s%s %s%-18s%s %s\n", \
                B,cmd,R,G,args,R,desc); \
    } while(0)

    tui_panel_header(color, "NeoDAX Interactive Shell  v1.1.1", w - 4);
    fprintf(stdout, "  |\n");
    tui_psec(color, "NAVIGATE", w - 4);
    PCMD("pd / p / pdf",    "[func|addr] [n]", "disassemble function or N instructions");
    PCMD("? / info / i",    "[addr|symbol]",   "sym + func + xrefs at address");
    PCMD("is",              "",                "binary header + section table");
    PCMD("fl / afl",        "",                "list all detected functions");
    PCMD("sl",              "",                "list all symbols");
    PCMD("xr / axt",        "[addr|symbol]",   "cross-references to address");
    PCMD("seek / s",        "<addr|symbol>",   "move analysis cursor");
    fprintf(stdout, "  |\n");
    tui_psec(color, "ANALYSIS", w - 4);
    PCMD("cfg / agf",       "[func]",   "control flow graph");
    PCMD("ssa",             "[func]",   "NR — NeoDAX Representation (lifted from binary)");
    PCMD("dsa",             "[func|all]","DSA — Dynamic Single Assignment (omit=usage, all=full scan)");
    PCMD("dec / pdg",       "[func]",   "decompile to pseudo-C");
    PCMD("sym / symexec",   "[func]",   "symbolic execution");
    PCMD("ivf / aa",        "",         "instruction validity filter + obfuscation scan");
    PCMD("poly / pm",       "",         "polymorphic obfuscation map (region detection)");
    PCMD("aire / ai",       "",         "AIRE: Assisted Intelligence Reverse Engineering");
    PCMD("vmtrace / vt",    "",         "VM dispatch flow trace (from last emulation)");
    PCMD("ent / entropy",   "",         "entropy / packed region scan");
    PCMD("cg / agc",        "",         "call graph tree");
    PCMD("rda",             "",         "recursive descent disassembly");
    fprintf(stdout, "  |\n");
    tui_psec(color, "EMULATE", w - 4);
    PCMD("run / r",         "[func]",   "emulate: full run from start (clears step state)");
    PCMD("step / si",       "init [f]", "init step session for func f");
    PCMD("step / si",       "[n]",      "advance N instructions from last PC (default 1)");
    PCMD("step reset",      "",         "clear active step session");
    PCMD("reg / dr",        "[func]",   "register dump after emulation");
    fprintf(stdout, "  |\n");
    tui_psec(color, "MEMORY", w - 4);
    PCMD("px / x",          "[addr] [n]", "hex dump N bytes");
    PCMD("string / ps",     "[addr]",     "print string at address");
    fprintf(stdout, "  |\n");
    tui_psec(color, "ANNOTATE", w - 4);
    PCMD("cc / CC",         "<addr> <text>", "add/update comment");
    PCMD("rename / afn",    "<old> <new>",   "rename function");
    fprintf(stdout, "  |\n");
    tui_psec(color, "SHELL / MISC", w - 4);
    PCMD("o / open",        "<path>",    "load binary");
    PCMD("grep / /",        "<pattern>", "grep hex pattern");
    PCMD("!<cmd>",          "",          "run shell command");
    PCMD("q / quit",        "",          "exit");
    PCMD("help / ?",        "",          "this reference");
    fprintf(stdout, "  |\n");
    tui_psec(color, "ALIASES", w - 4);
    fprintf(stdout, "  |  %spd=p=pdf  fl=afl  xr=axt  cfg=agf  cg=agc\n",G);
    fprintf(stdout, "  |  %sdec=pdg  sym=symexec  ent=entropy  ivf=aa\n", G);
    fprintf(stdout, "  |  %srun=r  reg=dr  px=x  cc=CC  o=open  seek=s\n",G);
    fprintf(stdout, "  |\n");
    tui_psec(color, "TIPS", w - 4);
    fprintf(stdout,"  |  %s* func accepts: name, hex addr, sub_<addr>\n",M);
    fprintf(stdout,"  |  %s* omit func to use current cursor\n",M);
    fprintf(stdout,"  |  %s* %sseek main%s + %spd%s  -> jump + disassemble\n",M,R,B,R,B);
    fprintf(stdout,"  |  %s* %s? 0x<addr>%s  shows sym, func owner, xrefs\n",M,R,B);
    fprintf(stdout, "  |\n");
    tui_panel_footer(color, w - 4);
    (void)Y; (void)W;
#undef PCMD
}

static int tokenise(char *line, char *argv[], int max) {
    int n = 0;
    char *p = line;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        argv[n++] = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) { *p = '\0'; p++; }
    }
    return n;
}

static void print_prompt(dax_binary_t *bin, int color) {
    const char *fname = (bin && bin->filepath[0])
        ? strrchr(bin->filepath, '/') : NULL;
    if (fname) fname++;
    else if (bin) fname = bin->filepath;
    else fname = "?";
    if (color)
        fprintf(stdout,
                "\033[0;90m|\033[0m "
                "\033[1;32m%s\033[0m"
                "\033[0;90m ->\033[0m "
                "\033[1;34m>\033[0m ",
                fname);
    else
        fprintf(stdout, "[dax:%s]> ", fname);
    fflush(stdout);
}

int dax_interactive(dax_binary_t *bin, dax_opts_t *opts) {
    char    line[2048];
    char   *argv[32];
    int     argc;
    int     c = opts ? opts->color : 1;
    int     w = tui_width();
    uint64_t cursor;
    int     first_run = 1;

    DAX_GUARD_BIN_RET(bin, -1);
    cursor = bin->entry;

    const char *C = c ? T_GRY  : "";
    const char *R = c ? T_RST  : "";
    const char *W = c ? T_WHT  : "";
    const char *Y = c ? T_YEL  : "";

    tui_panel_header(c, "NeoDAX Interactive Shell", w - 4);
    if (bin && bin->filepath[0]) {
        const char *fname = strrchr(bin->filepath, '/');
        fname = fname ? fname + 1 : bin->filepath;
        fprintf(stdout, "  %s|  %s+  loaded  %s%-30s%s\n",
                C, R, W, fname, R);
    }
    fprintf(stdout, "  %s|  %stype %shelp%s or %s?%s for reference%s\n",
            C, R, Y, R, Y, R, R);
    fprintf(stdout, "  |\n");
    tui_panel_footer(c, w - 4);

    if (opts && opts->initial_shell_cmd[0]) {
        fprintf(stdout, "  %s-> auto: %s%s%s\n\n",
                c ? T_GRY : "", c ? T_YEL : "",
                opts->initial_shell_cmd, c ? T_RST : "");
        strncpy(line, opts->initial_shell_cmd, sizeof(line) - 1);
        line[sizeof(line) - 1] = '\0';
        opts->initial_shell_cmd[0] = '\0';
        argc = tokenise(line, argv, 32);
        if (argc > 0) {
            first_run = 0;
            goto dispatch;
        }
    }

    for (;;) {
        const char *cmd;

        if (!first_run) tui_status(c, bin, cursor);
        first_run = 0;
        print_prompt(bin, c);

        if (!fgets(line, sizeof(line), stdin)) {
            fprintf(stdout, "\n");
            break;
        }
        { char *nl = strchr(line, '\n'); if (nl) *nl = '\0'; }
        { char *p = line; while (*p == ' ' || *p == '\t') p++; if (!*p) continue; }

        argc = tokenise(line, argv, 32);
        if (argc == 0) continue;

dispatch:
        cmd = argv[0];

        if (!strcmp(cmd,"q")||!strcmp(cmd,"quit")||!strcmp(cmd,"exit")) {
            fprintf(stdout, "\n  %s" BOX_DBL BOX_DH " bye.%s\n\n", c?T_GRY:"", R);
            break;
        }

        if (!strcmp(cmd,"help")||(!strcmp(cmd,"?")&&argc==1)) {
            print_help(c); continue;
        }

        if (cmd[0] == '!') {
            const char *shell_cmd = line + 1;
            while (*shell_cmd == ' ') shell_cmd++;
            if (!shell_cmd[0]) { fprintf(stdout,"  usage: !<command>\n"); continue; }
            {
                int pip[2];
                if (pipe(pip) != 0) {
                    fprintf(stdout,"  x pipe failed\n"); continue;
                }
                {
                    pid_t pid = fork();
                    if (pid < 0) {
                        close(pip[0]); close(pip[1]);
                        fprintf(stdout,"  x fork failed\n"); continue;
                    }
                    if (pid == 0) {
                        close(pip[0]);
                        dup2(pip[1], STDOUT_FILENO);
                        dup2(pip[1], STDERR_FILENO);
                        close(pip[1]);
                        execl("/bin/sh","sh","-c",shell_cmd,(char*)NULL);
                        execl("/system/bin/sh","sh","-c",shell_cmd,(char*)NULL);
                        _exit(127);
                    }
                    close(pip[1]);
                    {
                        int flags = fcntl(pip[0], F_GETFL, 0);
                        fcntl(pip[0], F_SETFL, flags | O_NONBLOCK);
                    }
                    {
                        char buf[4096];
                        size_t total = 0;
                        int done = 0, trunc = 0;
                        while (!done && !trunc) {
                            fd_set rds;
                            struct timeval tv = {5,0};
                            ssize_t nr;
                            ssize_t wi;
                            FD_ZERO(&rds); FD_SET(pip[0],&rds);
                            if (select(pip[0]+1,&rds,NULL,NULL,&tv)<=0) break;
                            nr = read(pip[0], buf, sizeof(buf));
                            if (nr <= 0) { done = 1; break; }
                            for (wi=0;wi<nr;wi++) {
                                unsigned char ch=(unsigned char)buf[wi];
                                fputc((ch=='\n'||ch=='\r'||ch=='\t'||(ch>=0x20&&ch<0x7f))?(int)ch:'.',stdout);
                            }
                            fflush(stdout);
                            total += (size_t)nr;
                            if (total >= 256*1024) trunc=1;
                        }
                        close(pip[0]);
                        {
                            int ws=0;
                            pid_t rp=waitpid(pid,&ws,WNOHANG);
                            if (rp==0) {
                                struct timeval tv2={2,0}; fd_set d; FD_ZERO(&d);
                                select(0,&d,NULL,NULL,&tv2);
                                waitpid(pid,&ws,WNOHANG);
                                if (rp==0) kill(pid,SIGTERM);
                                waitpid(pid,&ws,0);
                            }
                            if (total==0&&WEXITSTATUS(ws)!=0)
                                fprintf(stdout,"  %sexited %d%s\n",c?T_DYEL:"",WEXITSTATUS(ws),R);
                        }
                        if (trunc) fprintf(stdout,"\n  %s[truncated @ 256KB]%s\n",c?T_GRY:"",R);
                        fflush(stdout);
                    }
                }
            }
            continue;
        }

        if (!strcmp(cmd,"o")||!strcmp(cmd,"open")) {
            if (argc<2) { fprintf(stdout,"  x usage: o <filepath>\n"); continue; }
            if (bin) dax_free_binary(bin);
            memset(bin, 0, sizeof(dax_binary_t));
            if (dax_load_binary(argv[1], bin) != 0) {
                fprintf(stdout,"  %sx could not load: %s%s\n",c?T_DRED:"",argv[1],R);
                continue;
            }
            dax_sym_load(bin); dax_xref_build(bin); dax_compute_sha256(bin);
            dax_print_banner(bin, opts);
            cursor = bin->entry;
            fprintf(stdout,"  %s+ %s%s\n",c?T_DGRN:"",argv[1],R);
            continue;
        }

        if (!strcmp(cmd,"is")||!strcmp(cmd,"i")||!strcmp(cmd,"info")) {
            if (bin) { dax_print_banner(bin, opts); dax_print_sections(bin, opts); }
            continue;
        }

        if (!strcmp(cmd,"fl")||!strcmp(cmd,"afl")) {
            int i;
            if (!bin) continue;
            fprintf(stdout,"\n  %s%-6s  %-18s  %-10s  %s%s\n",
                    c?T_YEL:"","IDX","ADDR","SIZE","NAME",R);
            fprintf(stdout,"  %s",c?T_GRY:"");
            { int j; for(j=0;j<56;j++) fprintf(stdout,BOX_H); }
            fprintf(stdout,"%s\n",R);
            for (i=0;i<bin->nfunctions;i++) {
                dax_func_t *fn=&bin->functions[i];
                /* Derive end from nearest next func/symbol if not set */
                if (fn->end == 0 || fn->end <= fn->start) {
                    uint64_t nearest = (uint64_t)-1;
                    int j;
                    for (j=0;j<bin->nfunctions;j++) {
                        if (j==i) continue;
                        if (bin->functions[j].start > fn->start &&
                            bin->functions[j].start < nearest)
                            nearest = bin->functions[j].start;
                    }
                    for (j=0;j<bin->nsymbols;j++) {
                        if (bin->symbols[j].address > fn->start &&
                            bin->symbols[j].address < nearest)
                            nearest = bin->symbols[j].address;
                    }
                    if (nearest != (uint64_t)-1)
                        fn->end = nearest;
                }
                uint64_t sz2=(fn->end>fn->start)?fn->end-fn->start:0;
                fprintf(stdout,"  %s%-6d%s  %s0x%016llx%s  %s%-10llu%s  %s%s%s\n",
                        c?T_GRY:"",i,R,
                        c?T_BLU:"",(unsigned long long)fn->start,R,
                        c?T_GRY:"",(unsigned long long)sz2,R,
                        c?T_WHT:"",fn->name[0]?fn->name:"(unnamed)",R);
            }
            fprintf(stdout,"\n  %s%d function(s)%s\n\n",c?T_GRY:"",bin->nfunctions,R);
            continue;
        }

        if (!strcmp(cmd,"sl")||!strcmp(cmd,"is~sym")) {
            int i;
            if (!bin) continue;
            fprintf(stdout,"\n  %s%-18s  %-10s  %s%s\n",c?T_YEL:"","ADDR","TYPE","NAME",R);
            fprintf(stdout,"  %s",c?T_GRY:"");
            { int j; for(j=0;j<56;j++) fprintf(stdout,BOX_H); }
            fprintf(stdout,"%s\n",R);
            for (i=0;i<bin->nsymbols;i++) {
                dax_symbol_t *sym=&bin->symbols[i];
                const char *tn=(sym->type==SYM_FUNC)?"func":
                               (sym->type==SYM_OBJECT)?"object":
                               (sym->type==SYM_IMPORT)?"import":"local";
                fprintf(stdout,"  %s0x%016llx%s  %s%-10s%s  %s%s%s\n",
                        c?T_BLU:"",(unsigned long long)sym->address,R,
                        c?T_GRY:"",tn,R,
                        c?T_WHT:"",sym->demangled[0]?sym->demangled:sym->name,R);
            }
            fprintf(stdout,"\n  %s%d symbol(s)%s\n\n",c?T_GRY:"",bin->nsymbols,R);
            continue;
        }

        if (!strcmp(cmd,"xr")||!strcmp(cmd,"axt")) {
            dax_xref_t xbuf[64];
            int nx, i;
            uint64_t addr2;
            if (!bin) continue;
            addr2=(argc>=2)?parse_addr(bin,argv[1]):cursor;
            if (addr2==0&&argc>=2) {
                fprintf(stdout,"  %sx unknown: %s%s\n",c?T_DYEL:"",argv[1],R);
                continue;
            }
            nx=dax_xref_find_to(bin,addr2,xbuf,64);
            fprintf(stdout,"\n  %sxrefs -> %s0x%llx%s\n",
                    c?T_GRY:"",c?T_BLU:"",(unsigned long long)addr2,R);
            if (nx==0) fprintf(stdout,"  %s(none)%s\n",c?T_GRY:"",R);
            else for (i=0;i<nx;i++)
                fprintf(stdout,"  %s0x%016llx%s  %s(%s)%s\n",
                        c?T_BLU:"",(unsigned long long)xbuf[i].from,R,
                        c?T_GRY:"",xbuf[i].is_call?"call":"jmp",R);
            fprintf(stdout,"\n");
            continue;
        }

        if (!strcmp(cmd,"pd")||!strcmp(cmd,"pdf")||!strcmp(cmd,"p")) {
            uint64_t da; int dn;
            if (!bin) continue;
            da=cursor; dn=32;
            if (argc>=2) {
                int fi2=find_func(bin,argv[1]);
                if (fi2>=0) {
                    dax_func_t *pdfn = &bin->functions[fi2];
                    da = pdfn->start;
                    /* Derive end if not set */
                    if (pdfn->end == 0 || pdfn->end <= da) {
                        uint64_t nearest = (uint64_t)-1;
                        int _j;
                        for (_j=0;_j<bin->nfunctions;_j++) {
                            if (_j==fi2) continue;
                            if (bin->functions[_j].start > da &&
                                bin->functions[_j].start < nearest)
                                nearest = bin->functions[_j].start;
                        }
                        for (_j=0;_j<bin->nsymbols;_j++) {
                            if (bin->symbols[_j].address > da &&
                                bin->symbols[_j].address < nearest)
                                nearest = bin->symbols[_j].address;
                        }
                        if (nearest != (uint64_t)-1) pdfn->end = nearest;
                    }
                    dn=(pdfn->end>da)
                       ?(int)((pdfn->end-da)/(bin->arch==ARCH_X86_64?6:4))+4:64;
                } else { da=parse_addr(bin,argv[1]); if(!da) da=cursor; }
            }
            if (argc>=3) dn=(int)strtol(argv[2],NULL,0);
            cursor=da;
            if (da==0) { fprintf(stdout,"  x unknown address/function\n"); continue; }
            disasm_range(bin, da, dn, opts);
            continue;
        }

        if (!strcmp(cmd,"?")||!strcmp(cmd,"is~")) {
            uint64_t addr2; dax_func_t *fn; dax_symbol_t *sym;
            if (!bin) continue;
            addr2=(argc>=2)?parse_addr(bin,argv[1]):cursor;
            if (addr2==0&&argc>=2) {
                fprintf(stdout,"  %sx unknown: %s%s\n",c?T_DYEL:"",argv[1],R);
                continue;
            }
            fn=dax_func_find(bin,addr2); sym=dax_sym_find(bin,addr2);
            fprintf(stdout,"\n  %s0x%llx%s\n",c?T_BLU:"",(unsigned long long)addr2,R);
            if (sym) {
                const char *sn=sym->demangled[0]?sym->demangled:sym->name;
                fprintf(stdout,"  %ssymbol%s  %s%s%s\n",c?T_GRY:"",R,c?T_WHT:"",sn,R);
            }
            if (fn) {
                uint64_t fsz=(fn->end>fn->start)?fn->end-fn->start:0;
                fprintf(stdout,"  %sfunc  %s  %s%s%s  %s(%llu bytes)%s\n",
                        c?T_GRY:"",R,c?T_WHT:"",fn->name,R,
                        c?T_GRY:"",(unsigned long long)fsz,R);
            }
            {
                dax_xref_t xb2[16]; int nx2=dax_xref_find_to(bin,addr2,xb2,16); int i2;
                if (nx2>0) {
                    fprintf(stdout,"  %sxrefs%s",c?T_GRY:"",R);
                    for(i2=0;i2<nx2;i2++)
                        fprintf(stdout," %s0x%llx%s",c?T_BLU:"",(unsigned long long)xb2[i2].from,R);
                    fprintf(stdout,"\n");
                }
            }
            fprintf(stdout,"\n");
            continue;
        }

        if (!strcmp(cmd,"cfg")||!strcmp(cmd,"agf")) {
            int fi3;
            if (!bin) continue;
            fi3=(argc>=2)?find_func(bin,argv[1]):0;
            if (fi3<0) fi3=0;

            /* Build CFG on demand if blocks not yet populated for this func */
            {
                int has_blocks = 0, bi;
                for (bi = 0; bi < bin->nblocks && bi < DAX_MAX_BLOCKS; bi++) {
                    if (bin->blocks[bi].func_idx == fi3) { has_blocks = 1; break; }
                }
                if (!has_blocks && fi3 >= 0 && fi3 < bin->nfunctions && fi3 < DAX_MAX_FUNCTIONS) {
                    int si2;
                    dax_func_t *fn = &bin->functions[fi3];
                    for (si2 = 0; si2 < bin->nsections && si2 < DAX_MAX_SECTIONS; si2++) {
                        dax_section_t *sec = &bin->sections[si2];
                        if (fn->start >= sec->vaddr &&
                            fn->start <  sec->vaddr + sec->size &&
                            sec->offset + sec->size <= bin->size) {
                            dax_cfg_build(bin,
                                          bin->data + sec->offset,
                                          (size_t)sec->size,
                                          sec->vaddr, fi3);
                            break;
                        }
                    }
                }
            }

            dax_cfg_print(bin,fi3,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"ssa")) {
            int fi4;
            if (!bin) continue;
            fi4=(argc>=2)?find_func(bin,argv[1]):0;
            if (fi4<0) fi4=0;
            dax_ssa_lift_func(bin,fi4,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"dsa")) {
            if (!bin) continue;
            /* 'dsa all' — run DSA over every function and print summary */
            if (argc >= 2 && !strcmp(argv[1],"all")) {
                dsa_func_t *df_all = (dsa_func_t *)calloc(1, DAX_DSA_FUNC_SIZE);
                if (!df_all) { fprintf(stdout, "  out of memory\n"); continue; }
                int fi_all;
                for (fi_all = 0; fi_all < bin->nfunctions && fi_all < DAX_MAX_FUNCTIONS; fi_all++) {
                    dax_dsa_build_func(bin, fi_all, df_all);
                    dax_dsa_print(bin, fi_all, df_all, opts, stdout);
                    memset(df_all, 0, DAX_DSA_FUNC_SIZE);
                }
                free(df_all);
                continue;
            }
            /* no argument — show usage hint instead of segfaulting */
            if (argc < 2) {
                const char *CH     = opts->color ? "\033[1;36m" : "";
                const char *CG     = opts->color ? "\033[1;32m" : "";
                const char *CD     = opts->color ? "\033[0;90m" : "";
                const char *CReset = opts->color ? "\033[0m"    : "";
                fprintf(stdout, "\n  %sDSA — Dynamic Single Assignment%s\n\n", CH, CReset);
                fprintf(stdout, "  %sUsage:%s\n", CD, CReset);
                fprintf(stdout, "    %sdsa%s <func_name|index>   %sanalyse one function%s\n",
                        CG, CReset, CD, CReset);
                fprintf(stdout, "    %sdsa all%s                  %sanalyse all functions%s\n",
                        CG, CReset, CD, CReset);
                if (bin->nfunctions > 0) {
                    fprintf(stdout, "\n  %sAvailable functions (first 10):%s\n", CD, CReset);
                    int fi_hint, lim = bin->nfunctions < 10 ? bin->nfunctions : 10;
                    for (fi_hint = 0; fi_hint < lim; fi_hint++)
                        fprintf(stdout, "    %s[%d]%s  %s%s%s\n",
                                CD, fi_hint, CReset,
                                CG, bin->functions[fi_hint].name[0]
                                    ? bin->functions[fi_hint].name : "<unnamed>", CReset);
                    if (bin->nfunctions > 10)
                        fprintf(stdout, "    %s... and %d more  (use 'fl' to list all)%s\n",
                                CD, bin->nfunctions - 10, CReset);
                }
                fprintf(stdout, "\n");
                continue;
            }
            int fi_dsa = find_func(bin, argv[1]);
            if (fi_dsa < 0) {
                fprintf(stdout, "  function not found: %s\n", argv[1]);
                continue;
            }
            {
                dsa_func_t *df_buf = (dsa_func_t *)calloc(1, DAX_DSA_FUNC_SIZE);
                if (!df_buf) { fprintf(stdout, "  out of memory\n"); continue; }
                dax_dsa_build_func(bin, fi_dsa, df_buf);
                dax_dsa_print(bin, fi_dsa, df_buf, opts, stdout);
                free(df_buf);
            }
            continue;
        }

        if (!strcmp(cmd,"dec")||!strcmp(cmd,"pdg")) {
            int fi5;
            if (!bin) continue;
            fi5=(argc>=2)?find_func(bin,argv[1]):0;
            if (fi5<0) fi5=0;
            dax_decompile_func(bin,fi5,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"sym")||!strcmp(cmd,"symexec")) {
            int fi6;
            if (!bin) continue;
            fi6=(argc>=2)?find_func(bin,argv[1]):0;
            if (fi6<0) fi6=0;
            dax_symexec_func(bin,fi6,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"ivf")||!strcmp(cmd,"aa")) {
            if (!bin) continue;
            dax_ivf_scan(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"aire")||!strcmp(cmd,"ai")) {
            if (!bin) continue;
            /* run poly_map first to populate poly_regions for AIRE rules */
            dax_poly_map(bin,opts,stdout);
            dax_aire_analyze(bin,opts,stdout);
            continue;
        }

        /* ── AIRE memory: record last interactive command for this binary ── */
        if (bin && bin->sha256[0]) {
            aire_memory_t mem2;
            memset(&mem2, 0, sizeof(mem2));
            FILE *mfp2 = fopen(AIRE_MEMORY_FILE, "rb");
            if (mfp2) { fread(&mem2, sizeof(aire_memory_t), 1, mfp2); fclose(mfp2); }
            for (int _mi = 0; _mi < mem2.count && _mi < AIRE_MEMORY_MAX_ENTRIES; _mi++) {
                if (strcmp(mem2.entries[_mi].sha256, bin->sha256) == 0) {
                    strncpy(mem2.entries[_mi].last_cmd, cmd,
                            sizeof(mem2.entries[_mi].last_cmd)-1);
                    FILE *wfp2 = fopen(AIRE_MEMORY_FILE, "wb");
                    if (wfp2) { fwrite(&mem2, sizeof(aire_memory_t), 1, wfp2); fclose(wfp2); }
                    break;
                }
            }
        }

        if (!strcmp(cmd,"poly")||!strcmp(cmd,"pm")) {
            if (!bin) continue;
            dax_poly_map(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"vmtrace")||!strcmp(cmd,"vt")) {
            if (!bin) continue;
            dax_vm_trace(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"ent")||!strcmp(cmd,"entropy")) {
            if (!bin) continue;
            dax_entropy_scan(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"cg")||!strcmp(cmd,"agc")) {
            if (!bin) continue;
            dax_callgraph_print(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"rda")) {
            if (!bin) continue;
            dax_rda_all(bin,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"px")||!strcmp(cmd,"x")) {
            uint64_t ha; int hn;
            if (!bin) continue;
            ha=(argc>=2)?parse_addr(bin,argv[1]):cursor;
            hn=(argc>=3)?(int)strtol(argv[2],NULL,0):256;
            if (!ha&&argc>=2) { fprintf(stdout,"  x unknown address\n"); continue; }
            if (!ha) ha=cursor;
            hexdump(bin,ha,hn,c);
            cursor=ha+(uint64_t)hn;
            continue;
        }

        if (!strcmp(cmd,"string")||!strcmp(cmd,"ps")) {
            uint64_t sa2; int si2; int found2=0;
            if (!bin) continue;
            sa2=(argc>=2)?parse_addr(bin,argv[1]):cursor;
            if (!sa2&&argc>=2) { fprintf(stdout,"  x unknown address\n"); continue; }
            for (si2=0;si2<bin->nsections;si2++) {
                dax_section_t *sec2=&bin->sections[si2];
                size_t off2,avail2,len2; uint8_t *d2;
                if (sa2<sec2->vaddr||sa2>=sec2->vaddr+sec2->size) continue;
                off2=(size_t)(sa2-sec2->vaddr);
                d2=bin->data+sec2->offset+off2;
                avail2=sec2->size-off2; len2=0;
                while(len2<avail2&&len2<256&&d2[len2]) len2++;
                fprintf(stdout,"  %s\"%.*s\"%s\n",c?T_WHT:"",(int)len2,(char*)d2,R);
                found2=1; break;
            }
            if (!found2) fprintf(stdout,"  x not in any section\n");
            continue;
        }

        if (!strcmp(cmd,"cc")||!strcmp(cmd,"CC")) {
            uint64_t ca2; char ctxt[256]=""; int k;
            if (!bin) continue;
            if (argc<3) { fprintf(stdout,"  x usage: cc <addr> <text>\n"); continue; }
            ca2=parse_addr(bin,argv[1]);
            if (!ca2) { fprintf(stdout,"  x unknown address\n"); continue; }
            for (k=2;k<argc;k++) {
                if (k>2) strncat(ctxt," ",sizeof(ctxt)-strlen(ctxt)-1);
                strncat(ctxt,argv[k],sizeof(ctxt)-strlen(ctxt)-1);
            }
            dax_comment_add(bin,ca2,ctxt);
            fprintf(stdout,"  %s+ comment @ 0x%llx%s\n",
                    c?T_DGRN:"",(unsigned long long)ca2,R);
            continue;
        }

        if (!strcmp(cmd,"rename")||!strcmp(cmd,"afn")) {
            int fi7;
            if (!bin) continue;
            if (argc<3) { fprintf(stdout,"  x usage: rename <func> <newname>\n"); continue; }
            fi7=find_func(bin,argv[1]);
            if (fi7<0) {
                fprintf(stdout,"  %sx '%s' not found%s\n",c?T_DRED:"",argv[1],R);
                continue;
            }
            if (strlen(argv[2])>=sizeof(bin->functions[fi7].name)) {
                fprintf(stdout,"  x name too long\n"); continue;
            }
            strncpy(bin->functions[fi7].name,argv[2],sizeof(bin->functions[fi7].name)-1);
            bin->functions[fi7].name[sizeof(bin->functions[fi7].name)-1]='\0';
            fprintf(stdout,"  %s+ renamed -> %s%s%s\n",
                    c?T_DGRN:"",c?T_WHT:"",argv[2],R);
            continue;
        }

        if (!strcmp(cmd,"run")||!strcmp(cmd,"r")) {
            if (!bin) continue;
            /* run = restart emulation from beginning (clears step state) */
            g_step_state.active = 0;
            cmd_run(bin,opts,argc>=2?argv[1]:NULL);
            continue;
        }

        if (!strcmp(cmd,"step")||!strcmp(cmd,"si")) {
            if (!bin) continue;
            /*
             * step semantics:
             *   step init [func]  — initialise step session for a function
             *   step [n]          — advance N instructions (default 1)
             *                       from the LAST stopped PC (no restart)
             *   step reset        — clear active session
             *
             * run / r always restarts from 0.
             */
            if (argc >= 2 && !strcmp(argv[1],"init")) {
                int fi8 = (argc>=3) ? find_func(bin,argv[2]) : 0;
                if (fi8 < 0) fi8 = 0;
                dax_step_init(bin, fi8, opts, stdout);
            } else if (argc >= 2 && !strcmp(argv[1],"reset")) {
                g_step_state.active = 0;
                fprintf(stdout,"  %s[STEP]%s session cleared\n",
                        c?T_YEL:"", R);
            } else if (!g_step_state.active) {
                /* no session: init automatically on first function */
                int fi8 = (argc>=2) ? find_func(bin,argv[1]) : 0;
                if (fi8 < 0) fi8 = 0;
                dax_step_init(bin, fi8, opts, stdout);
                dax_step_next(bin, 1, opts, stdout);
            } else {
                /* advance existing session */
                int nstep = 1;
                if (argc >= 2) {
                    char *ep; long v = strtol(argv[1],&ep,10);
                    if (ep != argv[1] && v > 0) nstep = (int)v;
                }
                dax_step_next(bin, nstep, opts, stdout);
            }
            continue;
        }

        if (!strcmp(cmd,"reg")||!strcmp(cmd,"dr")) {
            int fi9;
            if (!bin) continue;
            fi9=(argc>=2)?find_func(bin,argv[1]):0;
            if (fi9<0) fi9=0;
            dax_emulate_func(bin,fi9,NULL,0,opts,stdout);
            continue;
        }

        if (!strcmp(cmd,"grep")||!strcmp(cmd,"/")) {
            const char *pat; int si3; int found=0;
            if (!bin||!bin->data||bin->size==0) {
                fprintf(stdout,"  x no binary loaded\n"); continue;
            }
            if (argc<2) { fprintf(stdout,"  x usage: grep <pattern>\n"); continue; }
            pat=argv[1];
            for (si3=0;si3<bin->nsections;si3++) {
                dax_section_t *sec3=&bin->sections[si3];
                uint8_t *d3; size_t sz3,j3;
                if (sec3->offset+sec3->size>bin->size) continue;
                d3=bin->data+sec3->offset; sz3=sec3->size;
                for (j3=0;j3+strlen(pat)<=sz3;j3++) {
                    if (memcmp(d3+j3,pat,strlen(pat))==0) {
                        uint64_t ma=sec3->vaddr+(uint64_t)j3;
                        fprintf(stdout,"  %s0x%016llx%s  %s%s%s  %s[%s]%s\n",
                                c?T_BLU:"",(unsigned long long)ma,R,
                                c?T_GRN:"",pat,R,c?T_GRY:"",sec3->name,R);
                        found++;
                        if (found>=64) {
                            fprintf(stdout,"  %s...(64 results)%s\n",c?T_GRY:"",R);
                            goto grep_done;
                        }
                    }
                }
            }
grep_done:
            if (!found) fprintf(stdout,"  %s(none)%s\n",c?T_GRY:"",R);
            fprintf(stdout,"\n");
            continue;
        }

        if (!strcmp(cmd,"s")||!strcmp(cmd,"seek")) {
            uint64_t na;
            if (!bin) continue;
            if (argc<2) {
                fprintf(stdout,"  %scursor%s  %s0x%016llx%s\n",
                        c?T_GRY:"",R,c?T_BLU:"",(unsigned long long)cursor,R);
                continue;
            }
            na=parse_addr(bin,argv[1]);
            if (na) {
                cursor=na;
                fprintf(stdout,"  %s-> %s0x%016llx%s\n",
                        c?T_GRY:"",c?T_BLU:"",(unsigned long long)cursor,R);
            } else {
                fprintf(stdout,"  %sx unknown: %s%s\n",c?T_DYEL:"",argv[1],R);
            }
            continue;
        }

        fprintf(stdout,"  %sx unknown command: %s%s%s  (type %shelp%s)\n",
                c?T_DYEL:"",c?T_WHT:"",cmd,R,c?T_DCYN:"",R);
    }

    (void)W; (void)Y; (void)C;
    return 0;
}
