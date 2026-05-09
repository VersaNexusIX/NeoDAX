#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "dax.h"
#include "arm64.h"
#include "plugin.h"

/* ── Microkernel fault isolation ─────────────────────────────────────────── */
#define DAX_GUARD_DEFINE_GLOBALS
#include "dax_guard.h"

volatile int g_dax_fault       = 0;
char         g_dax_fault_msg[256] = {0};

/*
 * main.c — NeoDAX entry point
 *
 * Handles CLI argument parsing, feature dispatch, binary loading,
 * and top-level output coordination. All heavy lifting lives in
 * the individual src/ modules; this file is the glue.
 *
 * Υπάρχει ένα κλειδί στο χέρι σου
 * Τι κάνεις και κοιτάς το main.c χαχαχα
 * GIDK 😈
 */

/*
 * print_usage — renders the full help page to stderr with ANSI color.
 * Called by -h / --help, or on invalid argument.
 */
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
    fprintf(o, "  %s╔═══╗%s \n", B, R);
    fprintf(o, "  %s║ █ ║%s ███╗   ██╗███████╗ ██████╗%s\n", B, Y, R);
    fprintf(o, "  %s║ █ ║%s ████╗  ██║██╔════╝██╔═══██╗%s\n", B, Y, R);
    fprintf(o, "  %s║ █ ║%s ██╔██╗ ██║█████╗  ██║   ██║%s  %sv%s%s\n", B, Y, R, DG, DAX_VERSION, R);
    fprintf(o, "  %s║ █ ║%s ██║╚██╗██║██╔══╝  ██║   ██║%s  %sBinary Analysis & RE Tool%s\n", B, Y, R, DG, R);
    fprintf(o, "  %s║ █ ║%s ██║ ╚████║███████╗╚██████╔╝%s\n", B, Y, R);
    fprintf(o, "  %s╚═══╝%s ╚═╝  ╚═══╝╚══════╝ ╚═════╝ %s\n", B, Y, R);
    fprintf(o, "\n");

    fprintf(o, "  %sUSAGE%s\n", W, R);
    fprintf(o, "  %s  neodax%s %s[options]%s %s<binary>%s\n", C, R, DG, R, G, R);
    fprintf(o, "  %s  neodax%s %s[options]%s %s<file.daxc>%s\n", C, R, DG, R, C, R);
    fprintf(o, "\n");

#define FLAG(f,a,d)  fprintf(o,"  %s%-12s%s%-14s%s%s%s\n",W,f,DG,a,R,d,R)
#define FLAGL(f,a,d) fprintf(o,"  %s%s%s %s%s%s  %s%s%s\n",W,f,DG,a ? a : "",R,R,R,d,R)
#define SEC(n,col)   fprintf(o,"\n  %s▸ %s%s\n",col,n,R)
#define DIVIDER      fprintf(o,"  %s%s%s\n",DG,"─────────────────────────────────────────────────────",R)

    DIVIDER;
    SEC("DISASSEMBLY", B);
    FLAG("-a", "",          "show hex bytes alongside each instruction");
    FLAG("-s", "<section>", "disassemble specific section  (default: .text)");
    FLAG("-S", "",          "disassemble ALL executable sections");
    FLAG("-A", "<addr>",    "start disassembly at address (hex)");
    FLAG("-E", "<addr>",    "stop disassembly at address (hex)");
    FLAG("-l", "",          "list all sections with metadata");

    DIVIDER;
    SEC("ANALYSIS", G);
    FLAG("-y", "", "resolve symbols  (symtab / dynsym / PE exports)");
    FLAG("-d", "", "demangle C++ Itanium ABI names");
    FLAG("-f", "", "detect function boundaries & sizes");
    FLAG("-g", "", "instruction group coloring  (call/branch/ret/arith)");
    FLAG("-r", "", "cross-reference annotations  (callers / callees)");
    FLAG("-t", "", "annotate string references  (ASCII + UTF-8 + UTF-16)");
    FLAG("-C", "", "control flow graph  (basic blocks + edges)");
    FLAG("-L", "", "loop detection  (natural loops via dominators)");
    FLAG("-G", "", "call graph  (who calls who, tree view)");
    FLAG("-W", "", "switch / dispatch table detection");
    FLAG("-u", "", "scan Unicode strings  (UTF-8, UTF-16LE/BE)");

    DIVIDER;
    SEC("ADVANCED ANALYSIS", Y);
    FLAG("-P", "", "symbolic execution  (multi-path, opaque folding, VM-aware)");
    FLAG("-Q", "", "NR lifting  (NeoDAX Representation — inter-function IR)");
    FLAG("-D", "", "decompile  (pseudo-C from NR with type inference + resolved calls)");
    FLAG("-I", "", "emulate  (concrete ARM64 execution engine)");
    FLAG("-e", "", "entropy analysis  (packed / encrypted region detection)");
    FLAG("-R", "", "recursive descent  (follow control flow, mark dead bytes)");
    FLAG("-V", "", "instruction validity + obfuscation filter  (IVF + VM detector)");
    FLAG("-i", "", "interactive shell  (r2/GDB-style REPL — type help inside)");
    FLAGL("--poly",     NULL, "polymorphic obfuscation map  (mutation cluster detection)");
    FLAGL("--aire",     NULL, "AIRE: Assisted Intelligence Reverse Engineering insights");
    FLAGL("--vm-trace", NULL, "VM dispatch flow trace  (requires -I or prior emulation)");
    FLAGL("--dsa",      NULL, "DSA: Dynamic Single Assignment over all functions");
    fprintf(o, "\n");
    fprintf(o, "  %s  -x%s   %senable standard suite%s  %s(-y -d -f -g -r -t -u -C -L -G -W)%s\n",
            RD, R, W, R, DG, R);
    fprintf(o, "  %s  -X%s   %senable everything%s       %s(-x + -P -Q -D -I -e -R -V -i --poly --aire --dsa)%s\n",
            RD, R, W, R, DG, R);

    DIVIDER;
    SEC("OUTPUT / FILES", C);
    FLAG("-o", "<file.daxc>", "save snapshot  (symbols, CFG, xrefs, comments)");
    FLAG("-c", "",            "convert .daxc → annotated .S assembly file");
    FLAG("-n", "",            "no color  (for piping / grep / logging)");
    FLAGL("-eox <folder>", NULL, "load plugins from folder (.so files compiled from NeoX.c)");
    FLAGL("-eox-list",     NULL, "list all loaded plugins and their hooks");
    FLAG("-v", "", "verbose mode  (instruction counts, section info)");

    DIVIDER;
    SEC("INFO", M);
    FLAG("--version", "", "print version and exit");
    FLAG("--help",    "", "this help page");
    FLAG("--detail",  "", "show host system & hardware info");
    FLAG("--support", "", "list supported binary formats and architectures");

    DIVIDER;
    SEC("EXAMPLES", M);
    fprintf(o, "  %s$%s neodax %s./binary%s\n",                              G, R, G, R);
    fprintf(o, "  %s$%s neodax %s-x%s ./binary\n",                           G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-X -i%s ./binary\n",                        G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-P -V%s ./binary\n",                        G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-x -o%s analysis.daxc ./binary\n",          G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-c%s analysis.daxc\n",                      G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-s .plt -a%s ./binary\n",                   G, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-eox%s ./plugins/ %s-V%s ./binary\n",       G, R, Y, R, Y, R);
    fprintf(o, "  %s$%s neodax %s-eox%s ./plugins/ %s-eox-list%s ./binary\n",G, R, Y, R, Y, R);
    DIVIDER;
    fprintf(o, "\n");

#undef FLAG
#undef FLAGL
#undef SEC
#undef DIVIDER
}

/*
 * print_version — prints the short version string to stdout.
 * Called by --version.
 */
static void print_version(void) {
    const char *Y  = "\033[1;33m";
    const char *DG = "\033[0;90m";
    const char *R  = "\033[0m";
    printf("%sNeoDAX%s %sv%s%s\n", Y, R, DG, DAX_VERSION, R);
}

/*
 * print_detail — queries the host system via /proc and uname(1)
 * to report CPU, OS, memory, and GPU info.
 * Called by --detail.
 */
static void print_detail(void) {
    const char *Y  = "\033[1;33m";
    const char *W  = "\033[1;37m";
    const char *G  = "\033[1;32m";
    const char *DG = "\033[0;90m";
    const char *C  = "\033[1;36m";
    const char *R  = "\033[0m";

    char cpu_model[256]  = "unknown";
    char os_name[256]    = "unknown";
    char mem_info[64]    = "unknown";
    char gpu_info[256]   = "not detected";
    FILE *fp;

    /* Read CPU model from /proc/cpuinfo (Linux) */
    fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    colon++;
                    while (*colon == ' ') colon++;
                    strncpy(cpu_model, colon, sizeof(cpu_model) - 1);
                    size_t n = strlen(cpu_model);
                    while (n > 0 && (cpu_model[n-1] == '\n' || cpu_model[n-1] == '\r'))
                        cpu_model[--n] = '\0';
                    break;
                }
            }
        }
        fclose(fp);
    }

    /* Read total memory from /proc/meminfo (Linux) */
    fp = fopen("/proc/meminfo", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "MemTotal:", 9) == 0) {
                unsigned long kb = 0;
                sscanf(line + 9, "%lu", &kb);
                snprintf(mem_info, sizeof(mem_info), "%.1f GB", kb / 1024.0 / 1024.0);
                break;
            }
        }
        fclose(fp);
    }

    /* Read OS info — matches setup.sh detect_platform logic */
    fp = fopen("/etc/os-release", "r");
    if (fp) {
        char line[256];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *val = line + 12;
                if (*val == '"') val++;
                strncpy(os_name, val, sizeof(os_name) - 1);
                size_t n = strlen(os_name);
                while (n > 0 && (os_name[n-1] == '\n' || os_name[n-1] == '\r' || os_name[n-1] == '"'))
                    os_name[--n] = '\0';
                break;
            }
        }
        fclose(fp);
    }
    /* macOS / BSD fallback — sw_vers or uname */
    if (strcmp(os_name, "unknown") == 0) {
        FILE *sw = popen("sw_vers -productName 2>/dev/null", "r");
        if (sw) {
            char prod[64] = "", ver[64] = "";
            if (fgets(prod, sizeof(prod), sw)) {
                size_t n = strlen(prod);
                while (n > 0 && (prod[n-1] == '\n' || prod[n-1] == '\r')) prod[--n] = '\0';
            }
            pclose(sw);
            FILE *sv = popen("sw_vers -productVersion 2>/dev/null", "r");
            if (sv) {
                if (fgets(ver, sizeof(ver), sv)) {
                    size_t n = strlen(ver);
                    while (n > 0 && (ver[n-1] == '\n' || ver[n-1] == '\r')) ver[--n] = '\0';
                }
                pclose(sv);
            }
            if (prod[0] && ver[0])
                snprintf(os_name, sizeof(os_name), "%s %s", prod, ver);
            else if (prod[0])
                strncpy(os_name, prod, sizeof(os_name) - 1);
        }
    }
    /* Final fallback: uname -sr */
    if (strcmp(os_name, "unknown") == 0) {
        FILE *un = popen("uname -sr 2>/dev/null", "r");
        if (un) {
            if (fgets(os_name, sizeof(os_name), un)) {
                size_t n = strlen(os_name);
                while (n > 0 && (os_name[n-1] == '\n' || os_name[n-1] == '\r')) os_name[--n] = '\0';
            }
            pclose(un);
        }
    }

    /* Attempt GPU detection via /proc/driver/nvidia/version or /sys/class/drm */
    fp = fopen("/proc/driver/nvidia/version", "r");
    if (fp) {
        char line[256];
        if (fgets(line, sizeof(line), fp)) {
            /* strip newline */
            size_t n = strlen(line);
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
            snprintf(gpu_info, sizeof(gpu_info), "NVIDIA (driver: %s)", line);
        }
        fclose(fp);
    } else {
        /* Fallback: look for card name under /sys/class/drm */
        FILE *gfp = popen("cat /sys/class/drm/card0/device/uevent 2>/dev/null | grep DRIVER", "r");
        if (gfp) {
            char line[256];
            if (fgets(line, sizeof(line), gfp)) {
                size_t n = strlen(line);
                while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
                snprintf(gpu_info, sizeof(gpu_info), "%s", line);
            }
            pclose(gfp);
        }
    }

    printf("\n");
    printf("  %s▸ NeoDAX System Details%s\n", Y, R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("  %s%-16s%s %s%s%s\n", W, "Version",    R, G,  DAX_VERSION, R);
    printf("  %s%-16s%s %s%s%s\n", W, "CPU",        R, C,  cpu_model,   R);
    printf("  %s%-16s%s %s%s%s\n", W, "Memory",     R, C,  mem_info,    R);
    printf("  %s%-16s%s %s%s%s\n", W, "OS",         R, DG, os_name,     R);
    printf("  %s%-16s%s %s%s%s\n", W, "GPU",        R, G,  gpu_info,    R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("\n");
}

/*
 * print_support — prints a static compatibility table of all
 * binary formats and CPU architectures NeoDAX can analyse.
 * Called by --support.
 */
static void print_support(void) {
    const char *Y  = "\033[1;33m";
    const char *W  = "\033[1;37m";
    const char *G  = "\033[1;32m";
    const char *DG = "\033[0;90m";
    const char *C  = "\033[1;36m";
    const char *M  = "\033[1;35m";
    const char *R  = "\033[0m";

    printf("\n");
    printf("  %s▸ Supported Binary Formats%s\n", Y, R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("  %s%-12s%s %s%s%s\n", W, "ELF32",  R, G,  "32-bit ELF (Linux, Android, BSD)", R);
    printf("  %s%-12s%s %s%s%s\n", W, "ELF64",  R, G,  "64-bit ELF (Linux, Android, BSD)", R);
    printf("  %s%-12s%s %s%s%s\n", W, "PE32",   R, G,  "32-bit Windows Portable Executable", R);
    printf("  %s%-12s%s %s%s%s\n", W, "PE64+",  R, G,  "64-bit Windows Portable Executable", R);
    printf("  %s%-12s%s %s%s%s\n", W, "Mach-O", R, C,  "Apple macOS / iOS (arm64, x86_64)", R);
    printf("  %s%-12s%s %s%s%s\n", W, "Raw",    R, DG, "Headerless shellcode / firmware blobs", R);
    printf("  %s%-12s%s %s%s%s\n", W, ".daxc",  R, M,  "NeoDAX snapshot (symbols, CFG, xrefs)", R);
    printf("\n");

    printf("  %s▸ Supported CPU Architectures%s\n", Y, R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("  %s%-16s%s %s%s%s\n", W, "x86_64",       R, G, "Intel / AMD 64-bit  (full decode + decompile)", R);
    printf("  %s%-16s%s %s%s%s\n", W, "AArch64",      R, G, "ARM 64-bit  (A-profile, M-profile stubs)", R);
    printf("  %s%-16s%s %s%s%s\n", W, "RISC-V RV64GC",R, C, "RISC-V 64-bit  (G+C extensions)", R);
    printf("\n");

    printf("  %s▸ Supported Operating Systems%s\n", Y, R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("  %s%-16s%s %s%s%s\n", W, "Linux",   R, G,  "Full support  (ELF, proc maps, debug)", R);
    printf("  %s%-16s%s %s%s%s\n", W, "Android", R, G,  "ELF / ART binary analysis", R);
    printf("  %s%-16s%s %s%s%s\n", W, "macOS",   R, C,  "Mach-O support  (arm64 + x86_64)", R);
    printf("  %s%-16s%s %s%s%s\n", W, "Windows", R, DG, "PE32/PE64+ analysis", R);
    printf("  %s%-16s%s %s%s%s\n", W, "BSD",     R, DG, "ELF-based BSDs  (FreeBSD, NetBSD, OpenBSD)", R);
    printf("  %s─────────────────────────────────────────────%s\n", DG, R);
    printf("\n");
}

/*
 * easter_key — philosophical text on the relationship between
 * keys and locks, rendered in Greek. Triggered by --key.
 */
static void easter_key(void) {
    const char *Y  = "\033[1;33m";
    const char *DG = "\033[0;90m";
    const char *W  = "\033[1;37m";
    const char *C  = "\033[1;36m";
    const char *R  = "\033[0m";

    printf("\n");
    printf("  %s╔══════════════════════════════════════════════════╗%s\n", Y, R);
    printf("  %s║%s          %sΤο Κλειδί και η Κλειδαριά%s              %s║%s\n", Y, R, W, R, Y, R);
    printf("  %s╚══════════════════════════════════════════════════╝%s\n", Y, R);
    printf("\n");
    printf("  %sΈνα κλειδί χωρίς κλειδαριά δεν είναι παρά ένα κομμάτι%s\n", C, R);
    printf("  %sμετάλλου — όμορφο, ίσως, αλλά άχρηστο. Μια κλειδαριά%s\n", C, R);
    printf("  %sχωρίς κλειδί είναι υπόσχεση που δεν τηρήθηκε ποτέ.%s\n", C, R);
    printf("\n");
    printf("  %sΗ αλήθεια βρίσκεται στη σχέση τους:%s\n", W, R);
    printf("  %sτο κλειδί γνωρίζει τη μορφή της κλειδαριάς%s\n", DG, R);
    printf("  %sκαλύτερα από όσο η κλειδαριά γνωρίζει τον εαυτό της.%s\n", DG, R);
    printf("\n");
    printf("  %sΟ Ηράκλειτος έλεγε ότι «τα αντίθετα συμπίπτουν».%s\n", C, R);
    printf("  %sΤο κλείδωμα και το ξεκλείδωμα είναι η ίδια κίνηση —%s\n", C, R);
    printf("  %sαπλώς διαφορετική κατεύθυνση. Η ασφάλεια και η πρόσβαση%s\n", C, R);
    printf("  %sδεν είναι εχθροί· είναι δύο εκφράσεις της ίδιας βούλησης.%s\n", C, R);
    printf("\n");
    printf("  %sΌταν αναλύεις ένα δυαδικό αρχείο, κρατάς το κλειδί.%s\n", W, R);
    printf("  %sΤο πρόγραμμα είναι η κλειδαριά — κατασκευασμένο για να%s\n", W, R);
    printf("  %sμείνει κλειστό. Αλλά κάθε κλειδαριά έχει σχεδιαστεί%s\n", W, R);
    printf("  %sαπό κάποιον που κατείχε ήδη το κλειδί.%s\n", W, R);
    printf("\n");
    printf("  %sΗ κατανόηση δεν είναι διάρρηξη — είναι αναγνώριση.%s\n", Y, R);
    printf("  %sΤο κλειδί δεν «σπάει» την κλειδαριά· την ακούει.%s\n", Y, R);
    printf("\n");
    printf("  %s                              — NeoDAX v%s%s\n", DG, DAX_VERSION, R);
    printf("\n");
}

/*
 * easter_rtx — GPU ego-check easter egg. Detects whether the
 * host has an RTX 5090 Ti; responds accordingly with dramatic flair.
 * Triggered by --rtx-5090-ti.
 */
static void easter_rtx(void) {
    const char *Y  = "\033[1;33m";
    const char *G  = "\033[1;32m";
    const char *RD = "\033[1;31m";
    const char *DG = "\033[0;90m";
    const char *W  = "\033[1;37m";
    const char *C  = "\033[1;36m";
    const char *R  = "\033[0m";

    char gpu_buf[512] = {0};
    int  has_rtx5090ti = 0;

    /* Check for NVIDIA GPU name via /proc/driver/nvidia/gpus (if present) */
    FILE *fp = popen("cat /proc/driver/nvidia/gpus/*/information 2>/dev/null | grep 'Model'", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            size_t n = strlen(line);
            while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
            strncat(gpu_buf, line, sizeof(gpu_buf) - strlen(gpu_buf) - 1);
            if (strstr(line, "5090") && strstr(line, "Ti")) {
                has_rtx5090ti = 1;
            }
        }
        pclose(fp);
    }

    /* Fallback: /sys DRM uevent */
    if (gpu_buf[0] == '\0') {
        fp = popen("cat /sys/class/drm/card*/device/uevent 2>/dev/null | grep -i 'ID_MODEL\\|DRIVER'", "r");
        if (fp) {
            char line[512];
            while (fgets(line, sizeof(line), fp)) {
                size_t n = strlen(line);
                while (n > 0 && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
                strncat(gpu_buf, line, sizeof(gpu_buf) - strlen(gpu_buf) - 1);
                if (strstr(line, "5090") && strstr(line, "Ti")) {
                    has_rtx5090ti = 1;
                }
            }
            pclose(fp);
        }
    }

    if (has_rtx5090ti) {
        /* The user actually has one. Treat with appropriate reverence. */
        printf("\n");
        printf("  %s┌─────────────────────────────────────────────────┐%s\n", G, R);
        printf("  %s│%s   %s🟢 RTX 5090 Ti DETECTED — άγιε του GPU θεού%s   %s│%s\n", G, R, W, R, G, R);
        printf("  %s└─────────────────────────────────────────────────┘%s\n", G, R);
        printf("\n");
        printf("  %sΛοιπόν... έχεις την κάρτα. Σε κάποια παράλληλη%s\n", C, R);
        printf("  %sPCIe lane, η GPU σου αναπνέει 575W και τρέχει%s\n", C, R);
        printf("  %sπερισσότερους transistors από ό,τι ο εγκέφαλός σου.%s\n", C, R);
        printf("  %sΜπράβο. Ειλικρινά. Αλλά... γιατί τρέχεις%s\n", C, R);
        printf("  %sέναν %sCLI disassembler%s%s σε αυτό το τέρας;%s\n", C, Y, R, C, R);
        printf("  %sΑυτή η GPU άξιζε καλύτερη μοίρα. 😂%s\n", Y, R);
        printf("\n");
    } else {
        /* No RTX 5090 Ti found. Roast accordingly. */
        printf("\n");
        printf("  %s┌─────────────────────────────────────────────────────────┐%s\n", RD, R);
        printf("  %s│%s  %s GPU AUDIT COMPLETE — αποτελέσματα: καταστροφικά%s       %s│%s\n", RD, R, W, R, RD, R);
        printf("  %s└─────────────────────────────────────────────────────────┘%s\n", RD, R);
        printf("\n");

        if (gpu_buf[0]) {
            printf("  %sΑνιχνεύθηκε:%s %s%s%s\n", DG, R, Y, gpu_buf, R);
            printf("\n");
        }

        printf("  %sΕσύ ούτε καν έχεις GPU ☠️%s\n", RD, R);
        printf("\n");
        printf("  %sΕνώ η RTX 5090 Ti κάθεται σε κάποιο %sdata center%s%s\n", DG, Y, R, DG);
        printf("  %sκαι τρέχει LLMs με 1.7TB/s bandwidth, εσύ%s\n", DG, R);
        printf("  %sτρέχεις NeoDAX στο integrated graphics του%s\n", DG, R);
        printf("  %smainboard σαν να είναι 2008. Ο ήχος του%s\n", DG, R);
        printf("  %sψύκτη σου είναι στην πραγματικότητα το%s\n", DG, R);
        printf("  %sκλάμα του CPU που προσπαθεί να κάνει shader math.%s\n", DG, R);
        printf("\n");
        printf("  %s«Βάλε GPU», είπαν. «Δεν χρειάζομαι», είπες.%s\n", C, R);
        printf("  %sΚαι τώρα κοιτάς --rtx-5090-ti στο CLI σαν%s\n", C, R);
        printf("  %sνα μπορεί αυτή η εντολή να σου εμφυτεύσει VRAM.%s\n", C, R);
        printf("  %sΔεν μπορεί. Λυπάμαι. 💀%s\n", Y, R);
        printf("\n");
        printf("  %sΤεχνική σύσταση:%s %sπήγαινε στη Nvidia και αγόρασε%s\n", W, R, DG, R);
        printf("  %sκάτι που έχει περισσότερους CUDA cores%s\n", DG, R);
        printf("  %sαπό ό,τι εσύ έχεις νευρώνες. Δεν είναι δύσκολο.%s\n", DG, R);
        printf("\n");
    }
}

/*
 * neodax_header_line — prints a horizontal rule of box-drawing dashes,
 * optionally wrapped in color escape codes.
 */
static void neodax_header_line(int use_color, int width) {
    int i;
    if (use_color) printf("%s", COL_SECTION);
    for (i = 0; i < width; i++) printf("─");
    if (use_color) printf("%s", COL_RESET);
    printf("\n");
}

/*
 * dax_print_banner — renders the per-binary header block with file identity,
 * format, arch, OS/ABI, address layout, size/count metrics, and hardening flags.
 */
void dax_print_banner(dax_binary_t *bin, dax_opts_t *opts) {
    int color = opts ? opts->color : 1;
    const char *R  = color ? COL_RESET   : "";
    const char *DG = color ? COL_COMMENT : "";
    const char *W  = color ? COL_MNEM    : "";
    const char *GN = color ? COL_SECTION : "";
    const char *AD = color ? COL_ADDR    : "";
    const char *EN = color ? COL_ENTRY   : "";
    const char *MT = color ? COL_META    : "";
    const char *CY = color ? "\033[1;36m" : "";
    const char *YL = color ? "\033[1;33m" : "";
    int bw = DAX_BANNER_WIDTH;

#define ROW(k,v,vc)  printf("  %s%-15s%s %s%s%s\n", W, k, R, vc, v, R)
#define ROWF(k,f,...) printf("  %s%-15s%s " f "\n", W, k, R, __VA_ARGS__)
#define ROWHEX(k,v,vc) printf("  %s%-15s%s %s0x%016llx%s\n", W, k, R, vc, (unsigned long long)(v), R)

    printf("\n");
    neodax_header_line(color, bw);
    printf("%s"
        "  ███╗   ██╗███████╗ ██████╗ \n"
        "  ████╗  ██║██╔════╝██╔═══██╗\n"
        "  ██╔██╗ ██║█████╗  ██║   ██║\n"
        "  ██║╚██╗██║██╔══╝  ██║   ██║\n"
        "  ██║ ╚████║███████╗╚██████╔╝\n"
        "  ╚═╝  ╚═══╝╚══════╝ ╚═════╝ %s\n",
        color ? "\033[1;33m" : "", R);
    printf("%s  NeoDAX v%s  ·  Binary Analysis & Reverse Engineering%s\n",
           DG, DAX_VERSION, R);
    neodax_header_line(color, bw);
    printf("\n");

    /* Primary identity fields */
    ROW("File",    bin->filepath,            CY);
    ROW("Format",  dax_fmt_str(bin->fmt),    MT);
    ROW("Arch",    dax_arch_str(bin->arch),  YL);
    ROW("OS/ABI",  dax_os_str(bin->os),      DG);
    ROWHEX("Entry", bin->entry, EN);
    ROWHEX("Base",  bin->base,  AD);

    printf("\n");

    /* Size and count metrics, printed as two-column pairs */
    {
        char lbuf[64], rbuf[64];

        snprintf(lbuf, 64, "%llu bytes", (unsigned long long)bin->image_size);
        snprintf(rbuf, 64, "%d", bin->nsections);
        printf("  %s%-15s%s %s%-22s%s  %s%-15s%s %s%s%s\n",
               W, "Image Size", R, GN, bin->image_size ? lbuf : "—", R,
               W, "Sections",   R, GN, rbuf, R);

        snprintf(lbuf, 64, "%llu bytes", (unsigned long long)bin->code_size);
        snprintf(rbuf, 64, "%llu bytes", (unsigned long long)bin->data_size);
        printf("  %s%-15s%s %s%-22s%s  %s%-15s%s %s%s%s\n",
               W, "Code Size", R, AD, bin->code_size ? lbuf : "—", R,
               W, "Data Size", R, DG, bin->data_size ? rbuf : "—", R);

        snprintf(lbuf, 64, "%d", bin->nsymbols);
        snprintf(rbuf, 64, "%d", bin->nfunctions);
        printf("  %s%-15s%s %s%-22s%s  %s%-15s%s %s%s%s\n",
               W, "Symbols",   R, CY, bin->nsymbols   ? lbuf : "—", R,
               W, "Functions", R, CY, bin->nfunctions ? rbuf : "—", R);

        if (bin->nblocks || bin->nxrefs) {
            snprintf(lbuf, 64, "%d", bin->nblocks);
            snprintf(rbuf, 64, "%d", bin->nxrefs);
            printf("  %s%-15s%s %s%-22s%s  %s%-15s%s %s%s%s\n",
                   W, "CFG Blocks", R, DG, bin->nblocks ? lbuf : "—", R,
                   W, "Xrefs",      R, DG, bin->nxrefs  ? rbuf : "—", R);
        }
    }

    printf("\n");

    /* Binary hardening flags */
    {
        const char *pie_c  = (bin->is_pie)      ? GN : DG;
        const char *str_c  = (bin->is_stripped)  ? "\033[1;31m" : GN;
        const char *dbg_c  = (bin->has_debug)    ? GN : DG;
        printf("  %sPIE%s %-6s  %sStripped%s %-6s  %sDebug%s %-6s",
               W, R, bin->is_pie      ? "yes" : "no",
               W, R, bin->is_stripped ? "yes" : "no",
               W, R, bin->has_debug   ? "yes" : "no");
        (void)pie_c; (void)str_c; (void)dbg_c;
        printf("\n");
    }

    if (bin->build_id[0])
        ROW("Build-ID", bin->build_id, DG);
    if (bin->sha256[0])
        ROW("SHA-256", bin->sha256, DG);

    printf("\n");
    neodax_header_line(color, bw);
    printf("\n");

#undef ROW
#undef ROWF
#undef ROWHEX
}

/*
 * dax_print_sections — tabulates every section in the binary with its
 * type, virtual address, file offset, size, permission flags, and
 * instruction count (if already disassembled).
 */
void dax_print_sections(dax_binary_t *bin, dax_opts_t *opts) {
    int c = opts ? opts->color : 1;
    int i;
    static const char *stlabel[] = {
        "code", "data", "rodata", "bss", "plt", "got", "dyn", "dbg", "other"
    };
    extern const char *dax_sec_type_color(dax_sec_type_t t, int color);

    printf("\n");
    if (c) printf("%s", COL_MNEM);
    printf("  %-28s %-8s %-18s %-12s %-14s %-8s %s\n",
           "Section", "Type", "VirtAddr", "FileOffset", "Size", "Flags", "Insns");
    if (c) printf("%s", COL_RESET);
    if (c) printf("%s", COL_COMMENT);
    { int j; for (j = 0; j < 110; j++) printf("─"); }
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

/*
 * dax_arch_str — maps dax_arch_t enum to a human-readable string.
 */
const char *dax_arch_str(dax_arch_t a) {
    switch (a) {
        case ARCH_X86_64:  return "x86_64";
        case ARCH_ARM64:   return "AArch64 (ARM64)";
        case ARCH_RISCV64: return "RISC-V RV64GC";
        default:           return "unknown";
    }
}

/*
 * dax_fmt_str — maps dax_fmt_t enum to a human-readable string.
 */
const char *dax_fmt_str(dax_fmt_t f) {
    switch (f) {
        case FMT_ELF32: return "ELF32";
        case FMT_ELF64: return "ELF64";
        case FMT_PE32:  return "PE32";
        case FMT_PE64:  return "PE64+";
        case FMT_RAW:   return "Raw";
        default:        return "unknown";
    }
}

/*
 * dax_os_str — maps dax_os_t enum to a human-readable platform string.
 */
const char *dax_os_str(dax_os_t o) {
    switch (o) {
        case DAX_PLAT_LINUX:   return "Linux";
        case DAX_PLAT_ANDROID: return "Android";
        case DAX_PLAT_BSD:     return "BSD/macOS";
        case DAX_PLAT_UNIX:    return "UNIX/SysV";
        case DAX_PLAT_WINDOWS: return "Windows";
        default:               return "unknown";
    }
}

#ifndef NEODAX_NODE
/*
 * main — CLI entry point. Loads optional config, parses argv, dispatches
 * to the appropriate analysis pipeline, and prints timing on exit.
 */
int main(int argc, char **argv) {
    /* Probe well-known config file locations; load the first one found. */
    {
        const char *cfg_paths[] = {
            "config.dax-ng",
            "./config.dax-ng",
            "/data/data/com.termux/files/home/NeoDAX/NeoDAX-patched/config.dax-ng",
            NULL
        };
        int ci;
        for (ci = 0; cfg_paths[ci]; ci++) {
            FILE *cfp = fopen(cfg_paths[ci], "r");
            if (cfp) { fclose(cfp); dax_config_load(cfg_paths[ci]); break; }
        }
    }

    dax_binary_t          bin;
    dax_opts_t            opts;
    dax_plugin_registry_t plugin_reg;
    int                   list_only   = 0;
    int                   to_asm      = 0;
    int                   is_daxc     = 0;
    int                   i;
    char                  wiz_binary[512] = {0};
    const char           *filepath    = NULL;
    struct timespec       ts_start, ts_end;

    dax_print_correction(argc, argv, stderr);

    memset(&bin,  0, sizeof(bin));
    memset(&opts, 0, sizeof(opts));
    opts.show_addr    = 1;
    opts.color        = 1;
    opts.start_addr   = 0;
    opts.end_addr     = (uint64_t)-1;
    strncpy(opts.section, ".text", sizeof(opts.section) - 1);
    opts.plugin_dir[0] = '\0';
    opts.list_plugins  = 0;

    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            /*
             * Long-option dispatch. Checked before single-char switch
             * so that "--version" etc. are handled cleanly.
             */
            if (!strncmp(argv[i], "-eox", 4)) {
                if (argv[i][4] == '\0') {
                    if (i + 1 < argc) strncpy(opts.plugin_dir, argv[++i], 511);
                } else if (!strcmp(argv[i] + 4, "-list")) {
                    opts.list_plugins = 1;
                }
                continue;
            }

            if (!strcmp(argv[i], "--version")) { print_version();  return 0; }
            if (!strcmp(argv[i], "--help"))    { print_usage();    return 0; }
            if (!strcmp(argv[i], "--detail"))  { print_detail();   return 0; }
            if (!strcmp(argv[i], "--support")) { print_support();  return 0; }

            /* New analysis flags */
            if (!strcmp(argv[i], "--poly"))     { opts.poly_map  = 1; continue; }
            if (!strcmp(argv[i], "--aire"))     { opts.aire      = 1; continue; }
            if (!strcmp(argv[i], "--vm-trace")) { opts.vm_trace  = 1; continue; }
            if (!strcmp(argv[i], "--dsa"))      { opts.dsa       = 1; continue; }

            /* Easter eggs — intentionally absent from --help output */
            if (!strcmp(argv[i], "--key"))         { easter_key();    return 0; }
            if (!strcmp(argv[i], "--rtx-5090-ti")) { easter_rtx();    return 0; }

            /*
             * Single-character option switch.
             * Each case maps directly to the corresponding dax_opts_t field.
             */
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
                case 'P': opts.symexec      = 1; break;
                case 'Q': opts.ssa          = 1; break;
                case 'D': opts.decompile    = 1; break;
                case 'I': opts.emulate      = 1; break;
                case 'e': opts.entropy      = 1; break;
                case 'R': opts.rda          = 1; break;
                case 'V': opts.ivf          = 1; break;
                case 'i': opts.interactive  = 1; break;
                case 'c': to_asm            = 1; break;
                case 'x':
                    /* Standard suite: symbols, demangle, funcs, groups,
                     * xrefs, strings, CFG, loops, callgraph, switches, unicode */
                    opts.symbols = opts.demangle = opts.funcs = 1;
                    opts.groups  = opts.xrefs = opts.strings = opts.cfg = 1;
                    opts.loops   = opts.callgraph = opts.switches = 1;
                    opts.unicode = 1;
                    break;
                case 'X':
                    /* Everything: standard suite + advanced analysis + interactive */
                    opts.symbols = opts.demangle = opts.funcs = 1;
                    opts.groups  = opts.xrefs = opts.strings = opts.cfg = 1;
                    opts.loops   = opts.callgraph = opts.switches = 1;
                    opts.unicode = 1;
                    opts.symexec = opts.ssa = opts.decompile = opts.emulate = 1;
                    opts.entropy = opts.rda = opts.ivf = 1;
                    opts.poly_map = opts.aire = opts.vm_trace = 1;
                    opts.dsa = 1;
                    opts.interactive = 1;
                    break;
                case 'h': print_usage(); return 0;
                case 's':
                    if (i+1 < argc) strncpy(opts.section, argv[++i], sizeof(opts.section)-1);
                    break;
                case 'A':
                    if (i+1 < argc) opts.start_addr = (uint64_t)strtoull(argv[++i], NULL, 16);
                    break;
                case 'E':
                    if (i+1 < argc) opts.end_addr = (uint64_t)strtoull(argv[++i], NULL, 16);
                    break;
                case 'o':
                    if (i+1 < argc) strncpy(opts.output_daxc, argv[++i], 511);
                    break;
                default:
                    fprintf(stderr, "neodax: unknown option '%s'\n", argv[i]);
                    print_usage(); return 1;
            }
        } else {
            filepath = argv[i];
        }
    }

    memset(&plugin_reg, 0, sizeof(plugin_reg));
    if (opts.plugin_dir[0]) {
        int np = dax_plugin_load_dir(&plugin_reg, opts.plugin_dir);
        if (opts.color)
            printf("  \033[0;90m\u2502\033[0m \033[1;32m\u2714\033[0m  plugins: "
                   "\033[1;37m%d\033[0m loaded from \033[0;90m%s\033[0m\n",
                   np, opts.plugin_dir);
        else
            printf("  [plugins] loaded %d from %s\n", np, opts.plugin_dir);
        if (plugin_reg.nerrors > 0) {
            int pi2;
            for (pi2 = 0; pi2 < plugin_reg.nerrors; pi2++) {
                if (opts.color)
                    fprintf(stderr, "  \033[0;90m\u2502\033[0m \033[0;31m\u2718\033[0m  %s\033[0m\n",
                            plugin_reg.load_errors[pi2]);
                else
                    fprintf(stderr, "  [plugin error] %s\n", plugin_reg.load_errors[pi2]);
            }
        }
    }

    if (opts.list_plugins) {
        dax_plugin_list(&plugin_reg, stdout, opts.color);
        dax_plugin_free(&plugin_reg);
        return 0;
    }

    if (!filepath && opts.plugin_dir[0] && plugin_reg.count > 0) {
        const char *CY = opts.color ? "\033[1;33m" : "";
        const char *CG = opts.color ? "\033[1;32m" : "";
        const char *CB = opts.color ? "\033[1;34m" : "";
        const char *CD = opts.color ? "\033[0;90m" : "";
        const char *R  = opts.color ? "\033[0m"    : "";
        int pi3, wiz_tries = 0;

        printf("\n  %s\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
               " NeoDAX  eox "
               "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557%s\n",
               CY, R);
        printf("  %s\u2551%s  %d plugin(s) active  %s\u2192 opening interactive shell%s\n",
               CY, R, plugin_reg.count, CD, R);
        for (pi3 = 0; pi3 < plugin_reg.count; pi3++)
            printf("  %s\u2551%s  %s+%s %-16s  %s%s%s\n",
                   CY, R, CG, R, plugin_reg.plugins[pi3]->name,
                   CD, plugin_reg.plugins[pi3]->description, R);
        printf("  %s\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
               "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
               "\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550"
               "\u2550\u2550\u255d%s\n\n", CY, R);

        for (;;) {
            printf("  %s\u25b6 Binary%s : ", CB, R);
            fflush(stdout);
            if (!fgets(wiz_binary, sizeof(wiz_binary), stdin)) { dax_plugin_free(&plugin_reg); return 1; }
            {
                size_t n = strlen(wiz_binary);
                while (n > 0 && (wiz_binary[n-1] == '\n' || wiz_binary[n-1] == '\r' || wiz_binary[n-1] == ' '))
                    wiz_binary[--n] = '\0';
            }
            if (!wiz_binary[0]) {
                if (++wiz_tries >= 3) {
                    fprintf(stderr, "neodax: no binary specified\n");
                    dax_plugin_free(&plugin_reg); return 1;
                }
                printf("  %s  \u2514\u2500 empty, try again%s\n", CD, R);
                continue;
            }
            {
                FILE *chk = fopen(wiz_binary, "rb");
                if (!chk) {
                    printf("  %s  \u2514\u2500 not found: %s%s%s\n", CD, CY, wiz_binary, R);
                    if (++wiz_tries >= 5) {
                        fprintf(stderr, "neodax: too many failed attempts\n");
                        dax_plugin_free(&plugin_reg); return 1;
                    }
                    continue;
                }
                fclose(chk);
            }
            break;
        }
        filepath = wiz_binary;
        opts.interactive = 1;
        opts.symbols     = 1;
        opts.funcs       = 1;
        printf("  %s  \u2514\u2500 loading %s%s%s ...%s\n\n", CD, CG, filepath, CD, R);
    }

    if (!filepath) {
        fprintf(stderr, "neodax: no input file\n");
        dax_plugin_free(&plugin_reg);
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

    DAX_RUN_PASS("post-load plugins", opts.color,
        dax_plugin_run_post_load(&plugin_reg, &bin, &opts));

    DAX_RUN_PASS("hardening", opts.color, dax_harden_all(&bin, opts.color));
    DAX_RUN_PASS("sha256",    opts.color, dax_compute_sha256(&bin));

    /* Clamp all counters once after load, before anything iterates them */
    dax_clamp_counts(&bin);

    if (opts.callgraph) opts.xrefs = 1;
    if (opts.loops)     opts.cfg   = 1;
    if (opts.symexec || opts.ssa || opts.decompile || opts.emulate) {
        opts.funcs   = 1;
        opts.symbols = 1;
        opts.cfg     = 1;
    }

    if (opts.symbols || opts.funcs || opts.xrefs || opts.strings || opts.cfg) {
        DAX_RUN_PASS("sym-load",  opts.color, dax_sym_load(&bin));
        if (opts.xrefs || opts.cfg)
            DAX_RUN_PASS("xref-build", opts.color, dax_xref_build(&bin));
    }

    /* Re-clamp after symbol load (nsymbols may have grown) */
    dax_clamp_counts(&bin);

    if (opts.unicode)
        DAX_RUN_PASS("unicode-scan", opts.color, dax_scan_unicode(&bin));

    if ((opts.cfg || opts.loops)) {
        int si, fi;

        /* ── func-detect: guard each section before passing to decoder ── */
        for (si = 0; si < bin.nsections && si < DAX_MAX_SECTIONS; si++) {
            dax_section_t *sec = &bin.sections[si];
            if (sec->type != SEC_TYPE_CODE) continue;
            if (sec->size == 0) continue;
            if (sec->offset > bin.size) continue;
            if (sec->size > bin.size - sec->offset) continue;  /* overflow-safe */
            DAX_RUN_PASS("func-detect", opts.color,
                dax_func_detect(&bin,
                                bin.data + sec->offset,
                                (size_t)sec->size,
                                sec->vaddr, sec));
        }
        dax_clamp_counts(&bin);

        DAX_RUN_PASS("symexec-prepass", opts.color, dax_symexec_prepass(&bin));
        dax_clamp_counts(&bin);

        /* ── ARM64 indirect-target resolver (inline mini-emulator) ── */
        if (bin.arch == ARCH_ARM64 && bin.functions && bin.symbols) {
            int fi2;
            for (fi2 = 0; fi2 < bin.nfunctions && fi2 < DAX_MAX_FUNCTIONS; fi2++) {
                dax_func_t *fn2 = &bin.functions[fi2];
                int si3;
                uint8_t  *code2 = NULL;
                uint64_t  base2 = 0;
                size_t    csz   = 0;
                size_t    foff  = 0, fend = 0;

                /* Find containing section — validated */
                for (si3 = 0; si3 < bin.nsections && si3 < DAX_MAX_SECTIONS; si3++) {
                    dax_section_t *sec2 = &bin.sections[si3];
                    if (sec2->size == 0) continue;
                    if (sec2->offset > bin.size) continue;
                    if (sec2->size > bin.size - sec2->offset) continue;
                    if (fn2->start < sec2->vaddr ||
                        fn2->start >= sec2->vaddr + sec2->size) continue;
                    code2 = bin.data + sec2->offset;
                    base2 = sec2->vaddr;
                    csz   = (size_t)sec2->size;
                    break;
                }
                if (!code2 || fn2->start < base2) continue;

                foff = (size_t)(fn2->start - base2);
                fend = (fn2->end > fn2->start && fn2->end <= base2 + csz)
                       ? (size_t)(fn2->end - base2) : foff + 512;
                if (fend > csz) fend = csz;

                uint64_t regs[32]; int known[32]; int r;
                for (r = 0; r < 32; r++) { regs[r] = 0; known[r] = 0; }

                int budget = 4096;
                while (foff + 4 <= fend && foff + 4 <= csz && budget-- > 0) {
                    uint32_t raw2 = (uint32_t)(code2[foff])   |
                                    (code2[foff+1] <<  8)     |
                                    (code2[foff+2] << 16)     |
                                    (code2[foff+3] << 24);
                    a64_insn_t a64i2;
                    a64_decode(raw2, base2 + foff, &a64i2);
                    const char *m = a64i2.mnemonic;
                    const char *o = a64i2.operands;
                    foff += 4;

                    /* Null-guard decoder output */
                    if (!m || !o) continue;

                    char op1[32]="", op2[32]="", op3[32]="";
                    { const char *p = o; char *d = op1; int j = 0;
                      while (*p && *p != ',' && j < 31) { *d++ = *p++; j++; }
                      *d = '\0'; if (*p == ',') p++;
                      d = op2; j = 0; while (*p == ' ') p++;
                      while (*p && *p != ',' && j < 31) { *d++ = *p++; j++; }
                      *d = '\0'; if (*p == ',') p++;
                      d = op3; j = 0; while (*p == ' ') p++;
                      while (*p && *p != ',' && j < 31) { *d++ = *p++; j++; }
                      *d = '\0'; }

                    int rd = -1, rs1 = -1, rs2 = -1;
                    if ((op1[0]=='x'||op1[0]=='w') && op1[1]>='0' && op1[1]<='9')
                        rd = atoi(op1 + 1);
                    if ((op2[0]=='x'||op2[0]=='w') && op2[1]>='0' && op2[1]<='9')
                        rs1 = atoi(op2 + 1);
                    if ((op3[0]=='x'||op3[0]=='w') && op3[1]>='0' && op3[1]<='9')
                        rs2 = atoi(op3 + 1);
                    /* Bounds-check reg indices before any array use */
                    if (rd  < 0 || rd  > 30) rd  = -1;
                    if (rs1 < 0 || rs1 > 30) rs1 = -1;
                    if (rs2 < 0 || rs2 > 30) rs2 = -1;

                    if ((strcmp(m,"movz")==0||strcmp(m,"mov")==0) && rd>=0 && op2[0]=='#') {
                        regs[rd] = (uint64_t)strtoull(op2+1, NULL, 0); known[rd] = 1;
                    } else if (strcmp(m,"adr")==0 && rd>=0 && op2[0]=='0') {
                        regs[rd] = (uint64_t)strtoull(op2, NULL, 16); known[rd] = 1;
                    } else if (strcmp(m,"adrp")==0 && rd>=0 && op2[0]=='0') {
                        regs[rd] = (uint64_t)strtoull(op2,NULL,16) & ~0xFFFULL; known[rd] = 1;
                    } else if ((strcmp(m,"add")==0||strcmp(m,"adds")==0) && rd>=0 && rs1>=0) {
                        if (known[rs1] && op3[0]=='#') {
                            regs[rd] = regs[rs1] + (uint64_t)strtoull(op3+1,NULL,0); known[rd] = 1;
                        } else if (known[rs1] && rs2>=0 && known[rs2]) {
                            regs[rd] = regs[rs1] + regs[rs2]; known[rd] = 1;
                        } else { known[rd] = 0; }
                    } else if ((strcmp(m,"sub")==0||strcmp(m,"subs")==0) && rd>=0 && rs1>=0) {
                        if (known[rs1] && op3[0]=='#') {
                            regs[rd] = regs[rs1] - (uint64_t)strtoull(op3+1,NULL,0); known[rd] = 1;
                        } else if (known[rs1] && rs2>=0 && known[rs2]) {
                            regs[rd] = regs[rs1] - regs[rs2]; known[rd] = 1;
                        } else { known[rd] = 0; }
                    } else if (strcmp(m,"br")==0 && op1[0]=='x') {
                        int br_reg = atoi(op1 + 1);
                        /* Guard br_reg before array access */
                        if (br_reg >= 0 && br_reg <= 30 && known[br_reg]) {
                            uint64_t tgt2 = regs[br_reg];
                            if (tgt2 >= base2 && tgt2 < base2 + csz &&
                                bin.nsymbols < DAX_MAX_SYMBOLS && bin.symbols) {
                                int dup = 0, si4;
                                for (si4 = 0; si4 < bin.nsymbols; si4++)
                                    if (bin.symbols[si4].address == tgt2) { dup = 1; break; }
                                if (!dup) {
                                    dax_symbol_t *ns = &bin.symbols[bin.nsymbols++];
                                    memset(ns, 0, sizeof(*ns));
                                    ns->address = tgt2;
                                    snprintf(ns->name, DAX_SYM_NAME_LEN,
                                             "indirect_tgt_0x%llx",
                                             (unsigned long long)tgt2);
                                    ns->type = SYM_LOCAL;
                                }
                            }
                        }
                        break;
                    } else if (strncmp(m,"ret",3)==0) {
                        break;
                    } else if (rd >= 0) {
                        known[rd] = 0;
                    }
                } /* while decode */
            } /* for fi2 */
        } /* ARM64 indirect resolver */

        /* ── CFG build: guard each function's section bounds ── */
        for (fi = 0; fi < bin.nfunctions && fi < DAX_MAX_FUNCTIONS; fi++) {
            dax_func_t *fn = &bin.functions[fi];
            int si2;
            for (si2 = 0; si2 < bin.nsections && si2 < DAX_MAX_SECTIONS; si2++) {
                dax_section_t *sec = &bin.sections[si2];
                if (fn->start < sec->vaddr ||
                    fn->start >= sec->vaddr + sec->size) continue;
                if (sec->size == 0) continue;
                if (sec->offset > bin.size) continue;
                if (sec->size > bin.size - sec->offset) continue;
                DAX_RUN_PASS("cfg-build", opts.color,
                    dax_cfg_build(&bin,
                                  bin.data + sec->offset,
                                  (size_t)sec->size,
                                  sec->vaddr, fi));
                break;
            }
        }
        dax_clamp_counts(&bin);
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
        DAX_RUN_PASS("disasm", opts.color, dax_disasm_x86_64(&bin, &opts, stdout));
    else if (bin.arch == ARCH_ARM64)
        DAX_RUN_PASS("disasm", opts.color, dax_disasm_arm64(&bin, &opts, stdout));
    else if (bin.arch == ARCH_RISCV64)
        DAX_RUN_PASS("disasm", opts.color, dax_disasm_riscv64(&bin, &opts, stdout));
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
        for (fi = 0; fi < bin.nfunctions && fi < DAX_MAX_FUNCTIONS; fi++)
            DAX_RUN_PASS("cfg-print", opts.color,
                dax_cfg_print(&bin, fi, &opts, stdout));
    }

    if (opts.loops)
        DAX_RUN_PASS("loops", opts.color, dax_loop_print_all(&bin, &opts, stdout));

    if (opts.callgraph)
        DAX_RUN_PASS("callgraph", opts.color, dax_callgraph_print(&bin, &opts, stdout));

    if (opts.switches) {
        int si;
        int col = opts.color;
        printf("\n");
        if (col) printf("%s", COL_FUNC);
        printf("  ══════════════ SWITCH DETECTION ══════════════\n");
        if (col) printf("%s", COL_RESET);
        for (si = 0; si < bin.nsections && si < DAX_MAX_SECTIONS; si++) {
            dax_section_t *sw_sec = &bin.sections[si];
            if (sw_sec->type != SEC_TYPE_CODE) continue;
            if (sw_sec->size == 0) continue;
            if (sw_sec->offset > bin.size) continue;
            if (sw_sec->size > bin.size - sw_sec->offset) continue;
            if (col) printf("%s  [%s]%s\n", COL_SECTION, sw_sec->name, COL_RESET);
            DAX_RUN_PASS("switch-detect", col,
                dax_switch_detect(&bin, &opts,
                                  bin.data + sw_sec->offset,
                                  (size_t)sw_sec->size,
                                  sw_sec->vaddr, stdout));
        }
        printf("\n");
    }

    if (opts.unicode)
        DAX_RUN_PASS("unicode-print", opts.color,
            dax_print_unicode_strings(&bin, &opts, stdout));

    if (opts.symexec)
        DAX_RUN_PASS("symexec", opts.color, dax_symexec_all(&bin, &opts, stdout));

    if (opts.ssa)
        DAX_RUN_PASS("ssa", opts.color, dax_ssa_lift_all(&bin, &opts, stdout));

    if (opts.decompile)
        DAX_RUN_PASS("decompile", opts.color, dax_decompile_all(&bin, &opts, stdout));

    if (opts.emulate)
        DAX_RUN_PASS("emulate", opts.color, dax_emulate_all(&bin, &opts, stdout));

    /* ── DSA: Dynamic Single Assignment over all functions ── */
    if (opts.dsa) {
        int fi_dsa;
        dsa_func_t *df_main = (dsa_func_t *)calloc(1, DAX_DSA_FUNC_SIZE);
        if (df_main) {
            int col = opts.color;
            printf("\n");
            if (col) printf("%s", COL_FUNC);
            printf("  ══════════════ DSA — DYNAMIC SINGLE ASSIGNMENT ══════════════\n");
            if (col) printf("%s", COL_RESET);
            for (fi_dsa = 0; fi_dsa < bin.nfunctions && fi_dsa < DAX_MAX_FUNCTIONS; fi_dsa++) {
                DAX_RUN_PASS("dsa-build", col,
                    dax_dsa_build_func(&bin, fi_dsa, df_main));
                DAX_RUN_PASS("dsa-print", col,
                    dax_dsa_print(&bin, fi_dsa, df_main, &opts, stdout));
                memset(df_main, 0, DAX_DSA_FUNC_SIZE);
            }
            free(df_main);
        }
    }

    if (opts.entropy)
        DAX_RUN_PASS("entropy", opts.color, dax_entropy_scan(&bin, &opts, stdout));

    if (opts.rda)
        DAX_RUN_PASS("rda", opts.color, dax_rda_all(&bin, &opts, stdout));

    if (opts.ivf) {
        DAX_RUN_PASS("ivf", opts.color, dax_ivf_scan(&bin, &opts, stdout));
        DAX_RUN_PASS("ivf-plugins", opts.color,
            dax_plugin_run_ivf(&plugin_reg, &bin, &opts, stdout));
    }

    if (opts.poly_map)
        DAX_RUN_PASS("poly-map", opts.color, dax_poly_map(&bin, &opts, stdout));

    if (opts.vm_trace)
        DAX_RUN_PASS("vm-trace", opts.color, dax_vm_trace(&bin, &opts, stdout));

    if (opts.aire) {
        if (!opts.poly_map)
            DAX_RUN_PASS("poly-map(aire)", opts.color, dax_poly_map(&bin, &opts, stdout));
        DAX_RUN_PASS("aire", opts.color, dax_aire_analyze(&bin, &opts, stdout));
    }

    if (opts.output_daxc[0])
        DAX_RUN_PASS("daxc-write", opts.color,
            dax_daxc_write(&bin, &opts, opts.output_daxc));

    /* interactive shell: not wrapped — it owns stdin, faults are handled inside */
    if (opts.interactive)
        dax_interactive(&bin, &opts);

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
#endif
