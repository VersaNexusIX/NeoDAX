#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include "dax.h"

/*
 * correct.c — pre-flight argument correction engine
 *
 * Before main() does any real work it calls dax_print_correction().
 * That function parses argv, compares every flag against KNOWN_FLAGS
 * and COMMON_MISTAKES, and prints a colour-coded "Command Analysis"
 * box with warnings, typo-fixes, and usage hints.
 *
 * Levenshtein edit-distance is used for fuzzy flag matching so that
 * single-character typos like "-ff" or "-yy" are caught automatically.
 */

#define CORR_MAX_FLAGS  128
#define CORR_MAX_FILES  16

/*
 * known_flag_t — one entry in the canonical flag table.
 * takes_arg == 1 means the flag consumes the next argv token.
 */
typedef struct {
    const char *flag;
    const char *desc;
    int         takes_arg;
    const char *arg_hint;
} known_flag_t;

/*
 * KNOWN_FLAGS — complete list of every valid NeoDAX flag.
 * This table is used for both fuzzy-matching and exact look-ups.
 * Keep in sync with the switch() in main.c and print_usage().
 */
static const known_flag_t KNOWN_FLAGS[] = {
    /* ── Disassembly ─────────────────────────────────────────────── */
    {"-a", "show hex bytes alongside each instruction",           0, NULL},
    {"-s", "disassemble specific section  (default: .text)",      1, "<section>"},
    {"-S", "disassemble ALL executable sections",                 0, NULL},
    {"-A", "start disassembly at address (hex)",                  1, "<addr>"},
    {"-E", "stop disassembly at address (hex)",                   1, "<addr>"},
    {"-l", "list all sections with metadata",                     0, NULL},

    /* ── Standard analysis ───────────────────────────────────────── */
    {"-y", "resolve symbols (symtab / dynsym / PE exports)",      0, NULL},
    {"-d", "demangle C++ Itanium ABI names",                      0, NULL},
    {"-f", "detect function boundaries and sizes",                0, NULL},
    {"-g", "instruction group coloring (call/branch/ret/arith)",  0, NULL},
    {"-r", "cross-reference annotations (callers / callees)",     0, NULL},
    {"-t", "annotate string references (ASCII + UTF-8 + UTF-16)", 0, NULL},
    {"-C", "control flow graph (basic blocks + edges)",           0, NULL},
    {"-L", "loop detection (natural loops via dominators)",       0, NULL},
    {"-G", "call graph (who calls who, tree view)",               0, NULL},
    {"-W", "switch / dispatch table detection",                   0, NULL},
    {"-u", "scan Unicode strings (UTF-8, UTF-16LE/BE)",           0, NULL},

    /* ── Advanced analysis ───────────────────────────────────────── */
    {"-P", "symbolic execution (multi-path, opaque folding, VM-aware)", 0, NULL},
    {"-Q", "SSA lifting (Static Single Assignment IR)",           0, NULL},
    {"-D", "decompile (pseudo-C output from SSA IR)",             0, NULL},
    {"-I", "emulate (concrete ARM64 execution engine)",           0, NULL},
    {"-e", "entropy analysis (packed / encrypted region detection)", 0, NULL},
    {"-R", "recursive descent (follow control flow, mark dead bytes)", 0, NULL},
    {"-V", "instruction validity + obfuscation filter (IVF + VM detector)", 0, NULL},
    {"-i", "interactive shell (r2/GDB-style REPL)",               0, NULL},

    /* ── Suite shorthands ────────────────────────────────────────── */
    {"-x", "standard suite: -y -d -f -g -r -t -u -C -L -G -W",  0, NULL},
    {"-X", "everything: -x plus -P -Q -D -I -e -R -V -i",        0, NULL},

    /* ── Output / files ──────────────────────────────────────────── */
    {"-o",        "save analysis snapshot to .daxc file",         1, "<file.daxc>"},
    {"-c",        "convert .daxc snapshot to annotated .S assembly", 0, NULL},
    {"-n",        "no color output (for piping / grep / logging)", 0, NULL},
    {"-v",        "verbose mode (instruction counts, section info)", 0, NULL},
    {"-h",        "show help page",                               0, NULL},
    {"-eox",      "load plugins from folder (NeoX.c compiled .so files)", 1, "<folder>"},
    {"-eox-list", "list all loaded plugins and their hooks",      0, NULL},

    /* ── Long info options ───────────────────────────────────────── */
    {"--version", "print version and exit",                       0, NULL},
    {"--help",    "show help page",                               0, NULL},
    {"--detail",  "show host system and hardware information",    0, NULL},
    {"--support", "list supported binary formats and architectures", 0, NULL},

    {NULL, NULL, 0, NULL}
};

/*
 * COMMON_MISTAKES — exact wrong→right mapping table.
 * Entries where right == NULL mean "no clean replacement; show note only".
 * These are checked before fuzzy matching so the message is more precise.
 */
static const struct {
    const char *wrong;
    const char *right;
    const char *note;
} COMMON_MISTAKES[] = {
    /* Long-form aliases that now resolve to real flags */
    {"--verbose",     "-v",   NULL},
    {"--color",       NULL,   "color is on by default; use -n to disable"},
    {"--no-color",    "-n",   NULL},
    {"--symbols",     "-y",   NULL},
    {"--funcs",       "-f",   NULL},
    {"--functions",   "-f",   NULL},
    {"--xrefs",       "-r",   NULL},
    {"--cfg",         "-C",   NULL},
    {"--loops",       "-L",   NULL},
    {"--callgraph",   "-G",   NULL},
    {"--unicode",     "-u",   NULL},
    {"--strings",     "-t",   NULL},
    {"--entropy",     "-e",   NULL},
    {"--ivf",         "-V",   NULL},
    {"--rda",         "-R",   NULL},
    {"--ssa",         "-Q",   NULL},
    {"--decompile",   "-D",   NULL},
    {"--emulate",     "-I",   NULL},
    {"--symexec",     "-P",   NULL},
    {"--interactive", "-i",   NULL},
    {"--plugin",      "-eox", NULL},
    {"--plugins",     "-eox", NULL},
    {"-plugins",      "-eox", NULL},
    {"-plugin",       "-eox", NULL},

    /* Single-char near-misses */
    {"-p", "-P",  "did you want -P (symbolic exec) or -e (entropy)?"},
    {"-b", "-a",  "did you want -a (show bytes)?"},
    {"-z", "-V",  "did you want -V (IVF scan)?"},
    {"-q", "-n",  "did you want -n (no color / quiet)?"},
    {"-O", "-o",  NULL},
    {"-F", "-f",  NULL},
    {"-U", "-u",  NULL},
    {"-T", "-t",  NULL},
    {"-m", "-u",  "did you want -u (Unicode strings)?"},
    {"-k", "-x",  "did you want -x (standard analysis suite)?"},
    {"-K", "-X",  "did you want -X (full analysis suite)?"},
    {"-w", "-W",  NULL},
    {"-j", "-Q",  "did you want -Q (SSA lifting)?"},
    {"-J", "-Q",  "did you want -Q (SSA)?"},
    {"-M", "-G",  "did you want -G (call graph)?"},
    {"-N", NULL,  "did you want -n (no color)?"},
    {"-B", "-a",  "did you want -a (show bytes)?"},
    {"-H", "-h",  NULL},

    {NULL, NULL, NULL}
};

/*
 * levenshtein — standard DP edit-distance between two strings.
 * Case-insensitive. Returns 99 if either string is longer than 32 chars.
 */
static int levenshtein(const char *a, const char *b) {
    int la = (int)strlen(a);
    int lb = (int)strlen(b);
    int i, j;
    int dp[34][34];

    if (la == 0) return lb;
    if (lb == 0) return la;
    if (la > 32 || lb > 32) return 99;

    for (i = 0; i <= la; i++) dp[i][0] = i;
    for (j = 0; j <= lb; j++) dp[0][j] = j;

    for (i = 1; i <= la; i++) {
        for (j = 1; j <= lb; j++) {
            int cost = (tolower((unsigned char)a[i-1]) !=
                        tolower((unsigned char)b[j-1])) ? 1 : 0;
            int del  = dp[i-1][j]   + 1;
            int ins  = dp[i][j-1]   + 1;
            int sub  = dp[i-1][j-1] + cost;
            dp[i][j] = del < ins ? (del < sub ? del : sub)
                                 : (ins < sub ? ins : sub);
        }
    }
    return dp[la][lb];
}

/* exact_mistake — returns the wrong-string if flag is in COMMON_MISTAKES. */
static const char *exact_mistake(const char *flag) {
    int i;
    for (i = 0; COMMON_MISTAKES[i].wrong; i++)
        if (strcmp(flag, COMMON_MISTAKES[i].wrong) == 0)
            return COMMON_MISTAKES[i].wrong;
    return NULL;
}

/* mistake_right — returns the canonical replacement for a known mistake. */
static const char *mistake_right(const char *flag) {
    int i;
    for (i = 0; COMMON_MISTAKES[i].wrong; i++)
        if (strcmp(flag, COMMON_MISTAKES[i].wrong) == 0)
            return COMMON_MISTAKES[i].right;
    return NULL;
}

/* mistake_note — returns any supplementary note for a known mistake. */
static const char *mistake_note(const char *flag) {
    int i;
    for (i = 0; COMMON_MISTAKES[i].wrong; i++)
        if (strcmp(flag, COMMON_MISTAKES[i].wrong) == 0)
            return COMMON_MISTAKES[i].note;
    return NULL;
}

/*
 * best_flag_match — finds the KNOWN_FLAGS entry with the lowest
 * Levenshtein distance to bad. Writes the distance into *dist_out.
 */
static const known_flag_t *best_flag_match(const char *bad, int *dist_out) {
    const known_flag_t *best = NULL;
    int best_dist = 99;
    int i;
    for (i = 0; KNOWN_FLAGS[i].flag; i++) {
        int d = levenshtein(bad, KNOWN_FLAGS[i].flag);
        if (d < best_dist) { best_dist = d; best = &KNOWN_FLAGS[i]; }
    }
    if (dist_out) *dist_out = best_dist;
    return best;
}

/* find_flag — exact look-up of a flag string in KNOWN_FLAGS. */
static const known_flag_t *find_flag(const char *flag) {
    int i;
    for (i = 0; KNOWN_FLAGS[i].flag; i++)
        if (strcmp(KNOWN_FLAGS[i].flag, flag) == 0)
            return &KNOWN_FLAGS[i];
    return NULL;
}

/* is_daxc_file — returns 1 if the path ends with ".daxc". */
static int is_daxc_file(const char *s) {
    size_t l = strlen(s);
    return l > 5 && strcmp(s + l - 5, ".daxc") == 0;
}

/* looks_like_binary — heuristic: anything that doesn't start with '-'. */
static int looks_like_binary(const char *s) {
    if (s[0] == '-') return 0;
    return 1;
}

/*
 * corr_result_t — output structure produced by dax_correct_args().
 * messages is a newline-separated log of all warnings/errors/hints.
 * corrected holds the best-guess reconstructed command line.
 */
typedef struct {
    int  has_errors;
    int  has_warnings;
    int  has_hints;
    char corrected[2048];
    char messages[8192];
} corr_result_t;

/* corr_append — safe append to a fixed-size message buffer. */
static void corr_append(char *buf, size_t bufsz, const char *msg) {
    size_t cur = strlen(buf);
    size_t add = strlen(msg);
    if (cur + add + 1 < bufsz)
        memcpy(buf + cur, msg, add + 1);
}

/* corr_warn — append a formatted warning line and set has_warnings. */
static void corr_warn(corr_result_t *res, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    corr_append(res->messages, sizeof(res->messages), tmp);
    res->has_warnings = 1;
}

/* corr_err — append a formatted error line and set has_errors. */
static void corr_err(corr_result_t *res, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    corr_append(res->messages, sizeof(res->messages), tmp);
    res->has_errors = 1;
}

/* corr_hint — append a formatted hint line and set has_hints. */
static void corr_hint(corr_result_t *res, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    corr_append(res->messages, sizeof(res->messages), tmp);
    res->has_hints = 1;
}

/*
 * dax_correct_args — core correction pass.
 *
 * Iterates argv once. For each token it decides:
 *   1. Non-flag token  → record as a file path candidate.
 *   2. -eox / -eox-list special cases handled before the generic path.
 *   3. Long options that are now valid (--version, --help, --detail,
 *      --support) are passed through unchanged.
 *   4. Exact entry in COMMON_MISTAKES → warn and substitute.
 *   5. Exact entry in KNOWN_FLAGS → accept as-is.
 *   6. Fuzzy match with edit-distance <= 2 → warn and substitute.
 *   7. Otherwise → error (unknown flag).
 *
 * Additional semantic checks after the loop:
 *   - No input file specified.
 *   - -c used with a binary instead of a .daxc snapshot.
 *   - -o with a .daxc argument but no binary.
 */
void dax_correct_args(int argc, char **argv, corr_result_t *res) {
    int  i;
    int  files[CORR_MAX_FILES];
    int  nfiles      = 0;
    char fixed_args[CORR_MAX_FLAGS][128];
    int  nfixed      = 0;
    int  has_c_flag  = 0;
    int  has_o_flag  = 0;
    int  has_eox     = 0;
    int  has_eox_list= 0;
    /* Flags that are self-contained and never need a binary target */
    int  has_standalone = 0;
    int  daxc_pos    = -1;
    int  binary_pos  = -1;
    int  eox_has_dir = 0;

    memset(res, 0, sizeof(*res));

    for (i = 1; i < argc && nfixed < CORR_MAX_FLAGS - 2; i++) {
        char *a = argv[i];

        /* ── Non-flag: file path ─────────────────────────────────── */
        if (a[0] != '-') {
            if (nfiles < CORR_MAX_FILES) files[nfiles++] = i;
            strncpy(fixed_args[nfixed++], a, 127);
            if (is_daxc_file(a))           daxc_pos   = i;
            else if (looks_like_binary(a)) binary_pos = i;
            continue;
        }

        /* ── Plugin loader flags (special multi-token handling) ───── */
        if (!strcmp(a, "-eox")) {
            has_eox = 1;
            strncpy(fixed_args[nfixed++], a, 127);
            if (i + 1 < argc && argv[i+1][0] != '-') {
                i++;
                strncpy(fixed_args[nfixed++], argv[i], 127);
                eox_has_dir = 1;
            } else {
                corr_err(res,
                    "  \033[1;31merror\033[0m    \033[1;37m-eox\033[0m requires a folder argument"
                    "  \033[0;90m(e.g. -eox ./plugins/)\033[0m\n");
            }
            continue;
        }

        if (!strcmp(a, "-eox-list")) {
            has_eox_list = 1;
            strncpy(fixed_args[nfixed++], a, 127);
            if (!has_eox) {
                corr_warn(res,
                    "  \033[1;33mwarning\033[0m  \033[1;37m-eox-list\033[0m is only useful with"
                    " \033[1;32m-eox <folder>\033[0m"
                    " \033[0;90m(no plugins loaded yet)\033[0m\n");
            }
            continue;
        }

        /* ── Valid long options — pass through unchanged ──────────── */
        if (!strcmp(a, "--version") || !strcmp(a, "--help") ||
            !strcmp(a, "--detail")  || !strcmp(a, "--support")) {
            strncpy(fixed_args[nfixed++], a, 127);
            has_standalone = 1;
            continue;
        }

        /* ── Easter eggs — no binary needed ───────────────────────── */
        if (!strcmp(a, "--key") || !strcmp(a, "--rtx-5090-ti")) {
            strncpy(fixed_args[nfixed++], a, 127);
            has_standalone = 1;
            continue;
        }

        /* ── Exact mistake table hit ──────────────────────────────── */
        if (exact_mistake(a)) {
            const char *right = mistake_right(a);
            const char *note  = mistake_note(a);
            if (right) {
                const known_flag_t *kf = find_flag(right);
                corr_warn(res,
                    "  \033[1;33mwarning\033[0m  \033[1;37m%s\033[0m"
                    "  \342\206\222  \033[1;32m%s\033[0m"
                    " \033[0;90m(%s)\033[0m\n",
                    a, right, kf ? kf->desc : "");
                if (note)
                    corr_hint(res, "  \033[1;33mhint\033[0m     %s\n", note);
                strncpy(fixed_args[nfixed++], right, 127);
                if (kf && kf->takes_arg && i + 1 < argc && argv[i+1][0] != '-') {
                    i++;
                    strncpy(fixed_args[nfixed++], argv[i], 127);
                }
                if (!strcmp(right, "-c")) has_c_flag = 1;
                if (!strcmp(right, "-o")) has_o_flag = 1;
            } else {
                if (note)
                    corr_hint(res,
                        "  \033[1;33mhint\033[0m     \033[1;37m%s\033[0m: %s\n", a, note);
                else
                    corr_err(res,
                        "  \033[1;31merror\033[0m    unknown flag \033[1;37m%s\033[0m"
                        " \033[0;90m(no replacement known)\033[0m\n", a);
            }
            continue;
        }

        /* ── Exact known flag or fuzzy match ──────────────────────── */
        {
            int dist = 0;
            const known_flag_t *kf = find_flag(a);

            if (kf) {
                /* Exact match — accept verbatim. */
                strncpy(fixed_args[nfixed++], a, 127);
                if (!strcmp(a, "-c")) has_c_flag = 1;
                if (!strcmp(a, "-o")) has_o_flag = 1;
                /* -h needs no binary target */
                if (!strcmp(a, "-h")) has_standalone = 1;
                if (kf->takes_arg && i + 1 < argc && argv[i+1][0] != '-') {
                    i++;
                    strncpy(fixed_args[nfixed++], argv[i], 127);
                } else if (kf->takes_arg) {
                    corr_err(res,
                        "  \033[1;31merror\033[0m    \033[1;37m%s\033[0m requires an argument"
                        " \033[0;90m(%s)\033[0m\n",
                        a, kf->arg_hint ? kf->arg_hint : "value");
                }
            } else {
                /* Fuzzy match via edit-distance. */
                const known_flag_t *best = best_flag_match(a, &dist);

                if (dist == 0) {
                    strncpy(fixed_args[nfixed++], a, 127);
                } else if (dist <= 2 && best) {
                    corr_warn(res,
                        "  \033[1;33mwarning\033[0m  typo \033[1;37m%s\033[0m"
                        "  \342\206\222  \033[1;32m%s\033[0m"
                        " \033[0;90m(%s)\033[0m\n",
                        a, best->flag, best->desc);
                    strncpy(fixed_args[nfixed++], best->flag, 127);
                    if (!strcmp(best->flag, "-c")) has_c_flag = 1;
                    if (!strcmp(best->flag, "-o")) has_o_flag = 1;
                    if (best->takes_arg && i + 1 < argc && argv[i+1][0] != '-') {
                        i++;
                        strncpy(fixed_args[nfixed++], argv[i], 127);
                    }
                } else {
                    corr_err(res,
                        "  \033[1;31merror\033[0m    unknown flag \033[1;37m%s\033[0m"
                        " \033[0;90m(closest: %s — edit distance %d)\033[0m\n",
                        a, best ? best->flag : "?", dist);
                }
            }
        }
    }

    /* ── Semantic checks after the flag loop ──────────────────────── */

    /* Warn when no input file was given (and not just listing plugins). */
    if (nfiles == 0 && !has_c_flag && !has_eox_list && !has_standalone && argc > 1) {
        int all_flags = 1, j;
        for (j = 0; j < nfixed; j++)
            if (fixed_args[j][0] != '-') { all_flags = 0; break; }
        if (all_flags)
            corr_err(res,
                "  \033[1;31merror\033[0m    no input file specified"
                " \033[0;90m(add a binary path after your flags)\033[0m\n");
    }

    /* Warn when -c is paired with a plain binary instead of .daxc. */
    if (has_c_flag && nfiles >= 2) {
        int found_daxc = 0, found_bin = 0, j;
        for (j = 0; j < nfiles; j++) {
            if (is_daxc_file(argv[files[j]])) found_daxc = 1;
            else found_bin = 1;
        }
        if (found_daxc && found_bin) {
            corr_warn(res,
                "  \033[1;33mwarning\033[0m  \033[0;90m-c\033[0m converts"
                " \033[1;36m.daxc \342\206\222 .S\033[0m and only takes a"
                " \033[1;36m.daxc\033[0m file, not a binary\n");
            if (daxc_pos >= 0 && binary_pos >= 0) {
                corr_hint(res,
                    "  \033[1;33mhint\033[0m     to create a snapshot first:"
                    " \033[1;32mneodax -x -o out.daxc %s\033[0m\n",
                    argv[binary_pos]);
                corr_hint(res,
                    "  \033[1;33mhint\033[0m     then convert it:"
                    " \033[1;32mneodax -c out.daxc\033[0m\n");
            }
        }
    }

    if (has_c_flag && nfiles == 1 && binary_pos >= 0 &&
        !is_daxc_file(argv[binary_pos])) {
        corr_warn(res,
            "  \033[1;33mwarning\033[0m  \033[1;37m-c\033[0m expects a"
            " \033[1;36m.daxc\033[0m file, but got \033[1;37m%s\033[0m\n",
            argv[binary_pos]);
        corr_hint(res,
            "  \033[1;33mhint\033[0m     create a snapshot first:"
            " \033[1;32mneodax -x -o snap.daxc %s\033[0m"
            " then \033[1;32mneodax -c snap.daxc\033[0m\n",
            argv[binary_pos]);
    }

    /* Hint when -o is used with a .daxc argument (likely meant to load it). */
    if (has_o_flag && daxc_pos >= 0 && binary_pos < 0 && !has_c_flag) {
        corr_hint(res,
            "  \033[1;33mhint\033[0m     \033[0;90m-o\033[0m saves a snapshot of a binary."
            " Did you mean to load it with:"
            " \033[1;32mneodax %s\033[0m?\n", argv[daxc_pos]);
    }

    /* Suppress unused-variable warnings for flags tracked but not yet used. */
    (void)has_eox;
    (void)has_eox_list;
    (void)has_standalone;
    (void)eox_has_dir;
    (void)has_o_flag;

    /* Reconstruct the corrected command line string. */
    {
        char *p = res->corrected;
        int   j;
        strncpy(p, "neodax", 2047);
        p[2047] = '\0';
        for (j = 0; j < nfixed; j++) {
            size_t rem = 2047 - strlen(p);
            if (rem > 2) strncat(p, " ", 1);
            rem = 2047 - strlen(p);
            if (rem > 1) strncat(p, fixed_args[j], rem - 1);
        }
    }
}

/*
 * dax_print_correction — public entry point called from main().
 *
 * Runs dax_correct_args() and, if any issues were found, renders the
 * "Command Analysis" box to *out. Exits silently when argv is clean.
 */
void dax_print_correction(int argc, char **argv, FILE *out) {
    corr_result_t res;
    int           c = 1;
    int           i;

    dax_correct_args(argc, argv, &res);

    /* Nothing to report — return immediately and keep startup fast. */
    if (!res.has_errors && !res.has_warnings && !res.has_hints) return;

    fprintf(out, "\n");
    fprintf(out, "%s  \342\224\214\342\224\200 Command Analysis %s%s\n",
            c ? "\033[0;90m" : "",
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200",
            c ? "\033[0m" : "");

    fprintf(out, "%s  \342\224\202%s  \033[0;90myou typed:\033[0m  \033[1;37m",
            c ? "\033[0;90m" : "", c ? "\033[0m" : "");
    fprintf(out, "neodax");
    for (i = 1; i < argc; i++) fprintf(out, " %s", argv[i]);
    fprintf(out, "\033[0m\n");

    if (res.messages[0]) {
        char  msgbuf[8192];
        char *line;
        strncpy(msgbuf, res.messages, sizeof(msgbuf) - 1);
        msgbuf[sizeof(msgbuf) - 1] = '\0';
        fprintf(out, "%s  \342\224\202%s\n", c ? "\033[0;90m" : "", c ? "\033[0m" : "");
        line = strtok(msgbuf, "\n");
        while (line) {
            fprintf(out, "%s  \342\224\202%s%s\n",
                    c ? "\033[0;90m" : "", c ? "\033[0m" : "", line);
            line = strtok(NULL, "\n");
        }
    }

    if (!res.has_errors && res.corrected[0] &&
        strcmp(res.corrected, argv[0]) != 0) {
        fprintf(out, "%s  \342\224\202%s\n", c ? "\033[0;90m" : "", c ? "\033[0m" : "");
        fprintf(out, "%s  \342\224\202%s  \033[0;32mcorrected:\033[0m  \033[1;32m%s\033[0m\n",
                c ? "\033[0;90m" : "", c ? "\033[0m" : "", res.corrected);
    }

    fprintf(out, "%s  \342\224\224%s%s\n\n",
            c ? "\033[0;90m" : "",
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200"
            "\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200",
            c ? "\033[0m" : "");
}
