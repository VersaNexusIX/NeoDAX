#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dax.h"

#define CORR_MAX_FLAGS  64
#define CORR_MAX_FILES  16

typedef struct {
    const char *flag;
    const char *desc;
    int         takes_arg;
} known_flag_t;

static const known_flag_t KNOWN_FLAGS[] = {
    {"-a", "show hex bytes",            0},
    {"-s", "section name",              1},
    {"-S", "all sections",              0},
    {"-A", "start address (hex)",       1},
    {"-E", "end address (hex)",         1},
    {"-l", "list sections",             0},
    {"-n", "no color",                  0},
    {"-v", "verbose",                   0},
    {"-y", "symbol resolving",          0},
    {"-d", "demangle C++",              0},
    {"-f", "function detection",        0},
    {"-g", "instruction groups",        0},
    {"-r", "cross-references",          0},
    {"-t", "string annotations",        0},
    {"-C", "control flow graph",        0},
    {"-x", "enable all analysis",       0},
    {"-u", "unicode string scan",        0},
    {"-W", "switch detection",            0},
    {"-c", "convert .daxc to .S",       0},
    {"-o", "output .daxc file",         1},
    {"-L", "loop detection",            0},
    {"-G", "call graph",                0},
    {"-h", "help",                      0},
    {NULL, NULL, 0}
};

static int levenshtein(const char *a, const char *b) {
    int la = (int)strlen(a);
    int lb = (int)strlen(b);
    int i, j;
    int *dp;

    if (la == 0) return lb;
    if (lb == 0) return la;
    if (la > 32 || lb > 32) return 99;

    dp = (int *)calloc((la + 1) * (lb + 1), sizeof(int));
    if (!dp) return 99;

    for (i = 0; i <= la; i++) dp[i * (lb+1) + 0] = i;
    for (j = 0; j <= lb; j++) dp[0 * (lb+1) + j] = j;

    for (i = 1; i <= la; i++) {
        for (j = 1; j <= lb; j++) {
            int cost = (tolower((unsigned char)a[i-1]) !=
                        tolower((unsigned char)b[j-1])) ? 1 : 0;
            int del  = dp[(i-1)*(lb+1)+j] + 1;
            int ins  = dp[i*(lb+1)+(j-1)] + 1;
            int sub  = dp[(i-1)*(lb+1)+(j-1)] + cost;
            dp[i*(lb+1)+j] = del < ins ? (del < sub ? del : sub)
                                        : (ins < sub ? ins : sub);
        }
    }
    { int r = dp[la*(lb+1)+lb]; free(dp); return r; }
}

static const char *best_flag_match(const char *bad, int *dist_out) {
    const known_flag_t *best = NULL;
    int best_dist = 99;
    int i;

    for (i = 0; KNOWN_FLAGS[i].flag; i++) {
        int d = levenshtein(bad, KNOWN_FLAGS[i].flag);
        if (d < best_dist) { best_dist = d; best = &KNOWN_FLAGS[i]; }
    }
    if (dist_out) *dist_out = best_dist;
    return best ? best->flag : NULL;
}

static int is_daxc_file(const char *s) {
    size_t l = strlen(s);
    return l > 5 && strcmp(s + l - 5, ".daxc") == 0;
}

static int looks_like_binary(const char *s) {
    if (s[0] == '-') return 0;
    if (strchr(s, '.')) {
        const char *ext = strrchr(s, '.');
        if (strcmp(ext, ".daxc") == 0) return 1;
        if (strcmp(ext, ".elf")  == 0) return 1;
        if (strcmp(ext, ".so")   == 0) return 1;
        if (strcmp(ext, ".exe")  == 0) return 1;
    }
    return 1;
}

static int flag_takes_arg(const char *flag) {
    int i;
    for (i = 0; KNOWN_FLAGS[i].flag; i++)
        if (strcmp(KNOWN_FLAGS[i].flag, flag) == 0)
            return KNOWN_FLAGS[i].takes_arg;
    return 0;
}

typedef struct {
    int         has_errors;
    int         has_warnings;
    char        corrected[2048];
    char        messages[4096];
} corr_result_t;

static void corr_append(char *buf, size_t bufsz, const char *msg) {
    size_t cur = strlen(buf);
    if (cur + strlen(msg) + 1 < bufsz)
        strcat(buf, msg);
}

void dax_correct_args(int argc, char **argv, corr_result_t *res) {
    int    i;
    int    files[CORR_MAX_FILES];
    int    nfiles = 0;
    int    flags_seen[CORR_MAX_FLAGS];
    int    nflags = 0;
    char   fixed_args[CORR_MAX_FLAGS][64];
    int    nfixed = 0;
    char   tmp[256];
    int    has_c_flag   = 0;
    int    has_o_flag   = 0;
    int    c_flag_pos   = -1;
    int    daxc_pos     = -1;
    int    binary_pos   = -1;

    memset(res, 0, sizeof(*res));

    for (i = 1; i < argc && nfixed < CORR_MAX_FLAGS - 1; i++) {
        char *a = argv[i];

        if (a[0] == '-') {
            int dist = 0;
            const char *suggestion = best_flag_match(a, &dist);

            if (dist == 0) {
                strncpy(fixed_args[nfixed++], a, 63);
                flags_seen[nflags++ % CORR_MAX_FLAGS] = i; (void)flags_seen[0];
                if (strcmp(a, "-c") == 0) { has_c_flag = 1; c_flag_pos = i; }
                if (strcmp(a, "-o") == 0) { has_o_flag = 1; }
                if (flag_takes_arg(a) && i + 1 < argc) {
                    i++;
                    strncpy(fixed_args[nfixed++], argv[i], 63);
                }
            } else if (dist <= 2 && suggestion) {
                snprintf(tmp, sizeof(tmp),
                    "  \033[1;33mwarning\033[0m  typo \033[1;37m%s\033[0m"
                    "  →  did you mean \033[1;32m%s\033[0m (%s)?\n",
                    a, suggestion, KNOWN_FLAGS[0].desc);
                { int k;
                  for (k = 0; KNOWN_FLAGS[k].flag; k++)
                      if (strcmp(KNOWN_FLAGS[k].flag, suggestion) == 0)
                          snprintf(tmp, sizeof(tmp),
                              "  \033[1;33mwarning\033[0m  typo \033[1;37m%s\033[0m"
                              "  →  did you mean \033[1;32m%s\033[0m"
                              " \033[0;90m(%s)\033[0m?\n",
                              a, suggestion, KNOWN_FLAGS[k].desc);
                }
                corr_append(res->messages, sizeof(res->messages), tmp);
                strncpy(fixed_args[nfixed++], suggestion, 63);
                res->has_warnings = 1;
                if (strcmp(suggestion, "-c") == 0) { has_c_flag = 1; c_flag_pos = i; }
                if (strcmp(suggestion, "-o") == 0) { has_o_flag = 1; }
                if (flag_takes_arg(suggestion) && i + 1 < argc) {
                    i++;
                    strncpy(fixed_args[nfixed++], argv[i], 63);
                }
            } else {
                snprintf(tmp, sizeof(tmp),
                    "  \033[1;31merror\033[0m    unknown flag \033[1;37m%s\033[0m"
                    " \033[0;90m(no close match found)\033[0m\n", a);
                corr_append(res->messages, sizeof(res->messages), tmp);
                res->has_errors = 1;
            }
        } else {
            if (nfiles < CORR_MAX_FILES) files[nfiles++] = i;
            strncpy(fixed_args[nfixed++], a, 63);

            if (is_daxc_file(a)) daxc_pos = i;
            else if (looks_like_binary(a)) binary_pos = i;
        }
    }

    if (has_c_flag && nfiles >= 2) {
        int found_daxc = 0, found_bin = 0, j;
        for (j = 0; j < nfiles; j++) {
            if (is_daxc_file(argv[files[j]])) found_daxc = 1;
            else found_bin = 1;
        }

        if (found_daxc && found_bin) {
            snprintf(tmp, sizeof(tmp),
                "  \033[1;33mwarning\033[0m  \033[0;90m-c\033[0m converts"
                " \033[1;36m.daxc → .S\033[0m, it only takes a \033[1;36m.daxc\033[0m"
                " file, not a binary\n");
            corr_append(res->messages, sizeof(res->messages), tmp);

            if (daxc_pos >= 0 && binary_pos >= 0) {
                const char *daxc_name = argv[daxc_pos];
                const char *bin_name  = argv[binary_pos];
                snprintf(tmp, sizeof(tmp),
                    "  \033[1;33mhint\033[0m     to disassemble binary, use:"
                    " \033[1;32mdax -x -o out.daxc %s\033[0m then"
                    " \033[1;32mdax -c out.daxc\033[0m\n", bin_name);
                corr_append(res->messages, sizeof(res->messages), tmp);
                snprintf(tmp, sizeof(tmp),
                    "  \033[1;33mhint\033[0m     or to convert existing"
                    " .daxc: \033[1;32mdax -c %s\033[0m\n", daxc_name);
                corr_append(res->messages, sizeof(res->messages), tmp);
            }
            res->has_warnings = 1;
        }
    }
    (void)has_o_flag; (void)c_flag_pos; (void)daxc_pos; (void)binary_pos;

    {
        char *p = res->corrected;
        int   first = 1;
        int   j;
        strncpy(p, "neodax", 2047);
        p[2047] = '\0';
        for (j = 0; j < nfixed; j++) {
            size_t rem = 2047 - strlen(p);
            if (rem > 1) { strncat(p, " ", rem - 1); rem = 2047 - strlen(p); }
            if (rem > 1)   strncat(p, fixed_args[j], rem - 1);
            (void)first;
        }
        first = 0;
    }
}

void dax_print_correction(int argc, char **argv, FILE *out) {
    corr_result_t res;
    int           c = 1;
    int           i;

    dax_correct_args(argc, argv, &res);

    if (!res.has_errors && !res.has_warnings) return;

    fprintf(out, "\n");
    fprintf(out, "%s  ┌─ Command Analysis ──────────────────────────────────────────┐%s\n",
            c ? "\033[0;90m" : "", c ? "\033[0m" : "");

    fprintf(out, "%s  │%s  \033[0;90myou typed:\033[0m  \033[1;37m",
            c ? "\033[0;90m" : "", c ? "\033[0m" : "");
    fprintf(out, "neodax");
    for (i = 1; i < argc; i++) fprintf(out, " %s", argv[i]);
    fprintf(out, "\033[0m\n");

    if (res.messages[0]) {
        fprintf(out, "%s  │%s\n", c ? "\033[0;90m" : "", c ? "\033[0m" : "");
        {
            char *line = strtok(res.messages, "\n");
            while (line) {
                fprintf(out, "%s  │%s%s\n",
                        c ? "\033[0;90m" : "", c ? "\033[0m" : "", line);
                line = strtok(NULL, "\n");
            }
        }
    }

    if (res.has_warnings && !res.has_errors && res.corrected[0]) {
        fprintf(out, "%s  │%s\n", c ? "\033[0;90m" : "", c ? "\033[0m" : "");
        fprintf(out, "%s  │%s  \033[0;32mcorrected:\033[0m  \033[1;32m%s\033[0m\n",
                c ? "\033[0;90m" : "", c ? "\033[0m" : "", res.corrected);
    }

    fprintf(out, "%s  └─────────────────────────────────────────────────────────────┘%s\n\n",
            c ? "\033[0;90m" : "", c ? "\033[0m" : "");
}
