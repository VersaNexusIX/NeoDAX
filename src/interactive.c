#include <stdio.h>
#include "dax.h"

int dax_interactive(dax_binary_t *bin, dax_opts_t *opts) {
    (void)bin;
    (void)opts;
    fprintf(stderr, "neodax: interactive TUI mode has been removed in NeoDAX v%s\n", DAX_VERSION);
    return -1;
}
