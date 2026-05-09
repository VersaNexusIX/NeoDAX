#ifndef DAX_PLUGIN_H
#define DAX_PLUGIN_H

#include "dax.h"

int  dax_plugin_load_dir(dax_plugin_registry_t *reg, const char *dir);
void dax_plugin_run_post_load(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts);
void dax_plugin_run_pre_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_post_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_ivf(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out);
void dax_plugin_run_banner(dax_plugin_registry_t *reg, FILE *out, int color);
void dax_plugin_list(dax_plugin_registry_t *reg, FILE *out, int color);
void dax_plugin_free(dax_plugin_registry_t *reg);

#endif
