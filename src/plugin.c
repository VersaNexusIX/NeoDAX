#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <dirent.h>
#include <limits.h>
#include <unistd.h>
#include "dax.h"

#define NEOX_ENTRY_SYMBOL  "neox_plugin_init"
#define NEOX_SOURCE_FILE   "NeoX.c"

typedef dax_plugin_t *(*neox_init_fn)(void);

static int ends_with(const char *s, const char *suffix) {
    size_t sl = strlen(s), xl = strlen(suffix);
    return sl >= xl && strcmp(s + sl - xl, suffix) == 0;
}

static time_t file_mtime(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return st.st_mtime;
}

static int is_dir(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISDIR(st.st_mode);
}

static int is_file(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static void find_include_dir(char *out, size_t outsz) {
    char self[PATH_MAX] = {0};
    char candidate[PATH_MAX];
    struct stat st;

    if (readlink("/proc/self/exe", self, PATH_MAX - 1) > 0) {
        char *slash = strrchr(self, '/');
        if (slash) {
            *slash = '\0';
            snprintf(candidate, PATH_MAX, "%s/../include", self);
            if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
                strncpy(out, candidate, outsz - 1);
                return;
            }
            snprintf(candidate, PATH_MAX, "%s/include", self);
            if (stat(candidate, &st) == 0 && S_ISDIR(st.st_mode)) {
                strncpy(out, candidate, outsz - 1);
                return;
            }
        }
    }

    static const char *fallbacks[] = {
        "./include",
        "../include",
        "/usr/local/include/neodax",
        "/usr/include/neodax",
        NULL
    };
    int i;
    for (i = 0; fallbacks[i]; i++) {
        if (stat(fallbacks[i], &st) == 0 && S_ISDIR(st.st_mode)) {
            strncpy(out, fallbacks[i], outsz - 1);
            return;
        }
    }

    strncpy(out, "./include", outsz - 1);
}

static int build_plugin(const char *src_path, const char *so_path,
                        const char *include_dir, int color,
                        char *errbuf, size_t errsz) {
    char   cmd[PATH_MAX * 3 + 256];
    char   cc[64] = "gcc";
    char   outbuf[2048] = {0};
    FILE  *fp;
    int    ret;
    const char *CY = color ? "\033[1;33m" : "";
    const char *CG = color ? "\033[1;32m" : "";
    const char *CR = color ? "\033[1;31m" : "";
    const char *CD = color ? "\033[0;90m" : "";
    const char *R  = color ? "\033[0m"    : "";

    if (getenv("CC")) strncpy(cc, getenv("CC"), 63);
    else if (access("/usr/bin/clang", X_OK) == 0 && access("/usr/bin/gcc", X_OK) != 0)
        strncpy(cc, "clang", 63);

    fprintf(stdout, "  %s[eox-build]%s  compiling %s%s%s\n",
            CY, R, CD, src_path, R);

    snprintf(cmd, sizeof(cmd),
             "%s -O2 -shared -fPIC -Wall -I%s -o %s %s 2>&1",
             cc, include_dir, so_path, src_path);

    fp = popen(cmd, "r");
    if (!fp) {
        snprintf(errbuf, errsz, "popen failed: %s", cmd);
        return -1;
    }

    {
        char line[512];
        size_t pos = 0;
        while (fgets(line, sizeof(line), fp) && pos + strlen(line) + 1 < sizeof(outbuf)) {
            memcpy(outbuf + pos, line, strlen(line));
            pos += strlen(line);
        }
    }

    ret = pclose(fp);

    if (ret != 0) {
        fprintf(stdout, "  %s[eox-build]%s  %sFAILED%s  %s\n",
                CY, R, CR, R, src_path);
        if (outbuf[0]) {
            char *line = strtok(outbuf, "\n");
            while (line) {
                fprintf(stdout, "  %s           %s%s\n", CD, line, R);
                line = strtok(NULL, "\n");
            }
        }
        snprintf(errbuf, errsz, "compile failed: %s", src_path);
        return -1;
    }

    fprintf(stdout, "  %s[eox-build]%s  %sOK%s  → %s%s%s\n",
            CY, R, CG, R, CD, so_path, R);
    return 0;
}

static int try_build_and_load(dax_plugin_registry_t *reg,
                              const char *subdir_path,
                              const char *include_dir,
                              int color) {
    char src[PATH_MAX], so[PATH_MAX], tmp[PATH_MAX];
    char errbuf[256];
    const char *dirname_start;
    char plugin_name[64];
    size_t i;

    snprintf(src, PATH_MAX, "%s/" NEOX_SOURCE_FILE, subdir_path);
    if (!is_file(src)) return -1;

    dirname_start = strrchr(subdir_path, '/');
    dirname_start = dirname_start ? dirname_start + 1 : subdir_path;
    strncpy(plugin_name, dirname_start, 63);
    for (i = 0; plugin_name[i]; i++)
        if (plugin_name[i] == ' ' || plugin_name[i] == '\t') plugin_name[i] = '_';

    snprintf(so, PATH_MAX, "%s/%s.so", subdir_path, plugin_name);

    snprintf(tmp, PATH_MAX, "%s/%s.so.tmp", subdir_path, plugin_name);

    {
        time_t src_t = file_mtime(src);
        time_t so_t  = file_mtime(so);
        int    needs_build = (so_t == 0) || (src_t > so_t);

        if (!needs_build) {
            char extra[PATH_MAX];
            DIR           *sd;
            struct dirent *se;
            sd = opendir(subdir_path);
            if (sd) {
                while ((se = readdir(sd)) != NULL) {
                    if (!ends_with(se->d_name, ".c")) continue;
                    if (strcmp(se->d_name, NEOX_SOURCE_FILE) == 0) continue;
                    snprintf(extra, PATH_MAX, "%s/%s", subdir_path, se->d_name);
                    if (file_mtime(extra) > so_t) { needs_build = 1; break; }
                }
                closedir(sd);
            }
        }

        if (!needs_build) {
            int r = 0;
            void *h = dlopen(so, RTLD_NOW | RTLD_GLOBAL);
            if (h) {
                neox_init_fn init = (neox_init_fn)(uintptr_t)dlsym(h, NEOX_ENTRY_SYMBOL);
                if (init) {
                    dax_plugin_t *p = init();
                    if (p && p->magic == DAX_PLUGIN_MAGIC && p->version == DAX_PLUGIN_VERSION) {
                        reg->plugins[reg->count++] = p;
                        return 1;
                    }
                }
                dlclose(h);
            }
            needs_build = 1;
            (void)r;
        }

        if (needs_build) {
            char srcs[PATH_MAX * 8] = "";
            DIR           *sd2;
            struct dirent *se2;

            strncat(srcs, src, PATH_MAX - 1);

            sd2 = opendir(subdir_path);
            if (sd2) {
                while ((se2 = readdir(sd2)) != NULL) {
                    char extra2[PATH_MAX];
                    if (!ends_with(se2->d_name, ".c")) continue;
                    if (strcmp(se2->d_name, NEOX_SOURCE_FILE) == 0) continue;
                    snprintf(extra2, PATH_MAX, "%s/%s", subdir_path, se2->d_name);
                    if (strlen(srcs) + strlen(extra2) + 2 < sizeof(srcs)) {
                        strncat(srcs, " ", 1);
                        strncat(srcs, extra2, PATH_MAX - 1);
                    }
                }
                closedir(sd2);
            }

            {
                char cmd[PATH_MAX * 4 + 256];
                char cc[64] = "gcc";
                char outbuf[2048] = {0};
                FILE *fp;
                int ret;
                const char *CY = color ? "\033[1;33m" : "";
                const char *CG = color ? "\033[1;32m" : "";
                const char *CR = color ? "\033[1;31m" : "";
                const char *CD = color ? "\033[0;90m" : "";
                const char *R  = color ? "\033[0m"    : "";

                if (getenv("CC"))
                    strncpy(cc, getenv("CC"), 63);
                else if (access("/usr/bin/clang", X_OK) == 0 &&
                         access("/usr/bin/gcc",   X_OK) != 0)
                    strncpy(cc, "clang", 63);

                fprintf(stdout, "  %s[eox-build]%s  compiling %s%s/%s%s\n",
                        CY, R, CD, plugin_name, NEOX_SOURCE_FILE, R);

                snprintf(cmd, sizeof(cmd),
                         "%s -O2 -shared -fPIC -Wall -I%s -o %s %s 2>&1",
                         cc, include_dir, tmp, srcs);

                fp = popen(cmd, "r");
                if (!fp) {
                    snprintf(reg->load_errors[reg->nerrors < DAX_MAX_PLUGINS ? reg->nerrors++ : reg->nerrors - 1],
                             255, "%s: popen failed", plugin_name);
                    return -1;
                }
                {
                    char line[512];
                    size_t pos = 0;
                    while (fgets(line, sizeof(line), fp) &&
                           pos + strlen(line) + 1 < sizeof(outbuf)) {
                        memcpy(outbuf + pos, line, strlen(line));
                        pos += strlen(line);
                    }
                }
                ret = pclose(fp);

                if (ret != 0) {
                    fprintf(stdout, "  %s[eox-build]%s  %sFAILED%s — %s%s%s\n",
                            CY, R, CR, R, CD, plugin_name, R);
                    if (outbuf[0]) {
                        char obcopy[2048];
                        char *line;
                        strncpy(obcopy, outbuf, sizeof(obcopy) - 1);
                        line = strtok(obcopy, "\n");
                        while (line) {
                            fprintf(stdout, "  %s  %s%s\n", CD, line, R);
                            line = strtok(NULL, "\n");
                        }
                    }
                    snprintf(errbuf, sizeof(errbuf), "%s: compile failed", plugin_name);
                    if (reg->nerrors < DAX_MAX_PLUGINS)
                        strncpy(reg->load_errors[reg->nerrors++], errbuf, 255);
                    remove(tmp);
                    return -1;
                }

                rename(tmp, so);
                fprintf(stdout, "  %s[eox-build]%s  %sOK%s  %s%s%s\n",
                        CY, R, CG, R, CD, so, R);
                (void)build_plugin;
                (void)errbuf;
            }
        }
    }

    {
        void *handle = dlopen(so, RTLD_NOW | RTLD_GLOBAL);
        if (!handle) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: dlopen: %s", so, dlerror());
            return -1;
        }

        neox_init_fn init = (neox_init_fn)(uintptr_t)dlsym(handle, NEOX_ENTRY_SYMBOL);
        if (!init) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: missing symbol %s", so, NEOX_ENTRY_SYMBOL);
            dlclose(handle);
            return -1;
        }

        dax_plugin_t *plugin = init();
        if (!plugin) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: neox_plugin_init() returned NULL", so);
            dlclose(handle);
            return -1;
        }
        if (plugin->magic != DAX_PLUGIN_MAGIC) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: bad magic 0x%08x (expected 0x%08x)",
                         so, plugin->magic, DAX_PLUGIN_MAGIC);
            dlclose(handle);
            return -1;
        }
        if (plugin->version != DAX_PLUGIN_VERSION) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: API version %d, host expects %d",
                         so, plugin->version, DAX_PLUGIN_VERSION);
            dlclose(handle);
            return -1;
        }
        {
            int k;
            for (k = 0; k < reg->count; k++) {
                if (strcmp(reg->plugins[k]->name, plugin->name) == 0) {
                    if (reg->nerrors < DAX_MAX_PLUGINS)
                        snprintf(reg->load_errors[reg->nerrors++], 255,
                                 "%s: duplicate name '%s'", so, plugin->name);
                    dlclose(handle);
                    return -1;
                }
            }
        }

        reg->plugins[reg->count++] = plugin;
        return 1;
    }
}

static int load_prebuilt(dax_plugin_registry_t *reg, const char *path) {
    void         *handle;
    neox_init_fn  init;
    dax_plugin_t *plugin;
    int           i;

    if (reg->count >= DAX_MAX_PLUGINS) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "plugin limit (%d) reached — skipping %s", DAX_MAX_PLUGINS, path);
        return -1;
    }

    handle = dlopen(path, RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "%s: %s", path, dlerror());
        return -1;
    }

    init = (neox_init_fn)(uintptr_t)dlsym(handle, NEOX_ENTRY_SYMBOL);
    if (!init) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "%s: missing symbol %s", path, NEOX_ENTRY_SYMBOL);
        dlclose(handle);
        return -1;
    }

    plugin = init();
    if (!plugin) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "%s: neox_plugin_init() returned NULL", path);
        dlclose(handle);
        return -1;
    }
    if (plugin->magic != DAX_PLUGIN_MAGIC) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "%s: bad magic 0x%08x", path, plugin->magic);
        dlclose(handle);
        return -1;
    }
    if (plugin->version != DAX_PLUGIN_VERSION) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "%s: API version %d, host expects %d",
                     path, plugin->version, DAX_PLUGIN_VERSION);
        dlclose(handle);
        return -1;
    }

    for (i = 0; i < reg->count; i++) {
        if (strcmp(reg->plugins[i]->name, plugin->name) == 0) {
            if (reg->nerrors < DAX_MAX_PLUGINS)
                snprintf(reg->load_errors[reg->nerrors++], 255,
                         "%s: duplicate name '%s'", path, plugin->name);
            dlclose(handle);
            return -1;
        }
    }

    reg->plugins[reg->count++] = plugin;
    return 0;
}

int dax_plugin_load_dir(dax_plugin_registry_t *reg, const char *dir) {
    DIR           *d;
    struct dirent *ent;
    char           path[PATH_MAX];
    char           include_dir[PATH_MAX] = {0};
    int            loaded  = 0;
    int            built   = 0;
    struct stat    st;
    int            color;

    memset(reg, 0, sizeof(*reg));

    color = isatty(1);

    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (reg->nerrors < DAX_MAX_PLUGINS)
            snprintf(reg->load_errors[reg->nerrors++], 255,
                     "not a directory: %s", dir);
        return 0;
    }

    find_include_dir(include_dir, sizeof(include_dir));

    d = opendir(dir);
    if (!d) return 0;

    while ((ent = readdir(d)) != NULL) {
        if (ent->d_name[0] == '.') continue;

        snprintf(path, PATH_MAX, "%s/%s", dir, ent->d_name);

        if (is_dir(path)) {
            char neox_src[PATH_MAX];
            snprintf(neox_src, PATH_MAX, "%s/" NEOX_SOURCE_FILE, path);
            if (is_file(neox_src)) {
                int r = try_build_and_load(reg, path, include_dir, color);
                if (r > 0) { loaded++; built++; }
                continue;
            }
        }

        if (!ends_with(ent->d_name, ".so") &&
            !ends_with(ent->d_name, ".dylib")) continue;

        if (load_prebuilt(reg, path) == 0)
            loaded++;
    }
    closedir(d);

    (void)built;
    return loaded;
}

void dax_plugin_run_post_load(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts) {
    int i;
    for (i = 0; i < reg->count; i++)
        if ((reg->plugins[i]->hooks & DAX_PLUGIN_HOOK_POST_LOAD) && reg->plugins[i]->on_post_load)
            reg->plugins[i]->on_post_load(bin, opts);
}

void dax_plugin_run_pre_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    for (i = 0; i < reg->count; i++)
        if ((reg->plugins[i]->hooks & DAX_PLUGIN_HOOK_PRE_DISASM) && reg->plugins[i]->on_pre_disasm)
            reg->plugins[i]->on_pre_disasm(bin, opts, out);
}

void dax_plugin_run_post_disasm(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    for (i = 0; i < reg->count; i++)
        if ((reg->plugins[i]->hooks & DAX_PLUGIN_HOOK_POST_DISASM) && reg->plugins[i]->on_post_disasm)
            reg->plugins[i]->on_post_disasm(bin, opts, out);
}

void dax_plugin_run_ivf(dax_plugin_registry_t *reg, dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int i;
    for (i = 0; i < reg->count; i++)
        if ((reg->plugins[i]->hooks & DAX_PLUGIN_HOOK_IVF) && reg->plugins[i]->on_ivf)
            reg->plugins[i]->on_ivf(bin, opts, out);
}

void dax_plugin_run_banner(dax_plugin_registry_t *reg, FILE *out, int color) {
    int i;
    for (i = 0; i < reg->count; i++)
        if ((reg->plugins[i]->hooks & DAX_PLUGIN_HOOK_BANNER) && reg->plugins[i]->on_banner)
            reg->plugins[i]->on_banner(out, color);
}

void dax_plugin_list(dax_plugin_registry_t *reg, FILE *out, int color) {
    int i;
    const char *R  = color ? "\033[0m"    : "";
    const char *CY = color ? "\033[1;33m" : "";
    const char *CG = color ? "\033[1;32m" : "";
    const char *CD = color ? "\033[0;90m" : "";
    const char *CB = color ? "\033[1;34m" : "";
    const char *CR = color ? "\033[1;31m" : "";

    fprintf(out, "\n");
    if (color) fprintf(out, "%s", CY);
    fprintf(out, "  \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550 LOADED PLUGINS \u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\n");
    if (color) fprintf(out, "%s", R);

    if (reg->count == 0) {
        fprintf(out, "  %sNo plugins loaded.%s\n", CD, R);
    } else {
        for (i = 0; i < reg->count; i++) {
            dax_plugin_t *p = reg->plugins[i];
            char hooks_str[128] = "";
            if (p->hooks & DAX_PLUGIN_HOOK_POST_LOAD)   strcat(hooks_str, "post_load ");
            if (p->hooks & DAX_PLUGIN_HOOK_PRE_DISASM)  strcat(hooks_str, "pre_disasm ");
            if (p->hooks & DAX_PLUGIN_HOOK_POST_DISASM) strcat(hooks_str, "post_disasm ");
            if (p->hooks & DAX_PLUGIN_HOOK_IVF)         strcat(hooks_str, "ivf ");
            if (p->hooks & DAX_PLUGIN_HOOK_UI_PANEL)    strcat(hooks_str, "ui_panel ");
            if (p->hooks & DAX_PLUGIN_HOOK_BANNER)      strcat(hooks_str, "banner ");
            fprintf(out, "\n  %s[%d]%s  %s%s%s  v%s  by %s%s%s\n",
                    CB, i, R, CG, p->name, R,
                    p->plugin_version[0] ? p->plugin_version : "?",
                    CD, p->author[0] ? p->author : "unknown", R);
            fprintf(out, "       %s%s%s\n", CD, p->description, R);
            fprintf(out, "       hooks: %s%s%s\n", CY, hooks_str[0] ? hooks_str : "none", R);
        }
    }

    if (reg->nerrors > 0) {
        fprintf(out, "\n  %sLoad errors:%s\n", CR, R);
        for (i = 0; i < reg->nerrors; i++)
            fprintf(out, "  %s  [!] %s%s\n", CR, reg->load_errors[i], R);
    }
    fprintf(out, "\n");
}

void dax_plugin_free(dax_plugin_registry_t *reg) {
    memset(reg, 0, sizeof(*reg));
}
