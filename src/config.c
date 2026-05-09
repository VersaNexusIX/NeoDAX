#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "dax.h"

#define DAXNG_MAX_LINE 512

static char g_cfg_version[32]   = DAX_VERSION;
static char g_cfg_name[64]      = "NeoDAX";
static char g_cfg_codename[64]  = "";
static char g_cfg_logo[7][256]  = {0};
static char g_cfg_tagline[128]  = "Binary Analysis & RE Tool";
static int  g_cfg_loaded        = 0;

static char *trim(char *s) {
    while (*s == ' ' || *s == '\t') s++;
    char *e = s + strlen(s);
    while (e > s && (e[-1] == ' ' || e[-1] == '\t' || e[-1] == '\r' || e[-1] == '\n')) e--;
    *e = '\0';
    return s;
}

static void parse_escape(const char *src, char *dst, size_t dsz) {
    size_t wi = 0;
    const char *p = src;
    while (*p && wi + 4 < dsz) {
        if (p[0] == '\\' && p[1] == '0' && p[2] == '3' && p[3] == '3') {
            dst[wi++] = '\033';
            p += 4;
        } else if (p[0] == '\\' && p[1] == 'n') {
            dst[wi++] = '\n'; p += 2;
        } else if (p[0] == '\\' && p[1] == 't') {
            dst[wi++] = '\t'; p += 2;
        } else {
            dst[wi++] = *p++;
        }
    }
    dst[wi] = '\0';
}

void dax_config_load(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return;
    char line[DAXNG_MAX_LINE];
    int logo_idx = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *l = trim(line);
        if (!l[0] || l[0] == '#' || l[0] == '[') continue;
        char *eq = strchr(l, '=');
        if (!eq) continue;
        *eq = '\0';
        char *key = trim(l);
        char *val = trim(eq + 1);
        if (!strcmp(key, "version"))  { strncpy(g_cfg_version,  val, 31); }
        if (!strcmp(key, "name"))     { strncpy(g_cfg_name,     val, 63); }
        if (!strcmp(key, "codename")) { strncpy(g_cfg_codename, val, 63); }
        if (!strcmp(key, "tagline"))  { parse_escape(val, g_cfg_tagline, 127); }
        if (!strncmp(key, "line", 4) && isdigit((unsigned char)key[4])) {
            int li = key[4] - '1';
            if (li >= 0 && li < 7)
                parse_escape(val, g_cfg_logo[li], 255);
        }
    }
    fclose(fp);
    g_cfg_loaded = 1;
}

const char *dax_config_version(void)  { return g_cfg_version; }
const char *dax_config_name(void)     { return g_cfg_name; }
const char *dax_config_codename(void) { return g_cfg_codename; }
const char *dax_config_tagline(void)  { return g_cfg_tagline; }
const char *dax_config_logo(int line) {
    if (line < 0 || line >= 7) return "";
    return g_cfg_logo[line][0] ? g_cfg_logo[line] : "";
}
int dax_config_loaded(void) { return g_cfg_loaded; }
