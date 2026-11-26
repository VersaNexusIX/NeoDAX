# NeoDAX Plugin System

The NeoDAX plugin system lets you extend the analyzer with custom functions, IVF rules, UI panels, and banner output - without touching the core source.

> **License:** Apache 2.0

---

## Loading Plugins

```bash
neodax -eox ./my_plugins/ ./binary
neodax -eox ./my_plugins/ -eox-list ./binary
```

`-eox <folder>` loads all `.so` (Linux) or `.dylib` (macOS) files from the folder at startup.

`-eox-list` prints a table of all loaded plugins and their hooks.

---

## Plugin Requirements

Every plugin folder must contain a file named `NeoX.c` - this is the plugin entry source. Compile it to a shared library:

```bash
gcc -O2 -shared -fPIC -I/path/to/neodax/include -o myplugin.so NeoX.c
```

The compiled `.so` must export exactly one symbol:

```c
dax_plugin_t *neox_plugin_init(void);
```

NeoDAX calls this on load. It returns a pointer to a statically allocated `dax_plugin_t` struct.

---

## Plugin Struct

```c
typedef struct {
    uint32_t          magic;           // must be 0x584F454EU  ("NEOX")
    uint32_t          version;         // must be 1
    char              name[64];        // unique plugin name
    char              description[256];
    char              author[64];
    char              plugin_version[16];
    dax_plugin_hook_t hooks;           // bitmask of active hooks

    void (*on_post_load)(dax_binary_t *bin, dax_opts_t *opts);
    void (*on_pre_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_post_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ivf)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ui_panel)(dax_binary_t *bin, FILE *out);
    void (*on_banner)(FILE *out, int color);
} dax_plugin_t;
```

Set unused function pointers to `NULL`. Set `hooks` to the bitmask of hooks you implement.

---

## Available Hooks

| Hook constant | When it fires | Use for |
|--------------|--------------|---------|
| `DAX_PLUGIN_HOOK_POST_LOAD` | After binary is loaded and parsed | Custom metadata extraction, patching opts |
| `DAX_PLUGIN_HOOK_PRE_DISASM` | Before first disassembly output | Print a custom header |
| `DAX_PLUGIN_HOOK_POST_DISASM` | After all disassembly output | Print custom analysis after disasm |
| `DAX_PLUGIN_HOOK_IVF` | After the built-in IVF scan (which covers ARM64, x86-64, and RISC-V) | Add custom IVF rules for any architecture (ARM64, x86-64, RISC-V, or custom) |
| `DAX_PLUGIN_HOOK_UI_PANEL` | (reserved for web UI server) | Future: inject panel into web UI |
| `DAX_PLUGIN_HOOK_BANNER` | Before the binary info banner | Print plugin branding or status |

---

## Minimal Example Plugin

**`NeoX.c`:**

```c
#include <stdio.h>
#include "dax.h"

static void my_post_load(dax_binary_t *bin, dax_opts_t *opts) {
    (void)opts;
    printf("  [myplugin] loaded: %s  (%d functions)\n",
           bin->filepath, bin->nfunctions);
}

static dax_plugin_t g_plugin = {
    .magic          = 0x584F454EU,
    .version        = 1,
    .name           = "myplugin",
    .description    = "My custom analysis plugin",
    .author         = "you",
    .plugin_version = "1.0.0",
    .hooks          = DAX_PLUGIN_HOOK_POST_LOAD,
    .on_post_load   = my_post_load,
};

dax_plugin_t *neox_plugin_init(void) { return &g_plugin; }
```

**Build:**

```bash
gcc -O2 -shared -fPIC -I/path/to/neodax/include -o myplugin.so NeoX.c
neodax -eox . -V ./binary
```

---

## IVF Extension Plugin

An IVF plugin fires after the built-in scan and receives the same `dax_binary_t` and `FILE *out`. Print findings directly to `out`:

```c
static void my_ivf(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    // scan bin->sections[], decode instructions, print findings
    fprintf(out, "  [MY-RULE]  0x%016llx  suspicious pattern\n", addr);
}
```

---

## Plugin Structure on Disk

```
plugins/                    ← pass this folder to -eox
├── my_plugin/
│   ├── NeoX.c              ← required entry file (auto-compiled)
│   └── helpers.c           ← optional extra .c sources (also compiled)
└── ivf_ext/
    └── NeoX.c
```

**Just create a subfolder with `NeoX.c` - NeoDAX compiles it automatically:**

```bash
mkdir -p plugins/my_plugin
# write NeoX.c ...
neodax -eox plugins/ -V ./binary
```

Output on first run:
```
  [eox-build]  compiling my_plugin/NeoX.c
  [eox-build]  OK  → plugins/my_plugin/my_plugin.so
  [plugins] loaded 1 from plugins/
```

**Auto-build rules:**
- Every subdirectory containing `NeoX.c` is treated as a plugin source
- All `.c` files in the same subfolder are compiled together automatically
- Recompiles only when source is newer than the `.so` - fast on subsequent runs
- Output `.so` is placed next to the source: `plugins/<name>/<name>.so`
- Pre-built `.so` files placed directly in the `-eox` folder are also loaded
---

## Included Example Plugins

| Folder | Description |
|--------|-------------|
| `plugins/example_hello/` | Minimal post-load hook - prints binary info |
| `plugins/example_ivf_ext/` | IVF extension - cross-function flow analysis (tail calls, no-return hints, mid-func ret) |

Build any example:

```bash
cd plugins/example_hello && make
cp hello.so ../../my_plugins/
```

---

## Plugin Safety

- Plugins are loaded with `RTLD_NOW | RTLD_LOCAL` - they cannot override NeoDAX symbols.
- Magic (`0x584F454EU`) and version (`1`) are checked before calling `neox_plugin_init()`.
- Duplicate plugin names are rejected.
- Load errors are printed but do not abort the main analysis.
- Plugins with the wrong ABI version are rejected cleanly.

---

## Updating a Plugin

Change the version, edit `NeoX.c`, recompile, replace the `.so`:

```bash
make clean && make
cp myplugin.so /path/to/plugins/
neodax -eox /path/to/plugins/ -eox-list ./binary
```

Versioning for the overall NeoDAX host API is in `include/dax.h`:

```c
#define DAX_PLUGIN_VERSION 1
```

If this bumps, plugins must be recompiled.
