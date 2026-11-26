# Building Plugins

**Level:** 7 - Integration and Automation
**Prerequisites:** 75_ci_cd_integration.md
**What You Will Learn:** How to write, compile, and load NeoDAX plugins using the `-eox` system.

## What Plugins Can Do

A NeoDAX plugin is a shared library (`.so` on Linux, `.dylib` on macOS) that hooks into the analysis pipeline. Plugins can:

- Print custom info after a binary loads
- Add IVF detection rules
- Annotate or modify disassembly output
- Add UI panels to the web interface
- Print a custom banner

## The Entry File: NeoX.c

Every plugin must have a file named `NeoX.c` - this is the required entry point source. It must export one function:

```c
dax_plugin_t *neox_plugin_init(void);
```

NeoDAX looks for this symbol when it loads your `.so`. It returns a pointer to your plugin descriptor.

## Loading Plugins

```bash
neodax -eox ./plugins/ ./binary
neodax -eox ./plugins/ -eox-list ./binary
```

`-eox <folder>` loads all `.so` / `.dylib` files from that folder. `-eox-list` prints a summary of loaded plugins and their hooks.

## Writing Your First Plugin

Create a folder, write `NeoX.c`, compile:

```bash
mkdir my_plugin && cd my_plugin
```

**`NeoX.c`:**

```c
#include <stdio.h>
#include "dax.h"

static void on_load(dax_binary_t *bin, dax_opts_t *opts) {
    (void)opts;
    printf("  [myplugin]  %s  arch=%s  stripped=%s\n",
           bin->filepath,
           dax_arch_str(bin->arch),
           bin->is_stripped ? "yes" : "no");
}

static dax_plugin_t g_plugin = {
    .magic          = 0x584F454EU,
    .version        = 1,
    .name           = "myplugin",
    .description    = "Prints basic info after binary loads",
    .author         = "you",
    .plugin_version = "1.0.0",
    .hooks          = DAX_PLUGIN_HOOK_POST_LOAD,
    .on_post_load   = on_load,
};

dax_plugin_t *neox_plugin_init(void) { return &g_plugin; }
```

**Run - NeoDAX builds it automatically:**

```bash
mkdir -p plugins/myplugin
# place NeoX.c inside
neodax -eox plugins/ -V /bin/ls
```

Output on first run:
```
  [eox-build]  compiling myplugin/NeoX.c
  [eox-build]  OK  → plugins/myplugin/myplugin.so
```

Subsequent runs skip the compile step unless `NeoX.c` changed.

If you prefer to build manually:
```bash
gcc -O2 -shared -fPIC -I/path/to/NeoDAX/include -o myplugin.so NeoX.c
```

## Plugin Hooks Reference

```c
DAX_PLUGIN_HOOK_POST_LOAD    // fires after binary is parsed
DAX_PLUGIN_HOOK_PRE_DISASM   // fires before first disassembly line
DAX_PLUGIN_HOOK_POST_DISASM  // fires after all disassembly output
DAX_PLUGIN_HOOK_IVF          // fires after built-in IVF scan
DAX_PLUGIN_HOOK_UI_PANEL     // reserved for web UI
DAX_PLUGIN_HOOK_BANNER       // fires before the binary info banner
```

Set `hooks` to a bitmask OR of the hooks you want. Set the corresponding function pointer; unused ones stay `NULL`.

## Writing an IVF Extension

The most useful hook. Called after the built-in IVF scan with the same binary and output stream:

```c
static void my_ivf(dax_binary_t *bin, dax_opts_t *opts, FILE *out) {
    int c = opts ? opts->color : 1;
    const char *R  = c ? "\033[0m"    : "";
    const char *CY = c ? "\033[1;33m" : "";
    const char *CB = c ? "\033[1;34m" : "";
    int si;

    if (!bin || !bin->data || !out) return;

    fprintf(out, "\n  [MY-IVF-RULES]\n\n");

    for (si = 0; si < bin->nsections && si < DAX_MAX_SECTIONS; si++) {
        dax_section_t *sec = &bin->sections[si];
        size_t off;

        if (sec->type != SEC_TYPE_CODE) continue;
        if (sec->size == 0 || sec->offset > bin->size) continue;
        if (sec->size > bin->size - sec->offset) continue;

        uint8_t *code = bin->data + sec->offset;
        off = 0;

        while (off + 4 <= sec->size && bin->arch == ARCH_ARM64) {
            uint64_t addr = sec->vaddr + off;
            uint32_t raw  = (uint32_t)code[off] | ((uint32_t)code[off+1]<<8)
                           | ((uint32_t)code[off+2]<<16) | ((uint32_t)code[off+3]<<24);
            a64_insn_t insn;
            a64_decode(raw, addr, &insn);
            if (!insn.mnemonic || !insn.operands) { off += 4; continue; }

            /* example: flag any use of x18 (platform register) */
            if (strstr(insn.operands, "x18"))
                fprintf(out, "  %s[PLATFORM-REG]%s  %s0x%016llx%s  %s  x18 use - platform ABI violation\n",
                        CY, R, CB, (unsigned long long)addr, R, insn.mnemonic);

            off += 4;
        }
    }
}

static dax_plugin_t g_plugin = {
    .magic   = 0x584F454EU, .version = 1,
    .name    = "platform_reg_check",
    .hooks   = DAX_PLUGIN_HOOK_IVF,
    .on_ivf  = my_ivf,
};
```

## Plugin File Layout

```
plugins/                    ← pass this folder to -eox
├── my_plugin/
│   ├── NeoX.c              ← required entry file (auto-compiled)
│   └── helpers.c           ← optional extra .c (auto-included)
└── ivf_ext/
    └── NeoX.c
```

Just create the subfolder and write `NeoX.c`. No manual build step needed:

```bash
neodax -eox plugins/ -V ./binary
# compiles any NeoX.c that's new or changed, then loads
```

Pre-built `.so` files placed directly in the `-eox` folder are also loaded without recompiling.

## The dax_plugin_t Struct

```c
typedef struct {
    uint32_t          magic;            // 0x584F454EU  ← REQUIRED
    uint32_t          version;          // 1            ← REQUIRED
    char              name[64];
    char              description[256];
    char              author[64];
    char              plugin_version[16];
    dax_plugin_hook_t hooks;            // bitmask

    void (*on_post_load)(dax_binary_t *bin, dax_opts_t *opts);
    void (*on_pre_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_post_disasm)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ivf)(dax_binary_t *bin, dax_opts_t *opts, FILE *out);
    void (*on_ui_panel)(dax_binary_t *bin, FILE *out);
    void (*on_banner)(FILE *out, int color);
} dax_plugin_t;
```

Wrong magic or version causes NeoDAX to reject the plugin cleanly with an error message - no crash.

## Included Example Plugins

Located in the `plugins/` folder of the repository:

**`plugins/example_hello/`** - post-load hook that prints binary info and a banner line. Good starting template.

**`plugins/example_ivf_ext/`** - IVF hook that scans for tail calls, no-return hints, and mid-function returns across all functions. Demonstrates cross-function flow analysis.

Build either example:

```bash
cd plugins/example_hello
make
cp hello.so /path/to/my/plugins/
neodax -eox /path/to/my/plugins/ ./binary
```

## Listing Loaded Plugins

```bash
neodax -eox ./plugins/ -eox-list ./binary
```

Output:

```
  ══════════════════ LOADED PLUGINS ══════════════════

  [0]  hello  v1.0.0  by VersaNexusIX
       Example plugin - prints binary info after load
       hooks: post_load banner

  [1]  ivf_ext  v1.0.0  by VersaNexusIX
       IVF extension: cross-function flow analysis
       hooks: ivf
```

## Plugin Safety Rules

Plugins run inside the NeoDAX process. A segfault in your plugin takes down the whole program — the pass isolation layer does not cross shared library boundaries. Follow these rules in every plugin:

- Always check `bin != NULL` and `bin->data != NULL` before accessing any field
- Loop over sections with `si < bin->nsections && si < DAX_MAX_SECTIONS`
- Use `sec->size > bin->size - sec->offset` (not `sec->offset + sec->size > bin->size`) for overflow-safe bounds
- Null-check `insn.mnemonic` and `insn.operands` after every decoder call before passing to `strcmp`/`strstr`
- Never assume `bin->functions`, `bin->symbols`, or `bin->xrefs` are non-NULL without checking

See `77_fault_isolation.md` for the full guard pattern reference.

## Practice

1. Copy `plugins/example_hello/` to a new folder and rename the plugin in `NeoX.c`.
2. Compile and load it on `/bin/ls`.
3. Write an IVF plugin that flags any function with more than 20 indirect branches. Add the full overflow-safe section bounds check.
4. Use `-eox-list` to verify your plugin loaded correctly.
5. Run your plugin against a truncated ELF (`echo -n $'\x7fELF' > /tmp/bad.elf`). Verify it does not crash.

## Next

Continue to `77_fault_isolation.md` to learn how the fault isolation system works and how to write robust tools on top of NeoDAX.
