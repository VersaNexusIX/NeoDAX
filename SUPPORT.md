# Getting Help with NeoDAX

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Documentation First

Before asking, check:

| Document | Covers |
|---|---|
| [README.md](README.md) | Overview, quick start, feature list |
| [BUILDING.md](BUILDING.md) | Build instructions for all platforms |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Every CLI flag with examples |
| [API.md](API.md) | Full C API reference |
| [js/README.md](js/README.md) | JavaScript API and REST server |
| [NPM_USAGE.md](NPM_USAGE.md) | Using NeoDAX as an npm dependency |
| [EXAMPLES.md](EXAMPLES.md) | Common usage recipes |
| [FAQ.md](FAQ.md) | Frequently asked questions |
| [ALGORITHMS.md](ALGORITHMS.md) | How CFG, entropy, RDA work |

---

## Build Issues

Most issues fall into these categories:

**Missing Node.js headers:**
```bash
# Debian/Ubuntu
sudo apt install libnode-dev

# Termux — headers are bundled with nodejs
pkg install nodejs

# Fedora
sudo dnf install nodejs-devel
```

**`isprint` undeclared (Clang strict C99):**
Fixed in v1.0.0 — ensure you have the latest code.

**Linker error — `log2` undefined:**
```bash
# Check LDFLAGS in Makefile contains -lm
grep LDFLAGS Makefile   # should show: LDFLAGS = -lm
```

**`neodax.node` not found after `npm install`:**
```bash
# Trigger manual build
npm run build
# or
bash node_modules/neodax/../build_js.sh
```

See [BUILDING.md](BUILDING.md) for full troubleshooting.

---

## Reporting a Bug

1. Check [existing issues](https://github.com/VersaNexusIX/NeoDAX/issues)
2. Confirm on latest `main`
3. [Open a bug report](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=bug_report.md) with:
   - NeoDAX version, OS/arch, compiler
   - Reproduction steps
   - Expected vs actual output

**Security vulnerabilities:** do NOT open public issues. See [SECURITY.md](SECURITY.md).

---

## Asking a Question

Use [GitHub Discussions](https://github.com/VersaNexusIX/NeoDAX/discussions) for:
- How to use a specific feature
- Understanding CFG/SSA/decompiler output
- Architecture or format support questions
- Integration help (backend, Express, Fastify)

---

## Feature Requests

Open a [feature request](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=feature_request.md) or [Discussion](https://github.com/VersaNexusIX/NeoDAX/discussions). Include the problem you are solving and why it fits NeoDAX's scope.
