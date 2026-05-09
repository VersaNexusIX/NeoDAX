# Getting Help with NeoDAX

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Documentation First

Before opening an issue or discussion, check the relevant document below:

| Document | Covers |
|----------|--------|
| [README.md](README.md) | Overview, quick start, feature map |
| [BUILDING.md](BUILDING.md) | Build instructions for all platforms |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Every CLI flag with examples |
| [API.md](API.md) | Full C API reference |
| [js/README.md](js/README.md) | JavaScript API and REST server |
| [NPM_USAGE.md](NPM_USAGE.md) | Using NeoDAX as an npm dependency |
| [EXAMPLES.md](EXAMPLES.md) | Common usage recipes |
| [FAQ.md](FAQ.md) | Frequently asked questions |
| [ALGORITHMS.md](ALGORITHMS.md) | How CFG, entropy, and RDA work internally |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Build and runtime troubleshooting |

---

## Build Issues

Most build failures fall into one of these categories:

**Missing Node.js headers:**
```bash
# Debian / Ubuntu
sudo apt install libnode-dev

# Termux — headers are bundled with the nodejs package
pkg install nodejs

# Fedora
sudo dnf install nodejs-devel
```

**`isprint` undeclared (Clang strict C99):**
Fixed in v1.0.8. Ensure you are on the latest release (v1.1.1).

**Linker error — `log2` undefined:**
```bash
# Verify that LDFLAGS in the Makefile includes -lm
grep LDFLAGS Makefile
```

**`neodax.node` not found after `npm install`:**
```bash
# Trigger a manual build
npm run build
# or
bash node_modules/neodax/../build_js.sh
```

See [BUILDING.md](BUILDING.md) and [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for full details.

---

## Reporting a Bug

1. Check [existing issues](https://github.com/VersaNexusIX/NeoDAX/issues) to avoid duplicates.
2. Confirm the issue is reproducible on the latest `main`.
3. [Open a bug report](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=bug_report.md) and include:
   - NeoDAX version, OS, architecture, and compiler
   - Reproduction steps
   - Expected vs. actual output

**Security vulnerabilities:** do not open a public issue. See [SECURITY.md](SECURITY.md).

---

## Asking a Question

Use [GitHub Discussions](https://github.com/VersaNexusIX/NeoDAX/discussions) for:

- How to use a specific feature
- Understanding CFG, NR, or decompiler output
- Architecture or format support questions
- Integration help (backend services, Express, Fastify, Docker)

---

## Feature Requests

Open a [feature request](https://github.com/VersaNexusIX/NeoDAX/issues/new?template=feature_request.md) or start a [Discussion](https://github.com/VersaNexusIX/NeoDAX/discussions). Include the problem you are trying to solve and why it fits within NeoDAX's scope.
