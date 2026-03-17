# Publishing NeoDAX to npm

This document explains the full CI/CD pipeline and how to publish NeoDAX to npm.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX

---

## Overview

NeoDAX uses a four-workflow CI/CD system:

| Workflow | File | Trigger | Purpose |
|---|---|---|---|
| **CI** | `ci.yml` | push/PR to main | Build + test on Linux, macOS, Node matrix |
| **Prebuild** | `prebuild.yml` | tag push / manual | Build `.node` binaries for all platforms |
| **Publish** | `publish.yml` | tag push / manual | Full release pipeline → npm + GitHub Release |
| **Release** | `release.yml` | manual | Bump version, commit, tag, trigger publish |
| **Nightly** | `nightly.yml` | daily 02:00 UTC | Regression detection, opens issues on failure |
| **CodeQL** | `codeql.yml` | push/PR/weekly | Static security analysis of C source |

---

## One-Time Setup

### 1. Create an npm token

1. Log in to [npmjs.com](https://www.npmjs.com)
2. Go to your profile → **Access Tokens** → **Generate New Token**
3. Select **Automation** type
4. Copy the token

### 2. Add the token to GitHub Secrets

1. Open your repo on GitHub
2. **Settings** → **Secrets and variables** → **Actions**
3. Click **New repository secret**
4. Name: `NPM_TOKEN`
5. Value: paste your npm token

### 3. Create the `npm-publish` environment (optional, recommended)

Environments add an approval gate before publishing:

1. **Settings** → **Environments** → **New environment**
2. Name: `npm-publish`
3. Add **Required reviewers** if you want manual approval before each publish

### 4. Enable GitHub Actions

Make sure Actions are enabled for your repo: **Settings** → **Actions** → **Allow all actions**.

---

## Releasing a New Version

### Option A — Automated (recommended)

Use the **Release** workflow in the Actions tab:

1. Go to **Actions** → **Release** → **Run workflow**
2. Enter the new version (e.g. `1.1.0`)
3. Enter optional release notes
4. Click **Run workflow**

The workflow will:
- Update `js/package.json` version
- Add a CHANGELOG.md entry
- Commit the changes to `main`
- Create and push the tag `v1.1.0`
- The **Publish** workflow triggers automatically from the tag

### Option B — Manual tag push

```bash
# 1. Update version in js/package.json
vim js/package.json   # set "version": "1.1.0"

# 2. Update CHANGELOG.md
vim CHANGELOG.md      # add ## [1.1.0] section

# 3. Commit
git add js/package.json CHANGELOG.md
git commit -m "chore: release v1.1.0"
git push origin main

# 4. Tag
git tag -a v1.1.0 -m "NeoDAX v1.1.0"
git push origin v1.1.0
# → publish.yml triggers automatically
```

---

## Publish Pipeline Steps

When a tag `v*` is pushed, `publish.yml` runs:

```
validate          check tag matches package.json version
    ↓
test              build + npm test on Linux x64 + macOS arm64
    ↓
prebuilds         parallel build on 4 platforms:
                    linux-x64     (ubuntu-latest)
                    linux-arm64   (ubuntu-24.04-arm)
                    darwin-arm64  (macos-latest)
                    darwin-x64    (macos-13)
    ↓
publish           download all prebuilds
                  add to js/prebuilds/
                  npm publish --provenance
    ↓
release           create GitHub Release with .node files attached
                  extract CHANGELOG.md section as release notes
```

Total duration: ~10–15 minutes.

---

## Prebuilds

Prebuilds are pre-compiled `.node` files for each platform. When present, users get a zero-compile `npm install`:

```
js/prebuilds/
├── neodax-linux-x64.node
├── neodax-linux-arm64.node
├── neodax-darwin-arm64.node
└── neodax-darwin-x64.node
```

`index.js` checks for prebuilds automatically:
```js
// Order of lookup:
// 1. js/neodax.node           (local build, takes priority)
// 2. js/prebuilds/neodax-<platform>-<arch>.node
// 3. Throw with install instructions
```

### Generating prebuilds locally

```bash
# Run the prebuild workflow manually (Actions → Prebuild → Run workflow)
# Or build locally and copy:

make js
mkdir -p js/prebuilds
cp js/neodax.node js/prebuilds/neodax-linux-x64.node   # on Linux x64
# cp js/neodax.node js/prebuilds/neodax-darwin-arm64.node  # on macOS M-series
```

---

## Testing Before Publish

```bash
# Full test suite
node js/test/basic.js

# Dry-run publish (shows what would be uploaded)
cd js && npm pack --dry-run

# Inspect the package contents
cd js && npm pack
tar -tzf neodax-*.tgz

# Test the packed package
npm install ./neodax-1.0.0.tgz
node -e "const n=require('neodax');console.log(n.version());"
```

---

## npm Package Contents

Files included in the published package (controlled by `files` in `package.json`):

```
neodax/
├── index.js          JS wrapper class
├── index.d.ts        TypeScript declarations
├── README.md         documentation
├── scripts/
│   ├── install.js    postinstall build script
│   └── build.js      npm run build
├── server/
│   ├── server.js     REST API server
│   └── ui.html       Web UI
├── examples/         6 example scripts
├── src/              C source for native addon
└── prebuilds/        Pre-compiled .node files (4 platforms)
```

The C source (`src/`) is included so users can compile on unsupported platforms.

---

## What Happens on `npm install neodax`

```
npm install neodax
    ↓
npm downloads the package from registry
    ↓
postinstall: node scripts/install.js
    ↓
  1. Check if neodax.node already exists → done
  2. Check js/prebuilds/<platform>-<arch>.node → copy → done
  3. Find build_js.sh in repo root → run it → done
  4. Inline compile with clang/gcc → done
  5. If all fail: print helpful error, exit(0) so npm install succeeds
     → import will throw at runtime with instructions
```

---

## Adding a New Platform

To add a new prebuild target (e.g. Windows arm64 in future):

1. Add a matrix entry to `prebuild.yml` and `publish.yml`
2. Add the expected filename to the "Verify all expected prebuilds" step
3. Add `win32` handling to `build_js.sh` if needed
4. Update `index.js` `_findAddon()` platform mapping

---

## Troubleshooting

**`npm install neodax` fails to compile:**
```bash
# Check if C compiler is available
clang --version || gcc --version

# Manually trigger compilation
node node_modules/neodax/scripts/install.js
```

**CI fails on arm64 runner:**
The `ubuntu-24.04-arm` runner requires the repo has access to GitHub's ARM64 runner pool. Make sure your plan supports it (GitHub Free includes limited arm64 minutes).

**npm publish fails — 403:**
- Token type must be **Automation** (not Read-only or Publish)
- Run `npm whoami` locally to verify login: `npm login`
- Check the `npm-publish` environment protection rules aren't blocking

**Version mismatch error:**
The tag must match `js/package.json` version exactly. Use the Release workflow to keep them in sync, or manually update `package.json` before tagging.
