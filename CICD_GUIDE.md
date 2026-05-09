# CI/CD Guide

Documentation for all GitHub Actions workflows in NeoDAX.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX
> **Workflows:** `.github/workflows/`

---

## Workflow Overview

```
Every push / PR to main or dev
    ci.yml          Build and test on 5 platforms + Node matrix

Manual (Actions tab -> Run workflow)
    publish.yml     Full publish pipeline (test, prebuilds, npm publish)
    release.yml     Bump version, commit, tag
    prebuild.yml    Build prebuilds only (no publish)

Daily at 02:00 UTC
    nightly.yml     Regression detection; opens an issue on failure

Weekly, Monday 08:00 UTC
    codeql.yml      Static security analysis
```

---

## ci.yml — Continuous Integration

**Trigger:** Every push to `main` or `dev`, and every PR targeting `main`.
**Skips:** Changes limited to `*.md`, `docs/`, or `learn/`.

| Job | Runner | What it does |
|-----|--------|--------------|
| `linux-gcc` | ubuntu-latest x64 | Build (Code mode), CLI smoke test, JS test suite |
| `linux-clang` | ubuntu-latest x64 | Build with Clang |
| `linux-arm64` | ubuntu-24.04-arm | Build and test on real ARM64 hardware |
| `macos-arm64` | macos-latest | Build and test on Apple Silicon |
| `macos-x64` | macos-13 | Build and test on Intel Mac |
| `node-matrix` | ubuntu-latest x3 | JS addon on Node.js 18, 20, and 22 |
| `ci-pass` | ubuntu-latest | Gate job — fails if any required job fails |

`ci-pass` is the required status check for pull request merges.

---

## publish.yml — Manual npm Publish

**Trigger:** Manual only — go to Actions, select "Publish to npm", and click "Run workflow".

**Inputs:**

| Input | Description | Default |
|-------|-------------|---------|
| `dry_run` | Run the full pipeline without publishing | false |

**Flow:**

```
validate
    Read version from package.json

test (Linux x64 + macOS ARM64, in parallel)
    Build with setup.sh (Code mode)
    Run js/test/basic.js

prebuilds (4 parallel jobs)
    linux-x64       ubuntu-latest
    linux-arm64     ubuntu-24.04-arm
    darwin-arm64    macos-latest
    darwin-x64      macos-13

publish
    Download all 4 prebuilds
    Verify all artifacts are present
    npm publish --access public --provenance
    Create GitHub Release with prebuild attachments
```

**Required secrets:**

| Secret | Where to set |
|--------|--------------|
| `NPM_TOKEN` | Repository Settings > Secrets > Actions |

To generate an npm token: run `npm token create --type granular` on npmjs.com.

---

## release.yml — Version Bump

**Trigger:** Manual only — Actions tab, "Release", "Run workflow".

**Inputs:**

| Input | Description | Example |
|-------|-------------|---------|
| `version` | New version number | `1.1.1` |
| `prerelease` | Optional pre-release suffix | `beta.1` |

**What it does:**
1. Updates the version in `js/package.json`.
2. Updates the version string in the `setup.sh` banner.
3. Commits both files.
4. Creates and pushes the git tag.

After this workflow completes, run **publish.yml** to publish to npm.

---

## prebuild.yml — Build Prebuilds Only

**Trigger:** Manual only.

Builds `neodax.node` for all four supported platforms and uploads them as GitHub Actions artifacts (retained for 30 days). Does not publish to npm.

This is useful for verifying prebuilts before a full publish run.

---

## nightly.yml — Nightly Regression

**Trigger:** Daily at 02:00 UTC, or manually.

Runs a full build and analysis suite on Linux x64, macOS, and Linux ARM64. Automatically opens a GitHub issue if any job fails.

---

## codeql.yml — Security Analysis

**Trigger:** Weekly on Monday at 08:00 UTC, on every push to `main`, and manually.

Runs GitHub CodeQL on C source and JavaScript files using the `security-and-quality` query suite. Results appear in the repository's Security tab.

---

## npm Auto-build on Install

When a user runs `npm install neodax`, the `install` script in `package.json` runs `js/scripts/install.js` automatically. That script:

1. Checks if `neodax.node` already exists — done if found.
2. Checks `js/prebuilds/<platform>-<arch>.node` — copies it if a match is found.
3. Runs `build_js.sh` if present (git clone scenario).
4. Falls back to an inline `clang`/`gcc` compile using headers from the local Node.js installation.
5. If no compiler is available, prints install instructions and exits cleanly.

The user never needs to run `make` or any other command manually.
