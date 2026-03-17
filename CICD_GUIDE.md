# CI/CD Guide

Detailed documentation for all six GitHub Actions workflows.

> **Repository:** https://github.com/VersaNexusIX/NeoDAX  
> **Workflows:** `.github/workflows/`

---

## Workflow Overview

```
Every push / PR
    └── ci.yml          Build + test on 5 platforms + Node matrix

Every tag v*.*.*
    └── publish.yml     Full release pipeline
            ├── test    (Linux x64 + macOS ARM64)
            ├── prebuilds (4 platforms in parallel)
            ├── npm publish --provenance
            └── GitHub Release (prebuilds attached)

Manually in Actions tab
    └── release.yml     Bump version → commit → tag → triggers publish
    └── prebuild.yml    Build prebuilds only (no publish)

Daily at 02:00 UTC
    └── nightly.yml     Regression detection, issue on failure

Weekly Monday 08:00 UTC
    └── codeql.yml      Static security analysis
```

---

## ci.yml — Continuous Integration

**Trigger:** Every push to `main`/`dev`, every PR to `main`  
**Skips:** changes only to `*.md` or `docs/`

### Jobs

| Job | Runner | What it does |
|-----|--------|-------------|
| `linux-gcc` | ubuntu-latest x64 | Build with GCC, CLI smoke test (`-x -e -V`), JS test suite |
| `linux-clang` | ubuntu-latest x64 | Build with Clang |
| `linux-arm64` | ubuntu-24.04-arm | Build + test on real ARM64 |
| `macos-arm64` | macos-latest | Build + test on Apple Silicon |
| `macos-x64` | macos-13 | Build + test on Intel Mac |
| `node-matrix` | ubuntu-latest × 3 | JS addon on Node 18, 20, 22 |
| `ci-pass` | ubuntu-latest | Gate — fails if linux-gcc/linux-clang/macos-arm64 fail |

**`ci-pass`** is a required status check — pull requests cannot be merged unless this job passes.

---

## publish.yml — Release Pipeline

**Trigger:** Push of tag matching `v[0-9]+.[0-9]+.[0-9]+` (with optional pre-release suffix)

### Full flow

```
validate ─────────────────────────────────────────────────────┐
    tag == package.json version?                               │
                                                               ▼
test ─────────────────────────────────────────────────────────┤
    Linux x64 build + npm test                                 │
    macOS ARM64 build + npm test                               │
                                                               ▼
prebuilds (4 parallel jobs) ──────────────────────────────────┤
    linux-x64   →  neodax-linux-x64.node                      │
    linux-arm64 →  neodax-linux-arm64.node                     │
    darwin-arm64 → neodax-darwin-arm64.node                    │
    darwin-x64  →  neodax-darwin-x64.node                      │
                                                               ▼
publish ──────────────────────────────────────────────────────┤
    download all prebuilds                                     │
    verify 4 expected files present                            │
    npm publish --access public --provenance                   │
                                                               ▼
release ──────────────────────────────────────────────────────┘
    extract CHANGELOG.md section for this version
    create GitHub Release with prebuilds attached
```

**Dry run:** Set workflow input `dry_run: true` to run the whole pipeline without actually publishing.

### Required secret

`NPM_TOKEN` — Automation token from npmjs.com (Settings → Secrets → Actions).

### Environment protection

The `publish` job runs in the `npm-publish` environment. Configure this in GitHub Settings → Environments to require manual approval before each publish.

---

## release.yml — Version Bumper

**Trigger:** Manual dispatch only

**Inputs:**
- `version` — New version string (e.g. `1.1.0` or `1.2.0-beta.1`)
- `release_notes` — Short description for CHANGELOG
- `dry_run` — Commit + tag but don't push

**What it does:**
1. Validates version format (`X.Y.Z` or `X.Y.Z-prerelease`)
2. Checks the tag doesn't already exist
3. Updates `js/package.json` version field
4. Inserts a new section in `CHANGELOG.md`
5. Commits with message `chore: release v<version> [skip ci]`
6. Creates annotated tag
7. Pushes commit + tag → `publish.yml` triggers automatically

The `[skip ci]` in the commit message prevents `ci.yml` from running on the version bump commit.

---

## prebuild.yml — Standalone Prebuild

**Trigger:** Tag push or manual dispatch

**Difference from publish.yml:** Builds and uploads prebuilds only — does not publish to npm. Useful for:
- Testing the prebuild pipeline before a real release
- Generating prebuilds for a hotfix
- Adding a new platform to the prebuilds matrix

Each prebuild is uploaded as a GitHub Actions artifact (30-day retention) and attached to the GitHub Release (if triggered by a tag).

---

## nightly.yml — Nightly Regression Detection

**Trigger:** Daily at 02:00 UTC, also manual

**Matrix:**
- linux-x64 × Node 18, 20, 22
- linux-arm64 × Node 20
- macos-arm64 × Node 20

**Extra steps on Linux Node 20:** Runs `valgrind --leak-check=summary` as a non-fatal step. Valgrind issues are logged but don't fail the build — they're indicators for investigation.

**Automatic issue management:**
- If any job fails → checks for existing open `nightly-failure` issue → either updates it with a new comment or opens a new one
- If all jobs pass and a `nightly-failure` issue is open → adds a recovery comment and closes it

This provides a clean audit trail of regressions without creating duplicate issues.

---

## codeql.yml — Static Security Analysis

**Trigger:** Push/PR to `main` touching `src/**` or `js/src/**`, plus weekly Monday 08:00 UTC

**Language:** `c-cpp` with `security-and-quality` query suite

**What it finds:**
- Buffer overflows and OOB memory access in the ELF/PE parser
- Integer overflows in size/offset calculations
- Use-after-free patterns
- Format string vulnerabilities
- Unchecked return values from `malloc`/`calloc`

Results appear in the Security tab under Code Scanning Alerts.

---

## Setup Checklist

- [ ] `NPM_TOKEN` secret added to repository
- [ ] `npm-publish` environment created (optional, for approval gate)
- [ ] GitHub Actions enabled
- [ ] `ubuntu-24.04-arm` runner available for your plan (ARM64 jobs)
- [ ] Repository is public OR GitHub Advanced Security enabled (for CodeQL)

---

## Troubleshooting Workflows

**`validate` fails: "tag does not match package.json version"**  
Use the Release workflow to keep them in sync, or manually update `js/package.json` before tagging.

**ARM64 runner not available**  
`ubuntu-24.04-arm` requires GitHub's hosted ARM64 pool. If unavailable, comment out `linux-arm64` jobs in the affected workflows.

**npm publish fails with 403**  
Token type must be **Automation**. Verify: `npm whoami` locally, then check the token in npmjs.com Settings → Access Tokens.

**Nightly opens too many issues**  
The workflow deduplicates — only one open issue is maintained at a time. If you see duplicates, check if the `nightly-failure` label exists on your repo; create it if missing.
