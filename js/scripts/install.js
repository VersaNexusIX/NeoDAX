#!/usr/bin/env node
/**
 * NeoDAX native addon installer
 *
 * Called automatically by `npm install neodax`.
 *
 * Strategy:
 *   1. Check if a prebuilt binary exists for this platform/arch in prebuilds/
 *   2. If found → copy it to neodax.node and done
 *   3. If not → attempt to compile from source (requires C compiler + Node headers)
 *   4. If compile fails → print helpful instructions and exit(0) so npm install
 *      doesn't fail the whole project — import will throw a clear error at runtime
 */

'use strict';

const path    = require('path');
const fs      = require('fs');
const os      = require('os');
const { execSync, spawnSync } = require('child_process');

const ROOT    = path.join(__dirname, '..');     // js/ directory
const ADDON   = path.join(ROOT, 'neodax.node');
const REPO    = path.join(ROOT, '..');          // NeoDAX repo root
const BUILDS  = path.join(ROOT, 'prebuilds');

// ── helpers ──────────────────────────────────────────────────────────

function log(msg)  { process.stdout.write(`  [neodax] ${msg}\n`); }
function warn(msg) { process.stdout.write(`  [neodax] ⚠  ${msg}\n`); }
function ok(msg)   { process.stdout.write(`  [neodax] ✓  ${msg}\n`); }
function fail(msg) { process.stdout.write(`  [neodax] ✗  ${msg}\n`); }

function platform() {
    const p = process.platform;
    if (p === 'linux')  return 'linux';
    if (p === 'darwin') return 'darwin';
    return p;
}

function arch() {
    const a = process.arch;
    if (a === 'x64')   return 'x64';
    if (a === 'arm64') return 'arm64';
    return a;
}

// ── 1. Already built? ────────────────────────────────────────────────

if (fs.existsSync(ADDON)) {
    ok(`neodax.node already present — skipping build`);
    process.exit(0);
}

// ── 2. Prebuild? ─────────────────────────────────────────────────────

const tag      = `${platform()}-${arch()}`;
const prebuild = path.join(BUILDS, `neodax-${tag}.node`);

if (fs.existsSync(prebuild)) {
    log(`Using prebuild for ${tag}`);
    fs.copyFileSync(prebuild, ADDON);
    ok(`Installed from prebuild: ${prebuild}`);
    process.exit(0);
}

log(`No prebuild found for ${tag} — compiling from source…`);

// ── 3. Check build tools ─────────────────────────────────────────────

function which(cmd) {
    try {
        const r = spawnSync(process.platform === 'win32' ? 'where' : 'which',
                            [cmd], { encoding: 'utf8' });
        return r.status === 0 && r.stdout.trim().length > 0;
    } catch (_) { return false; }
}

const hasCC    = which('clang') || which('gcc') || which('cc');
const hasMake  = which('make') || which('gmake');

if (!hasCC) {
    warn('No C compiler found (need clang or gcc)');
    warn('Install it and run: npm rebuild');
    if (process.platform === 'linux') {
        warn('  Debian/Ubuntu:  sudo apt install build-essential');
        warn('  Termux/Android: pkg install clang');
        warn('  Fedora:         sudo dnf install gcc');
    } else if (process.platform === 'darwin') {
        warn('  macOS:          xcode-select --install');
    }
    process.exit(0);
}

if (!hasMake) {
    warn('make not found — trying direct compiler invocation via build_js.sh');
}

// ── 4. Compile ───────────────────────────────────────────────────────

const buildScript = path.join(REPO, 'build_js.sh');

if (fs.existsSync(buildScript)) {
    log(`Running build_js.sh from repo root: ${REPO}`);
    try {
        execSync(`bash "${buildScript}"`, {
            cwd:   REPO,
            stdio: 'inherit',
            env:   { ...process.env, NEODAX_QUIET: '1' }
        });
    } catch (e) {
        fail('build_js.sh failed — see output above');
        fail('You can retry with: npm rebuild');
        process.exit(0);
    }

    const builtNode = path.join(REPO, 'js', 'neodax.node');
    if (fs.existsSync(builtNode)) {
        if (builtNode !== ADDON) {
            fs.copyFileSync(builtNode, ADDON);
        }
        ok(`neodax.node built and installed at ${ADDON}`);
        process.exit(0);
    }
}

// ── 5. Fallback: inline compile ──────────────────────────────────────

log('Attempting inline compile…');

const nodeInc = path.join(
    process.execPath.replace(/\/bin\/node$/, '').replace(/\\bin\\node.exe$/, ''),
    'include', 'node'
);

const altIncs = [
    nodeInc,
    '/usr/include/node',
    '/usr/local/include/node',
    process.env.PREFIX ? `${process.env.PREFIX}/include/node` : null,
].filter(Boolean);

const nodeIncPath = altIncs.find(p => fs.existsSync(path.join(p, 'node_api.h')));

if (!nodeIncPath) {
    fail('Cannot find node_api.h — install Node.js dev headers');
    fail('  Debian/Ubuntu:  sudo apt install libnode-dev');
    fail('  Termux:         pkg install nodejs (headers included)');
    fail('You can retry with: npm rebuild');
    process.exit(0);
}

const srcDir  = path.join(REPO, 'src');
const incDir  = path.join(REPO, 'include');

const sources = [
    'neodax_napi.c',
    'loader.c','disasm.c','x86_decode.c','arm64_decode.c',
    'symbols.c','demangle.c','analysis.c','cfg.c','daxc.c',
    'interactive.c','loops.c','callgraph.c','correct.c',
    'riscv_decode.c','unicode.c','sha256.c','main.c',
    'symexec.c','decomp.c','emulate.c','entropy.c',
].map(f => f === 'neodax_napi.c'
    ? path.join(ROOT, 'src', f)
    : path.join(srcDir, f)).join(' ');

const cc    = which('clang') ? 'clang' : 'gcc';
const isAndroid = fs.existsSync('/data/data/com.termux') || process.env.TERMUX_VERSION;
const androidFlag = isAndroid ? '-DBUILD_OS_ANDROID -DBUILD_OS_LINUX' : '';
const ldFlags = process.platform === 'darwin'
    ? '-undefined dynamic_lookup'
    : '-Wl,--unresolved-symbols=ignore-all';

const cmd = [
    cc,
    '-shared -fPIC -O2',
    `-std=c99 -D_GNU_SOURCE`,
    `-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0`,
    androidFlag,
    `-I"${incDir}" -I"${nodeIncPath}"`,
    sources,
    ldFlags,
    '-lm',
    `-o "${ADDON}"`
].filter(Boolean).join(' ');

log(`Compiling with ${cc}…`);
try {
    execSync(cmd, { cwd: REPO, stdio: 'inherit' });
} catch (e) {
    fail('Compilation failed — see output above');
    fail('You can retry manually: cd <neodax-repo-root> && bash build_js.sh');
    process.exit(0);
}

if (fs.existsSync(ADDON)) {
    ok(`neodax.node compiled and ready`);
} else {
    fail(`neodax.node not produced — something went wrong`);
}
