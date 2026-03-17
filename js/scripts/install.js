#!/usr/bin/env node
/**
 * NeoDAX native addon installer
 * Called automatically by `npm install neodax`
 *
 * Works whether installed:
 *   - As npm package: node_modules/neodax/  (package root = repo root)
 *   - In js/ subdir of a git clone
 *
 * Strategy:
 *   1. Check if neodax.node already exists → done
 *   2. Check prebuilds/<platform>-<arch>.node → copy → done
 *   3. Run build_js.sh from repo root → done
 *   4. Inline compile with clang/gcc → done
 *   5. If all fail → print instructions, exit(0) so npm install succeeds
 */
'use strict';

const path    = require('path');
const fs      = require('fs');
const { spawnSync, execSync } = require('child_process');

// Determine package root and repo root
// When installed as npm package: __dirname = node_modules/neodax/js/scripts/
//   ROOT     = node_modules/neodax/js/
//   PKG_ROOT = node_modules/neodax/          (has src/, include/, build_js.sh)
// When run from git clone js/scripts/:
//   ROOT     = NeoDAX/js/
//   PKG_ROOT = NeoDAX/                       (has src/, include/, build_js.sh)
const ROOT     = path.join(__dirname, '..');
const PKG_ROOT = ROOT;
const ADDON    = path.join(ROOT, 'neodax.node');
const BUILDS   = path.join(ROOT, 'prebuilds');

function log(msg)  { process.stdout.write(`  [neodax] ${msg}\n`); }
function warn(msg) { process.stdout.write(`  [neodax] ⚠  ${msg}\n`); }
function ok(msg)   { process.stdout.write(`  [neodax] ✓  ${msg}\n`); }
function fail(msg) { process.stdout.write(`  [neodax] ✗  ${msg}\n`); }

function which(cmd) {
    try {
        const r = spawnSync('which', [cmd], { encoding: 'utf8' });
        return r.status === 0 && r.stdout.trim().length > 0;
    } catch (_) { return false; }
}

// ── 1. Already built? ────────────────────────────────────────────
if (fs.existsSync(ADDON)) {
    ok('neodax.node already present — skipping build');
    process.exit(0);
}

// ── 2. Prebuild? ─────────────────────────────────────────────────
const tag      = `${process.platform === 'linux' ? 'linux' : process.platform === 'darwin' ? 'darwin' : process.platform}-${process.arch}`;
const prebuild = path.join(BUILDS, `neodax-${tag}.node`);
if (fs.existsSync(prebuild)) {
    log(`Using prebuild for ${tag}`);
    fs.copyFileSync(prebuild, ADDON);
    ok(`Installed from prebuild: ${prebuild}`);
    process.exit(0);
}

log(`No prebuild for ${tag} — compiling from source…`);

if (!which('clang') && !which('gcc') && !which('cc')) {
    warn('No C compiler found (need clang or gcc)');
    if (process.platform === 'linux') {
        warn('  Debian/Ubuntu: sudo apt install build-essential libnode-dev');
        warn('  Termux:        pkg install clang');
        warn('  Fedora:        sudo dnf install gcc');
    } else if (process.platform === 'darwin') {
        warn('  macOS: xcode-select --install');
    }
    warn('After installing compiler, run: npm rebuild');
    process.exit(0);
}

// ── 3. Try build_js.sh ───────────────────────────────────────────
const buildScript = path.join(PKG_ROOT, 'build_js.sh');
if (fs.existsSync(buildScript)) {
    log(`Running build_js.sh…`);
    try {
        execSync(`bash "${buildScript}"`, { cwd: PKG_ROOT, stdio: 'inherit' });
        // build_js.sh outputs to PKG_ROOT/js/neodax.node
        const built = path.join(PKG_ROOT, 'js', 'neodax.node');
        if (fs.existsSync(built)) {
            if (built !== ADDON) fs.copyFileSync(built, ADDON);
            ok(`neodax.node built and installed`);
            process.exit(0);
        }
    } catch (_) {
        fail('build_js.sh failed — trying inline compile');
    }
}

// ── 4. Inline compile ────────────────────────────────────────────
const nodeIncs = [
    path.join(process.execPath, '../../include/node'),
    path.join(process.execPath, '../../../include/node'),
    '/usr/include/node',
    '/usr/local/include/node',
    process.env.PREFIX ? `${process.env.PREFIX}/include/node` : null,
].filter(Boolean);

// Also check node-gyp cache
const NODE_VER = process.version.slice(1);
for (const base of [`${process.env.HOME}/.cache/node-gyp`, `${process.env.HOME}/.node-gyp`]) {
    nodeIncs.push(path.join(base, NODE_VER, 'include', 'node'));
}

const nodeInc = nodeIncs.find(p => {
    try { return fs.existsSync(path.join(p, 'node_api.h')); } catch(_) { return false; }
});

if (!nodeInc) {
    fail('Cannot find node_api.h');
    fail('  Debian/Ubuntu: sudo apt install libnode-dev');
    fail('  Termux:        pkg install nodejs');
    fail('After installing headers, run: npm rebuild');
    process.exit(0);
}

const cc      = which('clang') ? 'clang' : 'gcc';
const isApple = process.platform === 'darwin';
const isAndroid = process.env.TERMUX_VERSION || fs.existsSync('/data/data/com.termux');
const srcDir  = path.join(PKG_ROOT, 'src');
const incDir  = path.join(PKG_ROOT, 'include');
const napiSrc = path.join(ROOT, 'src', 'neodax_napi.c');

const sources = [
    napiSrc,
    ...[ 'loader.c','disasm.c','x86_decode.c','arm64_decode.c',
         'symbols.c','demangle.c','analysis.c','cfg.c','daxc.c',
         'interactive.c','loops.c','callgraph.c','correct.c',
         'riscv_decode.c','unicode.c','sha256.c','main.c',
         'symexec.c','decomp.c','emulate.c','entropy.c','macho.c' ]
         .map(f => path.join(srcDir, f))
].join(' ');

const ldFlags = isApple
    ? '-undefined dynamic_lookup'
    : '-Wl,--unresolved-symbols=ignore-all';

const defines = isApple
    ? '-D_DARWIN_C_SOURCE -DBUILD_OS_DARWIN -DBUILD_OS_BSD'
    : `-D_GNU_SOURCE -DBUILD_OS_LINUX${isAndroid ? ' -DBUILD_OS_ANDROID' : ''}`;

const cmd = [
    cc,
    '-shared', isApple ? '' : '-fPIC',
    '-O2 -std=c99',
    '-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0',
    defines,
    `-I"${incDir}" -I"${nodeInc}"`,
    sources,
    ldFlags,
    '-lm',
    `-o "${ADDON}"`
].filter(Boolean).join(' ');

log(`Compiling with ${cc}…`);
try {
    execSync(cmd, { cwd: PKG_ROOT, stdio: 'inherit' });
} catch (_) {
    fail('Compilation failed — see output above');
    fail('You can retry: npm rebuild');
    process.exit(0);
}

if (fs.existsSync(ADDON)) {
    ok('neodax.node compiled and ready');
} else {
    fail('neodax.node not produced — something went wrong');
}
