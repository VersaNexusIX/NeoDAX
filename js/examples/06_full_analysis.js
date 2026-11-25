'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));
const { performance } = require('perf_hooks');

const target = process.argv[2] || '/bin/ls';

console.log(`\n  NeoDAX v${neodax.version()} — Full Analysis Pipeline\n`);

const t0 = performance.now();

neodax.withBinary(target, bin => {
    const t1 = performance.now();
    console.log(`  Loaded in ${(t1 - t0).toFixed(1)}ms`);
    console.log(`  File:   ${bin.file}`);
    console.log(`  Arch:   ${bin.arch}  |  Format: ${bin.format}  |  OS: ${bin.os}`);
    console.log(`  SHA256: ${bin.sha256}`);
    console.log();

    const t2 = performance.now();
    const result = bin.analyze();
    const t3 = performance.now();

    console.log(`  Analysis completed in ${(t3 - t2).toFixed(1)}ms\n`);

    const i = result.info;
    const stats = [
        ['Sections',  i.nsections],
        ['Symbols',   result.symbols.length],
        ['Functions', result.functions.length],
        ['Xrefs',     result.xrefs.length],
        ['CFG Blocks',i.nblocks],
        ['Unicode',   result.unicodeStrings.length],
        ['Total Insns', i.totalInsns],
        ['Code Size', Number(i.codeSize).toLocaleString() + ' B'],
        ['Data Size', Number(i.dataSize).toLocaleString() + ' B'],
        ['PIE',       i.isPie],
        ['Stripped',  i.isStripped],
        ['Debug',     i.hasDebug],
    ];

    console.log('  ── Summary ─────────────────────────────────────────────────');
    stats.forEach(([k, v]) => console.log(`  ${k.padEnd(16)} ${v}`));
    console.log();

    if (result.functions.length > 0) {
        const largest = [...result.functions]
            .filter(f => f.size > 0n)
            .sort((a, b) => (b.size > a.size ? 1 : b.size < a.size ? -1 : 0))
            .slice(0, 10);

        console.log('  ── Largest Functions ───────────────────────────────────────');
        console.log('  ' + 'Address'.padEnd(20) + 'Size'.padEnd(10) + 'Name');
        console.log('  ' + '─'.repeat(60));
        largest.forEach(f => {
            const addr = '0x' + f.start.toString(16).padStart(16, '0');
            console.log(`  ${addr.padEnd(20)}${Number(f.size).toString().padEnd(10)}${f.name}`);
        });
        console.log();
    }

    if (result.unicodeStrings.length > 0) {
        console.log('  ── Unicode String Samples ──────────────────────────────────');
        result.unicodeStrings.slice(0, 8).forEach(s => {
            const addr = '0x' + s.address.toString(16).padStart(16, '0');
            const val  = s.value.replace(/\n/g, '\\n').substring(0, 50);
            console.log(`  ${addr}  [${s.encoding}]  ${val}`);
        });
        console.log();
    }

    const totalMs = (performance.now() - t0).toFixed(1);
    console.log(`  Total wall time: ${totalMs}ms\n`);
});
