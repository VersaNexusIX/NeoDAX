'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));

const target = process.argv[2] || '/bin/ls';

console.log(`\n  NeoDAX v${neodax.version()} — Symbols & Functions\n`);

neodax.withBinary(target, bin => {
    const syms = bin.symbols();
    console.log(`  ── Symbols (${syms.length}) ─────────────────────────────────────`);
    if (syms.length === 0) {
        console.log('  (none — binary is stripped)');
    } else {
        const header = '  ' + 'Address'.padEnd(20) + 'Type'.padEnd(12) + 'Size'.padEnd(10) + 'Name';
        console.log(header);
        console.log('  ' + '─'.repeat(72));
        syms.slice(0, 40).forEach(s => {
            const addr = '0x' + s.address.toString(16).padStart(16, '0');
            const name = s.demangled || s.name;
            const size = s.size ? Number(s.size).toString() : '-';
            const entry = s.isEntry ? ' [entry]' : '';
            console.log(`  ${addr.padEnd(20)}${s.type.padEnd(12)}${size.padEnd(10)}${name}${entry}`);
        });
        if (syms.length > 40)
            console.log(`  ... and ${syms.length - 40} more`);
    }

    const fns = bin.functions();
    console.log(`\n  ── Functions (${fns.length}) ────────────────────────────────────`);
    const header2 = '  ' + 'Start'.padEnd(20) + 'End'.padEnd(20) + 'Size'.padEnd(10) + 'Name';
    console.log(header2);
    console.log('  ' + '─'.repeat(72));
    fns.slice(0, 40).forEach(f => {
        const start = '0x' + f.start.toString(16).padStart(16, '0');
        const end   = f.end ? '0x' + f.end.toString(16).padStart(16, '0') : '(unknown)';
        const size  = f.size ? Number(f.size).toString() : '-';
        const flags = [f.hasCalls ? 'calls' : '', f.hasLoops ? 'loops' : '']
            .filter(Boolean).join(',');
        console.log(`  ${start.padEnd(20)}${end.padEnd(20)}${size.padEnd(10)}${f.name}${flags ? ' [' + flags + ']' : ''}`);
    });
    if (fns.length > 40)
        console.log(`  ... and ${fns.length - 40} more`);
    console.log();
});
