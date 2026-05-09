'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));

const target = process.argv[2] || '/bin/ls';

console.log(`\n  NeoDAX v${neodax.version()} — Unicode String Scanner\n`);

neodax.withBinary(target, bin => {
    const strs = bin.unicodeStrings();

    if (strs.length === 0) {
        console.log('  (no Unicode strings found)\n');
        return;
    }

    const byEncoding = {};
    strs.forEach(s => {
        byEncoding[s.encoding] = (byEncoding[s.encoding] || 0) + 1;
    });

    console.log(`  Found ${strs.length} Unicode strings:`);
    Object.entries(byEncoding).forEach(([enc, n]) =>
        console.log(`    ${enc.padEnd(10)} ${n}`)
    );
    console.log();

    console.log('  ' + 'Address'.padEnd(20) + 'Encoding'.padEnd(12) + 'Bytes'.padEnd(8) + 'Value');
    console.log('  ' + '─'.repeat(80));

    strs.slice(0, 60).forEach(s => {
        const addr  = '0x' + s.address.toString(16).padStart(16, '0');
        const val   = s.value.replace(/[\n\r\t]/g, c =>
            c === '\n' ? '\\n' : c === '\r' ? '\\r' : '\\t'
        ).substring(0, 48);
        console.log(`  ${addr.padEnd(20)}${s.encoding.padEnd(12)}${String(s.byteLength).padEnd(8)}${val}`);
    });

    if (strs.length > 60)
        console.log(`  ... and ${strs.length - 60} more`);
    console.log();
});
