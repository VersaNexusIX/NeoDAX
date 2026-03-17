'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));
const path   = require('path');

const target = process.argv[2] || '/bin/ls';

console.log(`\n  NeoDAX v${neodax.version()} — Binary Info\n`);

neodax.withBinary(target, bin => {
    const i = bin.info;

    const row = (label, value) =>
        console.log(`  ${label.padEnd(14)} ${String(value)}`);

    console.log('  ' + '─'.repeat(56));
    row('File',       i.file);
    row('Format',     i.format);
    row('Arch',       i.arch);
    row('OS',         i.os);
    row('Entry',      '0x' + i.entry.toString(16).padStart(16, '0'));
    row('Base',       '0x' + i.base.toString(16).padStart(16, '0'));
    row('Image Size', Number(i.imageSize).toLocaleString() + ' bytes');
    row('Code Size',  Number(i.codeSize).toLocaleString()  + ' bytes');
    row('Data Size',  Number(i.dataSize).toLocaleString()  + ' bytes');
    row('Sections',   i.nsections);
    row('Symbols',    i.nsymbols);
    row('Functions',  i.nfunctions);
    row('Xrefs',      i.nxrefs);
    row('Unicode',    i.nustrings);
    row('PIE',        i.isPie);
    row('Stripped',   i.isStripped);
    row('Debug',      i.hasDebug);
    row('Build-ID',   i.buildId || '(none)');
    row('SHA-256',    i.sha256.substring(0, 32) + '...');
    console.log('  ' + '─'.repeat(56));

    const secs = bin.sections();
    console.log(`\n  Sections (${secs.length}):\n`);
    console.log('  ' + 'Name'.padEnd(28) + 'Type'.padEnd(10) + 'VirtAddr'.padEnd(20) + 'Size');
    console.log('  ' + '─'.repeat(72));
    secs.forEach(s => {
        const addr = '0x' + s.vaddr.toString(16).padStart(16, '0');
        const size = Number(s.size).toLocaleString().padStart(12);
        console.log(`  ${s.name.padEnd(28)}${s.type.padEnd(10)}${addr.padEnd(20)}${size}`);
    });
    console.log();
});
