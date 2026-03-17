'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));

const target  = process.argv[2] || '/bin/ls';
const section = process.argv[3] || '.text';
const group   = process.argv[4] || null;

console.log(`\n  NeoDAX v${neodax.version()} — Disassembly JSON\n`);
console.log(`  Target:  ${target}`);
console.log(`  Section: ${section}`);
if (group) console.log(`  Filter:  group=${group}`);
console.log();

neodax.withBinary(target, bin => {
    let insns = bin.disasmJson(section);

    if (insns.length === 0) {
        console.log(`  (no instructions decoded — section "${section}" not found or unsupported arch)`);
        return;
    }

    if (group) {
        insns = insns.filter(i => i.group === group);
        console.log(`  Found ${insns.length} "${group}" instructions\n`);
    } else {
        const byGroup = {};
        insns.forEach(i => {
            const g = i.group || 'unknown';
            byGroup[g] = (byGroup[g] || 0) + 1;
        });
        console.log(`  Total instructions: ${insns.length}`);
        console.log('  By group:');
        Object.entries(byGroup)
            .sort((a, b) => b[1] - a[1])
            .forEach(([g, n]) => console.log(`    ${g.padEnd(16)} ${n}`));
        console.log();
        insns = insns.slice(0, 30);
        console.log(`  First ${insns.length} instructions:\n`);
    }

    const header = '  ' + 'Address'.padEnd(20) + 'Bytes'.padEnd(28) + 'Group'.padEnd(14) + 'Instruction';
    console.log(header);
    console.log('  ' + '─'.repeat(90));

    insns.slice(0, 60).forEach(i => {
        const addr  = '0x' + i.address.toString(16).padStart(16, '0');
        const bytes = i.bytes.map(b => b.toString(16).padStart(2, '0')).join(' ');
        const grp   = (i.group || '').padEnd(14);
        const insn  = `${i.mnemonic} ${i.operands}`.trimEnd();
        const sym   = i.symbol ? `  <${i.symbol}>` : '';
        console.log(`  ${addr.padEnd(20)}${bytes.padEnd(28)}${grp}${insn}${sym}`);
    });

    if (insns.length > 60)
        console.log(`  ... and ${insns.length - 60} more`);
    console.log();
});
