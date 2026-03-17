'use strict';

const neodax = require(require('path').join(__dirname, '..', 'index.js'));

const target = process.argv[2] || '/bin/ls';

console.log(`\n  NeoDAX v${neodax.version()} — Cross-References & Call Graph\n`);

neodax.withBinary(target, bin => {
    const xrefs = bin.xrefs();
    const syms  = bin.symbols();
    const fns   = bin.functions();

    const addrToName = {};
    syms.forEach(s => { addrToName[s.address.toString()] = s.demangled || s.name; });
    fns.forEach(f  => { if (!addrToName[f.start.toString()]) addrToName[f.start.toString()] = f.name; });

    const resolveName = addr => addrToName[addr.toString()] || `sub_${addr.toString(16)}`;

    const calls  = xrefs.filter(x => x.isCall);
    const jumps  = xrefs.filter(x => !x.isCall);

    console.log(`  Total xrefs: ${xrefs.length}  (calls: ${calls.length}, jumps: ${jumps.length})\n`);

    const callCount = {};
    calls.forEach(x => {
        const key = x.to.toString();
        callCount[key] = (callCount[key] || 0) + 1;
    });

    const hotFunctions = Object.entries(callCount)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 20);

    if (hotFunctions.length > 0) {
        console.log('  ── Most-Called Functions ───────────────────────────────────');
        console.log('  ' + 'Address'.padEnd(20) + 'Calls'.padEnd(8) + 'Name');
        console.log('  ' + '─'.repeat(60));
        hotFunctions.forEach(([addrStr, count]) => {
            const addr = BigInt(addrStr);
            const name = resolveName(addr);
            const hex  = '0x' + addr.toString(16).padStart(16, '0');
            console.log(`  ${hex.padEnd(20)}${String(count).padEnd(8)}${name}`);
        });
        console.log();
    }

    console.log('  ── Call Graph (first 30 edges) ─────────────────────────────');
    console.log('  ' + 'From'.padEnd(20) + 'Caller'.padEnd(28) + '→  Callee');
    console.log('  ' + '─'.repeat(72));
    calls.slice(0, 30).forEach(x => {
        const from = '0x' + x.from.toString(16).padStart(16, '0');
        const caller = resolveName(x.from).substring(0, 24);
        const callee = resolveName(x.to);
        console.log(`  ${from.padEnd(20)}${caller.padEnd(28)}→  ${callee}`);
    });

    if (calls.length > 30)
        console.log(`  ... and ${calls.length - 30} more`);
    console.log();
});
