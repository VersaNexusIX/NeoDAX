#!/usr/bin/env node
/**
 * NeoDAX explicit rebuild script
 * Usage:
 *   node scripts/build.js           — build if neodax.node missing
 *   node scripts/build.js --force   — always rebuild
 *   npm run build
 *   npm run rebuild
 */

'use strict';

const path = require('path');
const fs   = require('fs');

const ADDON  = path.join(__dirname, '..', 'neodax.node');
const force  = process.argv.includes('--force');

if (!force && fs.existsSync(ADDON)) {
    console.log('  [neodax] neodax.node already built. Use --force to rebuild.');
    process.exit(0);
}

if (force && fs.existsSync(ADDON)) {
    fs.unlinkSync(ADDON);
}

require('./install.js');
