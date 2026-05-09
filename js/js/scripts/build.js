#!/usr/bin/env node
'use strict';

const path = require('path');
const fs   = require('fs');

const ADDON = path.join(__dirname, '..', 'neodax.node');
const force = process.argv.includes('--force');

if (!force && fs.existsSync(ADDON)) {
    console.log('  [neodax] neodax.node already built. Use --force to rebuild.');
    process.exit(0);
}

if (force && fs.existsSync(ADDON)) {
    fs.unlinkSync(ADDON);
}

require('./install.js');
