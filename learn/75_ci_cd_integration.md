# CI/CD Integration

**Level:** 7 - Integration and Automation
**Prerequisites:** 74_batch_analysis.md
**What You Will Learn:** How to integrate NeoDAX into continuous integration pipelines for automated security checks.

## Use Cases in CI/CD

NeoDAX can be part of an automated security gate that checks every build:

- Verify that a binary does not import unexpected functions
- Check that a shared library exports the expected API
- Detect if a build output has unexpectedly high entropy
- Verify that a binary is not stripped when it should not be
- Check that the binary has the expected architecture and format

## GitHub Actions Example

```yaml
name: Binary Analysis

on:
  push:
    branches: [main]
  pull_request:

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build project
        run: make

      - name: Setup NeoDAX
        run: |
          git clone https://github.com/VersaNexusIX/NeoDAX.git /tmp/neodax
          cd /tmp/neodax && make
          echo "/tmp/neodax" >> $GITHUB_PATH

      - name: Install Node.js addon
        run: |
          cd /tmp/neodax
          npm install --prefix js/

      - name: Analyze build output
        run: node .github/scripts/check_binary.js ./mybinary
```

## The Check Script

```javascript
// .github/scripts/check_binary.js
const neodax = require('/tmp/neodax/js')
const path   = process.argv[2]

if (!path) { console.error('Usage: check_binary.js <path>'); process.exit(1) }

let passed = true

neodax.withBinary(path, bin => {
    // Check 1: Expected architecture
    if (!bin.arch.includes('x86_64')) {
        console.error(`FAIL: Expected x86_64, got ${bin.arch}`)
        passed = false
    }

    // Check 2: Not too many unexpected imports
    const dangerousImports = ['system', 'execve', 'popen']
    const symbols = bin.symbols()
    for (const name of dangerousImports) {
        if (symbols.some(s => s.name.includes(name))) {
            console.error(`FAIL: Found dangerous import: ${name}`)
            passed = false
        }
    }

    // Check 3: No high entropy sections
    const entropy = bin.entropy()
    if (entropy.includes('PACKED')) {
        console.error('FAIL: High entropy detected, binary may be packed')
        passed = false
    }

    // Check 4: Not stripped (for debug builds)
    if (process.env.BUILD_TYPE === 'debug' && bin.isStripped) {
        console.error('FAIL: Binary is stripped but debug build expected symbols')
        passed = false
    }

    if (passed) {
        console.log('PASS: Binary analysis checks passed')
        console.log(`  Arch: ${bin.arch}`)
        console.log(`  Functions: ${bin.functions().length}`)
        console.log(`  SHA-256: ${bin.sha256}`)
    }
})

process.exit(passed ? 0 : 1)
```

## Generating Analysis Reports

For inclusion in pull request comments or build artifacts:

```javascript
neodax.withBinary(path, bin => {
    const r = bin.analyze()
    const report = `
## Binary Analysis Report

| Property | Value |
|----------|-------|
| Architecture | ${r.info.arch} |
| Format | ${r.info.format} |
| SHA-256 | ${r.info.sha256} |
| PIE | ${r.info.isPie} |
| Stripped | ${r.info.isStripped} |
| Functions | ${r.functions.length} |
| Sections | ${r.sections.length} |
| Symbols | ${r.symbols.length} |
`
    require('fs').writeFileSync('binary_report.md', report)
})
```

## Practice

1. Build a check script that fails if a binary imports more than 50 external symbols.
2. Test it on a statically linked binary (should fail) and a dynamically linked binary (might pass).
3. Write a GitHub Actions workflow that runs the check on every push.

## Next

Continue to `76_building_plugins.md`.
