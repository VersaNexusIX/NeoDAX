# TypeScript Usage

**Level:** 3 - JavaScript API
**Prerequisites:** 36_analyze_pipeline.md
**What You Will Learn:** How to use NeoDAX with TypeScript for type-safe analysis scripts.

## TypeScript Declarations

NeoDAX ships with full TypeScript declarations in `js/index.d.ts`. These are automatically used when you install via npm.

## Basic TypeScript Setup

Create a `tsconfig.json`:

```json
{
    "compilerOptions": {
        "target": "ES2020",
        "module": "commonjs",
        "strict": true,
        "esModuleInterop": true
    }
}
```

Install TypeScript if needed:

```bash
npm install -D typescript ts-node
```

## A Typed Analysis Script

```typescript
import neodax, { NeoDAXBinary, Section, DaxFunction } from 'neodax'

function analyzeCodeSections(bin: NeoDAXBinary): void {
    const codeSections: Section[] = bin.sections()
        .filter(s => s.type === 'code')

    codeSections.forEach(section => {
        console.log(section.name, 'size:', section.size.toString())
    })
}

function findComplexFunctions(bin: NeoDAXBinary, minLoops: number = 1): DaxFunction[] {
    return bin.functions()
        .filter(fn => fn.hasLoops && fn.hasCalls)
        .sort((a, b) => b.insnCount - a.insnCount)
}

neodax.withBinary(process.argv[2], (bin: NeoDAXBinary) => {
    console.log('Analyzing:', bin.file)
    analyzeCodeSections(bin)

    const complex = findComplexFunctions(bin)
    console.log('Complex functions:', complex.length)
    complex.slice(0, 5).forEach(fn => {
        console.log(' ', fn.name, fn.insnCount, 'insns')
    })
})
```

Run with ts-node:

```bash
npx ts-node analyze.ts /bin/ls
```

## Key Types

The main types from the declarations:

```typescript
interface NeoDAXBinary {
    arch: string
    format: string
    os: string
    entry: bigint
    sha256: string
    isPie: boolean
    isStripped: boolean
    hasDebug: boolean
    sections(): Section[]
    symbols(): Symbol[]
    functions(): DaxFunction[]
    xrefs(): Xref[]
    disasmJson(section: string, opts?: DisasmOptions): Instruction[]
    analyze(): AnalyzeResult
    close(): void
}

interface Section {
    name: string
    type: string
    vaddr: bigint
    size: bigint
    offset: bigint
    insnCount: number
}

interface DaxFunction {
    name: string
    start: bigint
    end: bigint
    size: bigint
    insnCount: number
    hasLoops: boolean
    hasCalls: boolean
}

interface Instruction {
    address: bigint
    mnemonic: string
    operands: string
    length: number
    group: string
    bytes: Uint8Array
    symbol: string | null
}
```

## Type Narrowing with Addresses

Since addresses are BigInt, comparisons require BigInt literals:

```typescript
const mainFn = bin.functions().find(fn => fn.start === 0x401234n)
//                                                             ^ BigInt literal
```

## Practice

1. Convert one of the JavaScript examples from previous files to TypeScript.
2. Add a type annotation to a function that returns `DaxFunction[]`.
3. Use the TypeScript compiler to catch a type error (try passing a string where BigInt is expected).

## Next

Continue to `38_async_patterns.md`.
