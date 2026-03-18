# Symbols and Names

**Level:** 1 - Basic Analysis
**Prerequisites:** 11_reading_sections.md
**What You Will Learn:** What symbols are, how to read them, and what to do when they are absent.

## What Symbols Are

A symbol is a named address. Every function and global variable in a compiled program has a symbol: a name associated with its starting address.

Symbols are stored in symbol tables within the binary. Two tables are relevant:

`.symtab` contains all symbols: internal functions, local variables, static functions, and global functions. This table exists in development builds but is usually removed when shipping software.

`.dynsym` contains only the symbols needed for dynamic linking: functions the binary imports from shared libraries and functions it exports for others to use. This table cannot be fully removed without breaking the binary, so it survives stripping.

## Reading Symbol Output

```bash
./neodax -y /bin/ls
```

Output looks like:

```
0x401234  func    main
0x401300  func    process_file
0x401500  func    printf@plt
0x401510  func    malloc@plt
0x404020  object  optarg
```

Each line shows the address, type, and name.

The `@plt` suffix means the symbol is a PLT stub for an imported function. When the binary calls `printf`, it actually calls the PLT stub, which in turn calls the real `printf` from libc.

## Symbol Types

NeoDAX reports two main symbol types:

`func`: A function symbol. Points to the start of executable code.

`object`: A data symbol. Points to a variable or data structure.

## Working with Stripped Binaries

When a binary is stripped, `.symtab` is gone. You lose all internal function names. What remains:

1. PLT stubs for imported functions (these have names).
2. Exported symbols if the binary is a shared library.
3. Names that NeoDAX reconstructs from heuristics, labeled `sub_<address>`.

For a stripped binary, `./neodax -y /bin/ls` may show only a few dozen PLT entries while reporting hundreds of detected functions.

## Using Symbol Context During Analysis

Even partial symbols provide useful context. If you see:

```
call   0x401510  ; malloc@plt
```

You know that this call allocates memory. If you then see:

```
call   0x401560  ; memcpy@plt
```

You can infer data is being copied into the newly allocated buffer. Following the PLT names gives you a rough narrative even without internal names.

## C++ Symbols

C++ compilers mangle symbol names to encode type information. A function like `MyClass::process(int, char*)` becomes something like `_ZN7MyClass7processEic`.

Use the `-d` flag to demangle these names:

```bash
./neodax -d -y /path/to/cpp_binary
```

NeoDAX implements the Itanium ABI demangling algorithm and expands mangled names into readable forms.

## Practice

1. Run `./neodax -y /bin/ls` and count the PLT symbols.
2. Find at least three PLT symbols that give you clues about what `ls` does (hint: look for `opendir`, `readdir`, `stat`).
3. If you have an unstripped binary available (compile a simple C program without `-s`), compare the symbol count before and after stripping.
4. Run `./neodax -d -y /path/to/a/cpp_binary` if you have one available.

## Next

Continue to `13_reading_disassembly.md`.
