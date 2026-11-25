# Symbol Demangling

**Level:** 4 - Advanced Analysis
**Prerequisites:** 45_obfuscation_detection.md
**What You Will Learn:** How C++ name mangling works and how NeoDAX demangles names for readability.

## Why C++ Names Are Mangled

C++ supports function overloading (multiple functions with the same name but different argument types) and namespaces. The linker, which works with flat name spaces, cannot distinguish `void foo(int)` from `void foo(double)`.

The solution is name mangling: the compiler encodes type information into the symbol name. The function `MyClass::process(int, const char*)` becomes `_ZN7MyClass7processEiPKc` in the symbol table.

## The Itanium ABI

The Itanium C++ ABI defines the mangling scheme used by GCC, Clang, and most compilers on Linux and macOS. NeoDAX implements full Itanium ABI demangling.

The `_Z` prefix identifies a mangled name. The encoding that follows describes the class name, function name, and parameter types using a compact notation.

## Demangling in the CLI

```bash
./neodax -d -y /path/to/cpp_binary
```

The `-d` flag enables demangling. All symbol names are demangled in the output.

Before demangling:

```
0x401234  func  _ZN7MyClass7processEiPKc
0x401290  func  _ZN7MyClass11handleErrorERKNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE
```

After demangling with `-d`:

```
0x401234  func  MyClass::process(int, char const*)
0x401290  func  MyClass::handleError(std::string const&)
```

## In JavaScript

```javascript
neodax.withBinary('/path/to/cpp_binary', bin => {
    const symbols = bin.symbols()
    symbols.filter(s => s.name.startsWith('_Z')).forEach(s => {
        console.log(s.demangled || s.name)
    })
})
```

The symbol object has both `name` (mangled) and `demangled` (demangled) fields. If demangling fails, `demangled` is an empty string.

## Reading Mangled Names

Even without demangling, you can extract some information from mangled names manually:

- `_ZN` prefix: nested name (a method in a class or namespace)
- The numbers encode string lengths: `_ZN7MyClass7process` has class name length 7 (`MyClass`) and method name length 7 (`process`)
- `E` ends the nested name
- Type letters: `i` = int, `c` = char, `d` = double, `v` = void, `b` = bool
- `P` prefix = pointer, `R` prefix = reference, `K` modifier = const

## Windows (MSVC) Mangling

The Microsoft Visual C++ compiler uses a different mangling scheme. NeoDAX implements the Itanium scheme. MSVC-mangled names start with `?` instead of `_Z`.

For Windows binaries, NeoDAX's demangler may not decode MSVC names. You can identify MSVC names by the `?` prefix.

## Practice

1. Find a C++ binary on your system (look in `/usr/lib` or `/usr/bin` for anything with `++` in its name or try `ls /usr/bin/*++`).
2. Run `./neodax -d -y <binary>` and read the demangled names.
3. Identify the class hierarchy from the method names.

## Next

You have completed Level 4 - Advanced Analysis. Continue to `50_symbolic_execution_intro.md` to begin Level 5.
