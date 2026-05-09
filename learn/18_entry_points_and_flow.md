# Entry Points and Execution Flow

**Level:** 1 - Basic Analysis
**Prerequisites:** 17_string_extraction.md
**What You Will Learn:** How to find where a program starts executing and trace its initial flow.

## The Entry Point

Every executable has an entry point: the address where execution begins when the OS loads the program.

For ELF executables, the entry point is the `e_entry` field in the ELF header. For C programs, this is not `main` but rather `_start`, a small stub in the C runtime that sets up the environment and then calls `main`.

NeoDAX reports the entry point in its analysis overview and you can disassemble from it directly:

```bash
./neodax -A 0x401040 /bin/ls   # use the reported entry point address
```

## The C Runtime Startup

On Linux with glibc, the execution flow from entry point to `main` looks like:

1. `_start`: Receives argc, argv, and envp from the OS. Calls `__libc_start_main`.
2. `__libc_start_main`: Initializes glibc, calls constructors, then calls `main`.
3. `main`: Your program's entry point.

On stripped binaries you will not see these names, but you can identify `_start` by its characteristic pattern: loading argc and argv from the stack, then calling an external function (which is `__libc_start_main`).

## Finding main on Stripped Binaries

On x86-64 Linux, `_start` passes the address of `main` as the first argument to `__libc_start_main`. Look for:

```
lea    rdi, [0x401234]    ; address of main
...
call   __libc_start_main@plt
```

The address loaded into `rdi` is `main`. On ARM64 the same pattern uses `x0` instead of `rdi`.

## Constructors and Destructors

ELF binaries can have constructor functions that run before `main` and destructor functions that run after `main` returns. These are listed in the `.init_array` and `.fini_array` sections.

Malware sometimes hides initialization code in constructors to complicate analysis.

## Tracing from Entry to main

A useful exercise is to trace execution from the entry point to `main` manually:

1. Start at the entry point.
2. Follow the first `call` instruction.
3. In the called function, look for another function address being loaded.
4. That address is likely `main`.

This teaches you to read execution flow even when symbol names are absent.

## Practice

1. Find the entry point of `/bin/ls` from NeoDAX output.
2. Disassemble from the entry point with `./neodax -A <entry_point> /bin/ls`.
3. Trace the first few calls manually.
4. Identify which address represents `main` (the function that actually implements the program logic).

## Next

You have completed Level 1 - Basic Analysis. Continue to `20_functions_detection.md` to begin Level 2.
