# Setting Up NeoDAX

**Level:** 0 - Foundation
**Prerequisites:** 01_what_is_binary_analysis.md
**What You Will Learn:** How to install NeoDAX on Linux, macOS, and Android.

## Installation Overview

NeoDAX has zero external dependencies. You only need a C compiler and GNU make. The build compiles all source files and produces a single executable called `neodax`.

## Linux

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
```

The build takes under a minute. When it finishes you will see the NeoDAX banner and a message confirming the build succeeded. The `neodax` binary is in the current directory.

Add it to your path for convenience:

```bash
sudo cp neodax /usr/local/bin/
```

Or keep it in the NeoDAX directory and call it as `./neodax`.

## macOS

Install the Xcode command line tools if you have not already:

```bash
xcode-select --install
```

Then build exactly as on Linux:

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
```

NeoDAX uses `arch/arm64_macos.S` on Apple Silicon and `arch/x86_64_macos.S` on Intel Mac. The Makefile selects the correct file automatically.

## Android with Termux

Termux provides a Linux-like environment on Android without root. Install the required packages first:

```bash
pkg install nodejs clang make git
```

Then clone and build:

```bash
git clone https://github.com/VersaNexusIX/NeoDAX.git
cd NeoDAX
make
```

The build works the same way as on Linux. The resulting `neodax` binary runs natively on ARM64 Android.

## Verifying the Installation

Run the help flag to confirm everything is working:

```bash
./neodax -h
```

You should see a list of all available flags. If you see this, the installation succeeded.

Try analyzing a system binary:

```bash
./neodax -l /bin/ls
```

On Linux this lists the ELF sections of `/bin/ls`. On macOS it lists the Mach-O sections.

## Building the JavaScript Addon

If you want to use the JavaScript API (covered in Level 3), you also need to build the native Node.js addon:

```bash
make js
```

This produces `js/neodax.node`. You can also install from npm directly, which builds the addon automatically:

```bash
npm install neodax
```

## Directory Layout After Building

```
NeoDAX/
  neodax          the CLI binary
  src/            C source files
  include/        header files
  arch/           platform assembly stubs
  js/
    neodax.node   the Node.js native addon (after make js)
    index.js      the JavaScript API wrapper
    server/       the REST API server
```

## Practice

1. Build NeoDAX and confirm it runs.
2. Run `./neodax -h` and read through the available flags.
3. Run `./neodax -l /bin/ls` (Linux) or `./neodax -l /bin/ls` (macOS).
4. Note how many sections are listed.

## Next

Continue to `03_your_first_binary.md`.
