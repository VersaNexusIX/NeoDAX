# Android Binary Analysis

**Level:** 6 - Real World Reverse Engineering
**Prerequisites:** 63_reverse_engineering_protocols.md
**What You Will Learn:** How to analyze Android native libraries and binaries with NeoDAX on Termux.

## Android Binary Formats

Android applications (APKs) contain several types of code:

**Dalvik bytecode (.dex files):** Java/Kotlin code compiled to Dalvik bytecode. NeoDAX does not analyze .dex files.

**Native libraries (.so files):** C/C++ code compiled as ELF shared objects for ARM64 or x86-64. NeoDAX analyzes these fully.

**Executable binaries:** Some apps ship standalone executable binaries in their `assets` or `lib` directories. These are ELF files.

## Extracting Native Libraries

APK files are ZIP archives. Extract them to access the native libraries:

```bash
cd /sdcard/Download
unzip myapp.apk -d myapp_extracted
ls myapp_extracted/lib/
# arm64-v8a/   armeabi-v7a/   x86/   x86_64/
```

The `arm64-v8a` directory contains ARM64 `.so` files, which are the most relevant on modern Android devices.

## Analyzing with NeoDAX on Termux

NeoDAX runs natively on Android with Termux. After extraction:

```bash
./neodax -l myapp_extracted/lib/arm64-v8a/libnative.so
./neodax -y myapp_extracted/lib/arm64-v8a/libnative.so
./neodax -x myapp_extracted/lib/arm64-v8a/libnative.so
```

## JNI Functions

Native libraries that interface with Java use JNI (Java Native Interface). JNI functions have names starting with `Java_`:

```
Java_com_example_app_MainActivity_checkLicense
Java_com_example_app_NativeLib_processData
```

These are the entry points where Java code calls into native code. They are excellent starting points for analysis because they represent the native library's public API.

```bash
./neodax -y mylib.so | grep "^Java_"
```

## Understanding JNI Signatures

JNI functions always receive two parameters before the user parameters:

- `x0/rdi`: JNI environment pointer
- `x1/rsi`: Java object (the `this` reference or class reference)
- `x2/rdx` onwards: actual parameters

A Java method `boolean checkLicense(String key)` corresponds to a C function:

```c
jboolean Java_com_example_app_MainActivity_checkLicense(
    JNIEnv *env,
    jobject thiz,
    jstring key
);
```

In the disassembly, the first two arguments are the JNI internals. The third is your actual parameter.

## Common Analysis Targets

**License checks:** Functions like `checkLicense`, `validateKey`, `verifyPurchase`. These are common targets for cracking.

**Anti-tampering:** Functions that verify APK integrity, check for root, or detect analysis tools.

**Cryptographic operations:** Functions that encrypt or decrypt data.

**C2 communication:** Functions that connect to remote servers.

## Practice

1. Install an APK on your Android device.
2. Extract it and find the native libraries.
3. List the JNI function names.
4. Pick one JNI function and analyze what it does.

## Next

Continue to `65_stripping_and_obfuscation.md`.
