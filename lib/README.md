# AES-GCM-SIV C library

This library provides an implementation of AES-GCM-SIV in C.
It is implemented with cryptographic hardware acceleration on some CPU architectures and operating systems.

## Table of Contents

- [How to build](#how-to-build)
- [Supported platforms](#supported-platforms)
- [Library usage](#library-usage)
- [Testing](#testing)
- [Benchmark](#benchmark)

## How to build

### Building with CMake

This library mainly supports CMake as a build system. The following tools are required for building it:
- CMake (minimum version `3.10`)
- make
- a C compiler

CMake should be used directly at the root directory of the project. The build steps are as follow:

```shell
# Create build directory
mkdir build
cd build

# Configure CMake
cmake aes-gcm-siv

# Compile library
make
```

It is possible to enable architecture-specific hardware acceleration for some cryptographic operations, by enabling intrinsics support during the configuration step.

1. The first way to achieve it is to set the flag `-DTARGET_PLATFORM=${ARCH}` value during the configuration.
CMake set the specific flags needed to enable intrinsics code generation (if supported) for this specific CPU architecture.

The `ARCH` value follows Android naming convention:
- `x86`: for `i686` CPU
- `x86_64`: for `x86-64` CPU
- `armeabi-v7a`: for `ARMv7` CPU
- `arm64-v8a`: for `Aarch64` or `ARMv8` CPUs

2. The second way to enable hardware acceleration support is to force intrinsics code generation during the configuration.
The C code detects which architecture is targeted from the preprocessor directives set by the compiler.

The flags to set are the following:
- `-DUSE_INTRINSICS=ON`: to enable intrinsics code generation (any architecture)
- `-DUSE_NEON=ON`: to enable ARM NEON intrinsics support (for `ARM` architectures)

3. Lastly, when the project is being built by the Android build system, CMake retrieves the value `ANDROID_ABI` that is setup automatically by the toolchain and assign it to `TARGET_PLATFORM`.
In this case, it is not needed to set any additional flags during the configuration phase, as everything is automated.

More information on supported targets and feature detection can be found in [Supported platforms](#supported-platforms).

### Building with SwiftPM

Alternatively to CMake, a [`Package.swift`](../Package.swift) file is also provided at the root of the project to facilitate building with SwiftPM.
However, the build with SwiftPM won't be fine-tuned with hardware acceleration, as the required flags are not enabled.

### Using other build systems

To build the project using other build systems, the following directories and files should be used:
- source code and private headers:
    ```
    lib/src
    ├── *.c
    ├── arm64: *.c, *.h
    ├── generic: *.c, *.h
    └── x86_64: *.c, *.h
    ```
- public headers:
    ```
    lib/include
    └── *.h
    ```

It might be possible to directly add the `-DUSE_INTRINSICS` flag to the compiler options to enable hardware accelerated code.
Depending on the compiler and its version, it might be able to have intrinsics feature flags enabled automatically.

## Supported platforms

This library is developed with the intent of being available for a wide range of CPU architectures and operating systems.
When it is built without hardware acceleration support, the code only uses standard portable C code, without any system calls.
It should allow building the library on any target that has a C compiler.

The library is however developed and tested on these environments:
- Linux (`x86-64`)
- MacOS (both Intel and Silicon)
- Android

Additionally, the library is tested with the following compilers:
- GCC
- Clang

Other CPU architecture and operating systems should also support the library but are not extensively tested against.
For instance, the library has been used on the following platforms:
- iOS
- WebAssembly (with Emscripten compiler)
- Windows (with MSVC compiler)

### Hardware acceleration

Some CPU architectures are offering hardware acceleration of cryptographic operations (such as AES-NI for Intel CPU).
The library can take advantage of these operations by using the intrinsics functions for the designated platforms.

More specifically, the following architectures take advantage of hardware instructions to speed up both the AES and the Polyval computations:
- `x86-64`
- `ARM-v8a`

The hardware acceleration optimizations are turned on if supported when the `USE_INTRISICS` feature is used at build time.

When hardware acceleration is enabled, the library does runtime checks to ensure that the CPU is supporting the cryptographic operation.
A fallback on the pure software-based implementation is done if the operations are not supported.

### Note on Intel `x86-64` feature checks

Runtime feature detection is done with the `cpuid` instruction and checks for the `AESNI` and `PCLMUL` flags.

The feature detection should work on any `x86-64` CPU, regardless of the operating system.

### Note on Intel `x86_64` feature checks

Runtime feature detection is done to check if `AES` and `PMULL` features are available.

As ARM doesn't provide an instruction to check CPU features, the detection is done through system calls, and are dependent to the operating system.

More especially, the checks on different operating systems are performed as follow:
- Linux (including Android): using `getauxval` to check for `HWCAP_AES` and `HWCAP_PMULL` capabilities
- MacOS: using `sysctlbyname` to check for `hw.optional.arm.FEAT_AES` and `hw.optional.arm.FEAT_PMULL`
- iOS: as there are no safe and easy way to detect hardware features at runtime, hardware acceleration is always disabled

## Library usage

Documentation for the API usage can be found in the header file [`aes_gmsiv.h`](./include/aes_gcmsiv.h).

Additionally, there is example code located in [`example`](./example), used to show how typical API calls are performed.
The example code can be built by CMake by setting the flag `-DBUILD_EXAMPLE=ON`.

### Note about thread safety

The initialization, setup of key, and release of the AES-GCM-SIV context **MUST** be done only once, by a single thread.
The thread performing these operation does not need to always be the same.

Once the context has been setup, it can be shared between multiple threads, and used in parallel to encrypt or decrypt date.

More specifically, the following functions **ARE NOT** thread-safe:
- `aes_gcmsiv_init`
- `aes_gcmsiv_free`
- `aes_gcmsiv_set_key`

However, the encryption and decryption routines can be used concurrently by multiple threads:
- `aes_gcmsiv_encrypt_with_tag`
- `aes_gcmsiv_decrypt_and_check`

Also, helper functions that are not relying on any context can safely be used at any time:
- `aes_gcmsiv_context_size`
- `aes_gcmsiv_encrypt_size`
- `aes_gcmsiv_decrypt_size`
- `aes_gcmsiv_get_status_code_msg`

## Testing

The tests for the library are located in [`tests`](./tests) and can be enabled with the CMake options `-DBUILD_TESTING=ON`.

It is possible to enable sanitizers for building the library with the following flags:
- `-DENABLE_ASAN=ON`: enable AddressSanitizer, for memory error and undefined behavior sanitizers
- `-DENABLE_TSAN=ON`: enable ThreadSanitizer, for data-race detector

The tests can then be run by running any of the following commands:
- `make test`
- `ctest`

The project has the following two test suites:
- [unit tests](./tests/unit_tests), that cover:
    - normal and invalid API operations
    - compliance with the KAT test vectors from [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
    - third party KAT test vectors generated with both [BoringSSL](https://boringssl.googlesource.com/) and [RustCrypto](https://github.com/RustCrypto)
- [thread safety tests](./tests/thread_safe), that cover:
    - concurrent encryption and decryption operations with a shared context don't lead to data races
    - *(enabled only if `ENABLE_TSAN` is `ON`)*

## Benchmark

The library can be benchmarked with the program located in [`benchmark`](./benchmark/).
Building the benchmark program can be done with the CMake option `-BUILD_BENCHMARK=ON`.

It benchmarks performances of AES-GCM-SIV with:
- both 128 and 256 bits keys
- authenticating data only (for Polyval performances)
- authenticating and encrypting data (for both AES and Polyval performances)
