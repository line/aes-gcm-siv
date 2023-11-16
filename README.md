# AES-GCM-SIV Library

## Overview

AES-GCM-SIV is an authenticated encryption algorithm designed to provide nonce misuse resistance, and is specified in [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452).

This repository provides C, Android, and Java implementations, and is optimized for high-performance in architectures with cryptographic hardware accelerators.

## Table of Contents

- [Getting started](#getting-started)
- [How to contribute](#how-to-contribute)
- [License](#license)
- [Further reading](#further-reading)

## Getting started

### C

The C implementation of AES-GCM-SIV provides the core functionality of the library, and is located in the [`lib`](./lib) repository.
It is optimized for high-performance encryption and decryption in specific CPU architecture.

Detailed instructions are available in this [`README.md`](./lib/README.md).

### Android

The Android implementation is done with a JNI (Java Native Interface) wrapper over the C implementation.
This allows to take advantage of the optimized C code when it is supported by the runtime architecture.
The JNI bindings are in the [`jni`](./jni) repository, and the Android code is located in the [`android`](./android) repository.

Detailed instructions are available in this [`README.md`](./android/README.md).

### Java

The Java implementation is done with a JNI (Java Native Interface) wrapper over the C implementation.
This allows to take advantage of the optimized C code when it is supported by the runtime architecture.
The JNI bindings are in the [`jni`](./jni) repository, and the Java code is located in the [`java`](./java) repository.

Detailed instructions are available in this [`README.md`](./java/README.md).

## How to contribute

We welcome your various contributions, including bug fixes, vulnerability reports, and more.
Please see the [CONTRIBUTING.md](./CONTRIBUTING.md) file for details.

## License

This library is provided under [Apache 2.0 license](./LICENSE).
In accordance with the Apache 2.0 license terms, users **MUST** distribute a copy of the Apache 2.0 license with the product using this library.

Additionally, the software-based AES implementation is taken from [Mbed TLS](https://github.com/Mbed-TLS/mbedtls), which is also distributed under the Apache 2.0 license.

Some modifications have been made to better suit the aes-gcm-siv library, and the modified source files retain the original copyright information, with additional notice that they have been modified.
The concerned files are the following:
- `lib/src/generic/aes_mbedtls.c`
- `lib/src/generic/aes_mbedtls.h`

## Further reading

More details on how the library has been optimized can be found in our blog post (available in English, Japanese and Korean):
- How we optimized the AES-GCM-SIV encryption algorithm: [https://engineering.linecorp.com/en/blog/AES-GCM-SIV-optimization](https://engineering.linecorp.com/en/blog/AES-GCM-SIV-optimization)
