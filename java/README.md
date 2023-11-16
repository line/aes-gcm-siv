# AES-GCM-SIV Java library

This library provides an implementation of AES-GCM-SIV in Java.
It is implemented as a wrapper over the [C library](../lib), with the help of a [JNI wrapper](../jni).

## Table of Contents

- [How to build](#how-to-build)
- [Runtime loading](#runtime-loading)
- [Library usage](#library-usage)
- [Testing](#testing)

## How to build

The library relies on Gradle for building.

The following tools are needed to build the library:
- Java Development Kit (minimum JDK 8)
- CMake (minimum version `3.10`)
- make
- a C compiler

### Local build

By default, the Gradle script builds the library for the environment where it is being built, as the Java code relies on the C library, which is native code.

To build the library, follow these steps:
```shell
# Move to Java directory
cd aes-gcm-siv/java

# Build with Gradle
./gradlew build
```

The produced JAR archive can be found in `aesgcmsiv/build/libs/`, with the name `aesgcmsiv-${VERSION}.jar`.
The version number follows [Semantic Versioning](https://semver.org/).

By default, builds are SNAPSHOT builds, and the suffix `-SNAPSHOT` is added to the version number.
It can be turned off for release builds with the Gradle option `-PsnapshotBuild=false`.

### Multi-platform build

It is possible to build the JAR archive such that the same archive can run on multiple architectures and operating systems.
The multi-platform library only supports these 4 CPU architectures: `x86`, `x86-64`, `arm` and `arm64`, and only for Linux, MacOS, and Windows.

The first step is to build the native JNI library for each of the targeted CPU architecture and operating systems.

The JNI library can be built with CMake, by configuring it directly from the root directory of the project, with the option `-DBUILD_JNI=ON`.
Further details on how to build the C library, especially on how to configure hardware acceleration, can be found in the [`README.md`](../lib/README.md).

Once the JNI library has been built, the JAR archive can be compiled with Gradle.

The steps to build the JAR archive are as follows:
```shell
# Move to Java directory
cd aes-gcm-siv/java

# Create stash directory
mkdir -p aesgcmsiv/build/stash

# Create arch specific directories
mkdir -p aesgcmsiv/build/stash/${ARCH}/

# Move the native C JNI libraries to their respective directory
...

# Build Java library
./gradlew -PlocalBuild=false build
```

The `ARCH` value and the name of the native C JNI library must follow the naming convention specified in [Runtime loading](#runtime-loading).

The produced JAR archive is located in the same directory as for local builds.

## Runtime loading

Multi-platform JAR archives try to load the resources that are included in the stash folder when being built.
To detect which resource it needs to load, it retrieves the runtime CPU architecture and operating system from the JVM properties.

Depending on the `os.arch` property, the native library is searched in one of these folders:
- `x86`: for `x86_64`, `amd64`, `x64`, or `x86-64` CPU architecture
- `x86-64`: for `x86`, `i386`, `ia-32`, or `i686` CPU architecture
- `arm`: for `arm`, `arm-v7`, `armv7`, or `arm32` CPU architecture
- `arm64`: for `aarch64`, `arm64`, or `arm-v8` CPU architecture

Then, the `os.name` property is checked with a `startWith` to see which library file to load:
- `linux`: loads `libaesgcmsiv_jni.so`
- `mac`: loads `libaesgcmsiv_jni.dylib`
- `windows`: loads `aesgcmsiv_jni.dll`

If the file cannot be found in the JAR archive, then an exception is raised.

The native JNI library is extracted from the JAR and copied in a temporary folder `${TEMP_DIR}/aesgcmsiv_jni-${RANDOM}`, where it can be loaded by the JVM.
The `TEMP_DIR` value is taken from the JVM property `java.io.tmpdir`, and should have permissions to create directory and files.
The `RANDOM` value is a random number prefix used to avoid collision of names as much as possible.

The temporary JNI library copied on the disk is marked as `deleteOnExit`, so it should be deleted automatically by the JVM when it stops.

## Library usage

Documentation of the code is directly included in the corresponding Java file, following Javadoc format.

Additionally, there is example code in [`AESGCMSIVExample.java`](./aesgcmsiv/src/test/java/com/linecorp/aesgcmsiv/AESGCMSIVExample.java), used to show how typical API calls are performed.

## Testing

Unit tests of the library are located in the file [`AESGCMSIVTest.java`](./aesgcmsiv/src/test/java/com/linecorp/aesgcmsiv/AESGCMSIVTest.java).

They can be run by Gradle with the command `./gradlew test`.

The unit tests cover:
- Java API usage calls
- KAT test vectors from [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
