# AES-GCM-SIV Android library

This library provides an implementation of AES-GCM-SIV for Android.
It is implemented as a wrapper over the [C library](../lib), with the help of a [JNI wrapper](../jni).

## Table of Contents

- [How to build](#how-to-build)
- [Library usage](#library-usage)
- [Testing](#testing)

## How to build

The library relies on Gradle for building.

The following tools are needed to build the library:
- Java Development Kit (JDK 17)
- Native Development Kit (version `25.1.8937393`)

To build the library, follow these steps:
```shell
# Move to Java directory
cd aes-gcm-siv/android

# Build with Gradle
./gradlew build
```

The environment variable `ANDROID_HOME` should point to the Android SDK path, or the file `local.properties` should have the `sdk.dir` variable set accordingly.

The produced AAR archive can be found in `aesgcmsiv/build/outputs/aar/`, with the name `aesgcmsiv-${FLAVOR}-${VERSION}.aar`.
The version number follows [Semantic Versioning](https://semver.org/).

By default, builds are SNAPSHOT builds, and the suffix `-SNAPSHOT` is added to the version number.
It can be turned off for release builds with the Gradle option `PsnapshotBuild=false`.

The produced AAR archive is compatible with Android SDK 24 minimum, and is built with support for all the available ABIs.

## Library usage

Documentation of the code is directly included in the corresponding Java file, following Javadoc format.

Additionally, there is example code in [`AESGCMSIVExample.java`](./aesgcmsiv/src/androidTest/java/com/linecorp/aesgcmsiv/AESGCMSIVExample.java), used to show how typical API calls are performed.

## Testing

Instrumented unit tests of the library are located in the file [`AESGCMSIVTest.java`](./aesgcmsiv/src/androidTest/java/com/linecorp/aesgcmsiv/AESGCMSIVTest.java).

They can be run by Gradle with the command `./gradlew connectedAndroidTest`, or more simply directly from Android Studio (with an Android Instrumented Tests configuration).

The unit tests cover:
- Java API usage calls
- KAT test vectors from [RFC 8452](https://www.rfc-editor.org/rfc/rfc8452)
