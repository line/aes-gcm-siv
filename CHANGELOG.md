# Changelog

## 1.3.1

- Update Android library to support [16K KB page sizes](https://developer.android.com/guide/practices/page-sizes) for `x86_64` and `arm64-v8a` devices

## 1.3.0

- Update Java library `ReseourceLoader`:
  - add a fallback on the class loader that is used when the Context class loader is `null`
  - refactor code to have better handling of synchronized sections and to avoid loading the library multiple times

## 1.2.0

- Add log information in the Java library when the ResourceLoader fails to load the native library

## 1.1.0

- Rename symbols of the generic AES implementation to avoid dupplicated symbols conflicts when a project would use both Mbed-TLS and this library as static libraries.
- Add feature flags `USE_FEWER_TABLES` and `USE_ROM_TABLES` to give more control on the lookup tables used for the generic AES implementation.

## 1.0.0

- First release of the library
