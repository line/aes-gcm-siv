# Changelog

## 1.1.0

- Rename symbols of the generic AES implementation to avoid dupplicated symbols conflicts when a project would use both Mbed-TLS and this library as static libraries.
- Add feature flags `USE_FEWER_TABLES` and `USE_ROM_TABLES` to give more control on the lookup tables used for the generic AES implementation.

## 1.0.0

- First release of the library
