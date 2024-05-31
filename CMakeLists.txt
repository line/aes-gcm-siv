cmake_minimum_required(VERSION 3.10)
project(AES_GCMSIV C CXX)

option(USE_INTRINSICS "Enable hardware acceleration primitives" OFF)
option(USE_NEON "Enable ARM Neon intrinsics flags" OFF)
option(USE_ROM_TABLES "Enable precomputed AES lookup tables" OFF)

option(BUILD_BENCHMARK "Build the benchmarking tree." OFF)
option(BUILD_EXAMPLE "Build the example tree." OFF)
option(BUILD_JNI "Build the JNI dynamic library." OFF)
option(BUILD_TESTING "Build the testing tree." OFF)

option(ENABLE_ASAN "Build with Address Sanitizer." OFF)
option(ENABLE_TSAN "Build with Thread Sanitizer." OFF)

if(BUILD_TESTING)
    find_program(MEMORYCHECK_COMMAND valgrind)
    set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full --error-exitcode=1")
endif()

include(CTest)

add_subdirectory(lib)

if(BUILD_JNI)
    add_subdirectory(jni)
endif()
