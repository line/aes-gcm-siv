if(NOT BUILD_BENCHMARK)
    return()
endif()

# Load programs and packages
option(THREADS_PREFER_PTHREAD_FLAG "Use -pthread for compiler and linker flag" ON)
find_package(Threads REQUIRED)

# Build Google Benchmark
if(NOT TARGET googlebenchmark)
    include(googlebenchmark.cmake)
endif()

# Build benchmark suites
set(TARGET_NAME aes_gcmsiv_benchmark)

set(SOURCES main.cpp)

add_executable(${TARGET_NAME} ${SOURCES})
set_target_properties(${TARGET_NAME} PROPERTIES CXX_STANDARD 11)

target_include_directories(${TARGET_NAME}
    PRIVATE .
    )

target_link_libraries(${TARGET_NAME}
    PRIVATE aes_gcmsiv
    PRIVATE googlebenchmark
    PRIVATE Threads::Threads
    )
