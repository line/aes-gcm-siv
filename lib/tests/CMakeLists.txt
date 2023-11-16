if(NOT BUILD_TESTING)
    return()
endif()

# Load programs and packages
option(THREADS_PREFER_PTHREAD_FLAG "Use -pthread for compiler and linker flag" ON)
find_package(Threads REQUIRED)

# Build Google Test
if(NOT TARGET googletest)
    include(googletest.cmake)
endif()

# Build test suites
add_subdirectory(thread_safe)
add_subdirectory(unit_tests)
