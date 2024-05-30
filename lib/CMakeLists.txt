# If ANDROID_ABI is defined, use this value as target platform
if(DEFINED ANDROID_ABI)
    set(TARGET_PLATFORM ${ANDROID_ABI})
endif()

# Enable intrinsics for x86_64 and arm64
if(TARGET_PLATFORM STREQUAL "x86_64")
    set(USE_INTRINSICS ON)
elseif(TARGET_PLATFORM STREQUAL "arm64-v8a")
    set(USE_INTRINSICS ON)
    set(USE_NEON ON)
endif()

# Build library
set(TARGET_NAME aes_gcmsiv)

set(SOURCES
    src/aes_gcmsiv.c
    src/utils.c
    src/arm64/aes_arm64.c
    src/arm64/polyval_arm64.c
    src/generic/aes_generic.c
    src/generic/polyval_generic.c
    src/x86_64/aes_x86_64.c
    src/x86_64/polyval_x86_64.c
    )

set(HEADERS
    include/aes_gcmsiv.h
    include/common.h
    include/utils.h
    src/arm64/aes_arm64.h
    src/arm64/polyval_arm64.h
    src/generic/aes_generic.h
    src/generic/polyval_generic.h
    src/x86_64/aes_x86_64.h
    src/x86_64/polyval_x86_64.h
    )

add_library(${TARGET_NAME} STATIC ${SOURCES} ${HEADERS})
set_target_properties(${TARGET_NAME} PROPERTIES C_STANDARD 11)
set_target_properties(${TARGET_NAME} PROPERTIES PUBLIC_HEADER ${HEADERS})

if(MSVC)
    target_compile_options(${TARGET_NAME}
        PRIVATE -Wall
        PRIVATE $<$<BOOL:${USE_INTRINSICS}>:-DUSE_INTRINSICS>
        )
else()
    target_compile_options(${TARGET_NAME}
        PUBLIC -Wall -Wextra -W -Wwrite-strings -Winit-self -Wpointer-arith
        PUBLIC -Wreturn-type -Waddress -Wsequence-point -Wformat-security
        PUBLIC -Wmissing-include-dirs -Wfloat-equal -Wshadow -Wcast-align
        PRIVATE $<$<BOOL:${USE_INTRINSICS}>:-DUSE_INTRINSICS>
        PRIVATE $<$<BOOL:${USE_NEON}>:-march=armv8-a+crypto>
        )

    # Set sanitizers flags
    target_compile_options(${TARGET_NAME}
        PRIVATE $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address$<SEMICOLON>-fsanitize=undefined>
        PRIVATE $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        )

    target_link_libraries(${TARGET_NAME}
        PRIVATE $<$<BOOL:${ENABLE_ASAN}>:-fsanitize=address$<SEMICOLON>-fsanitize=undefined>
        PRIVATE $<$<BOOL:${ENABLE_TSAN}>:-fsanitize=thread>
        )
endif()

target_include_directories(${TARGET_NAME}
    PUBLIC include
    PRIVATE src/arm64
    PRIVATE src/generic
    PRIVATE src/x86_64
    )

# Install rules
install(TARGETS ${TARGET_NAME}
    ARCHIVE DESTINATION lib
    PUBLIC_HEADER DESTINATION include
    )

# Benchmark, example and tests
add_subdirectory(benchmark)
add_subdirectory(example)
add_subdirectory(tests)
