# Add JNI to include path if needed
if(NOT ANDROID)
    find_package(JNI REQUIRED)
endif()

# Add compilation flags needed for shared libraries
target_compile_options(aes_gcmsiv
    PUBLIC -fvisibility=hidden
    )

set_property(TARGET aes_gcmsiv
    PROPERTY POSITION_INDEPENDENT_CODE ON
    )

# Build library
set(TARGET_NAME aesgcmsiv_jni)

set(SOURCES aesgcmsiv_jni.c)

set(HEADERS aesgcmsiv_jni.h)

add_library(${TARGET_NAME} SHARED ${SOURCES} ${HEADERS})
set_target_properties(${TARGET_NAME} PROPERTIES C_STANDARD 11)

target_compile_options(${TARGET_NAME}
    PUBLIC -Wall -Wextra -W -Wwrite-strings -Winit-self -Wpointer-arith
    PUBLIC -Wreturn-type -Waddress -Wsequence-point -Wformat-security
    PUBLIC -Wmissing-include-dirs -Wfloat-equal -Wshadow -Wcast-align
    )

target_include_directories(${TARGET_NAME}
    PUBLIC .
    PRIVATE $<$<BOOL:${JNI_FOUND}>:${JNI_INCLUDE_DIRS}>
    )

target_link_libraries(${TARGET_NAME}
    PRIVATE aes_gcmsiv
    )

add_custom_command(TARGET ${TARGET_NAME} POST_BUILD
    COMMAND ${CMAKE_STRIP} -x $<TARGET_FILE:${TARGET_NAME}>
    COMMENT "Strip non-global symbols from library"
    )
