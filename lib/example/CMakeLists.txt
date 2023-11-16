if(NOT BUILD_EXAMPLE)
    return()
endif()

# Build sample example
set(TARGET_NAME example)

set(SOURCES main.c)

add_executable(${TARGET_NAME} ${SOURCES})
set_target_properties(${TARGET_NAME} PROPERTIES C_STANDARD 11)

target_include_directories(${TARGET_NAME}
    PRIVATE .
    )

target_link_libraries(${TARGET_NAME}
    PRIVATE aes_gcmsiv
    )
