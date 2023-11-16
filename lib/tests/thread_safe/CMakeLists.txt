if(NOT ENABLE_TSAN)
    return()
endif()

set(TARGET_NAME thread_safe)

set(SOURCES main.c)

add_executable(${TARGET_NAME} ${SOURCES})
set_target_properties(${TARGET_NAME} PROPERTIES C_STANDARD 11)

target_include_directories(${TARGET_NAME}
    PRIVATE .
    )

target_link_libraries(${TARGET_NAME}
    PRIVATE aes_gcmsiv
    PRIVATE Threads::Threads
    )

add_test(NAME "${TARGET_NAME}" COMMAND ${TARGET_NAME})
