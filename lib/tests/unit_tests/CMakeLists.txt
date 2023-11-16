set(TARGET_NAME unit_tests)

set(SOURCES
    api.cpp
    kat.cpp
    main.cpp
    thirdparty_kat.cpp
    utils.cpp
    )

set(HEADERS
    utils.h
    )

add_executable(${TARGET_NAME} ${SOURCES} ${HEADERS})
set_target_properties(${TARGET_NAME} PROPERTIES CXX_STANDARD 11)

target_include_directories(${TARGET_NAME}
    PRIVATE .
    )

target_link_libraries(${TARGET_NAME}
    PRIVATE aes_gcmsiv
    PRIVATE googletest
    )

add_test(NAME ${TARGET_NAME} COMMAND ${TARGET_NAME})
