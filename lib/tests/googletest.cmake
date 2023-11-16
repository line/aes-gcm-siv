set(TARGET_NAME googletest)
set(GOOGLETEST_LIBDIR lib)

if(DEFINED ANDROID_ABI)
    set(GOOGLETEST_ROOT ${ANDROID_NDK}/sources/third_party/googletest/)

    add_library(gtest STATIC ${GOOGLETEST_ROOT}/src/gtest_main.cc ${GOOGLETEST_ROOT}/src/gtest-all.cc)

    target_include_directories(gtest
        PRIVATE ${GOOGLETEST_ROOT}
        PUBLIC ${GOOGLETEST_ROOT}/include
        )

    add_library(${TARGET_NAME} INTERFACE)

    target_link_libraries(${TARGET_NAME}
        INTERFACE gtest
        )
else()
    include(ExternalProject)

    if(CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
        get_filename_component(EMCMAKE_TOOLCHAIN_DIR "${CMAKE_TOOLCHAIN_FILE}" DIRECTORY)

        find_program(EMCMAKE_COMMAND emcmake "${EMCMAKE_TOOLCHAIN_DIR}")
        if(NOT EMCMAKE_COMMAND)
            message(FATAL_ERROR "emcmake command not found")
        endif()

        set(GTEST_CMAKE_COMMAND ${EMCMAKE_COMMAND} ${CMAKE_COMMAND})
    else()
        set(GTEST_CMAKE_COMMAND ${CMAKE_COMMAND})
    endif()

    ExternalProject_Add(${TARGET_NAME}_dl
        GIT_REPOSITORY    https://github.com/google/googletest.git
        GIT_CONFIG        advice.detachedHead=false
        GIT_SHALLOW       ON
        GIT_TAG           release-1.11.0
        CMAKE_CACHE_ARGS  -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR> -DCMAKE_INSTALL_LIBDIR:PATH=<INSTALL_DIR>/${GOOGLETEST_LIBDIR}
        CMAKE_COMMAND     ${GTEST_CMAKE_COMMAND}
        BUILD_COMMAND     ${CMAKE_COMMAND} --build <BINARY_DIR> --config $<CONFIG>
        UPDATE_COMMAND    ""
        )
    ExternalProject_Get_property(${TARGET_NAME}_dl INSTALL_DIR)

    add_library(${TARGET_NAME} INTERFACE)

    target_include_directories(${TARGET_NAME}
        INTERFACE ${INSTALL_DIR}/include
        )

    target_link_libraries(${TARGET_NAME}
        INTERFACE -L${INSTALL_DIR}/${GOOGLETEST_LIBDIR}
        INTERFACE gtest gmock Threads::Threads
        )

    add_dependencies(${TARGET_NAME} ${TARGET_NAME}_dl)
endif()
