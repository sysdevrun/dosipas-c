# dosipas-c: host build (library, CLI, tests) and ESP-IDF component.
#
# Host:
#   cmake -S . -B build && cmake --build build && ctest --test-dir build
# Options:
#   -DDOSIPAS_WITH_MBEDTLS=ON|OFF   signature verification (default ON)
#   -DDOSIPAS_MBEDTLS_TAG=v3.6.4    mbedTLS to download and build when no DOSIPAS_MBEDTLS_ROOT is given
#   -DDOSIPAS_MBEDTLS_ROOT=<dir>    an existing mbedTLS install (include/ and lib/libmbedcrypto.a)
#   -DDOSIPAS_SANITIZE=ON           build everything with ASan + UBSan
#   -DDOSIPAS_BUILD_TESTS=ON|OFF
#
# ESP-IDF: add this directory as a component (idf_component.yml is provided).
cmake_minimum_required(VERSION 3.16)

if(ESP_PLATFORM)
    idf_component_register(
        SRCS src/dosipas_decode.c src/dosipas_ticket.c src/dosipas_json.c src/dosipas_verify.c
             src/dosipas_summary.c src/dosipas_schema_tables.c
        INCLUDE_DIRS src
        REQUIRES mbedtls)
    target_compile_definitions(${COMPONENT_LIB} PRIVATE DOSIPAS_WITH_MBEDTLS=1)
    return()
endif()

project(dosipas C CXX)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)

option(DOSIPAS_WITH_MBEDTLS "Enable signature verification with mbedTLS" ON)
option(DOSIPAS_SANITIZE "Build with AddressSanitizer and UndefinedBehaviorSanitizer" OFF)
option(DOSIPAS_BUILD_TESTS "Build the test suite" ON)
set(DOSIPAS_MBEDTLS_TAG "v3.6.4" CACHE STRING "mbedTLS tag to fetch when no install is given")
set(DOSIPAS_MBEDTLS_ROOT "" CACHE PATH "Existing mbedTLS install prefix")

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_library(dosipas STATIC
    src/dosipas_decode.c
    src/dosipas_ticket.c
    src/dosipas_json.c
    src/dosipas_verify.c
    src/dosipas_summary.c
    src/dosipas_schema_tables.c)
target_include_directories(dosipas PUBLIC src)
target_compile_options(dosipas PRIVATE -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion)

if(DOSIPAS_WITH_MBEDTLS)
    if(DOSIPAS_MBEDTLS_ROOT STREQUAL "")
        set(DOSIPAS_MBEDTLS_ROOT "${CMAKE_SOURCE_DIR}/.deps/mbedtls-${DOSIPAS_MBEDTLS_TAG}")
        if(NOT EXISTS "${DOSIPAS_MBEDTLS_ROOT}/lib/libmbedcrypto.a")
            message(STATUS "fetching and building mbedTLS ${DOSIPAS_MBEDTLS_TAG} into ${DOSIPAS_MBEDTLS_ROOT}")
            execute_process(
                COMMAND sh "${CMAKE_SOURCE_DIR}/tools/fetch_mbedtls.sh" "${DOSIPAS_MBEDTLS_TAG}" "${DOSIPAS_MBEDTLS_ROOT}"
                RESULT_VARIABLE fetch_result)
            if(NOT fetch_result EQUAL 0)
                message(FATAL_ERROR "mbedTLS fetch failed; pass -DDOSIPAS_MBEDTLS_ROOT or -DDOSIPAS_WITH_MBEDTLS=OFF")
            endif()
        endif()
    endif()
    message(STATUS "mbedTLS: ${DOSIPAS_MBEDTLS_ROOT}")
    target_include_directories(dosipas PRIVATE "${DOSIPAS_MBEDTLS_ROOT}/include")
    target_compile_definitions(dosipas PRIVATE DOSIPAS_WITH_MBEDTLS=1)
    target_link_libraries(dosipas PUBLIC "${DOSIPAS_MBEDTLS_ROOT}/lib/libmbedcrypto.a")
else()
    target_compile_definitions(dosipas PRIVATE DOSIPAS_WITH_MBEDTLS=0)
endif()

if(DOSIPAS_SANITIZE)
    set(san_flags -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined)
    target_compile_options(dosipas PUBLIC ${san_flags})
    target_link_options(dosipas PUBLIC ${san_flags})
endif()

add_executable(dosipas_cli tools/dosipas_cli.c)
target_link_libraries(dosipas_cli PRIVATE dosipas)

if(DOSIPAS_BUILD_TESTS)
    enable_testing()
    add_executable(dosipas_tests
        test/test_dosipas/test_main.cpp
        test/test_dosipas/tjson.c
        test/test_dosipas/fixtures_data.c
        host/unity/unity.c)
    target_include_directories(dosipas_tests PRIVATE host/unity test/test_dosipas)
    target_compile_definitions(dosipas_tests PRIVATE UNITY_INCLUDE_DOUBLE UNITY_OUTPUT_COLOR)
    target_link_libraries(dosipas_tests PRIVATE dosipas)
    foreach(group golden times signed robustness verify summary metrics)
        add_test(NAME ${group} COMMAND dosipas_tests ${group})
    endforeach()
endif()
