# Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

cmake_minimum_required(VERSION 3.22)
project(OpenSSLConfigTest C)

option(TEST_LEGACY_PROVIDER "Test loading the legacy provider" ON)

# CONFIG mode is essential here; without it, CMake's own FindOpenSSL.cmake
# module may be used instead of OpenSSL's exported config, which is what
# this test is meant to exercise.
find_package(OpenSSL CONFIG REQUIRED)

# We build the same dummy program in three variants, covering the ways
# CMake's FindOpenSSL.cmake has traditionally promoted for linking against
# OpenSSL:
#
# ossl_config_dummy_vars    links with ${OPENSSL_LIBRARIES}, and calls
#                           libssl and libcrypto functions directly
# ossl_config_dummy_tgt     links with the OpenSSL::SSL and OpenSSL::Crypto
#                           targets, and calls libssl and libcrypto
#                           functions directly
# ossl_config_dummy_sslonly links with the OpenSSL::SSL target alone, and
#                           only calls libssl functions directly, relying
#                           on the implied libcrypto dependency

add_executable(ossl_config_dummy_vars dummy.c)
target_compile_definitions(ossl_config_dummy_vars PRIVATE DIRECT_CRYPTO_CALLS)
target_include_directories(ossl_config_dummy_vars PRIVATE ${OPENSSL_INCLUDE_DIR})
target_link_libraries(ossl_config_dummy_vars PRIVATE ${OPENSSL_LIBRARIES})

add_executable(ossl_config_dummy_tgt dummy.c)
target_compile_definitions(ossl_config_dummy_tgt PRIVATE DIRECT_CRYPTO_CALLS)
target_link_libraries(ossl_config_dummy_tgt PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_executable(ossl_config_dummy_sslonly dummy.c)
target_link_libraries(ossl_config_dummy_sslonly PRIVATE OpenSSL::SSL)

set(all_dummies
    ossl_config_dummy_vars ossl_config_dummy_tgt ossl_config_dummy_sslonly)
set(crypto_dummies
    ossl_config_dummy_vars ossl_config_dummy_tgt)

if(WIN32)
    # Console applications linking against the OpenSSL DLLs need applink,
    # when that target exists (it's absent in no-uplink configurations)
    if(TARGET OpenSSL::applink)
        foreach(dummy IN LISTS all_dummies)
            target_link_libraries(${dummy} PRIVATE OpenSSL::applink)
        endforeach()
    endif()

    # Copy the OpenSSL DLLs next to the binaries, so the tests can run
    if(DEFINED OPENSSL_LIBCRYPTO_SHARED)
        foreach(dummy IN LISTS all_dummies)
            add_custom_command(TARGET ${dummy} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different
                    "${OPENSSL_LIBCRYPTO_SHARED}" "${OPENSSL_LIBSSL_SHARED}"
                    $<TARGET_FILE_DIR:${dummy}>)
        endforeach()
    endif()
endif()

if(TEST_LEGACY_PROVIDER)
    foreach(dummy IN LISTS crypto_dummies)
        target_compile_definitions(${dummy} PRIVATE TEST_LEGACY_PROVIDER)
    endforeach()
endif()

enable_testing()

# The dummy programs are run through OpenSSL's util/wrap.pl (path passed in
# as OPENSSL_WRAP_PL), which sets up the loader path for the platform at
# hand, as well as OPENSSL_MODULES so the provider modules are found.
find_program(PERL_PROGRAM perl REQUIRED)

foreach(dummy IN LISTS all_dummies)
    add_test(NAME ${dummy}
        COMMAND ${PERL_PROGRAM} ${OPENSSL_WRAP_PL} $<TARGET_FILE:${dummy}>)
endforeach()
