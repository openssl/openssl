/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define STRINGIFY_IMPLEMENTATION_(a) #a
#define STRINGIFY(a) STRINGIFY_IMPLEMENTATION_(a)

#ifdef __clang__
/*
 * clang does not have GCC push pop
 * warning: clang attribute push can't be used within a namespace in clang up
 * til 8.0 so OPENSSL_TARGET_REGION and OPENSSL_UNTARGET_REGION must be
 * outside* of a namespace.
 */
#define OPENSSL_TARGET_REGION(T)                                       \
    _Pragma(STRINGIFY(clang attribute push(__attribute__((target(T))), \
        apply_to = function)))
#define OPENSSL_UNTARGET_REGION _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define OPENSSL_TARGET_REGION(T) \
    _Pragma("GCC push_options") _Pragma(STRINGIFY(GCC target(T)))
#define OPENSSL_UNTARGET_REGION _Pragma("GCC pop_options")
#endif

#ifndef OPENSSL_TARGET_REGION
#define OPENSSL_TARGET_REGION(T)
#define OPENSSL_UNTARGET_REGION
#endif

#define OPENSSL_TARGET_AVX2 \
    OPENSSL_TARGET_REGION("avx2")
#define OPENSSL_UNTARGET_AVX2 OPENSSL_UNTARGET_REGION

#include <string.h>
#include <immintrin.h>
#include <stddef.h>
#include <stdint.h>

#include "internal/cryptlib.h"
#include "crypto/evp.h"
#include "evp_local.h"
