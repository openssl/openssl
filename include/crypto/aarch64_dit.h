/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved. Copyright
 * (c) 2002, Oracle and/or its affiliates. All rights reserved
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_AARCH64_DIT_H
#define OPENSSL_AARCH64_DIT_H
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Data-independent timing.
 *
 * OSSL_ENABLE_DIT_FOR_SCOPE must be placed before code that uses instructions
 * whose timing depends on their data - otherwise constant-time code might not
 * be.
 *
 * OSSL_ENABLE_DIT_FOR_SCOPE can be placed at the beginning of a code section
 * that makes repeated calls to crypto functions.
 *
 * DIT state will automatically be restored to its previous value at the end of
 * the scope.
 *
 * This can reduce the overhead of repeatedly setting and resetting the state.
 *
 * Note that this requires the cleanup attribute to function, and that this
 * attribute is not supported in clang versions before 15. Support for the
 * cleanup attribute was introduced into GCC in version 4.0, which pre-dates
 * AArch64. Currently only these two compilers are supported; other compilers
 * can be added to the list below provided they support
 * __attribute__((cleanup()).
 */

#if defined(__aarch64__) && !defined(OSSL_NO_DIT)
#if !(defined(__GNUC__) || (defined(__clang__) && (__clang_major__ >= 15)))
#warning "Unsupported compiler - disabling DIT"
#define OSSL_NO_DIT
#endif
#endif

#if defined(__aarch64__) && !defined(OSSL_NO_DIT)

/* Internal functions used by OSSL_ENABLE_DIT_FOR_SCOPE */
void ossl_restore_original_dit(volatile int *dit_prev);
int ossl_ensure_dit_on(int);

#define OSSL_ENABLE_DIT_FOR_SCOPE                           \
    volatile int dit_prev_                                  \
        __attribute__((cleanup(ossl_restore_original_dit))) \
        __attribute__((unused))                             \
        = ossl_ensure_dit_on(1);

#else

#define OSSL_ENABLE_DIT_FOR_SCOPE

#endif /* __aarch64__ && !OSSL_NO_DIT */

#ifdef __cplusplus
}
#endif
#endif
