/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * This file provides implementation of various array allocation routines that
 * perform integer overflow checking for size calculation.  They are provided
 * in a separate file, so they can be included in various providers, such
 * as FIPS, directly, and not pulled through the core interface (as these are
 * mere wrappers for the existing allocation functions and a need
 *  to have variability in their implementation is not fereseen at this point).
 */

#include "internal/mem_alloc_utils.h"

void *CRYPTO_malloc_array(size_t num, size_t size, const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_malloc(bytes, file, line);
}

void *CRYPTO_calloc(size_t num, size_t size, const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_zalloc(bytes, file, line);
}

void *CRYPTO_aligned_alloc_array(size_t num, size_t size, size_t align,
                                 void **freeptr, const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line)) {
        *freeptr = NULL;

        return NULL;
    }

    return CRYPTO_aligned_alloc(bytes, align, freeptr, file, line);
}

void *CRYPTO_realloc_array(void *addr, size_t num, size_t size,
                           const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_realloc(addr, bytes, file, line);
}

void *CRYPTO_clear_realloc_array(void *addr, size_t old_num, size_t num,
                                 size_t size, const char *file, int line)
{
    size_t old_bytes, bytes;

    if (ossl_size_mul_of(old_num, size, &old_bytes, file, line) ||
        ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_clear_realloc(addr, old_bytes, bytes, file, line);
}

void *CRYPTO_secure_malloc_array(size_t num, size_t size,
                                 const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_secure_malloc(bytes, file, line);
}

void *CRYPTO_secure_calloc(size_t num, size_t size, const char *file, int line)
{
    size_t bytes;

    if (ossl_size_mul_of(num, size, &bytes, file, line))
        return NULL;

    return CRYPTO_secure_zalloc(bytes, file, line);
}
