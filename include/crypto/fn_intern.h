/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file A set of internal functions to manipulate the OSSL_FN d array, and
 * for introspection.
 */

#ifndef OPENSSL_FN_INTERN_H
#define OPENSSL_FN_INTERN_H
#pragma once

#include <stdbool.h>
#include "crypto/fn.h"

#ifdef __cplusplus
extern "C" {
#endif

#if OSSL_FN_BYTES == 4
/* 32-bit systems */
#define OSSL_FN_ULONG_C(n) UINT32_C(n)
#define OSSL_FN_ULONG64_C(hi32, lo32) OSSL_FN_ULONG_C(lo32), OSSL_FN_ULONG_C(hi32)
#elif OSSL_FN_BYTES == 8
/* 64-bit systems */
#define OSSL_FN_ULONG_C(n) UINT64_C(n)
#define OSSL_FN_ULONG64_C(hi32, lo32) (OSSL_FN_ULONG_C(hi32) << 32 | OSSL_FN_ULONG_C(lo32))
#else
#error "OpenSSL doesn't support large numbers on this platform"
#endif

int ossl_fn_set_words(OSSL_FN *f, const OSSL_FN_ULONG *words, size_t limbs);
const OSSL_FN_ULONG *ossl_fn_get_words(const OSSL_FN *f);

size_t ossl_fn_get_dsize(const OSSL_FN *f);

void ossl_fn_set_negative(OSSL_FN *f, bool neg);

bool ossl_fn_is_negative(const OSSL_FN *f);
bool ossl_fn_is_dynamically_allocated(const OSSL_FN *f);
bool ossl_fn_is_securely_allocated(const OSSL_FN *f);

#ifdef __cplusplus
}
#endif

#endif
