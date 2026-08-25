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
#include <openssl/bn.h> /* For BN_GENCB */
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

OSSL_FN_ULONG ossl_fn_add_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);
OSSL_FN_ULONG ossl_fn_sub_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);

/*
 * Miller-Rabin probabilistic primality test (FIPS 186-4 C.3.1, or the
 * enhanced variant C.3.2 when |enhanced| is nonzero).  |status| returns
 * the primality verdict (a BN_PRIMETEST_* code).  Returns 1 on success
 * (|status| is set), 0 on error.
 */
int ossl_fn_miller_rabin_is_prime(const OSSL_FN *w, int iterations,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, int enhanced, int *status,
    OSSL_LIB_CTX *libctx);

/*
 * Calculate the arena payload size that ossl_fn_miller_rabin_is_prime()
 * needs for a candidate of width |w|->dsize.  Returns 0 on arithmetic
 * overflow or invalid input.
 */
size_t ossl_fn_miller_rabin_is_prime_ctx_size(const OSSL_FN *w);

/*
 * Test whether |w| is probably prime, clamping |checks| to a minimum
 * round count based on the candidate's width.  When |do_trial_division|
 * is nonzero, small factors are weeded out first.  Returns 1 when probably
 * prime, 0 when composite, -1 on error.
 */
int ossl_fn_check_prime(const OSSL_FN *w, int checks, OSSL_FN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb, OSSL_LIB_CTX *libctx);

/*
 * Calculate the arena payload size that ossl_fn_check_prime() needs for a
 * candidate of width |w|->dsize.  Returns 0 on arithmetic overflow or
 * invalid input.
 */
size_t ossl_fn_check_prime_ctx_size(const OSSL_FN *w);

/*
 * Test whether |w| is probably prime, for key generation.  Always
 * trial-divides; |checks| is used unclamped.  Returns 1 when probably
 * prime, 0 when composite, -1 on error.
 */
int ossl_fn_check_generated_prime(const OSSL_FN *w, int checks,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, OSSL_LIB_CTX *libctx);

/*
 * Calculate the arena payload size that ossl_fn_check_generated_prime()
 * needs for a candidate of width |w|->dsize.  Returns 0 on arithmetic
 * overflow or invalid input.
 */
size_t ossl_fn_check_generated_prime_ctx_size(const OSSL_FN *w);

#ifdef __cplusplus
}
#endif

#endif
