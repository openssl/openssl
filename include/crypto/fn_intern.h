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

/*
 * OSSL_FN_LIMBS_N gives the number of OSSL_FN_ULONG limbs needed to hold a
 * number of bits, rounded to the limb width (for the group-prime constants,
 * all sizes being exact multiples of their bit counts).
 */
#define OSSL_FN_LIMBS_N(nbits) (((nbits) + (OSSL_FN_BYTES * 8 - 1)) / (OSSL_FN_BYTES * 8))

/*
 * OSSL_FN_HEADER_FIELDS is the shared field list between the runtime
 * struct ossl_fn_st (which appends a flexible array member) and the
 * static-constant union shapes declared by OSSL_FN_STATIC_DECLARE (which
 * append a fixed-size array).  Using the same macro for both guarantees
 * the header layouts stay in lockstep.
 */
#define OSSL_FN_HEADER_FIELDS                  \
    unsigned int is_dynamically_allocated : 1; \
    unsigned int is_securely_allocated : 1;    \
    int dsize

struct ossl_fn_st {
    OSSL_FN_HEADER_FIELDS;
    OSSL_FN_ULONG d[];
};

/*
 * Statically-allocated OSSL_FN storage for constants.
 *
 * These macros allow an OSSL_FN to exist in .rodata, statically initialized
 * at compile time.  This is used to back fixed constants (group parameters,
 * mathematical constants, etc.) so that they can be passed to OSSL_FN
 * functions directly, without materialization at runtime.
 *
 * The underlying mechanism is a union of the flexible-array-member OSSL_FN
 * type and a fixed-size-array type with identical header layout.  The
 * fixed-size member carries the actual limbs; reading through the OSSL_FN
 * member is well-defined because both members share the same initial
 * header fields, spelled identically through OSSL_FN_HEADER_FIELDS.
 */

/*
 * OSSL_FN_STATIC_DECLARE(name, nlimbs) declares a union type named
 * ossl_fn_static_##name and an extern storage object of that type.
 *
 *   name    the suffix used for the union type and storage object
 *   nlimbs  the number of OSSL_FN_ULONG limbs in the fixed array
 */
#define OSSL_FN_STATIC_DECLARE(name, nlimbs) \
    union ossl_fn_static_##name {            \
        OSSL_FN fn;                          \
        struct {                             \
            OSSL_FN_HEADER_FIELDS;           \
            OSSL_FN_ULONG d[nlimbs];         \
        } fixed;                             \
    };                                       \
    extern const union ossl_fn_static_##name \
        ossl_fn_static_##name##_storage

/*
 * OSSL_FN_STATIC_DEFINE(name, nlimbs, ...) defines the storage object
 * declared by OSSL_FN_STATIC_DECLARE, with the given limb values.
 *
 *   ...     the limb values, in little-endian order (least significant
 *           first), exactly as they would appear in a static array
 *           initializer for an OSSL_FN_ULONG array
 *
 * Access the OSSL_FN view of the storage object as
 *   &ossl_fn_static_##name##_storage.fn
 * Access the raw limbs (as a BN_ULONG array, since OSSL_FN_ULONG ==
 * BN_ULONG) as
 *   (BN_ULONG *)ossl_fn_static_##name##_storage.fixed.d
 */
#define OSSL_FN_STATIC_DEFINE(name, nlimbs, ...)           \
    const union ossl_fn_static_##name                      \
        ossl_fn_static_##name##_storage                    \
        = {                                                \
              .fixed = { 0, 0, (nlimbs), { __VA_ARGS__ } } \
          }

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

/*
 * Generate a probable prime (an RSA p or q candidate) per FIPS 186-5
 * A.1.6 (Steps 4 & 5), optionally enforcing |p| congruent to |c| mod 8.
 * |p| and |Xpout| must have room for nlen/2 bits; one limb of headroom
 * over that width lets a carry past the width be detected rather than
 * truncated.  Internally generated auxiliary primes and random draws
 * that are not returned are cleared.  Returns 1 on success, 0 on error.
 */
int ossl_fn_rsa_fips186_5_gen_prob_primes(OSSL_FN *p, OSSL_FN *Xpout,
    OSSL_FN *p1, OSSL_FN *p2, const OSSL_FN *Xp, const OSSL_FN *Xp1,
    const OSSL_FN *Xp2, int nlen, const OSSL_FN *e, OSSL_FN_CTX *ctx,
    BN_GENCB *cb, uint32_t c, OSSL_LIB_CTX *libctx);

/*
 * Calculate the arena payload size that
 * ossl_fn_rsa_fips186_5_gen_prob_primes() needs.  |p1|, |p2|, |Xp1|
 * and |Xp2| may be NULL, as for the operation.  Returns 0 on
 * arithmetic overflow or invalid input.
 */
size_t ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size(const OSSL_FN *p,
    const OSSL_FN *Xpout, const OSSL_FN *p1, const OSSL_FN *p2,
    const OSSL_FN *Xp1, const OSSL_FN *Xp2, int nlen, const OSSL_FN *e);

/*
 * Generate a probable prime factor per FIPS 186-5 B.9 from two
 * auxiliary primes using the Chinese Remainder Theorem.  Same width
 * contract as ossl_fn_rsa_fips186_5_gen_prob_primes().  Returns 1 on
 * success, 0 on error.
 */
int ossl_fn_rsa_fips186_5_derive_prime(OSSL_FN *Y, OSSL_FN *X,
    const OSSL_FN *Xin, const OSSL_FN *r1, const OSSL_FN *r2, int nlen,
    const OSSL_FN *e, OSSL_FN_CTX *ctx, BN_GENCB *cb, uint32_t c,
    OSSL_LIB_CTX *libctx);

/*
 * Calculate the arena payload size that
 * ossl_fn_rsa_fips186_5_derive_prime() needs.  Returns 0 on
 * arithmetic overflow or invalid input.
 */
size_t ossl_fn_rsa_fips186_5_derive_prime_ctx_size(const OSSL_FN *Y,
    const OSSL_FN *X, const OSSL_FN *r1, const OSSL_FN *r2, int nlen,
    const OSSL_FN *e);

#ifdef __cplusplus
}
#endif

#endif
