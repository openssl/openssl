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
#include "internal/common.h"
#include "internal/safe_math.h"
#include "crypto/fn.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Context-size composition helpers, shared by all the *_ctx_size()
 * functions, which all compose nested arena budgets the same way: sum the
 * operation's own scratch frame with the largest nested frame it may need.
 *
 * ossl_fn_ctx_add_size() adds two sizes overflow-safely, and
 * ossl_fn_ctx_max_size() picks the larger of two sequential frame budgets.
 * Both honour the *_ctx_size() result convention: 0 (error) is sticky,
 * OSSL_FN_CTX_SIZE_NONE counts as 0, and a resulting 0 maps back to
 * OSSL_FN_CTX_SIZE_NONE.
 */
static ossl_inline ossl_unused size_t ossl_fn_ctx_add_size(size_t a, size_t b)
{
    if (ossl_unlikely(a == 0 || b == 0))
        return 0;
    a = (a == OSSL_FN_CTX_SIZE_NONE) ? 0 : a;
    b = (b == OSSL_FN_CTX_SIZE_NONE) ? 0 : b;
    if (ossl_unlikely(b > OSSL_SAFE_MATH_MAXU(size_t) - a))
        return 0;
    a += b;
    return (a == 0) ? OSSL_FN_CTX_SIZE_NONE : a;
}

static ossl_inline ossl_unused size_t ossl_fn_ctx_max_size(size_t a, size_t b)
{
    if (ossl_unlikely(a == 0 || b == 0))
        return 0;
    a = (a == OSSL_FN_CTX_SIZE_NONE) ? 0 : a;
    b = (b == OSSL_FN_CTX_SIZE_NONE) ? 0 : b;
    a = (a > b) ? a : b;
    return (a == 0) ? OSSL_FN_CTX_SIZE_NONE : a;
}

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
 * number of bits, rounded up to a whole limb (exact for the group primes,
 * whose bit counts are all multiples of the limb width).
 */
#define OSSL_FN_LIMBS_N(nbits) (((nbits) + (OSSL_FN_BITS - 1)) / OSSL_FN_BITS)

/*
 * OSSL_FN_HEADER_FIELDS is the shared field list between the runtime
 * struct ossl_fn_st (which appends a flexible array member) and the
 * static-constant union shapes declared by OSSL_FN_STATIC_DECLARE (which
 * append a fixed-size array).  Using the same macro for both guarantees
 * the header layouts stay in lockstep.
 */
#define OSSL_FN_HEADER_FIELDS                                      \
    /* Flag: alloced with OSSL_FN_new() or OSSL_FN_secure_new() */ \
    unsigned int is_dynamically_allocated : 1;                     \
    /* Flag: alloced with OSSL_FN_secure_new() */                  \
    unsigned int is_securely_allocated : 1;                        \
                                                                   \
    /*                                                             \
     * The size of the d array that follows, in number of          \
     * OSSL_FN_ULONG.  The d array stores the number itself.       \
     *                                                             \
     * Note: |dsize| is an int, because it turns out that some     \
     * lower level (possibly assembler) functions expect that type \
     * (especially, that type size).                               \
     * This deviates from the design in                            \
     * doc/designs/fixed-size-large-numbers.md                     \
     */                                                            \
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
#define OSSL_FN_STATIC_DEFINE(name, nlimbs, ...)                   \
    const union ossl_fn_static_##name                              \
        ossl_fn_static_##name##_storage                            \
        = {                                                        \
              .fixed = { .dsize = (nlimbs), .d = { __VA_ARGS__ } } \
          }

/**
 * @brief Set an OSSL_FN from a little-endian array of limbs.
 *
 * Limbs of f beyond the given ones are zeroed.
 *
 * @param f the destination
 * @param words the limbs, least significant first
 * @param limbs the number of limbs in words; must not exceed f's width
 * @returns 1 on success, 0 on error
 */
int ossl_fn_set_words(OSSL_FN *f, const OSSL_FN_ULONG *words, size_t limbs);

/**
 * @brief Get the limbs of an OSSL_FN.
 *
 * @param f the number
 * @returns a pointer to f's ossl_fn_get_dsize(f) limbs, least significant
 * first, or NULL if f is NULL
 */
const OSSL_FN_ULONG *ossl_fn_get_words(const OSSL_FN *f);

/**
 * @brief Get the width of an OSSL_FN.
 *
 * @param f the number; must not be NULL
 * @returns the number of limbs
 */
size_t ossl_fn_get_dsize(const OSSL_FN *f);

/**
 * @brief Get the small-factors constant.
 *
 * The product of the primes 3..751 (see SP 800-89 5.3.3 step f), the
 * small-factors constant used by primality-related key validation.
 *
 * @returns a read-only view on static constant storage; never NULL, never to
 * be freed, cleared, or written to
 */
const OSSL_FN *ossl_fn_get0_small_factors(void);

/* doc-exempt: declared only, there is no definition */
void ossl_fn_set_negative(OSSL_FN *f, bool neg);

/* doc-exempt: declared only, there is no definition */
bool ossl_fn_is_negative(const OSSL_FN *f);

/**
 * @brief Tell whether an OSSL_FN was allocated with OSSL_FN_new() or
 * OSSL_FN_secure_new().
 *
 * @param f the number; must not be NULL
 * @returns true if f was allocated dynamically
 */
bool ossl_fn_is_dynamically_allocated(const OSSL_FN *f);

/**
 * @brief Tell whether an OSSL_FN was allocated with OSSL_FN_secure_new().
 *
 * @param f the number; must not be NULL
 * @returns true if f was allocated in secure memory
 */
bool ossl_fn_is_securely_allocated(const OSSL_FN *f);

/**
 * @brief Unsigned addition of limb arrays of any sizes: r = a + b,
 * truncated to rl limbs.
 *
 * The addition is performed at the precision of the wider operand.  See
 * crypto/fn/fn_addsub.c for the full carry contract.
 *
 * @param r the rl-limb result
 * @param rl the number of limbs in r
 * @param a the al-limb first addend
 * @param al the number of limbs in a
 * @param b the bl-limb second addend
 * @param bl the number of limbs in b
 * @returns the carry out of max(al, bl) limbs when rl <= max(al, bl);
 * otherwise the carry is absorbed into r and 0 is returned
 */
OSSL_FN_ULONG ossl_fn_add_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);

/**
 * @brief Unsigned subtraction of limb arrays of any sizes: r = a - b,
 * truncated to rl limbs.
 *
 * The subtraction is performed at the precision of the wider operand.  See
 * crypto/fn/fn_addsub.c for the full borrow contract.
 *
 * @param r the rl-limb result
 * @param rl the number of limbs in r
 * @param a the al-limb minuend
 * @param al the number of limbs in a
 * @param b the bl-limb subtrahend
 * @param bl the number of limbs in b
 * @returns the borrow out of max(al, bl) limbs when rl <= max(al, bl);
 * otherwise the borrow is propagated through r and the borrow out of rl
 * limbs is returned
 */
OSSL_FN_ULONG ossl_fn_sub_words(OSSL_FN_ULONG *r, size_t rl,
    const OSSL_FN_ULONG *a, size_t al,
    const OSSL_FN_ULONG *b, size_t bl);

/**
 * @brief Generate a DSA/ECDSA nonce 0 <= out < range, hedged against RNG
 * failure.
 *
 * The nonce mixes in |priv| and |message| alongside fresh random bytes, so an
 * RNG weakness is not fatal as long as |priv| stays secret.  This is the
 * OSSL_FN analogue of ossl_bn_gen_dsa_nonce_fixed_top().
 *
 * @param out receives the nonce; must hold at least num_bits(range) bits
 * @param range the exclusive upper bound
 * @param priv the private key
 * @param message the message
 * @param message_len the length of message in bytes
 * @param libctx used to fetch the digest and for RNG access
 * @returns 1 on success, 0 on error
 */
int ossl_fn_gen_dsa_nonce(OSSL_FN *out, const OSSL_FN *range,
    const OSSL_FN *priv, const unsigned char *message,
    size_t message_len, OSSL_LIB_CTX *libctx);

/**
 * @brief Miller-Rabin probabilistic primality test (FIPS 186-4 C.3.1, or the
 * enhanced variant C.3.2).
 *
 * @param w the candidate
 * @param iterations the number of rounds
 * @param ctx the arena, sized by ossl_fn_miller_rabin_is_prime_ctx_size()
 * @param cb the progress callback, or NULL
 * @param enhanced nonzero for the enhanced variant (C.3.2)
 * @param status receives the primality verdict (a BN_PRIMETEST_* code)
 * @param libctx the library context, for RNG access
 * @returns 1 on success (|status| is set), 0 on error
 */
int ossl_fn_miller_rabin_is_prime(const OSSL_FN *w, int iterations,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, int enhanced, int *status,
    OSSL_LIB_CTX *libctx);

/**
 * @brief Calculate the arena payload size that
 * ossl_fn_miller_rabin_is_prime() needs.
 *
 * @param w the candidate, or a width-only model of it: the nested sizing
 * functions inspect widths only
 * @returns the size, or 0 on arithmetic overflow or invalid input
 */
size_t ossl_fn_miller_rabin_is_prime_ctx_size(const OSSL_FN *w);

/**
 * @brief Test whether a number is probably prime.
 *
 * @param w the candidate
 * @param checks the number of Miller-Rabin rounds, clamped to a minimum
 * based on the candidate's size
 * @param ctx the arena, sized by ossl_fn_check_prime_ctx_size()
 * @param do_trial_division nonzero to weed out small factors first
 * @param cb the progress callback, or NULL
 * @param libctx the library context, for RNG access
 * @returns 1 when probably prime, 0 when composite, -1 on error
 */
int ossl_fn_check_prime(const OSSL_FN *w, int checks, OSSL_FN_CTX *ctx,
    int do_trial_division, BN_GENCB *cb, OSSL_LIB_CTX *libctx);

/**
 * @brief Calculate the arena payload size that ossl_fn_check_prime() needs.
 *
 * @param w the candidate; only its width is used
 * @returns the size, or 0 on arithmetic overflow or invalid input
 */
size_t ossl_fn_check_prime_ctx_size(const OSSL_FN *w);

/**
 * @brief Test whether a number is probably prime, for key generation.
 *
 * Always trial-divides.
 *
 * @param w the candidate
 * @param checks the number of Miller-Rabin rounds, used unclamped
 * @param ctx the arena, sized by ossl_fn_check_generated_prime_ctx_size()
 * @param cb the progress callback, or NULL
 * @param libctx the library context, for RNG access
 * @returns 1 when probably prime, 0 when composite, -1 on error
 */
int ossl_fn_check_generated_prime(const OSSL_FN *w, int checks,
    OSSL_FN_CTX *ctx, BN_GENCB *cb, OSSL_LIB_CTX *libctx);

/**
 * @brief Calculate the arena payload size that
 * ossl_fn_check_generated_prime() needs.
 *
 * @param w the candidate; only its width is used
 * @returns the size, or 0 on arithmetic overflow or invalid input
 */
size_t ossl_fn_check_generated_prime_ctx_size(const OSSL_FN *w);

/**
 * @brief Generate a probable prime (an RSA p or q candidate) per FIPS 186-5
 * A.1.6 (Steps 4 & 5).
 *
 * |p| and |Xpout| must have room for nlen/2 bits; one limb of headroom
 * over that width lets a carry past the width be detected rather than
 * truncated.  Internally generated auxiliary primes and random draws
 * that are not returned are cleared.
 *
 * @param p receives the prime
 * @param Xpout receives the random value the prime was derived from
 * @param p1 receives the first auxiliary prime, or NULL
 * @param p2 receives the second auxiliary prime, or NULL
 * @param Xp the starting random value, or NULL to generate one
 * @param Xp1 the starting value for the first auxiliary prime, or NULL to
 * generate one
 * @param Xp2 the starting value for the second auxiliary prime, or NULL to
 * generate one
 * @param nlen the modulus size in bits
 * @param e the public exponent
 * @param ctx the arena, sized by
 * ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size()
 * @param cb the progress callback, or NULL
 * @param c when nonzero, p is made congruent to c mod 8
 * @param libctx the library context, for RNG access
 * @returns 1 on success, 0 on error
 */
int ossl_fn_rsa_fips186_5_gen_prob_primes(OSSL_FN *p, OSSL_FN *Xpout,
    OSSL_FN *p1, OSSL_FN *p2, const OSSL_FN *Xp, const OSSL_FN *Xp1,
    const OSSL_FN *Xp2, int nlen, const OSSL_FN *e, OSSL_FN_CTX *ctx,
    BN_GENCB *cb, uint32_t c, OSSL_LIB_CTX *libctx);

/**
 * @brief Calculate the arena payload size that
 * ossl_fn_rsa_fips186_5_gen_prob_primes() needs.
 *
 * The arguments are those of the operation; |p1|, |p2|, |Xp1| and |Xp2| may
 * be NULL, as for the operation.
 *
 * @param p the prime
 * @param Xpout the random value the prime is derived from
 * @param p1 the first auxiliary prime, or NULL
 * @param p2 the second auxiliary prime, or NULL
 * @param Xp1 the starting value for the first auxiliary prime, or NULL
 * @param Xp2 the starting value for the second auxiliary prime, or NULL
 * @param nlen the modulus size in bits
 * @param e the public exponent
 * @returns the size, or 0 on arithmetic overflow or invalid input
 */
size_t ossl_fn_rsa_fips186_5_gen_prob_primes_ctx_size(const OSSL_FN *p,
    const OSSL_FN *Xpout, const OSSL_FN *p1, const OSSL_FN *p2,
    const OSSL_FN *Xp1, const OSSL_FN *Xp2, int nlen, const OSSL_FN *e);

/**
 * @brief Generate a probable prime factor per FIPS 186-5 B.9 from two
 * auxiliary primes using the Chinese Remainder Theorem.
 *
 * Same width contract as ossl_fn_rsa_fips186_5_gen_prob_primes().
 *
 * @param Y receives the prime
 * @param X receives the random value the prime was derived from
 * @param Xin the starting random value, or NULL to generate one
 * @param r1 the first auxiliary prime
 * @param r2 the second auxiliary prime
 * @param nlen the modulus size in bits
 * @param e the public exponent
 * @param ctx the arena, sized by
 * ossl_fn_rsa_fips186_5_derive_prime_ctx_size()
 * @param cb the progress callback, or NULL
 * @param c when nonzero, Y is made congruent to c mod 8
 * @param libctx the library context, for RNG access
 * @returns 1 on success, 0 on error
 */
int ossl_fn_rsa_fips186_5_derive_prime(OSSL_FN *Y, OSSL_FN *X,
    const OSSL_FN *Xin, const OSSL_FN *r1, const OSSL_FN *r2, int nlen,
    const OSSL_FN *e, OSSL_FN_CTX *ctx, BN_GENCB *cb, uint32_t c,
    OSSL_LIB_CTX *libctx);

/**
 * @brief Calculate the arena payload size that
 * ossl_fn_rsa_fips186_5_derive_prime() needs.
 *
 * @param Y the prime
 * @param X the random value the prime is derived from
 * @param r1 the first auxiliary prime
 * @param r2 the second auxiliary prime
 * @param nlen the modulus size in bits
 * @param e the public exponent
 * @returns the size, or 0 on arithmetic overflow or invalid input
 */
size_t ossl_fn_rsa_fips186_5_derive_prime_ctx_size(const OSSL_FN *Y,
    const OSSL_FN *X, const OSSL_FN *r1, const OSSL_FN *r2, int nlen,
    const OSSL_FN *e);

#ifdef __cplusplus
}
#endif

#endif
