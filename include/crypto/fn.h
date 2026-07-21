/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_FN_H
#define OPENSSL_FN_H
#pragma once

#include <stddef.h>
#include <openssl/opensslconf.h>
#include <openssl/bn_limbs.h>
#include <openssl/types.h>
#include "crypto/types.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @type OSSL_FN_ULONG is the type for the OSSL_FN limb.  It's made to be
 * compatible with BN_ULONG (quite literally).
 *
 * @def OSSL_FN_BYTES is defined with the size of OSSL_FN_ULONG, measured in
 * bytes.  This is mainly useful where 'sizeof(OSSL_FN_ULONG)' isn't suitable,
 * such as the C pre-processor.
 */

#ifdef BN_BYTES
typedef BN_ULONG OSSL_FN_ULONG;
#define OSSL_FN_BYTES BN_BYTES
#endif

#ifndef OSSL_FN_BYTES
#error "OpenSSL doesn't support large numbers on this platform"
#endif

/*
 * For practical reasons, we allow allocating OSSL_FNs in terms of limbs (what
 * the BIGNUM library calls "words"), bytes and bits.  The number of bytes and
 * bits are rounded up to the number of limbs that can fit them.
 */

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of limbs for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_limbs(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of limbs for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_limbs(size_t size);

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of bytes for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_bytes(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of bytes for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_bytes(size_t size);

/**
 * Allocate an OSSL_FN in memory.
 *
 * @param[in]   size    The number of bits for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_new_bits(size_t size);

/**
 * Allocate an OSSL_FN in secure memory.
 *
 * @param[in]   size    The number of bits for the number itself.
 *                      There's an additional few bytes allocated for bookkeeping.
 * @returns             an OSSL_FN instance.
 * @retval      NULL    on error.
 */
OSSL_FN *OSSL_FN_secure_new_bits(size_t size);

/**
 * Free an OSSL_FN instance if it was dynamically allocated.
 * Free it securely if it was allocated securely.
 *
 * @param[in]   f       The OSSL_FN instance to be freed.
 */
void OSSL_FN_free(OSSL_FN *f);

/**
 * Cleanse and free an OSSL_FN instance if it was dynamically allocated.
 * Cleanse and free it securely if it was allocated securely.
 * Merely cleanse it if it was not dynamically allocated.
 *
 * @param[in]   f       The OSSL_FN instance to be freed.
 */
void OSSL_FN_clear_free(OSSL_FN *f);

/**
 * Cleanse the data of an OSSL_FN instance, effectively making it zero.
 *
 * @param[in]   f       The OSSL_FN instance to be cleared.
 */
void OSSL_FN_clear(OSSL_FN *f);

/**
 * Set an OSSL_FN to a single-limb word value.
 *
 * @param[out]  a       The destination OSSL_FN
 * @param[in]   w       The OSSL_FN_ULONG word
 * @returns     1 on success, 0 on error
 *
 * @note Sets a->d[0] to @p w and zeroes the remaining limbs, so the full
 *       dsize array reflects the value @p w.  If a->dsize is 0 there is no
 *       limb to write and the call fails with
 *       OSSL_FN_R_RESULT_ARG_TOO_SMALL (OSSL_FN is fixed-size, so the
 *       destination cannot be grown).  The operation is constant-time with
 *       respect to @p w's value; the only branch is on the operand's public
 *       width (dsize).
 */
int OSSL_FN_set_word(OSSL_FN *a, OSSL_FN_ULONG w);

/**
 * Set an OSSL_FN to one.
 *
 * @param[out]  a       The destination OSSL_FN
 * @returns     1 on success, 0 on error
 *
 * @note Equivalent to OSSL_FN_set_word(a, 1), provided as a named function
 *       for readability at call sites.  Leak profile as for
 *       OSSL_FN_set_word().
 */
int OSSL_FN_one(OSSL_FN *a);

/**
 * Set an OSSL_FN to zero.
 *
 * @param[out]  a       The destination OSSL_FN
 * @returns     1 on success, 0 on error
 *
 * @note This is a plain value assignment, not a secure wipe; use
 *       OSSL_FN_clear() when the limbs may hold secret data and must be wiped
 *       irreversibly.  Equivalent to OSSL_FN_set_word(a, 0).  Leak profile as
 *       for OSSL_FN_set_word().
 */
int OSSL_FN_zero(OSSL_FN *a);

/**
 * Copy the contents of one OSSL_FN instance to another.
 *
 * @param[out]  a       The destination OSSL_FN
 * @param[in]   b       The source OSSL_FN
 * @returns     The destination on success, NULL on error.
 *
 * @note The destination must be at least as large as the source.
 * Any limbs beyond the source size are zeroed.
 */
OSSL_FN *OSSL_FN_copy(OSSL_FN *a, const OSSL_FN *b);

/**
 * Copy the contents of one OSSL_FN instance to another,
 * normally the shorter one, truncating the high bytes.
 *
 * @param[out]  a       The destination OSSL_FN
 * @param[in]   b       The source OSSL_FN
 * @returns     the destination.
 */
OSSL_FN *OSSL_FN_copy_truncate(OSSL_FN *a, const OSSL_FN *b);

/**
 * Calculate the arena payload size for an OSSL_FN_CTX.
 *
 * @param[in]   max_n_frames    Maximum number of simultaneously active frames.
 *                              This indicates the expected depth of call stack
 *                              that the resulting OSSL_FN_CTX will be used in.
 *                              Must be at least 1.
 * @param[in]   max_n_numbers   Maximum number of simultaneously active OSSL_FN.
 *                              Must be 0 if and only if @p max_n_limbs is 0.
 * @param[in]   max_n_limbs     Maximum number of simultaneously active OSSL_FN
 *                              limbs.  Must be 0 if and only if
 *                              @p max_n_numbers is 0.
 * @returns     The arena payload size, in bytes.
 * @retval      0               on arithmetic overflow or invalid argument.
 *
 * The returned size is the value to pass to OSSL_FN_CTX_new_size() or
 * OSSL_FN_CTX_secure_new_size().  It does not include sizeof(OSSL_FN_CTX).
 */
size_t OSSL_FN_CTX_size(size_t max_n_frames, size_t max_n_numbers,
    size_t max_n_limbs);

/**
 * Allocate a new OSSL_FN_CTX, given a set of input numbers.
 *
 * @param[in]   libctx          OpenSSL library context (currently unused)
 * @param[in]   max_n_frames    Maximum number of simultaneously active frames.
 *                              This indicates the expected depth of call stack
 *                              that the resulting OSSL_FN_CTX will be used in.
 * @param[in]   max_n_numbers   Maximum number of simultaneously active OSSL_FN.
 * @param[in]   max_n_limbs     Maximum number of simultaneously active OSSL_FN
 *                              limbs.
 * @returns     An allocated OSSL_FN_CTX, or NULL on error.
 */
OSSL_FN_CTX *OSSL_FN_CTX_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
    size_t max_n_numbers, size_t max_n_limbs);

/**
 * Allocate a new OSSL_FN_CTX with a given arena payload size.
 *
 * @param[in]   libctx          OpenSSL library context (currently unused)
 * @param[in]   size            Arena payload size in bytes, typically from
 *                              OSSL_FN_CTX_size().  A size of 0 is the error
 *                              return of OSSL_FN_CTX_size() and is treated as
 *                              an error here too.
 * @returns     An allocated OSSL_FN_CTX, or NULL on error.
 */
OSSL_FN_CTX *OSSL_FN_CTX_new_size(OSSL_LIB_CTX *libctx, size_t size);

/**
 * Allocate a new OSSL_FN_CTX in secure memory, given a set of input numbers.
 * Other than allocating in secure memory, this function does exactly the same
 * thing as OSSL_FN_CTX_new().
 */
OSSL_FN_CTX *OSSL_FN_CTX_secure_new(OSSL_LIB_CTX *libctx, size_t max_n_frames,
    size_t max_n_numbers, size_t max_n_limbs);

/**
 * Allocate a new OSSL_FN_CTX in secure memory with a given arena payload size.
 *
 * @param[in]   libctx          OpenSSL library context (currently unused)
 * @param[in]   size            Arena payload size in bytes, typically from
 *                              OSSL_FN_CTX_size().  A size of 0 is treated as
 *                              an error, as in OSSL_FN_CTX_new_size().
 * @returns     An allocated OSSL_FN_CTX, or NULL on error.
 */
OSSL_FN_CTX *OSSL_FN_CTX_secure_new_size(OSSL_LIB_CTX *libctx, size_t size);

/**
 * Report the peak number of frames, numbers, and limbs that were
 * simultaneously active during the lifetime of the OSSL_FN_CTX.
 * This can be used to determine suitable arena parameters for a
 * given workload.
 *
 * @param[in]   ctx             The OSSL_FN_CTX to query.  This may be NULL.
 * @param[out]  peak_n_frames   Peak number of simultaneously active frames
 * @param[out]  peak_n_numbers  Peak number of simultaneously active OSSL_FNs
 * @param[out]  peak_n_limbs    Peak total limbs across all active OSSL_FNs
 *
 * Any of the out parameters may be NULL.  If ctx is NULL, all out
 * parameters that are non-NULL are set to 0.
 */
void OSSL_FN_CTX_peak_usage(const OSSL_FN_CTX *ctx, size_t *peak_n_frames,
    size_t *peak_n_numbers, size_t *peak_n_limbs);

/**
 * Free an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to be freed.  This may be NULL.
 */
void OSSL_FN_CTX_free(OSSL_FN_CTX *ctx);

/**
 * Start a new OSSL_FN_CTX frame.  This *must* be called by any function
 * that wants to get a temporary OSSL_FN from the OSSL_FN_CTX.  The function
 * call this must also clean up with a OSSL_FN_CTX_end() call.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to start the frame in.
 * @returns     Ownership token of the started frame, NULL on error.
 *              This token must be passed to OSSL_FN_CTX_end().
 */
const void *OSSL_FN_CTX_start(OSSL_FN_CTX *ctx);

/**
 * End the last OSSL_FN_CTX frame, resetting back to the previous
 * frame.  If a function called OSSL_FN_CTX_start(), it *must* call
 * this function before returning.
 *
 * @param[in]   ctx     The OSSL_FN_CTX to start the frame in.
 * @param[in]   token   Ownership token returned by OSSL_FN_CTX_start().
 * @returns     1 on success, 0 on error.
 *
 * @note The token parameter is validated but not used for choosing a
 * frame; only the most recent frame can be ended. Passing an incorrect
 * token indicates a programming error and the function will fail.
 * If NULL is passed, nothing will be done but the function will return 1.
 */
int OSSL_FN_CTX_end(OSSL_FN_CTX *ctx, const void *token);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of limbs.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_limbs(OSSL_FN_CTX *ctx, size_t limbs);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of bytes.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_bytes(OSSL_FN_CTX *ctx, size_t bytes);

/**
 * Get a suitably sized OSSL_FN from an OSSL_FN_CTX.
 *
 * @param[in]   ctx     The OSSL_FN_CTX
 * @param[in]   limbs   The desired size of the resulting OSSL_FN,
 *                      in number of bits.
 * @returns     an OSSL_FN pointer on success, NULL on error.
 */
OSSL_FN *OSSL_FN_CTX_get_bits(OSSL_FN_CTX *ctx, size_t bits);

/*
 * Arithmetic functions treat the OSSL_FN 'd' array as a large 2's complement
 * unsigned integer, least significant limb first.  All carrys or borrows are
 * extended in the result and otherwise ignored.  This makes OSSL_FN functions
 * act just like operations on C unsigned integer types, but at a larger scale.
 */

/**
 * Return the number of significant bits in an OSSL_FN number.
 *
 * @param[in]           a       The operand
 * @returns             The number of significant bits, or zero if a is zero
 */
size_t OSSL_FN_num_bits(const OSSL_FN *a);

/**
 * Compare two OSSL_FN numbers as unsigned integers.
 *
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @returns             1 if a > b, -1 if a < b, 0 if a == b
 */
int OSSL_FN_cmp(const OSSL_FN *a, const OSSL_FN *b);

/**
 * Test whether bit @p n is set in @p a.
 *
 * @param[in]           a       The operand
 * @param[in]           n       The bit index (0 = least significant)
 * @returns             1 if bit @p n of @p a is set, 0 otherwise.
 *
 * @note An out-of-range index (n < 0 or n >= the operand's width in bits)
 *       reads as 0.  The only control flow branches on the operand's public
 *       width (its dsize), not on limb values; the returned value is the bit
 *       itself, which is the information the caller asked for.
 */
int OSSL_FN_is_bit_set(const OSSL_FN *a, int n);

/**
 * Test whether the unsigned value of @p a equals the single-limb word @p w.
 *
 * @param[in]           a       The operand
 * @param[in]           w       The OSSL_FN_ULONG word to compare against
 * @returns             1 if the unsigned value of @p a equals @p w, 0 otherwise
 *
 * @note Control flow branches only on the operand's public width (its dsize),
 *       not on limb values; the returned value is the equality test the caller
 *       asked for.
 */
int OSSL_FN_is_word(const OSSL_FN *a, OSSL_FN_ULONG w);

/**
 * Test whether @p a is zero.
 *
 * @param[in]           a       The operand
 * @returns             1 if @p a is zero, 0 otherwise
 *
 * @note Equivalent to OSSL_FN_is_word(a, 0), provided as a named predicate for
 *       readability at call sites.  Leak profile as for OSSL_FN_is_word():
 *       branches only on the operand's public width (its dsize).
 */
int OSSL_FN_is_zero(const OSSL_FN *a);

/**
 * Test whether @p a is one.
 *
 * @param[in]           a       The operand
 * @returns             1 if @p a is one, 0 otherwise
 *
 * @note Equivalent to OSSL_FN_is_word(a, 1), provided as a named predicate for
 *       readability at call sites.  Leak profile as for OSSL_FN_is_word():
 *       branches only on the operand's public width (its dsize).
 */
int OSSL_FN_is_one(const OSSL_FN *a);

/**
 * Test whether @p a is odd.
 *
 * @param[in]           a       The operand
 * @returns             the least significant bit of @p a (1 if odd, 0 if even)
 *
 * @note The only control flow branches on the operand's public width (its
 *       dsize), not on limb values; the returned value is the bit itself,
 *       which is the information the caller asked for.
 */
int OSSL_FN_is_odd(const OSSL_FN *a);

/*-
 * Top/bottom selectors for OSSL_FN_rand() / OSSL_FN_priv_rand().  These are
 * caller-chosen public parameters (not secrets); OSSL_FN_rand() branches on
 * them to shape the top and bottom bits of the result.  Each TOP_* value is
 * the number of high bits to force to 1 (0 = unconstrained, 1, 2), matching
 * the BOTTOM_* numbering (0 = unconstrained, 1 = force the low bit).
 */
#define OSSL_FN_RAND_TOP_ANY 0
#define OSSL_FN_RAND_TOP_ONE 1
#define OSSL_FN_RAND_TOP_TWO 2
#define OSSL_FN_RAND_BOTTOM_ANY 0
#define OSSL_FN_RAND_BOTTOM_ODD 1

/**
 * Fill @p rnd with @p bits random bits.
 *
 * @param[out]          rnd     The OSSL_FN for the result
 * @param[in]           bits    The number of random bits to generate
 * @param[in]           top     Top-bit selector (OSSL_FN_RAND_TOP_*)
 * @param[in]           bottom  Bottom-bit selector (OSSL_FN_RAND_BOTTOM_*)
 * @param[in]           strength The private strength of the generated bytes
 * @param[in]           libctx  The OpenSSL library context (for the DRBG)
 * @returns             1 on success, 0 on error
 *
 * Draws from the public DRBG pool via RAND_bytes_ex().  The library context
 * is taken directly as @p libctx.  The random bytes are drawn straight into
 * rnd->d (no intermediate buffer) and the top/bottom/mask constraints are
 * applied as limb value operations; a @p rnd too small for @p bits is
 * reported as OSSL_FN_R_RESULT_ARG_TOO_SMALL rather than grown.  Leak
 * profile as for OSSL_FN_priv_rand().
 */
int OSSL_FN_rand(OSSL_FN *rnd, size_t bits, int top, int bottom,
    size_t strength, OSSL_LIB_CTX *libctx);

/**
 * Fill @p rnd with @p bits random bits from the private DRBG pool.
 *
 * @param[out]          rnd     The OSSL_FN for the result
 * @param[in]           bits    The number of random bits to generate
 * @param[in]           top     Top-bit selector (OSSL_FN_RAND_TOP_*)
 * @param[in]           bottom  Bottom-bit selector (OSSL_FN_RAND_BOTTOM_*)
 * @param[in]           strength The private strength of the generated bytes
 * @param[in]           libctx  The OpenSSL library context (for the DRBG)
 * @returns             1 on success, 0 on error
 *
 * Draws from the private (non-forward-linkable) DRBG pool via
 * RAND_priv_bytes_ex().  This is the private counterpart of OSSL_FN_rand();
 * the public/private pool selection is exposed as separate functions rather
 * than a flag argument.  Control flow branches only on @p bits, @p top,
 * @p bottom (all caller-chosen, public) and on the byte-draw return value,
 * never on the random bytes themselves; the returned value is the random
 * number the caller asked for.
 *
 * @note See ossl_fn_rand() in crypto/fn/fn_rand.c for the byte-to-limb
 *       shaping mechanics.
 */
int OSSL_FN_priv_rand(OSSL_FN *rnd, size_t bits, int top, int bottom,
    size_t strength, OSSL_LIB_CTX *libctx);

/**
 * Generate 0 <= r < range.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           range   The exclusive upper bound (must be non-zero)
 * @param[in]           strength The private strength of the generated bytes
 * @param[in]           libctx  The OpenSSL library context (for the DRBG)
 * @returns             1 on success, 0 on error
 *
 * Draws from the public DRBG pool.  OSSL_FN is unsigned, so no sign
 * rejection is performed.  The loop iteration count leaks the magnitude of
 * @p range via OSSL_FN_num_bits() and the rejection probability.
 *
 * The destination @p r must be sized to hold at least
 * OSSL_FN_num_bits(@p range) bits.  Sizing @p r to hold one extra bit
 * (OSSL_FN_num_bits(@p range) + 1) additionally enables the optimized
 * "range = 100..._2" path, which draws n + 1 bits; an exactly-sized @p r
 * (room for exactly OSSL_FN_num_bits(@p range) bits) uses standard n-bit
 * rejection sampling instead.  An @p r too small for
 * OSSL_FN_num_bits(@p range) bits fails with OSSL_FN_R_RESULT_ARG_TOO_SMALL.
 */
int OSSL_FN_rand_range(OSSL_FN *r, const OSSL_FN *range, size_t strength,
    OSSL_LIB_CTX *libctx);

/**
 * Generate 0 <= r < range from the private DRBG pool.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           range   The exclusive upper bound (must be non-zero)
 * @param[in]           strength The private strength of the generated bytes
 * @param[in]           libctx  The OpenSSL library context (for the DRBG)
 * @returns             1 on success, 0 on error
 *
 * Draws from the private DRBG pool.  Leak profile and destination sizing
 * as for OSSL_FN_rand_range().
 */
int OSSL_FN_priv_rand_range(OSSL_FN *r, const OSSL_FN *range,
    size_t strength, OSSL_LIB_CTX *libctx);

/**
 * Shift an OSSL_FN number left by n bits.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           n       The number of bits to shift
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_lshift(OSSL_FN *r, const OSSL_FN *a, int n);

/**
 * Shift an OSSL_FN number left by one bit.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_lshift1(OSSL_FN *r, const OSSL_FN *a);

/**
 * Shift an OSSL_FN number right by n bits.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           n       The number of bits to shift
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_rshift(OSSL_FN *r, const OSSL_FN *a, int n);

/**
 * Shift an OSSL_FN number right by one bit.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_rshift1(OSSL_FN *r, const OSSL_FN *a);

/**
 * Add two OSSL_FN numbers.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b);

/**
 * Add an OSSL_FN_ULONG word to an OSSL_FN numbers.
 *
 * @param[in,out]       a       The OSSL_FN to add the word to
 * @param[in]           w       The OSSL_FN_ULONG word
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_add_word(OSSL_FN *a, OSSL_FN_ULONG w);

/**
 * Subtract two OSSL_FN numbers.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b);

/**
 * Subtract an OSSL_FN_ULONG word from an OSSL_FN numbers.
 *
 * @param[in,out]       a       The OSSL_FN to subtract the word from
 * @param[in]           w       The OSSL_FN_ULONG word
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_sub_word(OSSL_FN *a, OSSL_FN_ULONG w);

/**
 * Multiply two OSSL_FN numbers.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with res->dsize limbs, plus one frame
 * (currently 32 bytes).
 */
int OSSL_FN_mul(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mul() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mul().
 */
size_t OSSL_FN_mul_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b);

/**
 * Divide two OSSL_FN numbers.  Truncates the result to fit in q and r.
 *
 * @param[out]          q       The OSSL_FN for the quotient
 * @param[out]          r       The OSSL_FN for the remainder
 * @param[in]           n       The first operand (numerator)
 * @param[in]           d       The second operand (denominator)
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for:
 *   one OSSL_FN with ((n->dsize <= d->dsize) ? d->dsize : n->dsize) + 1 limbs
 *   one OSSL_FN with d->dsize limbs
 *   one OSSL_FN with d->dsize + 1 limbs
 *   one OSSL_FN with n->dsize limbs
 *   one frame (currently 32 bytes).
 * Note that this provides an upper bound.  Actual use of the arena may be
 * smaller - see OSSL_FN_div_ctx_size() for an exact, conditional value.
 */
int OSSL_FN_div(OSSL_FN *q, OSSL_FN *r, const OSSL_FN *n, const OSSL_FN *d,
    OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_div() needs.
 *
 * @param[in]           q       The OSSL_FN for the quotient, or NULL when
 *                              only the remainder is of interest.
 * @param[in]           r       The OSSL_FN for the remainder
 * @param[in]           n       The first operand (numerator)
 * @param[in]           d       The second operand (denominator)
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_div().
 * When q is NULL, the size is computed for the modulo case, i.e. as if
 * only the remainder is produced.
 */
size_t OSSL_FN_div_ctx_size(const OSSL_FN *q, const OSSL_FN *r,
    const OSSL_FN *n, const OSSL_FN *d);

/**
 * Add two OSSL_FN numbers modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with max(a->dsize, b->dsize) + 1
 * limbs, plus the requirements of OSSL_FN_mod(), plus one frame
 * (currently 32 bytes).
 */
int OSSL_FN_mod_add(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_add() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_add().
 */
size_t OSSL_FN_mod_add_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m);

/**
 * Add two OSSL_FN numbers modulo m.  This is a quick variant that may be
 * used if both a and b are less than m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_mod_add_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m);

/**
 * Subtract two OSSL_FN numbers modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for two temporary OSSL_FNs with m->dsize limbs each, plus an
 * additional temporary OSSL_FN with m->dsize limbs if r == m, plus the
 * requirements of OSSL_FN_mod(), plus one frame (currently 32 bytes).
 */
int OSSL_FN_mod_sub(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_sub() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_sub().
 */
size_t OSSL_FN_mod_sub_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m);

/**
 * Subtract two OSSL_FN numbers modulo m.  This is a quick variant that may
 * be used if a is less than m and b is of the same bit width as m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_mod_sub_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m);

/**
 * Multiply two OSSL_FN numbers modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with a->dsize + b->dsize limbs
 * (or 2 * a->dsize limbs if a == b), plus the largest of the
 * requirements of OSSL_FN_mul(), OSSL_FN_sqr(), and OSSL_FN_mod(),
 * plus one frame (currently 32 bytes).
 */
int OSSL_FN_mod_mul(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *b,
    const OSSL_FN *m, OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_mul() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The first operand
 * @param[in]           b       The second operand
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_mul().
 */
size_t OSSL_FN_mod_mul_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *b, const OSSL_FN *m);

/**
 * Square an OSSL_FN number modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with 2 * a->dsize limbs, plus the
 * larger of the requirements of OSSL_FN_sqr() and OSSL_FN_mod(),
 * plus one frame (currently 32 bytes).
 */
int OSSL_FN_mod_sqr(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m,
    OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_sqr() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_sqr().
 */
size_t OSSL_FN_mod_sqr_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *m);

/**
 * Left shift an OSSL_FN number by 1 bit, modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with m->dsize + 1 limbs, plus the
 * requirements of OSSL_FN_mod(), plus one frame (currently 32 bytes).
 */
int OSSL_FN_mod_lshift1(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m,
    OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_lshift1() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by
 * OSSL_FN_mod_lshift1().
 */
size_t OSSL_FN_mod_lshift1_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    const OSSL_FN *m);

/**
 * Left shift an OSSL_FN number by 1 bit, modulo m.  This is a quick
 * variant that may be used if a is less than m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           m       The modulus
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_mod_lshift1_quick(OSSL_FN *r, const OSSL_FN *a, const OSSL_FN *m);

/**
 * Left shift an OSSL_FN number by n bits, modulo m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           n       The number of bits to shift
 * @param[in]           m       The modulus
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for one temporary OSSL_FN with m->dsize limbs, plus the
 * requirements of OSSL_FN_mod(), plus one frame (currently 32 bytes).
 */
int OSSL_FN_mod_lshift(OSSL_FN *r, const OSSL_FN *a, int n, const OSSL_FN *m,
    OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_mod_lshift() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           n       The number of bits to shift
 * @param[in]           m       The modulus
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod_lshift().
 */
size_t OSSL_FN_mod_lshift_ctx_size(const OSSL_FN *r, const OSSL_FN *a,
    int n, const OSSL_FN *m);

/**
 * Left shift an OSSL_FN number by n bits, modulo m.  This is a quick
 * variant that may be used if a is less than m.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           n       The number of bits to shift
 * @param[in]           m       The modulus
 * @returns             1 on success, 0 on error
 */
int OSSL_FN_mod_lshift_quick(OSSL_FN *r, const OSSL_FN *a, int n,
    const OSSL_FN *m);

/**
 * Calculate modulo of two OSSL_FN numbers.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the remainder
 * @param[in]           n       The first operand (numerator)
 * @param[in]           d       The second operand (denominator)
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function has the same requirements on ctx as OSSL_FN_div().
 */
static inline int OSSL_FN_mod(OSSL_FN *r, const OSSL_FN *n, const OSSL_FN *d,
    OSSL_FN_CTX *ctx)
{
    return OSSL_FN_div(NULL, r, n, d, ctx);
}

/**
 * Calculate the arena payload size that OSSL_FN_mod() needs.
 *
 * @param[in]           r       The OSSL_FN for the remainder
 * @param[in]           n       The numerator
 * @param[in]           d       The denominator
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_mod().
 * This is a thin wrapper around OSSL_FN_div_ctx_size() with a NULL
 * quotient, since OSSL_FN_mod() is itself a wrapper around OSSL_FN_div().
 */
static inline size_t OSSL_FN_mod_ctx_size(const OSSL_FN *r,
    const OSSL_FN *n, const OSSL_FN *d)
{
    return OSSL_FN_div_ctx_size(NULL, r, n, d);
}

/**
 * Calculate the square of one OSSL_FN number.  Truncates the result to fit in r.
 *
 * @param[out]          r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @param[in]           ctx     A context to get temporary OSSL_FN
 *                              instances from.
 * @returns             1 on success, 0 on error
 *
 * @note This function currently requires that the OSSL_FN_CTX has free
 * space for two temporary OSSL_FNs, a->dsize * 2 limbs each, plus one
 * frame (currently 32 bytes).
 */
int OSSL_FN_sqr(OSSL_FN *r, const OSSL_FN *a, OSSL_FN_CTX *ctx);

/**
 * Calculate the arena payload size that OSSL_FN_sqr() needs.
 *
 * @param[in]           r       The OSSL_FN for the result
 * @param[in]           a       The operand
 * @returns             The arena payload size, in bytes.
 * @retval              0       on arithmetic overflow or invalid input.
 *
 * The returned size includes any frame budget needed by OSSL_FN_sqr().
 */
size_t OSSL_FN_sqr_ctx_size(const OSSL_FN *r, const OSSL_FN *a);

#ifdef __cplusplus
}
#endif

#endif
