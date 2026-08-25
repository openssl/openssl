/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdbool.h>
#include <limits.h>
#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include "internal/common.h"
#include "crypto/fn_constants.h"
#include "crypto/fnerr.h"
#include "../bn/bn_local.h" /* For BN_LLONG / BN_ULLONG */
#include "fn_local.h"
#include "internal/constant_time.h"

static OSSL_FN *ossl_fn_new_internal(size_t limbs, bool securely)
{
    /* Total size of the whole OSSL_FN, in bytes */
    size_t totalsize = ossl_fn_totalsize(limbs);
    if (totalsize == 0)
        return NULL;

    OSSL_FN *ret = NULL;

    if (securely)
        ret = OPENSSL_secure_zalloc(totalsize);
    else
        ret = OPENSSL_zalloc(totalsize);

    if (ret != NULL) {
        ret->dsize = (int)limbs;
        ret->is_dynamically_allocated = 1;
        ret->is_securely_allocated = securely;
    }
    return ret;
}

static void ossl_fn_free_internal(OSSL_FN *f, bool clear)
{
    if (f == NULL)
        return;

    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);
    size_t totalsize = limbssize + sizeof(OSSL_FN);

    if (f->is_dynamically_allocated) {
        if (f->is_securely_allocated)
            OPENSSL_secure_clear_free(f, totalsize);
        else if (clear)
            OPENSSL_clear_free(f, totalsize);
        else
            OPENSSL_free(f);
    } else if (clear) {
        OPENSSL_cleanse(f->d, limbssize);
    }
}

OSSL_FN *OSSL_FN_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, false);
}

OSSL_FN *OSSL_FN_secure_new_limbs(size_t size)
{
    return ossl_fn_new_internal(size, true);
}

OSSL_FN *OSSL_FN_new_bytes(size_t size)
{
    return OSSL_FN_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_secure_new_bytes(size_t size)
{
    return OSSL_FN_secure_new_limbs(ossl_fn_bytes_to_limbs(size));
}

OSSL_FN *OSSL_FN_new_bits(size_t size)
{
    return OSSL_FN_new_bytes(ossl_fn_bits_to_bytes(size));
}

OSSL_FN *OSSL_FN_secure_new_bits(size_t size)
{
    return OSSL_FN_secure_new_bytes(ossl_fn_bits_to_bytes(size));
}

void OSSL_FN_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, false);
}

void OSSL_FN_clear_free(OSSL_FN *f)
{
    ossl_fn_free_internal(f, true);
}

void OSSL_FN_clear(OSSL_FN *f)
{
    size_t limbssize = f->dsize * sizeof(OSSL_FN_ULONG);

    OPENSSL_cleanse(f->d, limbssize);
}

/*-
 * Sets a->d[0] to |w| and zeroes the remaining limbs, so the full dsize
 * array reflects the value |w|.  OSSL_FN is fixed-size: if a->dsize is 0
 * there is no limb to write and the call fails with
 * OSSL_FN_R_RESULT_ARG_TOO_SMALL (the same reason ossl_fn_set_words() raises
 * for an undersized destination).
 *
 * Constant-time with respect to |w|'s value: there is no value-dependent
 * control flow, since the full dsize array always holds the value.  The only
 * branch is on the operand's public width (dsize).
 */
int OSSL_FN_set_word(OSSL_FN *a, OSSL_FN_ULONG w)
{
    size_t dsize = (size_t)a->dsize;

    if (ossl_unlikely(dsize < 1)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }

    a->d[0] = w;
    if (dsize > 1)
        memset(&a->d[1], 0, sizeof(OSSL_FN_ULONG) * (dsize - 1));
    return 1;
}

/*-
 * Equivalent to OSSL_FN_set_word(a, 1).  Kept as a named function rather
 * than a macro or static inline, consistent with the rest of
 * crypto/fn/fn_lib.c.  Leak profile as for OSSL_FN_set_word().
 */
int OSSL_FN_one(OSSL_FN *a)
{
    return OSSL_FN_set_word(a, OSSL_FN_ULONG_C(1));
}

/*-
 * Equivalent to OSSL_FN_set_word(a, 0).  This is a plain value assignment,
 * not a secure wipe: the compiler may optimise the writes away if the value
 * is not subsequently observed.  Use OSSL_FN_clear() (which calls
 * OPENSSL_cleanse()) when the limbs may hold secret data and must be wiped
 * irreversibly.  Leak profile as for OSSL_FN_set_word().
 */
int OSSL_FN_zero(OSSL_FN *a)
{
    return OSSL_FN_set_word(a, OSSL_FN_ULONG_C(0));
}

/* The literal 1, backing OSSL_FN_value_one() */
OSSL_FN_STATIC_DEFINE(one, 1, 1);

const OSSL_FN *OSSL_FN_value_one(void)
{
    return &ossl_fn_static_one_storage.fn;
}

static size_t ossl_fn_num_bits_word(OSSL_FN_ULONG l)
{
    OSSL_FN_ULONG x, mask;
    size_t bits = (size_t)constant_time_select_int(
        (unsigned int)constant_time_is_zero_bn(l), 0, 1);

#if OSSL_FN_BITS > 32
    x = l >> 32;
    mask = ~constant_time_is_zero_bn(x);
    bits += 32 & (size_t)mask;
    l ^= (x ^ l) & mask;
#endif

    x = l >> 16;
    mask = ~constant_time_is_zero_bn(x);
    bits += 16 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = ~constant_time_is_zero_bn(x);
    bits += 8 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = ~constant_time_is_zero_bn(x);
    bits += 4 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = ~constant_time_is_zero_bn(x);
    bits += 2 & (size_t)mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = ~constant_time_is_zero_bn(x);
    bits += 1 & (size_t)mask;

    return bits;
}

size_t OSSL_FN_num_bits(const OSSL_FN *a)
{
    size_t i;
    size_t dsize = (size_t)a->dsize;
    size_t ret = 0;

    for (i = 0; i < dsize; i++) {
        size_t limb_bits = ossl_fn_num_bits_word(a->d[i]);
        size_t bits = i * OSSL_FN_BITS + limb_bits;
        size_t mask = (size_t)~constant_time_is_zero_bn(a->d[i]);

        ret = constant_time_select_s(mask, bits, ret);
    }

    return ret;
}

int OSSL_FN_cmp(const OSSL_FN *a, const OSSL_FN *b)
{
    size_t i;
    size_t asize = (size_t)a->dsize;
    size_t bsize = (size_t)b->dsize;
    size_t max = asize > bsize ? asize : bsize;
    int res = 0;

    for (i = 0; i < max; i++) {
        OSSL_FN_ULONG aw = i < asize ? a->d[i] : 0;
        OSSL_FN_ULONG bw = i < bsize ? b->d[i] : 0;

        res = constant_time_select_int(
            (unsigned int)constant_time_lt_bn(aw, bw), -1, res);
        res = constant_time_select_int(
            (unsigned int)constant_time_lt_bn(bw, aw), 1, res);
    }

    return res;
}

/*-
 * Returns bit |n| of |a|.  An out-of-range index (n >= the operand's width
 * in bits) reads as 0.  The only control flow branches on the operand's
 * public width (dsize); the returned value is the bit itself, which is the
 * information the caller asked for.
 */
int OSSL_FN_is_bit_set(const OSSL_FN *a, size_t n)
{
    size_t limb, off;

    limb = n / OSSL_FN_BITS;
    off = n % OSSL_FN_BITS;
    if (limb >= (size_t)a->dsize)
        return 0;
    return (a->d[limb] >> off) & OSSL_FN_ULONG_C(1);
}

/*-
 * Clears bit |n| of |a|.  An out-of-range index (n >= the operand's width
 * in bits) leaves |a| unchanged and fails with OSSL_FN_R_RESULT_ARG_TOO_SMALL;
 * OSSL_FN is fixed-size, so the operand cannot be grown to reach |n|.  The
 * only control flow branches on the operand's public width (dsize) and on
 * the caller-chosen index |n|, not on limb values; whether the bit was
 * previously set is not revealed.
 */
int OSSL_FN_clear_bit(OSSL_FN *a, size_t n)
{
    size_t limb, off;

    limb = n / OSSL_FN_BITS;
    off = n % OSSL_FN_BITS;
    if (limb >= (size_t)a->dsize) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }
    a->d[limb] &= ~(OSSL_FN_ULONG_C(1) << off);
    return 1;
}

/*-
 * Returns 1 if the unsigned value of |a| equals the single-limb word |w|.
 * Control flow branches only on the operand's public width (dsize); limb
 * values are combined with constant-time selects, so the number of limbs
 * inspected depends only on the public width, not on the operand's value.
 * The returned value is the equality test the caller asked for.
 */
int OSSL_FN_is_word(const OSSL_FN *a, OSSL_FN_ULONG w)
{
    size_t i;
    size_t dsize = (size_t)a->dsize;
    int res;

    if (dsize == 0)
        return w == 0;

    res = constant_time_select_int(
        (unsigned int)constant_time_eq_bn(a->d[0], w), 1, 0);
    for (i = 1; i < dsize; i++)
        res = constant_time_select_int(
            (unsigned int)constant_time_is_zero_bn(a->d[i]), res, 0);
    return res;
}

/*-
 * Equivalent to OSSL_FN_is_word(a, 0), kept as a named predicate for
 * readability at call sites.  Leak profile as for OSSL_FN_is_word():
 * branches only on the operand's public width (dsize).
 */
int OSSL_FN_is_zero(const OSSL_FN *a)
{
    return OSSL_FN_is_word(a, 0);
}

/*-
 * Equivalent to OSSL_FN_is_word(a, 1), kept as a named predicate for
 * readability at call sites.  Leak profile as for OSSL_FN_is_word():
 * branches only on the operand's public width (dsize).
 */
int OSSL_FN_is_one(const OSSL_FN *a)
{
    return OSSL_FN_is_word(a, 1);
}

/*-
 * Returns the least significant bit of |a|, which is the information the
 * caller asked for.  The only control flow branches on the operand's public
 * width (dsize), not on limb values.
 */
int OSSL_FN_is_odd(const OSSL_FN *a)
{
    if (a->dsize <= 0)
        return 0;
    return (int)(a->d[0] & OSSL_FN_ULONG_C(1));
}

/*-
 * Conditionally swap |a| and |b| if |condition| is non-zero.
 * Both operands must be the same width.
 *
 * Constant-time profile: |condition| is folded into an all-ones or all-zeros
 * mask, and every limb of both operands is written unconditionally, so
 * neither the condition nor the limb values steer control flow.  The only
 * branches are on the operands' public width.
 */
int OSSL_FN_consttime_swap(int condition, OSSL_FN *a, OSSL_FN *b)
{
    size_t i, dsize;
    OSSL_FN_ULONG mask;

    if (ossl_unlikely(a == b))
        return 1;

    /*
     * Swapping only the limbs the two have in common would leave the wider
     * operand holding a mix of both values, so a width mismatch is an error
     * rather than a partial swap.
     */
    if (ossl_unlikely(a->dsize != b->dsize)) {
        ERR_raise_data(ERR_LIB_OSSL_FN, OSSL_FN_R_MISMATCHED_WIDTHS,
            "Both operands must be the same width, but they are %zu bytes "
            "and %zu bytes",
            (size_t)a->dsize * sizeof(OSSL_FN_ULONG),
            (size_t)b->dsize * sizeof(OSSL_FN_ULONG));
        return 0;
    }

    /* All ones when condition is non-zero, all zeros when it is zero. */
    mask = ~constant_time_is_zero_bn((OSSL_FN_ULONG)condition);
    dsize = (size_t)a->dsize;

    for (i = 0; i < dsize; i++) {
        OSSL_FN_ULONG t = a->d[i];

        a->d[i] = constant_time_select_bn(mask, b->d[i], t);
        b->d[i] = constant_time_select_bn(mask, t, b->d[i]);
    }

    return 1;
}

/*-
 * Returns the least significant limb of |a| (0 when |a| has no limbs), which
 * is the information the caller asked for.  The only control flow branches
 * on the operand's public width (dsize), not on limb values.
 */
OSSL_FN_ULONG OSSL_FN_get_word(const OSSL_FN *a)
{
    if (a->dsize <= 0)
        return 0;
    return a->d[0];
}

/*-
 * Set bit |pos| (0 = least significant) of |a|, by absolute position.  No
 * expansion: an out-of-range position (|pos| >= the operand's width in bits)
 * is an error, not an implicit grow.  The only control flow branches on the
 * operand's public width (dsize), not on limb values.
 */
int OSSL_FN_set_bit(OSSL_FN *a, size_t pos)
{
    size_t limb = pos / OSSL_FN_BITS;
    size_t off = pos % OSSL_FN_BITS;

    if (limb >= (size_t)a->dsize) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }
    a->d[limb] |= OSSL_FN_ULONG_C(1) << off;
    return 1;
}

/*-
 * Compute |a| mod |w| for a single-limb word |w|.
 *
 * Returns (OSSL_FN_ULONG)-1 when |w| is 0 (the error sentinel), matching the
 * BN counterpart's convention.  Control flow branches only on the operand's
 * public width (dsize), not on limb values; the reduction itself is the
 * arithmetic the caller asked for.
 */
OSSL_FN_ULONG OSSL_FN_mod_word(const OSSL_FN *a, OSSL_FN_ULONG w)
{
    size_t i;

    if (w == 0)
        return (OSSL_FN_ULONG)-1;

#ifdef BN_LLONG
    {
        BN_ULLONG ret = 0;

        for (i = (size_t)a->dsize; i-- > 0;)
            ret = (BN_ULLONG)(((ret << (BN_ULLONG)OSSL_FN_BITS) | a->d[i])
                % (BN_ULLONG)w);
        return (OSSL_FN_ULONG)ret;
    }
#else
    if (w <= OSSL_FN_LOW_HALF_MASK) {
        /*
         * Fast path: reduce one half-limb at a time.  With |w| fitting in a
         * half-limb, the running remainder is smaller than |w| and the
         * shifts cannot overflow.
         */
        OSSL_FN_ULONG ret = 0;

        for (i = (size_t)a->dsize; i-- > 0;) {
            ret = ((ret << (OSSL_FN_BITS / 2))
                      | ((a->d[i] >> (OSSL_FN_BITS / 2)) & OSSL_FN_LOW_HALF_MASK))
                % w;
            ret = ((ret << (OSSL_FN_BITS / 2)) | (a->d[i] & OSSL_FN_LOW_HALF_MASK))
                % w;
        }
        return ret;
    } else {
        /*
         * Slow path for a wide |w| without a double-width type: reduce one
         * bit at a time, doubling modulo |w| without overflow (the running
         * remainder is always smaller than |w|).  The conditional
         * reduction steps are constant-time masks, not branches, so limb
         * values never affect control flow.
         */
        OSSL_FN_ULONG ret = 0;
        int bit;

        for (i = (size_t)a->dsize; i-- > 0;)
            for (bit = OSSL_FN_BITS - 1; bit >= 0; bit--) {
                /* 2 * ret >= w  iff  ret >= w - ret */
                OSSL_FN_ULONG over = ~constant_time_lt_bn(ret, w - ret);

                ret = constant_time_select_bn(over, ret - (w - ret),
                    ret + ret);
                ret += (a->d[i] >> bit) & 1;
                ret = constant_time_select_bn(constant_time_eq_bn(ret, w),
                    0, ret);
            }
        return ret;
    }
#endif
}

OSSL_FN *OSSL_FN_copy(OSSL_FN *a, const OSSL_FN *b)
{
    if (ossl_unlikely(a == b))
        return a;

    size_t al = a->dsize;
    size_t bl = b->dsize;

    if (al < bl) {
        ERR_raise_data(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL,
            "Needs to be at least %zu bytes, but is only %zu bytes",
            bl * sizeof(OSSL_FN_ULONG), al * sizeof(OSSL_FN_ULONG));
        return 0;
    }

    memcpy(a->d, b->d, bl * sizeof(OSSL_FN_ULONG));
    memset(a->d + bl, 0, (al - bl) * sizeof(OSSL_FN_ULONG));
    return a;
}

OSSL_FN *OSSL_FN_copy_truncate(OSSL_FN *a, const OSSL_FN *b)
{
    if (ossl_unlikely(a == b))
        return a;

    size_t al = a->dsize;
    size_t bl = b->dsize;

    if (ossl_unlikely(al > bl)) {
        memcpy(a->d, b->d, bl * sizeof(OSSL_FN_ULONG));
        memset(&a->d[bl], 0, sizeof(OSSL_FN_ULONG) * (al - bl));
    } else {
        memcpy(a->d, b->d, al * sizeof(OSSL_FN_ULONG));
    }

    return a;
}

/*-
 * Serialise |a| as |len| big-endian bytes into |out|, in constant time.
 *
 * The low |len| bytes of |a| are written most-significant first; |a|'s value
 * must fit in |len| bytes.  Returns 1 on success, 0 if |a| has a byte set
 * beyond |len| (i.e. does not fit) or on a NULL argument.
 *
 * Constant-time profile: the byte layout depends only on |len| and |a|'s
 * public width, never on its value.
 */
int OSSL_FN_to_bytes_be(const OSSL_FN *a, unsigned char *out, size_t len)
{
    size_t dsize, nbytes, i;
    unsigned char over = 0;

    if (ossl_unlikely(a == NULL || out == NULL))
        return 0;

    dsize = ossl_fn_get_dsize(a);
    nbytes = dsize * OSSL_FN_BYTES;

    for (i = 0; i < len; i++) {
        size_t limb = i / OSSL_FN_BYTES;

        out[len - 1 - i] = limb < dsize
            ? (unsigned char)(a->d[limb] >> (8 * (i % OSSL_FN_BYTES)))
            : 0;
    }
    /* Every byte of |a| beyond |len| must be zero for the value to fit. */
    for (; i < nbytes; i++)
        over |= (unsigned char)(a->d[i / OSSL_FN_BYTES] >> (8 * (i % OSSL_FN_BYTES)));

    return over == 0;
}

/*-
 * Load |len| big-endian bytes from |in| into |r|, in constant time.
 *
 * The bytes are read most-significant first and placed in |r|'s fixed width; a
 * shorter input is zero-extended.  The value must fit in |r|: it is an error
 * (return 0) for any input byte beyond |r|'s width to be non-zero, mirroring
 * OSSL_FN_to_bytes_be(), of which this is the counterpart (as BN_bin2bn() is of
 * BN_bn2binpad()).
 *
 * Constant-time profile: the byte layout depends only on |len| and |r|'s
 * public width, never on the bytes' values.
 */
int OSSL_FN_from_bytes_be(OSSL_FN *r, const unsigned char *in, size_t len)
{
    size_t rbytes, i;
    unsigned char over = 0;

    if (ossl_unlikely(r == NULL || in == NULL))
        return 0;

    rbytes = ossl_fn_get_dsize(r) * OSSL_FN_BYTES;

    for (i = 0; i < rbytes; i++) {
        size_t limb = i / OSSL_FN_BYTES;
        unsigned char b = i < len ? in[len - 1 - i] : 0;

        if (i % OSSL_FN_BYTES == 0)
            r->d[limb] = 0;
        r->d[limb] |= (OSSL_FN_ULONG)b << (8 * (i % OSSL_FN_BYTES));
    }
    /* Every input byte beyond |r|'s width must be zero for the value to fit. */
    for (; i < len; i++)
        over |= in[len - 1 - i];

    return over == 0;
}

/*-
 * Keep the low |n| bits of |a| and clear every bit at position |n| and above,
 * in place and in constant time.  |n| must be below |a|'s width.  The
 * counterpart of ossl_bn_mask_bits_fixed_top().
 *
 * Constant-time profile: which bits are cleared depends only on |n| and |a|'s
 * public width, never on its value.
 */
int OSSL_FN_mask_bits(OSSL_FN *a, int n)
{
    int w, b, i;

    if (ossl_unlikely(a == NULL)) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }
    if (n < 0) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_SHIFT);
        return 0;
    }

    w = n / OSSL_FN_BITS;
    b = n % OSSL_FN_BITS;
    if (w >= a->dsize) {
        /* |a| has fewer than |n| bits, so there is nothing to mask. */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_BITS_TOO_SMALL);
        return 0;
    }

    if (b != 0) {
        a->d[w] &= ((OSSL_FN_ULONG)1 << b) - 1;
        w++;
    }
    for (i = w; i < a->dsize; i++)
        a->d[i] = 0;

    return 1;
}
