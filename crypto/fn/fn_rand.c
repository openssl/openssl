/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/rand.h>
#include "crypto/fnerr.h"
#include "fn_local.h"

/*
 * Internal flag selecting which DRBG pool the bytes are drawn from.
 * NORMAL routes through RAND_bytes_ex(), PRIVATE through
 * RAND_priv_bytes_ex() (a non-forward-linkable source).  The same shaping
 * code feeds either pool; the flag selects which one, mirroring the
 * public/private split exposed by the OSSL_FN_rand() / OSSL_FN_priv_rand()
 * entry points.
 */
enum ossl_fn_rand_flag {
    NORMAL = 0,
    PRIVATE
};

/* Set bit |pos| (0 = least significant) of |a|, by absolute position. */
static void ossl_fn_set_bit(OSSL_FN *a, size_t pos)
{
    a->d[pos / OSSL_FN_BITS] |= OSSL_FN_ULONG_C(1) << (pos % OSSL_FN_BITS);
}

/*-
 * ossl_fn_rand() fills |rnd| with |bits| random bits, shaping the top and
 * bottom bits per the |top|/|bottom| requests.  The random bytes are drawn
 * directly into rnd->d's byte image (a whole number of limbs, so the result
 * is a random value regardless of the machine's byte order), and the
 * top/bottom/mask shaping is done directly on rnd->d's limbs as value
 * operations -- set bit |bits|-1 for TOP_ONE, bits |bits|-1 and |bits|-2
 * for TOP_TWO, clear the high bits of the top limb at |bits| and above,
 * set bit 0 for BOTTOM_ODD.  No intermediate byte buffer is needed, since
 * OSSL_FN's limbs are fixed-size.
 *
 * A destination too small for |bits| is an error
 * (OSSL_FN_R_RESULT_ARG_TOO_SMALL), not an implicit expansion.
 *
 * The leak profile: control flow branches on |bits|, |top|, |bottom| (all
 * caller-chosen, public) and on the byte-draw return value, never on the
 * random bytes themselves.  The result value of OSSL_FN_rand() /
 * OSSL_FN_priv_rand() is, of course, the random number the caller asked for.
 */
static int ossl_fn_rand(enum ossl_fn_rand_flag flag, OSSL_FN *rnd, size_t bits,
    int top, int bottom, size_t strength,
    OSSL_LIB_CTX *libctx)
{
    size_t limbs_needed, top_limb, i;

    if (rnd == NULL) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (bits == 0) {
        if (top != OSSL_FN_RAND_TOP_ANY || bottom != OSSL_FN_RAND_BOTTOM_ANY)
            goto toosmall;
        return OSSL_FN_zero(rnd);
    }
    if (bits == 1 && top > 0)
        goto toosmall;

    limbs_needed = bits / OSSL_FN_BITS;
    limbs_needed += (bits % OSSL_FN_BITS != 0) ? 1 : 0;
    if (limbs_needed > (size_t)rnd->dsize) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        return 0;
    }
    top_limb = limbs_needed - 1;

    /*
     * Draw random bytes directly into rnd->d's byte image.  A whole number
     * of limbs is filled so the result is a random value regardless of the
     * machine's byte order; the high bits of the top limb beyond |bits| are
     * masked off below.  The pool is selected by |flag|.
     */
    {
        size_t fill_bytes = limbs_needed * OSSL_FN_BYTES;
        int b = (flag == NORMAL)
            ? RAND_bytes_ex(libctx, (unsigned char *)rnd->d, fill_bytes,
                  (unsigned int)strength)
            : RAND_priv_bytes_ex(libctx, (unsigned char *)rnd->d, fill_bytes,
                  (unsigned int)strength);

        if (b <= 0)
            return 0;
    }

    /*
     * TODO(FIXNUM): a testing variant that mangles the byte buffer to
     * generate patterns more likely to trigger library bugs is not wired up
     * yet; if an OSSL_FN_bntest_rand() analogue is added for test coverage,
     * this is the spot for the mangle step.
     */

    /* Zero any limbs above those the bytes filled. */
    for (i = limbs_needed; i < (size_t)rnd->dsize; i++)
        rnd->d[i] = 0;

    /* Clear the high bits of the top limb at |bits| and above. */
    if (bits % OSSL_FN_BITS != 0)
        rnd->d[top_limb] &= (OSSL_FN_ULONG_C(1) << (bits % OSSL_FN_BITS)) - 1;

    /* Set the requested top bit(s); |bits| >= 2 is guaranteed for TOP_TWO. */
    if (top >= 0) {
        ossl_fn_set_bit(rnd, bits - 1);
        if (top) /* OSSL_FN_RAND_TOP_TWO */
            ossl_fn_set_bit(rnd, bits - 2);
    }

    /* Set the bottom bit if requested. */
    if (bottom) /* OSSL_FN_RAND_BOTTOM_ODD */
        rnd->d[0] |= OSSL_FN_ULONG_C(1);

    return 1;

toosmall:
    ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_BITS_TOO_SMALL);
    return 0;
}

/* Draw from the public DRBG pool (NORMAL). */
int OSSL_FN_rand(OSSL_FN *rnd, size_t bits, int top, int bottom,
    size_t strength, OSSL_LIB_CTX *libctx)
{
    return ossl_fn_rand(NORMAL, rnd, bits, top, bottom, strength, libctx);
}

/* Draw from the private DRBG pool (PRIVATE). */
int OSSL_FN_priv_rand(OSSL_FN *rnd, size_t bits, int top, int bottom,
    size_t strength, OSSL_LIB_CTX *libctx)
{
    return ossl_fn_rand(PRIVATE, rnd, bits, top, bottom, strength, libctx);
}

/*-
 * ossl_fn_rand_range() produces 0 <= r < range by rejection sampling.  The
 * libctx comes directly as an argument, as in ossl_fn_rand(); sign is never
 * considered, since OSSL_FN is unsigned.
 *
 * The leak profile: the loop iteration count leaks the magnitude of |range|
 * (via OSSL_FN_num_bits) and the rejection probability.
 *
 * The destination |r| must be sized to hold |num_bits(range) + 1| bits; the
 * "range = 100..._2" path draws n + 1 bits, and OSSL_FN cannot grow to fit,
 * so the caller must size |r| up front.
 */
static int ossl_fn_rand_range(enum ossl_fn_rand_flag flag, OSSL_FN *r,
    const OSSL_FN *range, size_t strength,
    OSSL_LIB_CTX *libctx)
{
    size_t n;
    int count = 100;

    if (r == NULL) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (OSSL_FN_is_zero(range)) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_RANGE);
        return 0;
    }

    n = OSSL_FN_num_bits(range); /* n > 0 */

    /* OSSL_FN_is_bit_set(range, n - 1) always holds */

    if (n == 1) {
        return OSSL_FN_zero(r);
    } else if (!OSSL_FN_is_bit_set(range, (int)(n - 2))
        && !OSSL_FN_is_bit_set(range, (int)(n - 3))) {
        /*
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range
         */
        do {
            if (!ossl_fn_rand(flag, r, n + 1, OSSL_FN_RAND_TOP_ANY,
                    OSSL_FN_RAND_BOTTOM_ANY, strength, libctx))
                return 0;

            /*
             * If r < 3*range, use r := r MOD range (which is either r, r -
             * range, or r - 2*range). Otherwise, iterate once more. Since
             * 3*range = 11..._2, each iteration succeeds with probability >=
             * .75.
             */
            if (OSSL_FN_cmp(r, range) >= 0) {
                if (!OSSL_FN_sub(r, r, range))
                    return 0;
                if (OSSL_FN_cmp(r, range) >= 0)
                    if (!OSSL_FN_sub(r, r, range))
                        return 0;
            }

            if (!--count) {
                ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_TOO_MANY_ITERATIONS);
                return 0;
            }

        } while (OSSL_FN_cmp(r, range) >= 0);
    } else {
        do {
            /* range = 11..._2  or  range = 101..._2 */
            if (!ossl_fn_rand(flag, r, n, OSSL_FN_RAND_TOP_ANY,
                    OSSL_FN_RAND_BOTTOM_ANY, strength, libctx))
                return 0;

            if (!--count) {
                ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_TOO_MANY_ITERATIONS);
                return 0;
            }
        } while (OSSL_FN_cmp(r, range) >= 0);
    }

    return 1;
}

/* Draw from the public DRBG pool (NORMAL). */
int OSSL_FN_rand_range(OSSL_FN *r, const OSSL_FN *range, size_t strength,
    OSSL_LIB_CTX *libctx)
{
    return ossl_fn_rand_range(NORMAL, r, range, strength, libctx);
}

/* Draw from the private DRBG pool (PRIVATE). */
int OSSL_FN_priv_rand_range(OSSL_FN *r, const OSSL_FN *range,
    size_t strength, OSSL_LIB_CTX *libctx)
{
    return ossl_fn_rand_range(PRIVATE, r, range, strength, libctx);
}
