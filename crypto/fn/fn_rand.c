/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
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
    /* TOP_TWO forces two high bits, so it needs at least two bits. */
    if (top == OSSL_FN_RAND_TOP_TWO && bits < 2)
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
    if (top != OSSL_FN_RAND_TOP_ANY) {
        ossl_fn_set_bit(rnd, bits - 1);
        if (top == OSSL_FN_RAND_TOP_TWO)
            ossl_fn_set_bit(rnd, bits - 2);
    }

    /* Set the bottom bit if requested. */
    if (bottom == OSSL_FN_RAND_BOTTOM_ODD)
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
 * The leak profile: control flow branches on |range|'s top bit pattern and on
 * |r|'s width (both public), and the loop iteration count leaks the magnitude
 * of |range| (via OSSL_FN_num_bits) and the rejection probability.
 *
 * The destination |r| must be sized to hold at least |num_bits(range)| bits.
 * The "range = 100..._2" path draws n + 1 bits and is taken only when |r|
 * has room for them; an exactly-sized |r| (room for exactly n bits) uses the
 * standard n-bit rejection path instead.
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
        && !OSSL_FN_is_bit_set(range, (int)(n - 3))
        && n < (size_t)r->dsize * OSSL_FN_BITS) {
        /*
         * range = 100..._2, so 3*range (= 11..._2) is exactly one bit longer
         * than range.  This draws n + 1 bits, so it is taken only when |r| has
         * room for them; an exactly-sized |r| (room for exactly n bits) falls
         * through to the standard n-bit rejection path below.
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

/*-
 * ossl_fn_gen_dsa_nonce() is the OSSL_FN analogue of
 * ossl_bn_gen_dsa_nonce_fixed_top(): it derives a nonce 0 <= out < range that
 * also mixes in |priv| and |message|, so that an RNG failure is not fatal as
 * long as |priv| remains secret.  DSA and ECDSA need it to keep the nonce,
 * which is derived from the private key, in constant-width OSSL_FN form.
 *
 * |libctx| is taken directly (the BIGNUM version only used its BN_CTX to derive
 * one) and is used for fetching the digest and for RNG access.  Unlike the
 * BIGNUM version there is no 0xff prefix byte: OSSL_FN_from_bytes_be() is
 * already constant-time, so it needs no set top byte to guard against.
 *
 * |out| must be sized to hold at least |num_bits(range)| bits; a narrower
 * destination is rejected with OSSL_FN_R_RESULT_ARG_TOO_SMALL.
 */
int ossl_fn_gen_dsa_nonce(OSSL_FN *out, const OSSL_FN *range,
    const OSSL_FN *priv, const unsigned char *message,
    size_t message_len, OSSL_LIB_CTX *libctx)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    /*
     * We use 512 bits of random data per iteration to ensure that we have at
     * least |range| bits of randomness.
     */
    unsigned char random_bytes[64];
    unsigned char digest[SHA512_DIGEST_LENGTH];
    unsigned done, todo;
    /* The number of hash bytes that span |range|. */
    const int range_bits = (int)OSSL_FN_num_bits(range);
    const unsigned num_k_bytes = (range_bits + 7) / 8;
    unsigned char private_bytes[96];
    unsigned char *k_bytes = NULL;
    const int max_n = 64; /* Number of iterations until giving up */
    int n;
    int ret = 0;
    EVP_MD *md = NULL;

    if (mdctx == NULL)
        goto end;

    if (range_bits == 0) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_INVALID_RANGE);
        goto end;
    }

    /*
     * |out| must be wide enough to hold every value below |range|, i.e. at
     * least |range_bits| bits.  A narrower destination cannot represent the
     * nonce: OSSL_FN_from_bytes_be() would reject all but the improbable draws
     * whose surplus high bits are zero, and even those would be biased by the
     * forced-zero high bits rather than uniform in [0, range).
     */
    if (ossl_fn_get_dsize(out) * OSSL_FN_BITS < (size_t)range_bits) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_RESULT_ARG_TOO_SMALL);
        goto end;
    }

    k_bytes = OPENSSL_malloc(num_k_bytes);
    if (k_bytes == NULL)
        goto end;

    /* We copy |priv| into a local buffer to avoid exposing its length. */
    if (!OSSL_FN_to_bytes_be(priv, private_bytes, sizeof(private_bytes))) {
        /*
         * No reasonable DSA or ECDSA key should have a private key this
         * large and we don't handle this case in order to avoid leaking the
         * length of the private key.
         */
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_OVERFLOW);
        goto end;
    }

    md = EVP_MD_fetch(libctx, "SHA512", NULL);
    if (md == NULL) {
        ERR_raise(ERR_LIB_OSSL_FN, ERR_R_FETCH_FAILED);
        goto end;
    }
    for (n = 0; n < max_n; n++) {
        unsigned char i = 0;

        for (done = 0; done < num_k_bytes;) {
            if (RAND_priv_bytes_ex(libctx, random_bytes, sizeof(random_bytes),
                    0)
                <= 0)
                goto end;

            if (!EVP_DigestInit_ex(mdctx, md, NULL)
                || !EVP_DigestUpdate(mdctx, &i, sizeof(i))
                || !EVP_DigestUpdate(mdctx, private_bytes,
                    sizeof(private_bytes))
                || !EVP_DigestUpdate(mdctx, message, message_len)
                || !EVP_DigestUpdate(mdctx, random_bytes,
                    sizeof(random_bytes))
                || !EVP_DigestFinal_ex(mdctx, digest, NULL))
                goto end;

            todo = num_k_bytes - done;
            if (todo > SHA512_DIGEST_LENGTH)
                todo = SHA512_DIGEST_LENGTH;
            memcpy(k_bytes + done, digest, todo);
            done += todo;
            ++i;
        }

        if (!OSSL_FN_from_bytes_be(out, k_bytes, num_k_bytes))
            goto end;

        /*
         * Rejection-filter into range, clearing the surplus bits first. When
         * |range|'s bit length is not a multiple of 8, the last loaded byte
         * carries high bits above it that must be masked off. When it is
         * byte-aligned the loaded value already has exactly that width, so
         * there is nothing to clear -- and masking to out's full width would be
         * a no-op that OSSL_FN_mask_bits() rejects anyway.
         */
        if (range_bits % 8 != 0 && !OSSL_FN_mask_bits(out, range_bits))
            goto end;

        if (OSSL_FN_cmp(out, range) < 0) {
            ret = 1;
            goto end;
        }
    }
    /* Failed to generate anything */
    ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_TOO_MANY_ITERATIONS);

end:
    EVP_MD_CTX_free(mdctx);
    EVP_MD_free(md);
    OPENSSL_clear_free(k_bytes, num_k_bytes);
    OPENSSL_cleanse(digest, sizeof(digest));
    OPENSSL_cleanse(random_bytes, sizeof(random_bytes));
    OPENSSL_cleanse(private_bytes, sizeof(private_bytes));
    return ret;
}
