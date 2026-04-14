/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <openssl/err.h>
#include "crypto/cryptlib.h"
#include "crypto/fnerr.h"
#include "../bn/bn_local.h" /* For using the low level bignum functions */
#include "fn_local.h"

#if !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM) \
    && !defined(PEDANTIC) && !defined(BN_DIV3W)
#if defined(__GNUC__) && __GNUC__ >= 2
#if defined(__i386) || defined(__i386__)
/*-
 * There were two reasons for implementing this template:
 * - GNU C generates a call to a function (__udivdi3 to be exact)
 *   in reply to ((((BN_ULLONG)n0)<<BN_BITS2)|n1)/d0 (I fail
 *   to understand why...);
 * - divl doesn't only calculate quotient, but also leaves
 *   remainder in %edx which we can definitely use here:-)
 */
#undef bn_div_words
#define bn_div_words(n0, n1, d0)        \
    ({                                  \
        asm volatile(                   \
            "divl   %4"                 \
            : "=a"(quo), "=d"(rem)      \
            : "a"(n1), "d"(n0), "r"(d0) \
            : "cc");                    \
        quo;                            \
    })
#define REMAINDER_IS_ALREADY_CALCULATED
#elif defined(__x86_64) && defined(SIXTY_FOUR_BIT_LONG)
/*
 * Same story here, but it's 128-bit by 64-bit division. Wow!
 */
#undef bn_div_words
#define bn_div_words(n0, n1, d0)        \
    ({                                  \
        asm volatile(                   \
            "divq   %4"                 \
            : "=a"(quo), "=d"(rem)      \
            : "a"(n1), "d"(n0), "r"(d0) \
            : "cc");                    \
        quo;                            \
    })
#define REMAINDER_IS_ALREADY_CALCULATED
#endif /* __<cpu> */
#endif /* __GNUC__ */
#endif /* OPENSSL_NO_ASM */

/*
 * Copy src to dst and align it to the left using lshift.
 * lshift is assumed to be less than OSSL_FN_BITS.
 */
static inline void copy_align_left(OSSL_FN *dst, const OSSL_FN *src, OSSL_FN_ULONG lshift)
{
    OSSL_FN_ULONG rshift = OSSL_FN_BITS - lshift;
    OSSL_FN_ULONG rmask;
    OSSL_FN_ULONG m;
    const OSSL_FN_ULONG *s = src->d;
    size_t sl = src->dsize;
    OSSL_FN_ULONG *d = dst->d;
    size_t dl = dst->dsize;
    size_t l = (dl < sl) ? dl : sl;
    size_t i;

    rshift %= OSSL_FN_BITS;

    /* rmask = 0 - (rshift != 0) */
    rmask = (OSSL_FN_ULONG)0 - rshift;
    rmask |= rmask >> 8;

    /* src and dst may be the same, that's why this loop is made this way */
    for (i = 0, m = 0; i < l; i++) {
        OSSL_FN_ULONG tmp = s[i];
        d[i] = ((tmp << lshift) | m) & OSSL_FN_MASK;
        m = (tmp >> rshift) & rmask;
    }

    for (; i < dl; i++) {
        d[i] = m;
        m = 0;
    }
}

/*
 * Copy src to dst and align it to the right using rshift.
 * rshift is assumed to be less than OSSL_FN_BITS.
 */
static inline void copy_align_right(OSSL_FN *dst, const OSSL_FN *src, OSSL_FN_ULONG rshift)
{
    OSSL_FN_ULONG lshift = OSSL_FN_BITS - rshift;
    OSSL_FN_ULONG lmask;
    const OSSL_FN_ULONG *s = src->d;
    size_t sl = src->dsize;
    OSSL_FN_ULONG *d = dst->d;
    size_t dl = dst->dsize;
    size_t i;
    size_t l = (dl < sl) ? dl : sl;

    lshift %= OSSL_FN_BITS;

    /* lmask = 0 - (lshift != 0) */
    lmask = (OSSL_FN_ULONG)0 - lshift;
    lmask |= lmask >> 8;

    /* Just to be safe */
    for (i = dl; i-- > l;)
        d[i] = 0;

    /*
     * m is a set of bits passed to the next limb down when shifting,
     * and needs proper bootstrapping: if the source is larger than the
     * destination, we must consider one source limb beyond the destination
     * size.  If not, m is simply starts with zero.
     */
    OSSL_FN_ULONG m = (dl < sl) ? (s[dl] << lshift) & lmask : 0;

    /* src and dst may be the same, that's why this loop is made this way */
    for (i = l; i-- > 0;) {
        OSSL_FN_ULONG tmp = s[i];
        d[i] = m | ((tmp >> rshift) & OSSL_FN_MASK);
        m = (tmp << lshift) & lmask;
    }
}

static inline OSSL_FN_ULONG div_words(OSSL_FN_ULONG *wnumtop, OSSL_FN_ULONG *wnum,
    OSSL_FN_ULONG d1, OSSL_FN_ULONG d0)
{
#if defined(BN_DIV3W)
    return bn_div_3_words(wnumtop, d1, d0);
#else
    OSSL_FN_ULONG n0 = wnumtop[0], n1 = wnumtop[-1], quo = 0, rem = 0;

    if (n0 == d0)
        quo = OSSL_FN_MASK;
    else { /* n0 < d0 */
        OSSL_FN_ULONG n2 = (wnumtop == wnum) ? 0 : wnumtop[-2];
#ifdef BN_LLONG
        BN_ULLONG t2;

#if defined(BN_LLONG) && defined(BN_DIV2W) && !defined(bn_div_words)
        quo = (OSSL_FN_ULONG)(((((BN_ULLONG)n0) << OSSL_FN_BITS) | n1) / d0);
#else
        quo = bn_div_words(n0, n1, d0);
#endif

#ifndef REMAINDER_IS_ALREADY_CALCULATED
        /*
         * rem doesn't have to be BN_ULLONG. The least we
         * know it's less that d0, isn't it?
         */
        rem = (n1 - quo * d0) & BN_MASK2;
#endif
        t2 = (BN_ULLONG)d1 * quo;

        for (;;) {
            if (t2 <= ((((BN_ULLONG)rem) << OSSL_FN_BITS) | n2))
                break;
            quo--;
            rem += d0;
            if (rem < d0)
                break; /* don't let rem overflow */
            t2 -= d1;
        }
#else /* !BN_LLONG */
        OSSL_FN_ULONG t2l, t2h;

        quo = bn_div_words(n0, n1, d0);
#ifndef REMAINDER_IS_ALREADY_CALCULATED
        rem = (n1 - quo * d0) & OSSL_FN_MASK;
#endif

#if defined(BN_UMULT_LOHI)
        BN_UMULT_LOHI(t2l, t2h, d1, quo);
#elif defined(BN_UMULT_HIGH)
        t2l = d1 * quo;
        t2h = BN_UMULT_HIGH(d1, quo);
#else
        {
            OSSL_FN_ULONG ql, qh;
            t2l = LBITS(d1);
            t2h = HBITS(d1);
            ql = LBITS(quo);
            qh = HBITS(quo);
            mul64(t2l, t2h, ql, qh); /* t2=(BN_ULLONG)d1*q; */
        }
#endif

        for (;;) {
            if ((t2h < rem) || ((t2h == rem) && (t2l <= n2)))
                break;
            quo--;
            rem += d0;
            if (rem < d0)
                break; /* don't let rem overflow */
            if (t2l < d1)
                t2h--;
            t2l -= d1;
        }
#endif /* !BN_LLONG */
    }

    return quo;
#endif /* !BN_DIV3W */
}

/* Trivia: this function implements Knuth's algorithm D */
int OSSL_FN_div(OSSL_FN *q, OSSL_FN *r, const OSSL_FN *n, const OSSL_FN *d, OSSL_FN_CTX *ctx)
{
    const void *token = OSSL_FN_CTX_start(ctx);
    if (token == NULL)
        return 0;

    size_t nl = n->dsize;
    size_t dl = d->dsize;
    size_t ql = (q == NULL) ? 0 : q->dsize;

    /*
     * We need to figure out the significant size of |d|, to avoid division by
     * zero if the highest limb(s) are zero.
     *
     * This doesn't quite give a sense that division can be constant time.
     * However, in the use cases where constant time is interesting (cryptosystems),
     * it can be argued that the denominator would have a constant enough size
     * within each cryptosystem (and size therein), so it's assumed that time
     * will be constant because of that.
     */
    while (dl > 0 && d->d[dl - 1] == 0)
        dl--;

    if (dl == 0) {
        ERR_raise(ERR_LIB_OSSL_FN, OSSL_FN_R_DIV_BY_ZERO);
        goto err;
    }

    /*
     * Because some assembler language instructions have those requirements,
     * the denominator need to be shifted "left" so the top bit is always 1.
     * To ensure that we still get correct results, the numerator will have
     * to be shifted left as many bits.  The resulting quotient will end up
     * correct, but the remainder will have to be shifted "right" before the
     * end of this function.
     */
    OSSL_FN_ULONG norm_shift = OSSL_FN_BITS - BN_num_bits_word(d->d[dl - 1]);

    /*
     * Store a copy the numerator in snum, padded with extra zeros if nl <= dl
     * eventually, this will contain the remainder.  Because it may be shifted
     * up to almost a full limb to the left (worst case scenario), an extra limb
     * need to be allocated.
     */
    size_t snuml = ((nl <= dl) ? dl : nl) + 1;
    OSSL_FN *snum = OSSL_FN_CTX_get_limbs(ctx, snuml);
    if (!ossl_assert(snuml <= INT_MAX && snum != NULL))
        goto err;
    copy_align_left(snum, n, norm_shift);

    /*
     * Store a copy of the denominator in sdiv, shifted left so that its top bit
     * is always 1.  This is necessary to avoid gnarly arithmetic exceptions when
     * the denominator's highest limb is a very small number.
     */
    size_t sdivl = dl;
    OSSL_FN *sdiv = OSSL_FN_CTX_get_limbs(ctx, sdivl);
    if (!ossl_assert(sdivl <= INT_MAX && sdiv != NULL))
        goto err;
    copy_align_left(sdiv, d, norm_shift);

    /*
     * The number of times we will iterate to perform division, i.e.
     * how often we will "shift" the divisor "window" over the numerator.
     * This also determines the size of the result.
     *
     * For the math oriented:
     *
     *    snuml - sdivl = ((nl <= dl) ? dl : nl) + 1 - dl
     * => snuml - sdivl = ((nl <= dl) ? 0 : nl - dl) + 1
     * => snuml - sdivl =  (nl <= dl) ? 1 : nl - dl + 1
     */
    size_t loop = snuml - sdivl;

    /*
     * Set up the quotient.  It will be stored directly in |q| if it has
     * enough space, otherwise temporary storage is allocated.
     */
    OSSL_FN *res = (ql < loop) ? OSSL_FN_CTX_get_limbs(ctx, loop) : q;
    if (!ossl_assert(res != NULL))
        goto err;

    /* Position of the next quotient limb to be calculated, plus one */
    OSSL_FN_ULONG *resp = &(res->d[loop]);

    /* Intermediary storage */
    OSSL_FN *tmp = OSSL_FN_CTX_get_limbs(ctx, sdivl + 1);
    if (!ossl_assert(tmp != NULL))
        goto err;

    /* Set up the "window" position in snum. */
    OSSL_FN_ULONG *wnum = &(snum->d[loop]);
    OSSL_FN_ULONG *wnumtop = &(snum->d[snuml - 1]);

    /* Get the top 2 words of the denominator */
    OSSL_FN_ULONG d0 = sdiv->d[sdivl - 1];
    OSSL_FN_ULONG d1 = (sdivl == 1) ? 0 : sdiv->d[sdivl - 2];

    size_t i;

    /* If res is larger than the expected result, zero the limbs above */
    for (i = res->dsize; i > loop;)
        res->d[--i] = 0;
    for (i = 0; i < loop; i++, wnumtop--) {
        OSSL_FN_ULONG quo, l0;
        /*
         * the first part of the loop uses the top two words of snum and sdiv
         * to calculate a OSSL_FN_ULONG quo such that | wnum - d * q | < d
         */
        quo = div_words(wnumtop, wnum, d1, d0);

        l0 = bn_mul_words(tmp->d, sdiv->d, (int)sdivl, quo);
        tmp->d[sdivl] = l0;
        wnum--;

        /*
         * ignore top values of the bignums just sub the two OSSL_FN_ULONG
         * arrays with bn_sub_words
         */
        l0 = bn_sub_words(wnum, wnum, tmp->d, (int)sdivl + 1);
        quo -= l0;

        /*
         * Note: As we have considered only the leading two OSSL_FN_ULONGs
         * in the calculation of q, d * q might be greater than wnum
         * (but then (q-1) * d is less than or equal to wnum)
         */
        size_t j;
        for (l0 = 0 - l0, j = 0; j < sdivl; j++)
            tmp->d[j] = sdiv->d[j] & l0;
        l0 = bn_add_words(wnum, wnum, tmp->d, (int)sdivl);
        (*wnumtop) += l0;
        assert((*wnumtop) == 0);

        /* store part of the result */
        *--resp = quo;
    }
    /* snum holds remainder, it's as wide as divisor */
    if (r != NULL)
        copy_align_right(r, snum, norm_shift);
    /* res holds the quotient for a total of loop limbs, and is separate from q if ql < loop */
    if (q != NULL && q != res && OSSL_FN_copy_truncate(q, res) == 0)
        goto err;

    OSSL_FN_CTX_end(ctx, token);
    return 1;
err:
    OSSL_FN_CTX_end(ctx, token);
    return 0;
}
