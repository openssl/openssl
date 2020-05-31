/* ====================================================================
 * Copyright (c) 2014 - 2018 The GmSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the GmSSL Project.
 *    (http://gmssl.org/)"
 *
 * 4. The name "GmSSL Project" must not be used to endorse or promote
 *    products derived from this software without prior written
 *    permission. For written permission, please contact
 *    guanzhi1980@gmail.com.
 *
 * 5. Products derived from this software may not be called "GmSSL"
 *    nor may "GmSSL" appear in their names without prior written
 *    permission of the GmSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the GmSSL Project
 *    (http://gmssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE GmSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE GmSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 */

/*
 * Copyright 2002-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bn_lcl.h"
#include "internal/cryptlib.h"

#define BN_SM2_256_TOP (256+BN_BITS2-1)/BN_BITS2

/* pre-computed tables are "carry-less" values of modulus*(i+1) */
#if BN_BITS2 == 64

/* p, 2p, 3p, 4p, 5p in little-endian */
static const BN_ULONG _sm2_p_256[][BN_SM2_256_TOP] = {
    {0xffffffffffffffffull, 0xffffffff00000000ull,
     0xffffffffffffffffull, 0xfffffffeffffffffull},
    {0xfffffffffffffffeull, 0xfffffffe00000001ull,
     0xffffffffffffffffull, 0xfffffffdffffffffull},
    {0xfffffffffffffffdull, 0xfffffffd00000002ull,
     0xffffffffffffffffull, 0xfffffffcffffffffull},
    {0xfffffffffffffffcull, 0xfffffffc00000003ull,
     0xffffffffffffffffull, 0xfffffffbffffffffull},
    {0xfffffffffffffffbull, 0xfffffffb00000004ull,
     0xffffffffffffffffull, 0xfffffffaffffffffull},
    {0xfffffffffffffffaull, 0xfffffffa00000005ull,
     0xffffffffffffffffull, 0xfffffff9ffffffffull},
    {0xfffffffffffffff9ull, 0xfffffff900000006ull,
     0xffffffffffffffffull, 0xfffffff8ffffffffull},
    {0xfffffffffffffff8ull, 0xfffffff800000007ull,
     0xffffffffffffffffull, 0xfffffff7ffffffffull},
    {0xfffffffffffffff7ull, 0xfffffff700000008ull,
     0xffffffffffffffffull, 0xfffffff6ffffffffull},
    {0xfffffffffffffff6ull, 0xfffffff600000009ull,
     0xffffffffffffffffull, 0xfffffff5ffffffffull},
    {0xfffffffffffffff5ull, 0xfffffff50000000aull,
     0xffffffffffffffffull, 0xfffffff4ffffffffull},
    {0xfffffffffffffff4ull, 0xfffffff40000000bull,
     0xffffffffffffffffull, 0xfffffff3ffffffffull},
    {0xfffffffffffffff3ull, 0xfffffff30000000cull,
     0xffffffffffffffffull, 0xfffffff2ffffffffull}
};

/* p^2 in little-endian */
static const BN_ULONG _sm2_p_256_sqr[] = {
    0x0000000000000001ull, 0x00000001fffffffeull,
    0xfffffffe00000001ull, 0x0000000200000000ull,
    0xfffffffdfffffffeull, 0xfffffffe00000003ull,
    0xffffffffffffffffull, 0xfffffffe00000000ull,
};

#elif BN_BITS2 == 32

static const BN_ULONG _sm2_p_256[][BN_SM2_256_TOP] = {
    {0xffffffff, 0xffffffff, 0x0, 0xffffffff,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffe},
    {0xfffffffe, 0xffffffff, 0x1, 0xfffffffe,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffd},
    {0xfffffffd, 0xffffffff, 0x2, 0xfffffffd,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffc},
    {0xfffffffc, 0xffffffff, 0x3, 0xfffffffc,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffb},
    {0xfffffffb, 0xffffffff, 0x4, 0xfffffffb,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffffa},
    {0xfffffffa, 0xffffffff, 0x5, 0xfffffffa,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff9},
    {0xfffffff9, 0xffffffff, 0x6, 0xfffffff9,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff8},
    {0xfffffff8, 0xffffffff, 0x7, 0xfffffff8,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff7},
    {0xfffffff7, 0xffffffff, 0x8, 0xfffffff7,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff6},
    {0xfffffff6, 0xffffffff, 0x9, 0xfffffff6,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff5},
    {0xfffffff5, 0xffffffff, 0xa, 0xfffffff5,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff4},
    {0xfffffff4, 0xffffffff, 0xb, 0xfffffff4,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff3},
    {0xfffffff3, 0xffffffff, 0xc, 0xfffffff3,
     0xffffffff, 0xffffffff, 0xffffffff, 0xfffffff2},
};

static const BN_ULONG _sm2_p_256_sqr[] = {
    0x00000001, 0x00000000, 0xfffffffe, 0x00000001,
    0x00000001, 0xfffffffe, 0x00000000, 0x00000002,
    0xfffffffe, 0xfffffffd, 0x00000003, 0xfffffffe,
    0xffffffff, 0xffffffff, 0x00000000, 0xfffffffe
};

#else
# error "unsupported BN_BITS2"
#endif

static const BIGNUM _bignum_sm2_p_256 = {
    (BN_ULONG *)_sm2_p_256[0],
    BN_SM2_256_TOP,
    BN_SM2_256_TOP,
    0,
    BN_FLG_STATIC_DATA
};

const BIGNUM *BN_get0_sm2_prime_256(void)
{
    return &_bignum_sm2_p_256;
}

static void sm2_cp_bn_0(BN_ULONG *dst, const BN_ULONG *src, int top, int max)
{
    int i;

#ifdef BN_DEBUG
    OPENSSL_assert(top <= max);
#endif
    for (i = 0; i < top; i++)
        dst[i] = src[i];
    for (; i < max; i++)
        dst[i] = 0;
}

static void sm2_cp_bn(BN_ULONG *dst, const BN_ULONG *src, int top)
{
    int i;

    for (i = 0; i < top; i++)
        dst[i] = src[i];
}

#if BN_BITS2 == 64
# define bn_cp_64(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_64_set_0(to, n)              (to)[n] = (BN_ULONG)0;
/*
 * two following macros are implemented under assumption that they
 * are called in a sequence with *ascending* n, i.e. as they are...
 */
# define bn_cp_32_naked(to, n, from, m)  (((n)&1)?(to[(n)/2]|=((m)&1)?(from[(m)/2]&BN_MASK2h):(from[(m)/2]<<32))\
                                                :(to[(n)/2] =((m)&1)?(from[(m)/2]>>32):(from[(m)/2]&BN_MASK2l)))
# define bn_32_set_0(to, n)              (((n)&1)?(to[(n)/2]&=BN_MASK2l):(to[(n)/2]=0));
# define bn_cp_32(to,n,from,m)           ((m)>=0)?bn_cp_32_naked(to,n,from,m):bn_32_set_0(to,n)
# if defined(L_ENDIAN)
#  if defined(__arch64__)
#   define NIST_INT64 long
#  else
#   define NIST_INT64 long long
#  endif
# endif
#else
# define bn_cp_64(to, n, from, m) \
        { \
        bn_cp_32(to, (n)*2, from, (m)*2); \
        bn_cp_32(to, (n)*2+1, from, (m)*2+1); \
        }
# define bn_64_set_0(to, n) \
        { \
        bn_32_set_0(to, (n)*2); \
        bn_32_set_0(to, (n)*2+1); \
        }
# define bn_cp_32(to, n, from, m)        (to)[n] = (m>=0)?((from)[m]):0;
# define bn_32_set_0(to, n)              (to)[n] = (BN_ULONG)0;
# if defined(_WIN32) && !defined(__GNUC__)
#  define NIST_INT64 __int64
# elif defined(BN_LLONG)
#  define NIST_INT64 long long
# endif
#endif                          /* BN_BITS2 != 64 */


typedef BN_ULONG (*bn_addsub_f) (BN_ULONG *, const BN_ULONG *,
                                 const BN_ULONG *, int);

#define sm2_set_256(to, from, a1, a2, a3, a4, a5, a6, a7, a8) \
        { \
        bn_cp_32(to, 0, from, (a8) - 8) \
        bn_cp_32(to, 1, from, (a7) - 8) \
        bn_cp_32(to, 2, from, (a6) - 8) \
        bn_cp_32(to, 3, from, (a5) - 8) \
        bn_cp_32(to, 4, from, (a4) - 8) \
        bn_cp_32(to, 5, from, (a3) - 8) \
        bn_cp_32(to, 6, from, (a2) - 8) \
        bn_cp_32(to, 7, from, (a1) - 8) \
        }

int BN_sm2_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
                   BN_CTX *ctx)
{
    int i, top = a->top;
    int carry = 0;
    register BN_ULONG *a_d = a->d, *r_d;
    union {
        BN_ULONG bn[BN_SM2_256_TOP];
        unsigned int ui[BN_SM2_256_TOP * sizeof(BN_ULONG) /
                        sizeof(unsigned int)];
    } buf;
    BN_ULONG c_d[BN_SM2_256_TOP], *res;
    PTR_SIZE_INT mask;
    union {
        bn_addsub_f f;
        PTR_SIZE_INT p;
    } u;
    static const BIGNUM _bignum_sm2_p_256_sqr = {
        (BN_ULONG *)_sm2_p_256_sqr,
        OSSL_NELEM(_sm2_p_256_sqr),
        OSSL_NELEM(_sm2_p_256_sqr),
        0, BN_FLG_STATIC_DATA
    };

    field = &_bignum_sm2_p_256; /* just to make sure */

    if (BN_is_negative(a) || BN_ucmp(a, &_bignum_sm2_p_256_sqr) >= 0)
        return BN_nnmod(r, a, field, ctx);

    i = BN_ucmp(field, a);
    if (i == 0) {
        BN_zero(r);
        return 1;
    } else if (i > 0)
        return (r == a) ? 1 : (BN_copy(r, a) != NULL);

    if (r != a) {
        if (!bn_wexpand(r, BN_SM2_256_TOP))
            return 0;
        r_d = r->d;
        sm2_cp_bn(r_d, a_d, BN_SM2_256_TOP);
    } else
        r_d = a_d;

    sm2_cp_bn_0(buf.bn, a_d + BN_SM2_256_TOP, top - BN_SM2_256_TOP,
                BN_SM2_256_TOP);

#if defined(NIST_INT64)
    {
        NIST_INT64 acc;         /* accumulator */
        unsigned int *rp = (unsigned int *)r_d;
        const unsigned int *bp = (const unsigned int *)buf.ui;

        acc = rp[0];
        acc += bp[8 - 8];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[0] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[1];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[1] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[2];
        acc -= bp[8 - 8];
        acc -= bp[9 - 8];
        acc -= bp[13 - 8];
        acc -= bp[14 - 8];
        rp[2] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[3];
        acc += bp[8 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[3] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[4];
        acc += bp[9 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[4] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[5];
        acc += bp[10 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[5] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[6];
        acc += bp[11 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        rp[6] = (unsigned int)acc;
        acc >>= 32;

        acc += rp[7];
        acc += bp[8 - 8];
        acc += bp[9 - 8];
        acc += bp[10 - 8];
        acc += bp[11 - 8];
        acc += bp[12 - 8];
        acc += bp[12 - 8];
        acc += bp[13 - 8];
        acc += bp[13 - 8];
        acc += bp[14 - 8];
        acc += bp[14 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        acc += bp[15 - 8];
        rp[7] = (unsigned int)acc;
        carry = (int)(acc >> 32);
    }
#else
    {
        BN_ULONG t_d[BN_SM2_256_TOP];

        /*
         * + 2(c6 + c7 + c8 + c9)
         */
	sm2_set_256(t_d, buf.bn, 12,  0, 15, 14, 13, 0, 14, 13);

	sm2_set_256(c_d, buf.bn, 13,  0,  0,  0, 14, 0, 15, 14);
	carry = (int)bn_add_words(t_d, t_d, c_d, BN_SM2_256_TOP);

	sm2_set_256(c_d, buf.bn, 14,  0,  0,  0,  0, 0,  0, 15);
	carry += (int)bn_add_words(t_d, c_d, c_d, BN_SM2_256_TOP);

	sm2_set_256(c_d, buf.bn, 15,  0,  0,  0,  0, 0,  0,  0);
	carry += (int)bn_add_words(t_d, c_d, c_d, BN_SM2_256_TOP);

        /* left shift */
        {
            register BN_ULONG *ap, t, c;
            ap = t_d;
            c = 0;
            for (i = BN_SM2_256_TOP; i != 0; --i) {
                t = *ap;
                *(ap++) = ((t << 1) | c) & BN_MASK2;
                c = (t & BN_TBIT) ? 1 : 0;
            }
            carry <<= 1;
            carry |= c;
        }
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	/*
	 * + c1 + c2 + c3 + c4 + c5
	 */
	sm2_set_256(t_d, buf.bn,  8, 11, 10,  9,  8, 0,  9,  8);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn,  9, 14, 13, 12, 11, 0, 10,  9);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn, 10, 15, 14, 13, 12, 0, 11, 10);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn, 11,  0,  0,  0,  0, 0, 12, 11);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn, 15,  0,  0,  0,  0, 0, 13, 12);
        carry += (int)bn_add_words(r_d, r_d, t_d, BN_SM2_256_TOP);

	/*
	 * - (c10 + c11 + c12 + c13)
	 */
	sm2_set_256(t_d, buf.bn,  0,  0,  0,  0,  0, 8,  0,  0);
	(void)bn_add_words(c_d, c_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn,  0,  0,  0,  0,  0, 9,  0,  0);
	(void)bn_add_words(c_d, c_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn,  0,  0,  0,  0,  0,13,  0,  0);
	(void)bn_add_words(c_d, c_d, t_d, BN_SM2_256_TOP);

	sm2_set_256(t_d, buf.bn,  0,  0,  0,  0,  0,14,  0,  0);
	(void)bn_add_words(c_d, c_d, t_d, BN_SM2_256_TOP);

	carry -= (int)bn_sub_words(r_d, r_d, c_d, BN_SM2_256_TOP);

    }
#endif
    /* see BN_nist_mod_224 for explanation */
    u.f = bn_sub_words;
    if (carry > 0)
        carry =
            (int)bn_sub_words(r_d, r_d, _sm2_p_256[carry - 1],
                              BN_SM2_256_TOP);
    else if (carry < 0) {
        carry =
            (int)bn_add_words(r_d, r_d, _sm2_p_256[-carry - 1],
                              BN_SM2_256_TOP);
        mask = 0 - (PTR_SIZE_INT) carry;
        u.p = ((PTR_SIZE_INT) bn_sub_words & mask) |
            ((PTR_SIZE_INT) bn_add_words & ~mask);
    } else
        carry = 1;

    mask =
        0 - (PTR_SIZE_INT) (*u.f) (c_d, r_d, _sm2_p_256[0], BN_SM2_256_TOP);
    mask &= 0 - (PTR_SIZE_INT) carry;
    res = c_d;
    res = (BN_ULONG *)(((PTR_SIZE_INT) res & ~mask) |
                       ((PTR_SIZE_INT) r_d & mask));
    sm2_cp_bn(r_d, res, BN_SM2_256_TOP);
    r->top = BN_SM2_256_TOP;
    bn_correct_top(r);

    return 1;
}

/* I dont think we need this */
#if 0
int (*BN_nist_mod_func(const BIGNUM *p)) (BIGNUM *r, const BIGNUM *a,
                                          const BIGNUM *field, BN_CTX *ctx) {
    if (BN_ucmp(&_bignum_nist_p_256, p) == 0)
        return BN_nist_mod_256;
    return 0;
}
#endif
