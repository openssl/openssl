/* crypto/bn/bn_nist.c */
/*
 * Written by Nils Larsch for the OpenSSL project
 */
/* ====================================================================
 * Copyright (c) 1998-2005 The OpenSSL Project.  All rights reserved.
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
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#include "bn_lcl.h"
#include "cryptlib.h"

#define BN_NIST_192_TOP	(192+BN_BITS2-1)/BN_BITS2
#define BN_NIST_224_TOP	(224+BN_BITS2-1)/BN_BITS2
#define BN_NIST_256_TOP	(256+BN_BITS2-1)/BN_BITS2
#define BN_NIST_384_TOP	(384+BN_BITS2-1)/BN_BITS2
#define BN_NIST_521_TOP	(521+BN_BITS2-1)/BN_BITS2

#if BN_BITS2 == 64
static const BN_ULONG _nist_p_192[] =
	{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFEULL,
	0xFFFFFFFFFFFFFFFFULL};
static const BN_ULONG _nist_p_224[] =
	{0x0000000000000001ULL,0xFFFFFFFF00000000ULL,
	0xFFFFFFFFFFFFFFFFULL,0x00000000FFFFFFFFULL};
static const BN_ULONG _nist_p_256[] =
	{0xFFFFFFFFFFFFFFFFULL,0x00000000FFFFFFFFULL,
	0x0000000000000000ULL,0xFFFFFFFF00000001ULL};
static const BN_ULONG _nist_p_384[] =
	{0x00000000FFFFFFFFULL,0xFFFFFFFF00000000ULL,
	0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
static const BN_ULONG _nist_p_521[] =
	{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0x00000000000001FFULL};
#elif BN_BITS2 == 32
static const BN_ULONG _nist_p_192[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
static const BN_ULONG _nist_p_224[] = {0x00000001,0x00000000,0x00000000,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
static const BN_ULONG _nist_p_256[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0x00000000,0x00000000,0x00000000,0x00000001,0xFFFFFFFF};
static const BN_ULONG _nist_p_384[] = {0xFFFFFFFF,0x00000000,0x00000000,
	0xFFFFFFFF,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
static const BN_ULONG _nist_p_521[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0x000001FF};
#endif

const BIGNUM *BN_get0_nist_prime_192(void)
	{
	static BIGNUM const_nist_192 = { (BN_ULONG *)_nist_p_192,
		BN_NIST_192_TOP, BN_NIST_192_TOP, 0, BN_FLG_STATIC_DATA };
	return &const_nist_192;
	}

const BIGNUM *BN_get0_nist_prime_224(void)
	{
	static BIGNUM const_nist_224 = { (BN_ULONG *)_nist_p_224,
		BN_NIST_224_TOP, BN_NIST_224_TOP, 0, BN_FLG_STATIC_DATA };
	return &const_nist_224;
	}

const BIGNUM *BN_get0_nist_prime_256(void)
	{
	static BIGNUM const_nist_256 = { (BN_ULONG *)_nist_p_256,
		BN_NIST_256_TOP, BN_NIST_256_TOP, 0, BN_FLG_STATIC_DATA };
	return &const_nist_256;
	}

const BIGNUM *BN_get0_nist_prime_384(void)
	{
	static BIGNUM const_nist_384 = { (BN_ULONG *)_nist_p_384,
		BN_NIST_384_TOP, BN_NIST_384_TOP, 0, BN_FLG_STATIC_DATA };
	return &const_nist_384;
	}

const BIGNUM *BN_get0_nist_prime_521(void)
	{
	static BIGNUM const_nist_521 = { (BN_ULONG *)_nist_p_521,
		BN_NIST_521_TOP, BN_NIST_521_TOP, 0, BN_FLG_STATIC_DATA };
	return &const_nist_521;
	}

#define BN_NIST_ADD_ONE(a)	while (!(*(a)=(*(a)+1)&BN_MASK2)) ++(a);

static void nist_cp_bn_0(BN_ULONG *buf, BN_ULONG *a, int top, int max)
        {
	int i;
        BN_ULONG *_tmp1 = (buf), *_tmp2 = (a);
        for (i = (top); i != 0; i--)
                *_tmp1++ = *_tmp2++;
        for (i = (max) - (top); i != 0; i--)
                *_tmp1++ = (BN_ULONG) 0;
        }

static void nist_cp_bn(BN_ULONG *buf, BN_ULONG *a, int top)
        { 
	int i;
        BN_ULONG *_tmp1 = (buf), *_tmp2 = (a);
        for (i = (top); i != 0; i--)
                *_tmp1++ = *_tmp2++;
        }

#if BN_BITS2 == 64
#define bn_cp_64(to, n, from, m)	(to)[n] = (m>=0)?((from)[m]):0;
#define bn_64_set_0(to, n)		(to)[n] = (BN_ULONG)0;
/* TBD */
#define bn_cp_32(to, n, from, m)	(to)[n] = (m>=0)?((from)[m]):0;
#define bn_32_set_0(to, n)		(to)[n] = (BN_ULONG)0;
#else
#define bn_cp_64(to, n, from, m) \
	{ \
	bn_cp_32(to, (n)*2, from, (m)*2); \
	bn_cp_32(to, (n)*2+1, from, (m)*2+1); \
	}
#define bn_64_set_0(to, n) \
	{ \
	bn_32_set_0(to, (n)*2); \
	bn_32_set_0(to, (n)*2+1); \
	}
#if BN_BITS2 == 32
#define bn_cp_32(to, n, from, m)	(to)[n] = (m>=0)?((from)[m]):0;
#define bn_32_set_0(to, n)		(to)[n] = (BN_ULONG)0;
#endif
#endif /* BN_BITS2 != 64 */


#define nist_set_192(to, from, a1, a2, a3) \
	{ \
	if (a3 != 0) bn_cp_64(to, 0, from, (a3) - 3) else bn_64_set_0(to, 0)\
	bn_cp_64(to, 1, from, (a2) - 3) \
	if (a1 != 0) bn_cp_64(to, 2, from, (a1) - 3) else bn_64_set_0(to, 2)\
	}

int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
	int      top = a->top, i;
	int      carry;
	register BN_ULONG *r_d, *a_d = a->d;
	BN_ULONG t_d[BN_NIST_192_TOP],
	         buf[BN_NIST_192_TOP],
		 c_d[BN_NIST_192_TOP],
		*res;
	size_t   mask;

	i = BN_ucmp(field, a);
	if (i == 0)
		{
		BN_zero(r);
		return 1;
		}
	else if (i > 0)
		return (r == a) ? 1 : (BN_copy(r ,a) != NULL);

	if (top == BN_NIST_192_TOP)
		return BN_usub(r, a, field);

	if (r != a)
		{
		if (!bn_wexpand(r, BN_NIST_192_TOP))
			return 0;
		r_d = r->d;
		nist_cp_bn(r_d, a_d, BN_NIST_192_TOP);
		}
	else
		r_d = a_d;

	nist_cp_bn_0(buf, a_d + BN_NIST_192_TOP, top - BN_NIST_192_TOP, BN_NIST_192_TOP);

	nist_set_192(t_d, buf, 0, 3, 3);
	carry = bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_192,BN_NIST_192_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));
	
	nist_set_192(t_d, buf, 4, 4, 0);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_192_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_192,BN_NIST_192_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	nist_set_192(t_d, buf, 5, 5, 5)
	carry = bn_add_words(r_d, res, t_d, BN_NIST_192_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_192,BN_NIST_192_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	nist_cp_bn(r_d, res, BN_NIST_192_TOP);
	r->top = BN_NIST_192_TOP;
	bn_correct_top(r);

	return 1;
	}

#define nist_set_224(to, from, a1, a2, a3, a4, a5, a6, a7) \
	{ \
	if (a7 != 0) bn_cp_32(to, 0, from, (a7) - 7) else bn_32_set_0(to, 0)\
	if (a6 != 0) bn_cp_32(to, 1, from, (a6) - 7) else bn_32_set_0(to, 1)\
	if (a5 != 0) bn_cp_32(to, 2, from, (a5) - 7) else bn_32_set_0(to, 2)\
	if (a4 != 0) bn_cp_32(to, 3, from, (a4) - 7) else bn_32_set_0(to, 3)\
	if (a3 != 0) bn_cp_32(to, 4, from, (a3) - 7) else bn_32_set_0(to, 4)\
	if (a2 != 0) bn_cp_32(to, 5, from, (a2) - 7) else bn_32_set_0(to, 5)\
	if (a1 != 0) bn_cp_32(to, 6, from, (a1) - 7) else bn_32_set_0(to, 6)\
	}

int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#if BN_BITS2 == 32
	int	top = a->top, i;
	int	carry;
	BN_ULONG *r_d, *a_d = a->d;
	BN_ULONG t_d[BN_NIST_224_TOP],
	         buf[BN_NIST_224_TOP],
		 c_d[BN_NIST_224_TOP],
		*res;
	size_t   mask;

	i = BN_ucmp(field, a);
	if (i == 0)
		{
		BN_zero(r);
		return 1;
		}
	else if (i > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (top == BN_NIST_224_TOP)
		return BN_usub(r, a, field);

	if (r != a)
		{
		if (!bn_wexpand(r, BN_NIST_224_TOP))
			return 0;
		r_d = r->d;
		nist_cp_bn(r_d, a_d, BN_NIST_224_TOP);
		}
	else
		r_d = a_d;

	nist_cp_bn_0(buf, a_d + BN_NIST_224_TOP, top - BN_NIST_224_TOP, BN_NIST_224_TOP);

	nist_set_224(t_d, buf, 10, 9, 8, 7, 0, 0, 0);
	carry = bn_add_words(r_d, r_d, t_d, BN_NIST_224_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_224,BN_NIST_224_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));
	
	nist_set_224(t_d, buf, 0, 13, 12, 11, 0, 0, 0);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_224_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_224,BN_NIST_224_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	nist_set_224(t_d, buf, 13, 12, 11, 10, 9, 8, 7);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_224_TOP);
	bn_add_words(c_d,r_d,_nist_p_224,BN_NIST_224_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));
#else
	if (bn_sub_words(r_d, res, t_d, BN_NIST_224_TOP))
		bn_add_words(r_d,r_d,_nist_p_224,BN_NIST_224_TOP);
#endif
	nist_set_224(t_d, buf, 0, 0, 0, 0, 13, 12, 11);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_224_TOP);
	bn_add_words(c_d,r_d,_nist_p_224,BN_NIST_224_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	nist_cp_bn(r_d, res, BN_NIST_224_TOP);
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_224_TOP))
		bn_add_words(r_d,r_d,_nist_p_224,BN_NIST_224_TOP);
#endif
	r->top = BN_NIST_224_TOP;
	bn_correct_top(r);

	return 1;
#else	/* BN_BITS!=32 */
	return 0;
#endif
	}

#define nist_set_256(to, from, a1, a2, a3, a4, a5, a6, a7, a8) \
	{ \
	if (a8 != 0) bn_cp_32(to, 0, from, (a8) - 8) else bn_32_set_0(to, 0)\
	if (a7 != 0) bn_cp_32(to, 1, from, (a7) - 8) else bn_32_set_0(to, 1)\
	if (a6 != 0) bn_cp_32(to, 2, from, (a6) - 8) else bn_32_set_0(to, 2)\
	if (a5 != 0) bn_cp_32(to, 3, from, (a5) - 8) else bn_32_set_0(to, 3)\
	if (a4 != 0) bn_cp_32(to, 4, from, (a4) - 8) else bn_32_set_0(to, 4)\
	if (a3 != 0) bn_cp_32(to, 5, from, (a3) - 8) else bn_32_set_0(to, 5)\
	if (a2 != 0) bn_cp_32(to, 6, from, (a2) - 8) else bn_32_set_0(to, 6)\
	if (a1 != 0) bn_cp_32(to, 7, from, (a1) - 8) else bn_32_set_0(to, 7)\
	}

int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#if BN_BITS2 == 32
	int	i, top = a->top;
	int	carry = 0;
	register BN_ULONG *a_d = a->d, *r_d;
	BN_ULONG t_d[BN_NIST_256_TOP],
	         buf[BN_NIST_256_TOP],
		 c_d[BN_NIST_256_TOP],
		*res;
	size_t   mask;

	i = BN_ucmp(field, a);
	if (i == 0)
		{
		BN_zero(r);
		return 1;
		}
	else if (i > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (top == BN_NIST_256_TOP)
		return BN_usub(r, a, field);

	if (r != a)
		{
		if (!bn_wexpand(r, BN_NIST_256_TOP))
			return 0;
		r_d = r->d;
		nist_cp_bn(r_d, a_d, BN_NIST_256_TOP);
		}
	else
		r_d = a_d;

	nist_cp_bn_0(buf, a_d + BN_NIST_256_TOP, top - BN_NIST_256_TOP, BN_NIST_256_TOP);

	/*S1*/
	nist_set_256(t_d, buf, 15, 14, 13, 12, 11, 0, 0, 0);
	/*S2*/
	nist_set_256(c_d,buf, 0, 15, 14, 13, 12, 0, 0, 0);
	carry = bn_add_words(t_d, t_d, c_d, BN_NIST_256_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,t_d,_nist_p_256,BN_NIST_256_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)t_d&~mask));

	carry = bn_add_words(t_d, res, res, BN_NIST_256_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,t_d,_nist_p_256,BN_NIST_256_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)t_d&~mask));

	carry = bn_add_words(r_d, r_d, res, BN_NIST_256_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S3*/
	nist_set_256(t_d, buf, 15, 14, 0, 0, 0, 10, 9, 8);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_256_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S4*/
	nist_set_256(t_d, buf, 8, 13, 15, 14, 13, 11, 10, 9);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_256_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*D1*/
	nist_set_256(t_d, buf, 10, 8, 0, 0, 0, 13, 12, 11);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_256_TOP);
	bn_add_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));	
#else
	if (bn_sub_words(r_d, res, t_d, BN_NIST_256_TOP))
		bn_add_words(r_d,r_d,_nist_p_256,BN_NIST_256_TOP);
#endif
	/*D2*/
	nist_set_256(t_d, buf, 11, 9, 0, 0, 15, 14, 13, 12);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_256_TOP);
	bn_add_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));	
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		bn_add_words(r_d,r_d,_nist_p_256,BN_NIST_256_TOP);
#endif
	/*D3*/
	nist_set_256(t_d, buf, 12, 0, 10, 9, 8, 15, 14, 13);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_256_TOP);
	bn_add_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));	
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		bn_add_words(r_d,r_d,_nist_p_256,BN_NIST_256_TOP);
#endif
	/*D4*/
	nist_set_256(t_d, buf, 13, 0, 11, 10, 9, 0, 15, 14);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_256_TOP);
	bn_add_words(c_d,r_d,_nist_p_256,BN_NIST_256_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));	

	nist_cp_bn(r_d, res, BN_NIST_384_TOP);
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		bn_add_words(r_d,r_d,_nist_p_256,BN_NIST_256_TOP);
#endif
	r->top = BN_NIST_256_TOP;
	bn_correct_top(r);

	return 1;
#else	/* BN_BITS!=32 */
	return 0;
#endif
	}

#define nist_set_384(to,from,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12) \
	{ \
	if (a12 != 0) bn_cp_32(to, 0, from,  (a12) - 12) else bn_32_set_0(to, 0)\
	if (a11 != 0) bn_cp_32(to, 1, from,  (a11) - 12) else bn_32_set_0(to, 1)\
	if (a10 != 0) bn_cp_32(to, 2, from,  (a10) - 12) else bn_32_set_0(to, 2)\
	if (a9 != 0)  bn_cp_32(to, 3, from,  (a9) - 12)  else bn_32_set_0(to, 3)\
	if (a8 != 0)  bn_cp_32(to, 4, from,  (a8) - 12)  else bn_32_set_0(to, 4)\
	if (a7 != 0)  bn_cp_32(to, 5, from,  (a7) - 12)  else bn_32_set_0(to, 5)\
	if (a6 != 0)  bn_cp_32(to, 6, from,  (a6) - 12)  else bn_32_set_0(to, 6)\
	if (a5 != 0)  bn_cp_32(to, 7, from,  (a5) - 12)  else bn_32_set_0(to, 7)\
	if (a4 != 0)  bn_cp_32(to, 8, from,  (a4) - 12)  else bn_32_set_0(to, 8)\
	if (a3 != 0)  bn_cp_32(to, 9, from,  (a3) - 12)  else bn_32_set_0(to, 9)\
	if (a2 != 0)  bn_cp_32(to, 10, from, (a2) - 12)  else bn_32_set_0(to, 10)\
	if (a1 != 0)  bn_cp_32(to, 11, from, (a1) - 12)  else bn_32_set_0(to, 11)\
	}

int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#if BN_BITS2 == 32
	int	i, top = a->top;
	int	carry = 0;
	register BN_ULONG *r_d, *a_d = a->d;
	BN_ULONG t_d[BN_NIST_384_TOP],
	         buf[BN_NIST_384_TOP],
		 c_d[BN_NIST_384_TOP],
		*res;
	size_t	 mask;

	i = BN_ucmp(field, a);
	if (i == 0)
		{
		BN_zero(r);
		return 1;
		}
	else if (i > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (top == BN_NIST_384_TOP)
		return BN_usub(r, a, field);

	if (r != a)
		{
		if (!bn_wexpand(r, BN_NIST_384_TOP))
			return 0;
		r_d = r->d;
		nist_cp_bn(r_d, a_d, BN_NIST_384_TOP);
		}
	else
		r_d = a_d;

	nist_cp_bn_0(buf, a_d + BN_NIST_384_TOP, top - BN_NIST_384_TOP, BN_NIST_384_TOP);

	/*S1*/
	nist_set_256(t_d, buf, 0, 0, 0, 0, 0, 23-4, 22-4, 21-4);
		/* left shift */
		{
		register BN_ULONG *ap,t,c;
		ap = t_d;
		c=0;
		for (i = 3; i != 0; --i)
			{
			t= *ap;
			*(ap++)=((t<<1)|c)&BN_MASK2;
			c=(t & BN_TBIT)?1:0;
			}
		*ap=c;
		}
	carry = bn_add_words(r_d+(128/BN_BITS2), r_d+(128/BN_BITS2), 
		t_d, BN_NIST_256_TOP);
	/*
	 * we need if (result>=modulus) subtract(result,modulus);
	 * in n-bit space this can be expressed as
	 * if (carry || result>=modulus) subtract(result,modulus);
	 * the catch is that comparison implies subtraction and
	 * therefore one can write tmp=subtract(result,modulus);
	 * and then if(carry || !borrow) result=tmp; this's what
	 * happens below, but without explicit if:-) a.
	 */
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S2 */
	carry = bn_add_words(r_d, res, buf, BN_NIST_384_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S3*/
	nist_set_384(t_d,buf,20,19,18,17,16,15,14,13,12,23,22,21);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_384_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S4*/
	nist_set_384(t_d,buf,19,18,17,16,15,14,13,12,20,0,23,0);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_384_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S5*/
	nist_set_384(t_d, buf,0,0,0,0,23,22,21,20,0,0,0,0);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_384_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*S6*/
	nist_set_384(t_d,buf,0,0,0,0,0,0,23,22,21,0,0,20);
	carry = bn_add_words(r_d, res, t_d, BN_NIST_384_TOP);
	mask = 0-(size_t)bn_sub_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = ~mask | (0-(size_t)carry);
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	/*D1*/
	nist_set_384(t_d,buf,22,21,20,19,18,17,16,15,14,13,12,23);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_384_TOP);
	bn_add_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));
#else
	if (bn_sub_words(r_d, res, t_d, BN_NIST_384_TOP))
		bn_add_words(r_d,r_d,_nist_p_384,BN_NIST_384_TOP);
#endif
	/*D2*/
	nist_set_384(t_d,buf,0,0,0,0,0,0,0,23,22,21,20,0);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_384_TOP);
	bn_add_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		bn_add_words(r_d,r_d,_nist_p_384,BN_NIST_384_TOP);
#endif
	/*D3*/
	nist_set_384(t_d,buf,0,0,0,0,0,0,0,23,23,0,0,0);
#if BRANCH_FREE
	carry = bn_sub_words(r_d, res, t_d, BN_NIST_384_TOP);
	bn_add_words(c_d,r_d,_nist_p_384,BN_NIST_384_TOP);
	mask = 0-(size_t)carry;
	res = (BN_ULONG *)(((size_t)c_d&mask) | ((size_t)r_d&~mask));

	nist_cp_bn(r_d, res, BN_NIST_384_TOP);
#else
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		bn_add_words(r_d,r_d,_nist_p_384,BN_NIST_384_TOP);
#endif
	r->top = BN_NIST_384_TOP;
	bn_correct_top(r);

	return 1;
#else	/* BN_BITS!=32 */
	return 0;
#endif
	}

int BN_nist_mod_521(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#if BN_BITS2 == 64
#define BN_NIST_521_TOP_MASK	(BN_ULONG)0x1FF
#elif BN_BITS2 == 32
#define BN_NIST_521_TOP_MASK	(BN_ULONG)0x1FF
#endif
	int	top, ret = 0;
	BN_ULONG *r_d;
	BIGNUM	*tmp;

	/* check whether a reduction is necessary */
	top = a->top;
	if (top < BN_NIST_521_TOP  || ( top == BN_NIST_521_TOP &&
           (!(a->d[BN_NIST_521_TOP-1] & ~(BN_NIST_521_TOP_MASK)))))
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	BN_CTX_start(ctx);
	tmp = BN_CTX_get(ctx);
	if (!tmp)
		goto err;

	if (!bn_wexpand(tmp, BN_NIST_521_TOP))
		goto err;
	nist_cp_bn(tmp->d, a->d, BN_NIST_521_TOP);

	tmp->top = BN_NIST_521_TOP;
        tmp->d[BN_NIST_521_TOP-1]  &= BN_NIST_521_TOP_MASK;
	bn_correct_top(tmp);

	if (!BN_rshift(r, a, 521))
		goto err;

	if (!BN_uadd(r, tmp, r))
		goto err;
	top = r->top;
	r_d = r->d;
	if (top == BN_NIST_521_TOP  && 
           (r_d[BN_NIST_521_TOP-1] & ~(BN_NIST_521_TOP_MASK)))
		{
		BN_NIST_ADD_ONE(r_d)
		r->d[BN_NIST_521_TOP-1] &= BN_NIST_521_TOP_MASK; 
		}
	bn_correct_top(r);

	ret = 1;
err:
	BN_CTX_end(ctx);

	bn_check_top(r);
	return ret;
	}
