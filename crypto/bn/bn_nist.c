/* crypto/bn/bn_nist.c */
/* ====================================================================
 * Copyright (c) 1998-2002 The OpenSSL Project.  All rights reserved.
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
const static BN_ULONG _nist_p_192[] =
	{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFEULL,
	0xFFFFFFFFFFFFFFFFULL};
const static BN_ULONG _nist_p_224[] =
	{0x0000000000000001ULL,0xFFFFFFFF00000000ULL,
	0xFFFFFFFFFFFFFFFFULL,0x00000000FFFFFFFFULL};
const static BN_ULONG _nist_p_256[] =
	{0xFFFFFFFFFFFFFFFFULL,0x00000000FFFFFFFFULL,
	0x0000000000000000ULL,0xFFFFFFFF00000001ULL};
const static BN_ULONG _nist_p_384[] =
	{0x00000000FFFFFFFFULL,0xFFFFFFFF00000000ULL,
	0xFFFFFFFFFFFFFFFEULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL};
const static BN_ULONG _nist_p_521[] =
	{0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,
	0x00000000000001FFULL};
#elif BN_BITS2 == 32
const static BN_ULONG _nist_p_192[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFE,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
const static BN_ULONG _nist_p_224[] = {0x00000001,0x00000000,0x00000000,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
const static BN_ULONG _nist_p_256[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0x00000000,0x00000000,0x00000000,0x00000001,0xFFFFFFFF};
const static BN_ULONG _nist_p_384[] = {0xFFFFFFFF,0x00000000,0x00000000,
	0xFFFFFFFF,0xFFFFFFFE,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF};
const static BN_ULONG _nist_p_521[] = {0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,0xFFFFFFFF,
	0xFFFFFFFF,0x000001FF};
#elif BN_BITS2 == 16
const static BN_ULONG _nist_p_192[] = {0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFE,
	0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF};
const static BN_ULONG _nist_p_224[] = {0x0001,0x0000,0x0000,0x0000,0x0000,
	0x0000,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF};
const static BN_ULONG _nist_p_256[] = {0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,
	0xFFFF,0x0000,0x0000,0x0000,0x0000,0x0000,0x0000,0x0001,0x0000,0xFFFF,
	0xFFFF};
const static BN_ULONG _nist_p_384[] = {0xFFFF,0xFFFF,0x0000,0x0000,0x0000,
	0x0000,0xFFFF,0xFFFF,0xFFFE,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,
	0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF};
const static BN_ULONG _nist_p_521[] = {0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,
	0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,
	0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,
	0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0xFFFF,0x01FF};
#elif BN_BITS2 == 8
const static BN_ULONG _nist_p_192[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF};
const static BN_ULONG _nist_p_224[] = {0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const static BN_ULONG _nist_p_256[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
	0x00,0x00,0x01,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF};
const static BN_ULONG _nist_p_384[] = {0xFF,0xFF,0xFF,0xFF,0x00,0x00,0x00,0x00,
	0x00,0x00,0x00,0x00,0xFF,0xFF,0xFF,0xFF,0xFE,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
const static BN_ULONG _nist_p_521[] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,
	0xFF,0x01};
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

/* some misc internal functions */
static BN_ULONG _256_data[BN_NIST_256_TOP*6];
static int _is_set_256_data = 0;
static void _init_256_data(void);

static BN_ULONG _384_data[BN_NIST_384_TOP*8];
static int _is_set_384_data = 0;
static void _init_384_data(void);

#define BN_NIST_ADD_ONE(a)	while (!(++(*(a)))) ++(a);
#define __buf_0			(BN_ULONG)0
#define __buf_0_1		(BN_ULONG)0
#define __buf_0_2		(BN_ULONG)0
#if BN_BITS2 == 64
#define BN_64_BIT_BUF(n)	BN_ULONG __buf_##n = (BN_ULONG)0;
#define BN_CP_64_TO_BUF(n)	__buf_##n = (a)[(n)];
#define BN_CP_64_FROM_BUF(a,n)	*(a)++ = __buf_##n;
#define BN_CASE_64_BIT(n,a)	case (n): __buf_##n = (a)[(n)];
#if	UINT_MAX == 4294967295UL
#define	nist32	unsigned int
#define BN_32_BIT_BUF(n)	nist32 __buf_##n = (nist32)0;
#define BN_CP_32_TO_BUF(n)	__buf_##n = ((nist32 *)(a))[(n)];
#define BN_CP_32_FROM_BUF(a,n)	*((nist32)(a))++ = __buf_##n;
#define BN_CASE_32_BIT(n,a)	case (n): __buf_##n = ((nist32)(a))[(n)];
#elif	ULONG_MAX == 4294967295UL
#define	nist32	unsigned long
#define BN_32_BIT_BUF(n)	nist32 __buf_##n = (nist32)0;
#define BN_CP_32_TO_BUF(n)	__buf_##n = ((nist32 *)(a))[(n)];
#define BN_CP_32_FROM_BUF(a,n)	*((nist32)(a))++ = __buf_##n;
#define BN_CASE_32_BIT(n,a)	case (n): __buf_##n = ((nist32)(a))[(n)];
#else
#define	NO_32_BIT_TYPE
#endif
#elif BN_BITS2 == 32
#define BN_64_BIT_BUF(n)	BN_ULONG __buf_##n##_1 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_2 = (BN_ULONG)0;
#define BN_CP_64_TO_BUF(n)	__buf_##n##_2 = (a)[2*(n)+1];\
				__buf_##n##_1 = (a)[2*(n)];
#define BN_CP_64_FROM_BUF(a,n)	*(a)++ = __buf_##n##_1;\
				*(a)++ = __buf_##n##_2;
#define BN_CASE_64_BIT(n,a)	case 2*(n)+1: __buf_##n##_2 = (a)[2*(n)+1];\
				case 2*(n):   __buf_##n##_1 = (a)[2*(n)];
				
#define BN_32_BIT_BUF(n)	BN_ULONG __buf_##n = (BN_ULONG)0;
#define BN_CP_32_TO_BUF(n)	__buf_##n = (a)[(n)];
#define BN_CP_32_FROM_BUF(a,n)	*(a)++ = __buf_##n;
#define BN_CASE_32_BIT(n,a)	case (n): __buf_##n = (a)[(n)];
#elif BN_BITS2 == 16
#define __buf_0_3		(BN_ULONG)0
#define __buf_0_4		(BN_ULONG)0
#define BN_64_BIT_BUF(n)	BN_ULONG __buf_##n##_1 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_2 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_3 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_4 = (BN_ULONG)0;
#define BN_CP_64_TO_BUF(n)	__buf_##n##_4 = (a)[4*(n)+3];\
				__buf_##n##_3 = (a)[4*(n)+2];\
				__buf_##n##_2 = (a)[4*(n)+1];\
				__buf_##n##_1 = (a)[4*(n)];
#define BN_CP_64_FROM_BUF(a,n)	*(a)++ = __buf_##n##_1;\
				*(a)++ = __buf_##n##_2;\
				*(a)++ = __buf_##n##_3;\
				*(a)++ = __buf_##n##_4;
#define BN_CASE_64_BIT(n,a)	case 4*(n)+3: __buf_##n##_4 = (a)[4*(n)+3];\
				case 4*(n)+2: __buf_##n##_3 = (a)[4*(n)+2];\
				case 4*(n)+1: __buf_##n##_2 = (a)[4*(n)+1];\
				case 4*(n):   __buf_##n##_1 = (a)[4*(n)];
#define BN_32_BIT_BUF(n)	BN_ULONG __buf_##n##_1 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_2 = (BN_ULONG)0;
#define BN_CP_32_TO_BUF(n)	__buf_##n##_1 = (a)[2*(n)];\
				__buf_##n##_2 = (a)[2*(n)+1];
#define BN_CP_32_FROM_BUF(a,n)	*(a)++ = __buf_##n##_1;\
				*(a)++ = __buf_##n##_2;
#define BN_CASE_32_BIT(n,a)	case 2*(n)+1: __buf_##n##_2 = (a)[2*(n)+1];\
				case 2*(n):   __buf_##n##_1 = (a)[2*(n)];
#elif BN_BITS2 == 8
#define __buf_0_3		(BN_ULONG)0
#define __buf_0_4		(BN_ULONG)0
#define __buf_0_5		(BN_ULONG)0
#define __buf_0_6		(BN_ULONG)0
#define __buf_0_7		(BN_ULONG)0
#define __buf_0_8		(BN_ULONG)0
#define BN_64_BIT_BUF(n)	BN_ULONG __buf_##n##_1 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_2 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_3 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_4 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_5 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_6 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_7 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_8 = (BN_ULONG)0;
#define BN_CP_64_TO_BUF(n)	__buf_##n##_8 = (a)[8*(n)+7];\
				__buf_##n##_7 = (a)[8*(n)+6];\
				__buf_##n##_6 = (a)[8*(n)+5];\
				__buf_##n##_5 = (a)[8*(n)+4];\
				__buf_##n##_4 = (a)[8*(n)+3];\
				__buf_##n##_3 = (a)[8*(n)+2];\
				__buf_##n##_2 = (a)[8*(n)+1];\
				__buf_##n##_1 = (a)[8*(n)];
#define BN_CP_64_FROM_BUF(a,n)	*(a)++ = __buf_##n##_1;\
				*(a)++ = __buf_##n##_2;\
				*(a)++ = __buf_##n##_3;\
				*(a)++ = __buf_##n##_4;\
				*(a)++ = __buf_##n##_5;\
				*(a)++ = __buf_##n##_6;\
				*(a)++ = __buf_##n##_7;\
				*(a)++ = __buf_##n##_8;
#define BN_CASE_64_BIT(n,a)	case 8*(n)+7: __buf_##n##_8 = (a)[8*(n)+7];\
				case 8*(n)+6: __buf_##n##_7 = (a)[8*(n)+6];\
				case 8*(n)+5: __buf_##n##_6 = (a)[8*(n)+5];\
				case 8*(n)+4: __buf_##n##_5 = (a)[8*(n)+4];\
				case 8*(n)+3: __buf_##n##_4 = (a)[8*(n)+3];\
				case 8*(n)+2: __buf_##n##_3 = (a)[8*(n)+2];\
				case 8*(n)+1: __buf_##n##_2 = (a)[8*(n)+1];\
				case 8*(n):   __buf_##n##_1 = (a)[8*(n)];
#define BN_32_BIT_BUF(n)	BN_ULONG __buf_##n##_1 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_2 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_3 = (BN_ULONG)0;\
				BN_ULONG __buf_##n##_4 = (BN_ULONG)0;
#define BN_CP_32_TO_BUF(n)	__buf_##n##_1 = (a)[4*(n)];\
				__buf_##n##_2 = (a)[4*(n)+1];\
				__buf_##n##_3 = (a)[4*(n)+2];\
				__buf_##n##_4 = (a)[4*(n)+3];
#define BN_CP_32_FROM_BUF(a,n)	*(a)++ = __buf_##n##_1;\
				*(a)++ = __buf_##n##_2;\
				*(a)++ = __buf_##n##_3;\
				*(a)++ = __buf_##n##_4;
#define BN_CASE_32_BIT(n,a)	case 4*(n)+3: __buf_##n##_4 = (a)[4*(n)+3];\
				case 4*(n)+2: __buf_##n##_3 = (a)[4*(n)+2];\
				case 4*(n)+1: __buf_##n##_2 = (a)[4*(n)+1];\
				case 4*(n):   __buf_##n##_1 = (a)[4*(n)];
#endif


#define BN_192_SET(d,a1,a2,a3) \
	{\
	register BN_ULONG *td = (d);\
	BN_CP_64_FROM_BUF(td,a3); BN_CP_64_FROM_BUF(td,a2);\
	BN_CP_64_FROM_BUF(td,a1);\
	}

int BN_nist_mod_192(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
	int      top;
	BN_ULONG carry = 0;
	register BN_ULONG *r_d, *a_d;
	BN_ULONG t_d[BN_NIST_192_TOP];
	BN_64_BIT_BUF(3)  BN_64_BIT_BUF(4)
	BN_64_BIT_BUF(5)

	top = BN_ucmp(field, a);
	if (top == 0)
		return BN_zero(r);
	else if (top > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (r != a)
		if (!BN_ncopy(r, a, BN_NIST_192_TOP))
			return 0;

	r_d = r->d;
	a_d = a->d;
	top = a->top-1;

	switch (top)
		{
		BN_CASE_64_BIT(5, a_d)
		BN_CASE_64_BIT(4, a_d)
		BN_CASE_64_BIT(3, a_d)
			break;
		default: /* a->top == field->top */
			return BN_usub(r, a, field);
		}

	BN_192_SET(t_d,0,3,3)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP))
		++carry;

	BN_192_SET(t_d,4,4,0)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP))
		++carry;

	BN_192_SET(t_d,5,5,5)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_192_TOP))
		++carry;

	while (carry)
		{
		if (bn_sub_words(r_d, r_d, _nist_p_192, BN_NIST_192_TOP))
			--carry; 
		}
	r->top = BN_NIST_192_TOP;

#if 1
	bn_clear_top2max(r);
#endif
	bn_correct_top(r);

	if (BN_ucmp(r, field) >= 0)
		{
		bn_sub_words(r_d, r_d, _nist_p_192, BN_NIST_192_TOP);
		bn_correct_top(r);
		}

	bn_check_top(r);
	return 1;
	}

#define BN_224_SET(d,a1,a2,a3,a4,a5,a6,a7) \
	{\
	register BN_ULONG *td = (d);\
	BN_CP_32_FROM_BUF(td,a7); BN_CP_32_FROM_BUF(td,a6);\
	BN_CP_32_FROM_BUF(td,a5); BN_CP_32_FROM_BUF(td,a4);\
	BN_CP_32_FROM_BUF(td,a3); BN_CP_32_FROM_BUF(td,a2);\
	BN_CP_32_FROM_BUF(td,a1);\
	}

int BN_nist_mod_224(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#ifndef NO_32_BIT_TYPE
	int	tmp_int;
	int	carry = 0;
	BN_ULONG *r_d, *a_d;
	BN_ULONG t_d[BN_NIST_224_TOP];
	BN_32_BIT_BUF(7)  BN_32_BIT_BUF(8)
	BN_32_BIT_BUF(9)  BN_32_BIT_BUF(10)
	BN_32_BIT_BUF(11) BN_32_BIT_BUF(12)
	BN_32_BIT_BUF(13)

	tmp_int = BN_ucmp(field, a);
	if (tmp_int == 0)
		return BN_zero(r);
	else if (tmp_int > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (r != a)
		if (!BN_ncopy(r, a, BN_NIST_224_TOP))
			return 0;

	r_d = r->d;
	a_d = a->d;

	tmp_int = a->top-1;

	switch (tmp_int)
		{
		BN_CASE_32_BIT(13, a_d)
		BN_CASE_32_BIT(12, a_d)
		BN_CASE_32_BIT(11, a_d)
		BN_CASE_32_BIT(10, a_d)
		BN_CASE_32_BIT(9,  a_d)
		BN_CASE_32_BIT(8,  a_d)
		BN_CASE_32_BIT(7,  a_d)
			break;
		default: /* a->top == field->top */
			return BN_usub(r, a, field);
		}

	BN_224_SET(t_d,10,9,8,7,0,0,0)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_224_TOP))
		++carry;
	BN_224_SET(t_d,0,13,12,11,0,0,0)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_224_TOP))
		++carry;
	BN_224_SET(t_d,13,12,11,10,9,8,7)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_224_TOP))
		--carry;
	BN_224_SET(t_d,0,0,0,0,13,12,11)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_224_TOP))
		--carry;

	if (carry > 0)
		while (carry)
			{
			if (bn_sub_words(r_d,r_d,_nist_p_224,BN_NIST_224_TOP))
				--carry;
			}
	else if (carry < 0)
		while (carry)
			{
			if (bn_add_words(r_d,r_d,_nist_p_224,BN_NIST_224_TOP))
				++carry;
			}

	r->top = BN_NIST_224_TOP;
#if 1
	bn_clear_top2max(r);
#endif
	bn_correct_top(r);

	if (BN_ucmp(r, field) >= 0)
		{
		bn_sub_words(r_d, r_d, _nist_p_224, BN_NIST_224_TOP);
		bn_correct_top(r);
		}
	bn_check_top(r);
	return 1;
#else
	return 0;
#endif
	}

static void _init_256_data(void)
	{
	int	i;
	BN_ULONG *tmp1 = _256_data;
	const BN_ULONG *tmp2 = tmp1;

	memcpy(tmp1, _nist_p_256, BN_NIST_256_TOP * sizeof(BN_ULONG));
	tmp1 += BN_NIST_256_TOP;

	for (i=0; i<5; i++)
		{
		bn_add_words(tmp1, _nist_p_256, tmp2, BN_NIST_256_TOP);
		tmp2  = tmp1;
		tmp1 += BN_NIST_256_TOP;
		}
	_is_set_256_data = 1;
	}

#define BN_256_SET(d,a1,a2,a3,a4,a5,a6,a7,a8) \
	{\
	register BN_ULONG *td = (d);\
	BN_CP_32_FROM_BUF(td,a8); BN_CP_32_FROM_BUF(td,a7);\
	BN_CP_32_FROM_BUF(td,a6); BN_CP_32_FROM_BUF(td,a5);\
	BN_CP_32_FROM_BUF(td,a4); BN_CP_32_FROM_BUF(td,a3);\
	BN_CP_32_FROM_BUF(td,a2); BN_CP_32_FROM_BUF(td,a1);\
	}

int BN_nist_mod_256(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#ifndef NO_32_BIT_TYPE
	int	tmp_int;
	int	carry = 0;
	register BN_ULONG *a_d, *r_d;
	BN_ULONG t_d[BN_NIST_256_TOP];
	BN_ULONG t_d2[BN_NIST_256_TOP];
	BN_32_BIT_BUF(8)  BN_32_BIT_BUF(9)
	BN_32_BIT_BUF(10) BN_32_BIT_BUF(11)
	BN_32_BIT_BUF(12) BN_32_BIT_BUF(13)
	BN_32_BIT_BUF(14) BN_32_BIT_BUF(15)

	if (!_is_set_256_data)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_BN);
		
		if (!_is_set_256_data)
			_init_256_data();
		
		CRYPTO_w_unlock(CRYPTO_LOCK_BN);
		}
	
	tmp_int = BN_ucmp(field, a);
	if (tmp_int == 0)
		return BN_zero(r);
	else if (tmp_int > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (r != a)
		if (!BN_ncopy(r, a, BN_NIST_256_TOP))
			return 0;

	tmp_int = a->top-1;

	a_d = a->d;
	r_d = r->d;
	switch (tmp_int)
		{
		BN_CASE_32_BIT(15, a_d)
		BN_CASE_32_BIT(14, a_d)
		BN_CASE_32_BIT(13, a_d)
		BN_CASE_32_BIT(12, a_d)
		BN_CASE_32_BIT(11, a_d)
		BN_CASE_32_BIT(10, a_d)
		BN_CASE_32_BIT(9,  a_d)
		BN_CASE_32_BIT(8,  a_d)
			break;
		default: /* a->top == field->top */
			return BN_usub(r, a, field);
		}

	/*S1*/
	BN_256_SET(t_d,15,14,13,12,11,0,0,0)
	/*S2*/
	BN_256_SET(t_d2,0,15,14,13,12,0,0,0)
	if (bn_add_words(t_d, t_d, t_d2, BN_NIST_256_TOP))
		carry = 2;
	/* left shift */
		{
		register BN_ULONG *ap,t,c;
		ap = t_d;
		c=0;
		for (tmp_int=BN_NIST_256_TOP; tmp_int != 0; --tmp_int)
			{
			t= *ap;
			*(ap++)=((t<<1)|c)&BN_MASK2;
			c=(t & BN_TBIT)?1:0;
			}
		if (c)
			++carry;
		}

	if (bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		++carry;
	/*S3*/
	BN_256_SET(t_d,15,14,0,0,0,10,9,8)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		++carry;
	/*S4*/
	BN_256_SET(t_d,8,13,15,14,13,11,10,9)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		++carry;
	/*D1*/
	BN_256_SET(t_d,10,8,0,0,0,13,12,11)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		--carry;
	/*D2*/
	BN_256_SET(t_d,11,9,0,0,15,14,13,12)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		--carry;
	/*D3*/
	BN_256_SET(t_d,12,0,10,9,8,15,14,13)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		--carry;
	/*D4*/
	BN_256_SET(t_d,13,0,11,10,9,0,15,14)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_256_TOP))
		--carry;
	
	if (carry)
		{
		if (carry > 0)
			bn_sub_words(r_d, r_d, _256_data + BN_NIST_256_TOP *
				--carry, BN_NIST_256_TOP);
		else
			{
			carry = -carry;
			bn_add_words(r_d, r_d, _256_data + BN_NIST_256_TOP *
				--carry, BN_NIST_256_TOP);
			}
		}

	r->top = BN_NIST_256_TOP;
#if 1
	bn_clear_top2max(r);
#endif
	bn_correct_top(r);

	if (BN_ucmp(r, field) >= 0)
		{
		bn_sub_words(r_d, r_d, _nist_p_256, BN_NIST_256_TOP);
		bn_correct_top(r);
		}
	bn_check_top(r);
	return 1;
#else
	return 0;
#endif
	}

static void _init_384_data(void)
	{
	int	i;
	BN_ULONG *tmp1 = _384_data;
	const BN_ULONG *tmp2 = tmp1;

	memcpy(tmp1, _nist_p_384, BN_NIST_384_TOP * sizeof(BN_ULONG));
	tmp1 += BN_NIST_384_TOP;

	for (i=0; i<7; i++)
		{
		bn_add_words(tmp1, _nist_p_384, tmp2, BN_NIST_384_TOP);
		tmp2  = tmp1;
		tmp1 += BN_NIST_384_TOP;
		}
	_is_set_384_data = 1;
	}

#define BN_384_SET(d,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12) \
	{\
	register BN_ULONG *td = (d);\
	BN_CP_32_FROM_BUF(td,a12); BN_CP_32_FROM_BUF(td,a11);\
	BN_CP_32_FROM_BUF(td,a10); BN_CP_32_FROM_BUF(td,a9);\
	BN_CP_32_FROM_BUF(td,a8);  BN_CP_32_FROM_BUF(td,a7);\
	BN_CP_32_FROM_BUF(td,a6);  BN_CP_32_FROM_BUF(td,a5);\
	BN_CP_32_FROM_BUF(td,a4);  BN_CP_32_FROM_BUF(td,a3);\
	BN_CP_32_FROM_BUF(td,a2);  BN_CP_32_FROM_BUF(td,a1);\
	}

int BN_nist_mod_384(BIGNUM *r, const BIGNUM *a, const BIGNUM *field,
	BN_CTX *ctx)
	{
#ifndef NO_32_BIT_TYPE
	int	tmp_int;
	int	carry = 0;
	register BN_ULONG *r_d, *a_d;
	BN_ULONG t_d[BN_NIST_384_TOP];
	BN_32_BIT_BUF(12) BN_32_BIT_BUF(13)
	BN_32_BIT_BUF(14) BN_32_BIT_BUF(15)
	BN_32_BIT_BUF(16) BN_32_BIT_BUF(17)
	BN_32_BIT_BUF(18) BN_32_BIT_BUF(19)
	BN_32_BIT_BUF(20) BN_32_BIT_BUF(21)
	BN_32_BIT_BUF(22) BN_32_BIT_BUF(23)

	if (!_is_set_384_data)
		{
		CRYPTO_w_lock(CRYPTO_LOCK_BN);
		
		if (!_is_set_384_data)
			_init_384_data();

		CRYPTO_w_unlock(CRYPTO_LOCK_BN);
		}

	tmp_int = BN_ucmp(field, a);
	if (tmp_int == 0)
		return BN_zero(r);
	else if (tmp_int > 0)
		return (r == a)? 1 : (BN_copy(r ,a) != NULL);

	if (r != a)
		if (!BN_ncopy(r, a, BN_NIST_384_TOP))
			return 0;

	r_d = r->d;
	a_d = a->d;
	tmp_int = a->top-1;

	switch (tmp_int)
		{
		BN_CASE_32_BIT(23, a_d)
		BN_CASE_32_BIT(22, a_d)
		BN_CASE_32_BIT(21, a_d)
		BN_CASE_32_BIT(20, a_d)
		BN_CASE_32_BIT(19, a_d)
		BN_CASE_32_BIT(18, a_d)
		BN_CASE_32_BIT(17, a_d)
		BN_CASE_32_BIT(16, a_d)
		BN_CASE_32_BIT(15, a_d)
		BN_CASE_32_BIT(14, a_d)
		BN_CASE_32_BIT(13, a_d)
		BN_CASE_32_BIT(12, a_d)
			break;
		default: /* a->top == field->top */
			return BN_usub(r, a, field);
		}

	/*S1*/
	BN_256_SET(t_d,0,0,0,0,0,23,22,21)
		/* left shift */
		{
		register BN_ULONG *ap,t,c;
		ap = t_d;
		c=0;
		for (tmp_int=BN_NIST_256_TOP; tmp_int != 0; --tmp_int)
			{
			t= *ap;
			*(ap++)=((t<<1)|c)&BN_MASK2;
			c=(t & BN_TBIT)?1:0;
			}
		}
	if (bn_add_words(r_d+(128/BN_BITS2), r_d+(128/BN_BITS2), 
		t_d, BN_NIST_256_TOP))
		++carry;
	/*S2*/
	BN_384_SET(t_d,23,22,21,20,19,18,17,16,15,14,13,12)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		++carry;
	/*S3*/
	BN_384_SET(t_d,20,19,18,17,16,15,14,13,12,23,22,21)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		++carry;
	/*S4*/
	BN_384_SET(t_d,19,18,17,16,15,14,13,12,20,0,23,0)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		++carry;
	/*S5*/
	BN_256_SET(t_d,0,0,0,0,23,22,21,20)
	if (bn_add_words(r_d+(128/BN_BITS2), r_d+(128/BN_BITS2), 
		t_d, BN_NIST_256_TOP))
		++carry;
	/*S6*/
	BN_384_SET(t_d,0,0,0,0,0,0,23,22,21,0,0,20)
	if (bn_add_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		++carry;
	/*D1*/
	BN_384_SET(t_d,22,21,20,19,18,17,16,15,14,13,12,23)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		--carry;
	/*D2*/
	BN_384_SET(t_d,0,0,0,0,0,0,0,23,22,21,20,0)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		--carry;
	/*D3*/
	BN_384_SET(t_d,0,0,0,0,0,0,0,23,23,0,0,0)
	if (bn_sub_words(r_d, r_d, t_d, BN_NIST_384_TOP))
		--carry;
	
	if (carry)
		{
		if (carry > 0)
			bn_sub_words(r_d, r_d, _384_data + BN_NIST_384_TOP *
				--carry, BN_NIST_384_TOP);
		else
			{
			carry = -carry;
			bn_add_words(r_d, r_d, _384_data + BN_NIST_384_TOP *
				--carry, BN_NIST_384_TOP);
			}
		}

	r->top = BN_NIST_384_TOP;
#if 1
	bn_clear_top2max(r);
#endif
	bn_correct_top(r);

	if (BN_ucmp(r, field) >= 0)
		{
		bn_sub_words(r_d, r_d, _nist_p_384, BN_NIST_384_TOP);
		bn_correct_top(r);
		}
	bn_check_top(r);
	return 1;
#else
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
#elif BN_BITS2 == 16
#define BN_NIST_521_TOP_MASK	(BN_ULONG)0x1FF
#elif BN_BITS2 == 8
#define BN_NIST_521_TOP_MASK	(BN_ULONG)0x1
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

	if (!BN_ncopy(tmp, a, BN_NIST_521_TOP))
		return 0;
	if (!BN_rshift(r, a, 521))
		return 0;

	if (tmp->top == BN_NIST_521_TOP)
		tmp->d[BN_NIST_521_TOP-1]  &= BN_NIST_521_TOP_MASK;

	bn_correct_top(tmp);
	if (!BN_uadd(r, tmp, r))
		return 0;
	top = r->top;
	r_d = r->d;
	if (top == BN_NIST_521_TOP  && 
           (r_d[BN_NIST_521_TOP-1] & ~(BN_NIST_521_TOP_MASK)))
		{
		BN_NIST_ADD_ONE(r_d)
		r_d[BN_NIST_521_TOP-1] &= BN_NIST_521_TOP_MASK; 
		}
	bn_correct_top(r);

	ret = 1;
err:
	BN_CTX_end(ctx);

	bn_check_top(r);
	return ret;
	}
