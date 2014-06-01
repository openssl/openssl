/* crypto/bn/bn_prime.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */
/* ====================================================================
 * Copyright (c) 1998-2001 The OpenSSL Project.  All rights reserved.
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

#include <stdio.h>
#include <time.h>
#include "cryptlib.h"
#include "bn_lcl.h"
#include <openssl/rand.h>

/* NB: these functions have been "upgraded", the deprecated versions (which are
 * compatibility wrappers using these functions) are in bn_depr.c.
 * - Geoff
 */

/* The quick sieve algorithm approach to weeding out primes is
 * Philip Zimmermann's, as implemented in PGP.  I have had a read of
 * his comments and implemented my own version.
 */
#include "bn_prime.h"

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont);
static int probable_prime(BIGNUM *rnd, int bits);
static int probable_prime_dh_safe(BIGNUM *rnd, int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx);

static const int prime_offsets[480] = {
	13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83,
	89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163,
	167, 169, 173, 179, 181, 191, 193, 197, 199, 211, 221, 223, 227, 229,
	233, 239, 241, 247, 251, 257, 263, 269, 271, 277, 281, 283, 289, 293,
	299, 307, 311, 313, 317, 323, 331, 337, 347, 349, 353, 359, 361, 367,
	373, 377, 379, 383, 389, 391, 397, 401, 403, 409, 419, 421, 431, 433,
	437, 439, 443, 449, 457, 461, 463, 467, 479, 481, 487, 491, 493, 499,
	503, 509, 521, 523, 527, 529, 533, 541, 547, 551, 557, 559, 563, 569,
	571, 577, 587, 589, 593, 599, 601, 607, 611, 613, 617, 619, 629, 631,
	641, 643, 647, 653, 659, 661, 667, 673, 677, 683, 689, 691, 697, 701,
	703, 709, 713, 719, 727, 731, 733, 739, 743, 751, 757, 761, 767, 769,
	773, 779, 787, 793, 797, 799, 809, 811, 817, 821, 823, 827, 829, 839,
	841, 851, 853, 857, 859, 863, 871, 877, 881, 883, 887, 893, 899, 901,
	907, 911, 919, 923, 929, 937, 941, 943, 947, 949, 953, 961, 967, 971,
	977, 983, 989, 991, 997, 1003, 1007, 1009, 1013, 1019, 1021, 1027, 1031,
	1033, 1037, 1039, 1049, 1051, 1061, 1063, 1069, 1073, 1079, 1081, 1087,
	1091, 1093, 1097, 1103, 1109, 1117, 1121, 1123, 1129, 1139, 1147, 1151,
	1153, 1157, 1159, 1163, 1171, 1181, 1187, 1189, 1193, 1201, 1207, 1213,
	1217, 1219, 1223, 1229, 1231, 1237, 1241, 1247, 1249, 1259, 1261, 1271,
	1273, 1277, 1279, 1283, 1289, 1291, 1297, 1301, 1303, 1307, 1313, 1319,
	1321, 1327, 1333, 1339, 1343, 1349, 1357, 1361, 1363, 1367, 1369, 1373,
	1381, 1387, 1391, 1399, 1403, 1409, 1411, 1417, 1423, 1427, 1429, 1433,
	1439, 1447, 1451, 1453, 1457, 1459, 1469, 1471, 1481, 1483, 1487, 1489,
	1493, 1499, 1501, 1511, 1513, 1517, 1523, 1531, 1537, 1541, 1543, 1549,
	1553, 1559, 1567, 1571, 1577, 1579, 1583, 1591, 1597, 1601, 1607, 1609,
	1613, 1619, 1621, 1627, 1633, 1637, 1643, 1649, 1651, 1657, 1663, 1667,
	1669, 1679, 1681, 1691, 1693, 1697, 1699, 1703, 1709, 1711, 1717, 1721,
	1723, 1733, 1739, 1741, 1747, 1751, 1753, 1759, 1763, 1769, 1777, 1781,
	1783, 1787, 1789, 1801, 1807, 1811, 1817, 1819, 1823, 1829, 1831, 1843,
	1847, 1849, 1853, 1861, 1867, 1871, 1873, 1877, 1879, 1889, 1891, 1901,
	1907, 1909, 1913, 1919, 1921, 1927, 1931, 1933, 1937, 1943, 1949, 1951,
	1957, 1961, 1963, 1973, 1979, 1987, 1993, 1997, 1999, 2003, 2011, 2017,
	2021, 2027, 2029, 2033, 2039, 2041, 2047, 2053, 2059, 2063, 2069, 2071,
	2077, 2081, 2083, 2087, 2089, 2099, 2111, 2113, 2117, 2119, 2129, 2131,
	2137, 2141, 2143, 2147, 2153, 2159, 2161, 2171, 2173, 2179, 2183, 2197,
	2201, 2203, 2207, 2209, 2213, 2221, 2227, 2231, 2237, 2239, 2243, 2249,
	2251, 2257, 2263, 2267, 2269, 2273, 2279, 2281, 2287, 2291, 2293, 2297,
	2309, 2311 };
static const int prime_offset_count = 480;
static const int prime_multiplier = 2310;
static const int prime_multiplier_bits = 11; /* 2^|prime_multiplier_bits|
						<= |prime_multiplier| */

static const int safe_prime_offsets[135] = {
	47, 59, 83, 107, 167, 179, 227, 263, 299, 347, 359, 383, 443, 467, 479,
	503, 527, 563, 587, 599, 647, 719, 767, 779, 839, 863, 887, 899, 923,
	983, 1007, 1019, 1103, 1139, 1187, 1223, 1259, 1283, 1307, 1319, 1367,
	1403, 1427, 1439, 1487, 1523, 1559, 1619, 1643, 1679, 1703, 1763, 1787,
	1823, 1847, 1907, 1943, 1979, 2027, 2039, 2063, 2099, 2147, 2159, 2183,
	2207, 2243, 2279, 2327, 2363, 2447, 2459, 2483, 2543, 2567, 2579, 2603,
	2627, 2687, 2699, 2747, 2819, 2867, 2879, 2903, 2939, 2963, 2987, 2999,
	3023, 3083, 3107, 3119, 3167, 3203, 3239, 3287, 3299, 3359, 3383, 3407,
	3419, 3467, 3503, 3527, 3539, 3623, 3659, 3743, 3779, 3803, 3827, 3863,
	3887, 3923, 3947, 3959, 4007, 4043, 4079, 4127, 4139, 4163, 4199, 4223,
	4259, 4283, 4307, 4343, 4427, 4463, 4547, 4559, 4583, 4619 };
static const int safe_prime_offset_count = 135;
static const int safe_prime_multiplier = 4620;
static const int safe_prime_multiplier_bits = 12; /* 2^|prime_multiplier_bits|
						<= |prime_multiplier| */

static const int first_prime_index = 5;


int BN_GENCB_call(BN_GENCB *cb, int a, int b)
	{
	/* No callback means continue */
	if(!cb) return 1;
	switch(cb->ver)
		{
	case 1:
		/* Deprecated-style callbacks */
		if(!cb->cb.cb_1)
			return 1;
		cb->cb.cb_1(a, b, cb->arg);
		return 1;
	case 2:
		/* New-style callbacks */
		return cb->cb.cb_2(a, b, cb);
	default:
		break;
		}
	/* Unrecognised callback type */
	return 0;
	}

int BN_generate_prime_ex(BIGNUM *ret, int bits, int safe,
	const BIGNUM *add, const BIGNUM *rem, BN_GENCB *cb)
	{
	BIGNUM *t;
	int found=0;
	int i,j,c1=0;
	BN_CTX *ctx;
	int checks = BN_prime_checks_for_size(bits);

	if (bits < 2)
		{
		/* There are no prime numbers this small. */
		BNerr(BN_F_BN_GENERATE_PRIME_EX, BN_R_BITS_TOO_SMALL);
		return 0;
		}
	else if (bits == 2 && safe)
		{
		/* The smallest safe prime (7) is three bits. */
		BNerr(BN_F_BN_GENERATE_PRIME_EX, BN_R_BITS_TOO_SMALL);
		return 0;
		}

	ctx=BN_CTX_new();
	if (ctx == NULL) goto err;
	BN_CTX_start(ctx);
	t = BN_CTX_get(ctx);
	if(!t) goto err;
loop: 
	/* make a random number and set the top and bottom bits */
	if (add == NULL)
		{
		if (!probable_prime(ret,bits)) goto err;
		}
	else
		{
		if (safe)
			{
			if (!probable_prime_dh_safe(ret,bits,add,rem,ctx))
				 goto err;
			}
		else
			{
			if (!bn_probable_prime_dh(ret,bits,add,rem,ctx))
				goto err;
			}
		}
	/* if (BN_mod_word(ret,(BN_ULONG)3) == 1) goto loop; */
	if(!BN_GENCB_call(cb, 0, c1++))
		/* aborted */
		goto err;

	if (!safe)
		{
		i=BN_is_prime_fasttest_ex(ret,checks,ctx,0,cb);
		if (i == -1) goto err;
		if (i == 0) goto loop;
		}
	else
		{
		/* for "safe prime" generation,
		 * check that (p-1)/2 is prime.
		 * Since a prime is odd, We just
		 * need to divide by 2 */
		if (!BN_rshift1(t,ret)) goto err;

		for (i=0; i<checks; i++)
			{
			j=BN_is_prime_fasttest_ex(ret,1,ctx,0,cb);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			j=BN_is_prime_fasttest_ex(t,1,ctx,0,cb);
			if (j == -1) goto err;
			if (j == 0) goto loop;

			if(!BN_GENCB_call(cb, 2, c1-1))
				goto err;
			/* We have a safe prime test pass */
			}
		}
	/* we have a prime :-) */
	found = 1;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
		}
	bn_check_top(ret);
	return found;
	}

int BN_is_prime_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed, BN_GENCB *cb)
	{
	return BN_is_prime_fasttest_ex(a, checks, ctx_passed, 0, cb);
	}

int BN_is_prime_fasttest_ex(const BIGNUM *a, int checks, BN_CTX *ctx_passed,
		int do_trial_division, BN_GENCB *cb)
	{
	int i, j, ret = -1;
	int k;
	BN_CTX *ctx = NULL;
	BIGNUM *A1, *A1_odd, *check; /* taken from ctx */
	BN_MONT_CTX *mont = NULL;
	const BIGNUM *A = NULL;

	if (BN_cmp(a, BN_value_one()) <= 0)
		return 0;
	
	if (checks == BN_prime_checks)
		checks = BN_prime_checks_for_size(BN_num_bits(a));

	/* first look for small factors */
	if (!BN_is_odd(a))
		/* a is even => a is prime if and only if a == 2 */
		return BN_is_word(a, 2);
	if (do_trial_division)
		{
		for (i = 1; i < NUMPRIMES; i++)
			if (BN_mod_word(a, primes[i]) == 0) 
				return 0;
		if(!BN_GENCB_call(cb, 1, -1))
			goto err;
		}

	if (ctx_passed != NULL)
		ctx = ctx_passed;
	else
		if ((ctx=BN_CTX_new()) == NULL)
			goto err;
	BN_CTX_start(ctx);

	/* A := abs(a) */
	if (a->neg)
		{
		BIGNUM *t;
		if ((t = BN_CTX_get(ctx)) == NULL) goto err;
		BN_copy(t, a);
		t->neg = 0;
		A = t;
		}
	else
		A = a;
	A1 = BN_CTX_get(ctx);
	A1_odd = BN_CTX_get(ctx);
	check = BN_CTX_get(ctx);
	if (check == NULL) goto err;

	/* compute A1 := A - 1 */
	if (!BN_copy(A1, A))
		goto err;
	if (!BN_sub_word(A1, 1))
		goto err;
	if (BN_is_zero(A1))
		{
		ret = 0;
		goto err;
		}

	/* write  A1  as  A1_odd * 2^k */
	k = 1;
	while (!BN_is_bit_set(A1, k))
		k++;
	if (!BN_rshift(A1_odd, A1, k))
		goto err;

	/* Montgomery setup for computations mod A */
	mont = BN_MONT_CTX_new();
	if (mont == NULL)
		goto err;
	if (!BN_MONT_CTX_set(mont, A, ctx))
		goto err;
	
	for (i = 0; i < checks; i++)
		{
		if (!BN_pseudo_rand_range(check, A1))
			goto err;
		if (!BN_add_word(check, 1))
			goto err;
		/* now 1 <= check < A */

		j = witness(check, A, A1, A1_odd, k, ctx, mont);
		if (j == -1) goto err;
		if (j)
			{
			ret=0;
			goto err;
			}
		if(!BN_GENCB_call(cb, 1, i))
			goto err;
		}
	ret=1;
err:
	if (ctx != NULL)
		{
		BN_CTX_end(ctx);
		if (ctx_passed == NULL)
			BN_CTX_free(ctx);
		}
	if (mont != NULL)
		BN_MONT_CTX_free(mont);

	return(ret);
	}

int bn_probable_prime_dh_unbiased(BIGNUM *rnd, int bits, BN_CTX *ctx)
	{
	int i;
	int ret = 0;

loop:
	if (!BN_rand(rnd, bits, 0, 1)) goto err;

	/* we now have a random number 'rand' to test. */

	for (i = 1; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= 1)
			{
			goto loop;
			}
		}
	ret=1;

err:
	bn_check_top(rnd);
	return(ret);
	}

int bn_probable_prime_dh_coprime(BIGNUM *rnd, int bits, BN_CTX *ctx)
	{
	int i;
	int j;
	int old_offset;
	int offset;
	BIGNUM *offset_index;
	BIGNUM *offset_count;
	int ret = 0;
	int base_offset = 0;
	
	OPENSSL_assert(bits > prime_multiplier_bits);
	
	BN_CTX_start(ctx);
	if ((offset_index = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_count = BN_CTX_get(ctx)) == NULL) goto err;
	
	BN_add_word(offset_count, prime_offset_count);

again:
	if (!BN_rand(rnd, bits - prime_multiplier_bits, 0, 1)) goto err;
	if (BN_is_bit_set(rnd, bits)) goto again;
	if (!BN_rand_range(offset_index, offset_count)) goto err;

	j = BN_get_word(offset_index);
	offset = prime_offsets[j];
	
	BN_mul_word(rnd, prime_multiplier);
	BN_add_word(rnd, offset);

	/* we now have a random number 'rand' to test. */

loop:
	/* skip coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) == 0)
			{
			j++;
			if (j >= prime_offset_count)
				{
				j = 0;
				base_offset = base_offset + prime_multiplier;
				}
			old_offset = offset;
			offset = base_offset + prime_offsets[j];
			if (!BN_add_word(rnd, offset - old_offset))
				goto err;
			goto loop;
			}
		}
	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return ret;
	}

int bn_probable_prime_dh_coprime_unbiased(BIGNUM *rnd, int bits, BN_CTX *ctx)
	{
	int i;
	BIGNUM *offset_index;
	BIGNUM *offset_count;
	int ret = 0;
	
	OPENSSL_assert(bits > prime_multiplier_bits);
	
	BN_CTX_start(ctx);
	if ((offset_index = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_count = BN_CTX_get(ctx)) == NULL) goto err;
	
	BN_add_word(offset_count, prime_offset_count);

loop:
	if (!BN_rand(rnd, bits - prime_multiplier_bits, 0, 1)) goto err;
	if (BN_is_bit_set(rnd, bits)) goto loop;
	if (!BN_rand_range(offset_index, offset_count)) goto err;
	
	BN_mul_word(rnd, prime_multiplier);
	BN_add_word(rnd, prime_offsets[BN_get_word(offset_index)]);

	/* we now have a random number 'rand' to test. */

	/* skip coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) == 0)
			{
			goto loop;
			}
		}
	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return ret;
	}

int bn_probable_prime_dh_coprime_safe(BIGNUM *rnd, int bits, BN_CTX *ctx)
	{
	int i;
	int j;
	int old_offset;
	int offset;
	BIGNUM *offset_index;
	BIGNUM *offset_count;
	int ret = 0;
	int base_offset = 0;
	
	OPENSSL_assert(bits > safe_prime_multiplier_bits);
	
	BN_CTX_start(ctx);
	if ((offset_index = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_count = BN_CTX_get(ctx)) == NULL) goto err;
	
	BN_add_word(offset_count, safe_prime_offset_count);

again:
	if (!BN_rand(rnd, bits - safe_prime_multiplier_bits, 0, 1)) goto err;
	if (BN_is_bit_set(rnd, bits)) goto again;
	if (!BN_rand_range(offset_index, offset_count)) goto err;

	j = BN_get_word(offset_index);
	offset = safe_prime_offsets[j];
	
	BN_mul_word(rnd, safe_prime_multiplier);
	BN_add_word(rnd, offset);

	/* we now have a random number 'rand' to test. */

loop:
	/* skip coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= 1)
			{
			j++;
			if (j >= safe_prime_offset_count)
				{
				j = 0;
				base_offset = base_offset + safe_prime_multiplier;
				}
			old_offset = offset;
			offset = base_offset + safe_prime_offsets[j];
			if (!BN_add_word(rnd, offset - old_offset))
				goto err;
			goto loop;
			}
		}
	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return ret;
	}

int bn_probable_prime_dh_coprime_unbiased_safe(BIGNUM *rnd, int bits,
	BN_CTX *ctx)
	{
	int i;
	BIGNUM *offset_index;
	BIGNUM *offset_count;
	int ret = 0;
	
	OPENSSL_assert(bits > safe_prime_multiplier_bits);
	
	BN_CTX_start(ctx);
	if ((offset_index = BN_CTX_get(ctx)) == NULL) goto err;
	if ((offset_count = BN_CTX_get(ctx)) == NULL) goto err;
	
	BN_add_word(offset_count, safe_prime_offset_count);

loop:
	if (!BN_rand(rnd, bits - safe_prime_multiplier_bits, 0, 1)) goto err;
	if (BN_is_bit_set(rnd, bits)) goto loop;
	if (!BN_rand_range(offset_index, offset_count)) goto err;
	
	BN_mul_word(rnd, safe_prime_multiplier);
	BN_add_word(rnd, safe_prime_offsets[BN_get_word(offset_index)]);

	/* we now have a random number 'rand' to test. */

	/* skip coprimes */
	for (i = first_prime_index; i < NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd, (BN_ULONG)primes[i]) <= 1)
			{
			goto loop;
			}
		}
	ret = 1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return ret;
	}

static int witness(BIGNUM *w, const BIGNUM *a, const BIGNUM *a1,
	const BIGNUM *a1_odd, int k, BN_CTX *ctx, BN_MONT_CTX *mont)
	{
	if (!BN_mod_exp_mont(w, w, a1_odd, a, ctx, mont)) /* w := w^a1_odd mod a */
		return -1;
	if (BN_is_one(w))
		return 0; /* probably prime */
	if (BN_cmp(w, a1) == 0)
		return 0; /* w == -1 (mod a),  'a' is probably prime */
	while (--k)
		{
		if (!BN_mod_mul(w, w, w, a, ctx)) /* w := w^2 mod a */
			return -1;
		if (BN_is_one(w))
			return 1; /* 'a' is composite, otherwise a previous 'w' would
			           * have been == -1 (mod 'a') */
		if (BN_cmp(w, a1) == 0)
			return 0; /* w == -1 (mod a), 'a' is probably prime */
		}
	/* If we get here, 'w' is the (a-1)/2-th power of the original 'w',
	 * and it is neither -1 nor +1 -- so 'a' cannot be prime */
	bn_check_top(w);
	return 1;
	}

static int probable_prime(BIGNUM *rnd, int bits)
	{
	int i;
	prime_t mods[NUMPRIMES];
	BN_ULONG delta;
	BN_ULONG maxdelta = BN_MASK2 - primes[NUMPRIMES-1];
	char is_single_word = bits <= BN_BITS2;

again:
	if (!BN_rand(rnd,bits,1,1)) return(0);
	/* we now have a random number 'rnd' to test. */
	for (i=1; i<NUMPRIMES; i++)
		mods[i]=(prime_t)BN_mod_word(rnd,(BN_ULONG)primes[i]);
	/* If bits is so small that it fits into a single word then we
	 * additionally don't want to exceed that many bits. */
	if (is_single_word)
		{
		BN_ULONG size_limit = (((BN_ULONG) 1) << bits) - BN_get_word(rnd) - 1;
		if (size_limit < maxdelta)
			maxdelta = size_limit;
		}
	delta=0;
loop:
	if (is_single_word)
		{
		BN_ULONG rnd_word = BN_get_word(rnd);

		/* In the case that the candidate prime is a single word then
		 * we check that:
		 *   1) It's greater than primes[i] because we shouldn't reject
		 *      3 as being a prime number because it's a multiple of
		 *      three.
		 *   2) That it's not a multiple of a known prime. We don't
		 *      check that rnd-1 is also coprime to all the known
		 *      primes because there aren't many small primes where
		 *      that's true. */
		for (i=1; i<NUMPRIMES && primes[i]<rnd_word; i++)
			{
			if ((mods[i]+delta)%primes[i] == 0)
				{
				delta+=2;
				if (delta > maxdelta) goto again;
				goto loop;
				}
			}
		}
	else
		{
		for (i=1; i<NUMPRIMES; i++)
			{
			/* check that rnd is not a prime and also
			 * that gcd(rnd-1,primes) == 1 (except for 2) */
			if (((mods[i]+delta)%primes[i]) <= 1)
				{
				delta+=2;
				if (delta > maxdelta) goto again;
				goto loop;
				}
			}
		}
	if (!BN_add_word(rnd,delta)) return(0);
	if (BN_num_bits(rnd) != bits)
		goto again;
	bn_check_top(rnd);
	return(1);
	}

int bn_probable_prime_dh(BIGNUM *rnd, int bits,
	const BIGNUM *add, const BIGNUM *rem, BN_CTX *ctx)
	{
	int i,ret=0;
	BIGNUM *t1;

	BN_CTX_start(ctx);
	if ((t1 = BN_CTX_get(ctx)) == NULL) goto err;

	if (!BN_rand(rnd,bits,0,1)) goto err;

	/* we need ((rnd-rem) % add) == 0 */

	if (!BN_mod(t1,rnd,add,ctx)) goto err;
	if (!BN_sub(rnd,rnd,t1)) goto err;
	if (rem == NULL)
		{ if (!BN_add_word(rnd,1)) goto err; }
	else
		{ if (!BN_add(rnd,rnd,rem)) goto err; }

	/* we now have a random number 'rand' to test. */

loop:
	for (i=1; i<NUMPRIMES; i++)
		{
		/* check that rnd is a prime */
		if (BN_mod_word(rnd,(BN_ULONG)primes[i]) <= 1)
			{
			if (!BN_add(rnd,rnd,add)) goto err;
			goto loop;
			}
		}
	ret=1;

err:
	BN_CTX_end(ctx);
	bn_check_top(rnd);
	return(ret);
	}

static int probable_prime_dh_safe(BIGNUM *p, int bits, const BIGNUM *padd,
	const BIGNUM *rem, BN_CTX *ctx)
	{
	int i,ret=0;
	BIGNUM *t1,*qadd,*q;

	bits--;
	BN_CTX_start(ctx);
	t1 = BN_CTX_get(ctx);
	q = BN_CTX_get(ctx);
	qadd = BN_CTX_get(ctx);
	if (qadd == NULL) goto err;

	if (!BN_rshift1(qadd,padd)) goto err;
		
	if (!BN_rand(q,bits,0,1)) goto err;

	/* we need ((rnd-rem) % add) == 0 */
	if (!BN_mod(t1,q,qadd,ctx)) goto err;
	if (!BN_sub(q,q,t1)) goto err;
	if (rem == NULL)
		{ if (!BN_add_word(q,1)) goto err; }
	else
		{
		if (!BN_rshift1(t1,rem)) goto err;
		if (!BN_add(q,q,t1)) goto err;
		}

	/* we now have a random number 'rand' to test. */
	if (!BN_lshift1(p,q)) goto err;
	if (!BN_add_word(p,1)) goto err;

loop:
	for (i=1; i<NUMPRIMES; i++)
		{
		/* check that p and q are prime */
		/* check that for p and q
		 * gcd(p-1,primes) == 1 (except for 2) */
		if ((BN_mod_word(p,(BN_ULONG)primes[i]) == 0) ||
			(BN_mod_word(q,(BN_ULONG)primes[i]) == 0))
			{
			if (!BN_add(p,p,padd)) goto err;
			if (!BN_add(q,q,qadd)) goto err;
			goto loop;
			}
		}
	ret=1;

err:
	BN_CTX_end(ctx);
	bn_check_top(p);
	return(ret);
	}
