/* crypto/ec/ec_mult.c */
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

#include <openssl/err.h>

#include "ec_lcl.h"


/* TODO: optional precomputation of multiples of the generator */



/*
 * wNAF-based interleaving multi-exponentation method
 * (<URL:http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp>)
 */


/* Determine the width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero.
 */
static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len, BN_CTX *ctx)
	{
	BIGNUM *c;
	int ok = 0;
	signed char *r = NULL;
	int sign = 1;
	int bit, next_bit, mask;
	size_t len = 0, j;
	
	BN_CTX_start(ctx);
	c = BN_CTX_get(ctx);
	if (c == NULL) goto err;
	
	if (w <= 0 || w > 7) /* 'signed char' can represent integers with absolute values less than 2^7 */
		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
		goto err;
		}
	bit = 1 << w; /* at most 128 */
	next_bit = bit << 1; /* at most 256 */
	mask = next_bit - 1; /* at most 255 */

	if (!BN_copy(c, scalar)) goto err;
	if (c->neg)
		{
		sign = -1;
		c->neg = 0;
		}

	len = BN_num_bits(c) + 1; /* wNAF may be one digit longer than binary representation */
	r = OPENSSL_malloc(len);
	if (r == NULL) goto err;

	j = 0;
	while (!BN_is_zero(c))
		{
		int u = 0;

		if (BN_is_odd(c)) 
			{
			if (c->d == NULL || c->top == 0)
				{
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			u = c->d[0] & mask;
			if (u & bit)
				{
				u -= next_bit;
				/* u < 0 */
				if (!BN_add_word(c, -u)) goto err;
				}
			else
				{
				/* u > 0 */
				if (!BN_sub_word(c, u)) goto err;
				}

			if (u <= -bit || u >= bit || !(u & 1) || c->neg)
				{
				ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
				goto err;
				}
			}

		r[j++] = sign * u;
		
		if (BN_is_odd(c))
			{
			ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
			goto err;
			}
		if (!BN_rshift1(c, c)) goto err;
		}

	if (j > len)
		{
		ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
		goto err;
		}
	len = j;
	ok = 1;

 err:
	BN_CTX_end(ctx);
	if (!ok)
		{
		OPENSSL_free(r);
		r = NULL;
		}
	if (ok)
		*ret_len = len;
	return r;
	}


/* TODO: table should be optimised for the wNAF-based implementation,
 *       sometimes smaller windows will give better performance
 *       (thus the boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b) \
		((size_t) \
		 ((b) >= 2000 ? 6 : \
		  (b) >=  800 ? 5 : \
		  (b) >=  300 ? 4 : \
		  (b) >=   70 ? 3 : \
		  (b) >=   20 ? 2 : \
		   1))

/* Compute
 *      \sum scalars[i]*points[i],
 * also including
 *      scalar*generator
 * in the addition if scalar != NULL
 */
int EC_POINTs_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
	size_t num, const EC_POINT *points[], const BIGNUM *scalars[], BN_CTX *ctx)
	{
	BN_CTX *new_ctx = NULL;
	EC_POINT *generator = NULL;
	EC_POINT *tmp = NULL;
	size_t totalnum;
	size_t i, j;
	int k;
	int r_is_inverted = 0;
	int r_is_at_infinity = 1;
	size_t *wsize = NULL; /* individual window sizes */
	signed char **wNAF = NULL; /* individual wNAFs */
	size_t *wNAF_len = NULL;
	size_t max_len = 0;
	size_t num_val;
	EC_POINT **val = NULL; /* precomputation */
	EC_POINT **v;
	EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' */
	int ret = 0;
	
	if (group->meth != r->meth)
		{
		ECerr(EC_F_EC_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
		return 0;
		}

	if ((scalar == NULL) && (num == 0))
		{
		return EC_POINT_set_to_infinity(group, r);
		}

	if (scalar != NULL)
		{
		generator = EC_GROUP_get0_generator(group);
		if (generator == NULL)
			{
			ECerr(EC_F_EC_POINTS_MUL, EC_R_UNDEFINED_GENERATOR);
			return 0;
			}
		}
	
	for (i = 0; i < num; i++)
		{
		if (group->meth != points[i]->meth)
			{
			ECerr(EC_F_EC_POINTS_MUL, EC_R_INCOMPATIBLE_OBJECTS);
			return 0;
			}
		}

	totalnum = num + (scalar != NULL);

	wsize = OPENSSL_malloc(totalnum * sizeof wsize[0]);
	wNAF_len = OPENSSL_malloc(totalnum * sizeof wNAF_len[0]);
	wNAF = OPENSSL_malloc((totalnum + 1) * sizeof wNAF[0]);
	if (wNAF != NULL)
		{
		wNAF[0] = NULL; /* preliminary pivot */
		}
	if (wsize == NULL || wNAF_len == NULL || wNAF == NULL) goto err;

	/* num_val := total number of points to precompute */
	num_val = 0;
	for (i = 0; i < totalnum; i++)
		{
		size_t bits;

		bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
		wsize[i] = EC_window_bits_for_scalar_size(bits);
		num_val += 1u << (wsize[i] - 1);
		}

	/* all precomputed points go into a single array 'val',
	 * 'val_sub[i]' is a pointer to the subarray for the i-th point */
	val = OPENSSL_malloc((num_val + 1) * sizeof val[0]);
	if (val == NULL) goto err;
	val[num_val] = NULL; /* pivot element */

	val_sub = OPENSSL_malloc(totalnum * sizeof val_sub[0]);
	if (val_sub == NULL) goto err;

	/* allocate points for precomputation */
	v = val;
	for (i = 0; i < totalnum; i++)
		{
		val_sub[i] = v;
		for (j = 0; j < (1u << (wsize[i] - 1)); j++)
			{
			*v = EC_POINT_new(group);
			if (*v == NULL) goto err;
			v++;
			}
		}
	if (!(v == val + num_val))
		{
		ECerr(EC_F_EC_POINTS_MUL, ERR_R_INTERNAL_ERROR);
		goto err;
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			goto err;
		}
	
	tmp = EC_POINT_new(group);
	if (tmp == NULL) goto err;

	/* prepare precomputed values:
	 *    val_sub[i][0] :=     points[i]
	 *    val_sub[i][1] := 3 * points[i]
	 *    val_sub[i][2] := 5 * points[i]
	 *    ...
	 */
	for (i = 0; i < totalnum; i++)
		{
		if (i < num)
			{
			if (!EC_POINT_copy(val_sub[i][0], points[i])) goto err;
			}
		else
			{
			if (!EC_POINT_copy(val_sub[i][0], generator)) goto err;
			}

		if (wsize[i] > 1)
			{
			if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx)) goto err;
			for (j = 1; j < (1u << (wsize[i] - 1)); j++)
				{
				if (!EC_POINT_add(group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx)) goto err;
				}
			}

		wNAF[i + 1] = NULL; /* make sure we always have a pivot */
		wNAF[i] = compute_wNAF((i < num ? scalars[i] : scalar), wsize[i], &wNAF_len[i], ctx);
		if (wNAF[i] == NULL) goto err;
		if (wNAF_len[i] > max_len)
			max_len = wNAF_len[i];
		}

#if 1 /* optional; EC_window_bits_for_scalar_size assumes we do this step */
	if (!EC_POINTs_make_affine(group, num_val, val, ctx)) goto err;
#endif

	r_is_at_infinity = 1;

	for (k = max_len - 1; k >= 0; k--)
		{
		if (!r_is_at_infinity)
			{
			if (!EC_POINT_dbl(group, r, r, ctx)) goto err;
			}
		
		for (i = 0; i < totalnum; i++)
			{
			if (wNAF_len[i] > (size_t)k)
				{
				int digit = wNAF[i][k];
				int is_neg;

				if (digit) 
					{
					is_neg = digit < 0;

					if (is_neg)
						digit = -digit;

					if (is_neg != r_is_inverted)
						{
						if (!r_is_at_infinity)
							{
							if (!EC_POINT_invert(group, r, ctx)) goto err;
							}
						r_is_inverted = !r_is_inverted;
						}

					/* digit > 0 */

					if (r_is_at_infinity)
						{
						if (!EC_POINT_copy(r, val_sub[i][digit >> 1])) goto err;
						r_is_at_infinity = 0;
						}
					else
						{
						if (!EC_POINT_add(group, r, r, val_sub[i][digit >> 1], ctx)) goto err;
						}
					}
				}
			}
		}

	if (r_is_at_infinity)
		{
		if (!EC_POINT_set_to_infinity(group, r)) goto err;
		}
	else
		{
		if (r_is_inverted)
			if (!EC_POINT_invert(group, r, ctx)) goto err;
		}
	
	ret = 1;

 err:
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	if (tmp != NULL)
		EC_POINT_free(tmp);
	if (wsize != NULL)
		OPENSSL_free(wsize);
	if (wNAF_len != NULL)
		OPENSSL_free(wNAF_len);
	if (wNAF != NULL)
		{
		signed char **w;
		
		for (w = wNAF; *w != NULL; w++)
			OPENSSL_free(*w);
		
		OPENSSL_free(wNAF);
		}
	if (val != NULL)
		{
		for (v = val; *v != NULL; v++)
			EC_POINT_clear_free(*v);

		OPENSSL_free(val);
		}
	if (val_sub != NULL)
		{
		OPENSSL_free(val_sub);
		}
	return ret;
	}


int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *g_scalar, const EC_POINT *point, const BIGNUM *p_scalar, BN_CTX *ctx)
	{
	const EC_POINT *points[1];
	const BIGNUM *scalars[1];

	points[0] = point;
	scalars[0] = p_scalar;

	return EC_POINTs_mul(group, r, g_scalar, (point != NULL && p_scalar != NULL), points, scalars, ctx);
	}


int EC_GROUP_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
	{
	const EC_POINT *generator;
	BN_CTX *new_ctx = NULL;
	BIGNUM *order;
	int ret = 0;

	generator = EC_GROUP_get0_generator(group);
	if (generator == NULL)
		{
		ECerr(EC_F_EC_GROUP_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
		return 0;
		}

	if (ctx == NULL)
		{
		ctx = new_ctx = BN_CTX_new();
		if (ctx == NULL)
			return 0;
		}
	
	BN_CTX_start(ctx);
	order = BN_CTX_get(ctx);
	if (order == NULL) goto err;
	
	if (!EC_GROUP_get_order(group, order, ctx)) return 0;
	if (BN_is_zero(order))
		{
		ECerr(EC_F_EC_GROUP_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
		goto err;
		}

	/* TODO */

	ret = 1;
	
 err:
	BN_CTX_end(ctx);
	if (new_ctx != NULL)
		BN_CTX_free(new_ctx);
	return ret;
	}
