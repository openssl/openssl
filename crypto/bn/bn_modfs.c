/*
 *
 *	bn_modfs.c
 *
 *	Some Modular Arithmetic Functions.
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "bn_modfs.h"

#define MAX_ROUNDS	10


int BN_legendre(BIGNUM *a, BIGNUM *p, BN_CTX *ctx) 
	{
	BIGNUM *x, *y, *y2;
	BN_ULONG m;
	int L;

	assert(a != NULL && p != NULL && ctx != NULL);

	BN_CTX_start(ctx);
	x = BN_CTX_get(ctx);
	y = BN_CTX_get(ctx);
	y2 = BN_CTX_get(ctx);
	if (y2 == NULL) goto err;

	if (!BN_nnmod(x, a, p, ctx)) goto err;
	if (BN_is_zero(x)) 
		{
		BN_CTX_end(ctx);
		return 0;
		}

	if (BN_copy(y, p) == NULL) goto err;
	L = 1;

	while (1)
		{
		if (!BN_rshift1(y2, y)) goto err;
		if (BN_cmp(x, y2) > 0)
			{
			if (!BN_sub(x, y, x)) goto err;
			if (BN_mod_word(y, 4) == 3)
				L = -L;			
			}
		while (BN_mod_word(x, 4) == 0)
			BN_div_word(x, 4);
		if (BN_mod_word(x, 2) == 0)
			{
			BN_div_word(x, 2);
			m = BN_mod_word(y, 8);
			if (m == 3 || m == 5) L = -L;			
			}
		if (BN_is_one(x)) 
			{
			BN_CTX_end(ctx);
			return L;
			}
		
		if (BN_mod_word(x, 4) == 3 && BN_mod_word(y, 4) == 3) L = -L;
		BN_swap(x, y);

		if (!BN_nnmod(x, x, y, ctx)) goto err;

		}


err:
	BN_CTX_end(ctx);
	return -2;

	}

int BN_mod_sqrt(BIGNUM *x, BIGNUM *a, BIGNUM *p, BN_CTX *ctx) 
/* x^2 = a (mod p) */
	{
	int ret;
	BIGNUM *n0, *n1, *r, *b, *m;
	int max;

	assert(x != NULL && a != NULL && p != NULL && ctx != NULL);
	assert(BN_cmp(a, p) < 0);

	ret = BN_legendre(a, p, ctx);
	if (ret < 0 || ret > 1) return 0;
	if (ret == 0)
		{
		if (!BN_zero(x)) return 0;
		return 1;
		}

	BN_CTX_start(ctx);
	n0 = BN_CTX_get(ctx);
	n1 = BN_CTX_get(ctx);
	if (n1 == NULL) goto err;

	if ((r = BN_new()) == NULL) goto err;
	if ((b = BN_new()) == NULL) goto err;
	if ((m = BN_new()) == NULL) goto err;


	if (!BN_zero(n0)) goto err;
	if (!BN_zero(n1)) goto err;
	if (!BN_zero(r)) goto err;
	if (!BN_zero(b)) goto err;
	if (!BN_zero(m)) goto err;

	max = 0;

	do
		{
		if (max++ > MAX_ROUNDS) goto err; /* if p is not prime could never stop*/
		if (!BN_add_word(m, 1)) goto err;
		ret = BN_legendre(m, p, ctx);
		if (ret < -1 || ret > 1) goto err;
		}
	while (ret != -1);

	if (BN_copy(n1, p) == NULL) goto err;
	if (!BN_sub_word(n1, 1)) goto err;

	while (!BN_is_odd(n1))
		{
		if (!BN_add_word(r, 1)) goto err;
		if (!BN_rshift1(n1, n1)) goto err;
		}

	if (!BN_mod_exp_simple(n0, m, n1, p, ctx)) goto err;

	if (!BN_sub_word(n1, 1)) goto err;
	if (!BN_rshift1(n1, n1)) goto err;
	if (!BN_mod_exp_simple(x, a, n1, p, ctx)) goto err;

	if (!BN_mod_sqr(b, x, p, ctx)) goto err;
	if (!BN_mod_mul(b, b, a, p, ctx)) goto err;

	if (!BN_mod_mul(x, x, a, p, ctx)) goto err;

	while (!BN_is_one(b))
		{
		if (!BN_one(m)) goto err;
		if (!BN_mod_sqr(n1, b, p, ctx)) goto err;
		while(!BN_is_one(n1))
			{
			if (!BN_mod_mul(n1, n1, n1, p, ctx)) goto err;
			if (!BN_add_word(m, 1)) goto err;
			}

		if (!BN_sub(r, r, m)) goto err;
		if (!BN_sub_word(r, 1)) goto err;
		if (r->neg) goto err;

		if (BN_copy(n1, n0) == NULL) goto err;
		while(!BN_is_zero(r))
			{
			if (!BN_mod_mul(n1, n1, n1, p, ctx)) goto err;
			if (!BN_sub_word(r, 1)) goto err;
			}

		if (!BN_mod_mul(n0, n1, n1, p, ctx)) goto err;
		if (BN_copy(r, m) == NULL) goto err;
		if (!BN_mod_mul(x, x, n1, p, ctx)) goto err;
		if (!BN_mod_mul(b, b, n0, p, ctx)) goto err;
		}


#ifdef TEST
	BN_mod_sqr(n0, x, p, ctx);
	if (BN_cmp(n0, a)) goto err;
#endif

	if (r != NULL) BN_clear_free(r);
	if (b != NULL) BN_clear_free(b);
	if (m != NULL) BN_clear_free(m);
	BN_CTX_end(ctx);
	return 1;
err:
	if (r != NULL) BN_clear_free(r);
	if (b != NULL) BN_clear_free(b);
	if (m != NULL) BN_clear_free(m);
	BN_CTX_end(ctx);
	return 0;
	}
