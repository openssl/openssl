/*
 *
 *	bn_mont2.c
 *
 *	Montgomery Modular Arithmetic Functions.
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "bn.h"
#include "bn_modfs.h"
#include "bn_mont2.h"

#define BN_mask_word(x, m) ((x->d[0]) & (m))

BN_MONTGOMERY *BN_mont_new()
{
	BN_MONTGOMERY *ret;

	ret=(BN_MONTGOMERY *)malloc(sizeof(BN_MONTGOMERY));

	if (ret == NULL) return NULL;

	if ((ret->p = BN_new()) == NULL)
	{
		free(ret);
		return NULL;
	}

	return ret;
}


void BN_mont_clear_free(BN_MONTGOMERY *mont)
{
	if (mont == NULL) return;

	if (mont->p != NULL) BN_clear_free(mont->p);

	mont->p_num_bytes = 0;
	mont->R_num_bits = 0;
	mont->p_inv_b_neg = 0;
}

int BN_to_mont(BIGNUM *x, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(x != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (!BN_lshift(x, x, mont->R_num_bits)) return 0;
	if (!BN_mod(x, x, mont->p, ctx)) return 0;

	return 1;
}


static BN_ULONG BN_mont_inv(BIGNUM *a, int e, BN_CTX *ctx)
/* y = a^{-1} (mod 2^e) for an odd number a */
{
	BN_ULONG y, exp, mask;
	BIGNUM *x, *xy, *x_sh;
	int i;

	assert(a != NULL && ctx != NULL);
	assert(e <= BN_BITS2);
	assert(BN_is_odd(a));
	assert(!BN_is_zero(a) && !a->neg);


	y = 1;
	exp = 2;
	mask = 3;
	if((x = BN_dup(a)) == NULL) return 0;
	if(!BN_mask_bits(x, e)) return 0;

	xy = ctx->bn[ctx->tos]; 
	x_sh = ctx->bn[ctx->tos + 1]; 
	ctx->tos += 2;

	if (BN_copy(xy, x) == NULL) goto err;
	if (!BN_lshift1(x_sh, x)) goto err;


	for (i = 2; i <= e; i++)
	{
		if (exp < BN_mask_word(xy, mask))
		{
			y = y + exp;
			if (!BN_add(xy, xy, x_sh)) goto err;
		}

		exp <<= 1;
		if (!BN_lshift1(x_sh, x_sh)) goto err;
		mask <<= 1;
		mask++;
	}


#ifdef TEST
	if (xy->d[0] != 1) goto err;
#endif

	if (x != NULL) BN_clear_free(x);
	ctx->tos -= 2;
	return y;


err:
	if (x != NULL) BN_clear_free(x);
	ctx->tos -= 2;
	return 0;

}

int BN_mont_set(BIGNUM *p, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(p != NULL && ctx != NULL);
	assert(mont != NULL);
	assert(mont->p != NULL);
	assert(!BN_is_zero(p) && !p->neg);


	mont->p_num_bytes = p->top;
	mont->R_num_bits = (mont->p_num_bytes) * BN_BITS2;

	if (BN_copy(mont->p, p) == NULL);
	
	mont->p_inv_b_neg =  BN_mont_inv(p, BN_BITS2, ctx);
	mont->p_inv_b_neg = 0 - mont->p_inv_b_neg;

	return 1;
}

static int BN_cpy_mul_word(BIGNUM *ret, BIGNUM *a, BN_ULONG w)
/* ret = a * w */
{
	if (BN_copy(ret, a) == NULL) return 0;

	if (!BN_mul_word(ret, w)) return 0;

	return 1;
}


int BN_mont_red(BIGNUM *y, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* yR^{-1} (mod p) */
{
	int i;
	BIGNUM *up, *p;
	BN_ULONG u;

	assert(y != NULL && mont != NULL && ctx != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(y, mont->p) < 0);
	assert(!y->neg);


	if (BN_is_zero(y)) return 1;

	p = mont->p;
	up = ctx->bn[ctx->tos]; 
	ctx->tos += 1;


	for (i = 0; i < mont->p_num_bytes; i++)
	{
		u = (y->d[0]) * mont->p_inv_b_neg;			/* u = y_0 * p' */

		if (!BN_cpy_mul_word(up, p, u)) goto err;	/* up = u * p */

		if (!BN_add(y, y, up)) goto err;			
#ifdef TEST
		if (y->d[0]) goto err;
#endif
		if (!BN_rshift(y, y, BN_BITS2)) goto err;	/* y = (y + up)/b */
	}


	if (BN_cmp(y, mont->p) >= 0) 
	{
		if (!BN_sub(y, y, mont->p)) goto err;
	}

	ctx->tos -= 1;
	return 1;

err:
	ctx->tos -= 1;
	return 0;

}


int BN_mont_mod_mul(BIGNUM *r, BIGNUM *x, BIGNUM *y, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* r = x * y mod p */
/* r != x && r! = y !!! */
{
	BIGNUM *xiy, *up;
	BN_ULONG u;
	int i;
	

	assert(r != x && r != y);
	assert(r != NULL && x != NULL  && y != NULL && mont != NULL && ctx != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(x, mont->p) < 0);
	assert(BN_cmp(y, mont->p) < 0);
	assert(!x->neg);
	assert(!y->neg);

	if (BN_is_zero(x) || BN_is_zero(y))
	{
		if (!BN_zero(r)) return 0;
		return 1;
	}



	xiy = ctx->bn[ctx->tos]; 
	up = ctx->bn[ctx->tos + 1]; 
	ctx->tos += 2;

	if (!BN_zero(r)) goto err;

	for (i = 0; i < x->top; i++)
	{
		u = (r->d[0] + x->d[i] * y->d[0]) * mont->p_inv_b_neg;

		if (!BN_cpy_mul_word(xiy, y, x->d[i])) goto err;
		if (!BN_cpy_mul_word(up, mont->p, u)) goto err;

		if (!BN_add(r, r, xiy)) goto err;
		if (!BN_add(r, r, up)) goto err;

#ifdef TEST
		if (r->d[0]) goto err;
#endif
		if (!BN_rshift(r, r, BN_BITS2)) goto err; 
	}

	for (i = x->top; i < mont->p_num_bytes; i++)
	{
		u = (r->d[0]) * mont->p_inv_b_neg;

		if (!BN_cpy_mul_word(up, mont->p, u)) goto err;

		if (!BN_add(r, r, up)) goto err;

#ifdef TEST
		if (r->d[0]) goto err;
#endif
		if (!BN_rshift(r, r, BN_BITS2)) goto err; 
	}


	if (BN_cmp(r, mont->p) >= 0) 
	{
		if (!BN_sub(r, r, mont->p)) goto err;
	}


	ctx->tos -= 2;
	return 1;

err:
	ctx->tos -= 2;
	return 0;
}

int BN_mont_mod_add(BIGNUM *r, BIGNUM *x, BIGNUM *y, BN_MONTGOMERY *mont)
{
	assert(r != NULL && x != NULL  && y != NULL && mont != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(x, mont->p) < 0);
	assert(BN_cmp(y, mont->p) < 0);
	assert(!x->neg);
	assert(!y->neg);

	if (!BN_add(r, x, y)) return 0;
	if (BN_cmp(r, mont->p) >= 0) 
	{
		if (!BN_sub(r, r, mont->p)) return 0;
	}

	return 1;
}


int BN_mont_mod_sub(BIGNUM *r, BIGNUM *x, BIGNUM *y, BN_MONTGOMERY *mont)
{
	assert(r != NULL && x != NULL  && y != NULL && mont != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(x, mont->p) < 0);
	assert(BN_cmp(y, mont->p) < 0);
	assert(!x->neg);
	assert(!y->neg);

	if (!BN_sub(r, x, y)) return 0;
	if (r->neg) 
	{
		if (!BN_add(r, r, mont->p)) return 0;
	}

	return 1;
}

int BN_mont_mod_lshift1(BIGNUM *r, BIGNUM *x, BN_MONTGOMERY *mont)
{
	assert(r != NULL && x != NULL && mont != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(x, mont->p) < 0);
	assert(!x->neg);

	if (!BN_lshift1(r, x)) return 0;

	if (BN_cmp(r, mont->p) >= 0) 
	{
		if (!BN_sub(r, r, mont->p)) return 0;
	}

	return 1;
}

int BN_mont_mod_lshift(BIGNUM *r, BIGNUM *x, int n, BN_MONTGOMERY *mont)
{
	int sh_nb;

	assert(r != NULL && x != NULL && mont != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(x, mont->p) < 0);
	assert(!x->neg);
	assert(n > 0);

	if (r != x)
	{
		if (BN_copy(r, x) == NULL) return 0;
	}

	while (n)
	{
		sh_nb = BN_num_bits(mont->p) - BN_num_bits(r);
		if (sh_nb > n) sh_nb = n;

		if (sh_nb)
		{
			if(!BN_lshift(r, r, sh_nb)) return 0;
		}
		else 
		{
			sh_nb = 1;
			if (!BN_lshift1(r, r)) return 0;
		}

		if (BN_cmp(r, mont->p) >= 0) 
		{
			if (!BN_sub(r, r, mont->p)) return 0;
		}

		n -= sh_nb;
	}

	return 1;
}
