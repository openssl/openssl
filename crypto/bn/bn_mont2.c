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

#include "bn_lcl.h"
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
	if (x->top > e/BN_BITS2)
		if(!BN_mask_bits(x, e)) return 0;

	BN_CTX_start(ctx);
	xy = BN_CTX_get(ctx);
	x_sh = BN_CTX_get(ctx);
	if (x_sh == NULL) goto err;

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
	BN_CTX_end(ctx);
	return y;


err:
	if (x != NULL) BN_clear_free(x);
	BN_CTX_end(ctx);
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
	if (!mont->p_inv_b_neg) return 0;
	mont->p_inv_b_neg = 0 - mont->p_inv_b_neg;

	return 1;
	}


#ifdef BN_LLONG
#define cpy_mul_add(r, b, a, w, c) { \
	BN_ULLONG t; \
	t = (BN_ULLONG)w * (a) + (b) + (c); \
	(r)= Lw(t); \
	(c)= Hw(t); \
	}

BN_ULONG BN_mul_add_rshift(BN_ULONG *r, BN_ULONG *a, int num, BN_ULONG w)
/* r = (r + a * w) >> BN_BITS2 */
	{
	BN_ULONG c = 0;

	mul_add(r[0], a[0], w, c);
	if (--num == 0) return c;
	a++;

	for (;;)
		{
		cpy_mul_add(r[0], r[1], a[0], w, c);
		if (--num == 0) break;
		cpy_mul_add(r[1], r[2], a[1], w, c);
		if (--num == 0) break;
		cpy_mul_add(r[2], r[3], a[2], w, c);
		if (--num == 0) break;
		cpy_mul_add(r[3], r[4], a[3], w, c);
		if (--num == 0) break;
		a += 4;
		r += 4;
		}
	
	return c;
	}
#else

#define cpy_mul_add(r, b, a, bl, bh, c) { \
	BN_ULONG l,h; \
 \
	h=(a); \
	l=LBITS(h); \
	h=HBITS(h); \
	mul64(l,h,(bl),(bh)); \
 \
	/* non-multiply part */ \
	l=(l+(c))&BN_MASK2; if (l < (c)) h++; \
	(c)=(b); \
	l=(l+(c))&BN_MASK2; if (l < (c)) h++; \
	(c)=h&BN_MASK2; \
	(r)=l; \
	}

static BN_ULONG BN_mul_add_rshift(BN_ULONG *r, BN_ULONG *a, int num, BN_ULONG w)
/* ret = (ret + a * w) << shift * BN_BITS2 */
	{
	BN_ULONG c = 0;
	BN_ULONG bl, bh;

	bl = LBITS(w);
	bh = HBITS(w);

	mul_add(r[0], a[0], bl, bh, c);
	if (--num == 0) return c;
	a++;

	for (;;)
		{
		cpy_mul_add(r[0], r[1], a[0], bl, bh, c);
		if (--num == 0) break;
		cpy_mul_add(r[1], r[2], a[1], bl, bh, c);
		if (--num == 0) break;
		cpy_mul_add(r[2], r[3], a[2], bl, bh, c);
		if (--num == 0) break;
		cpy_mul_add(r[3], r[4], a[3], bl, bh, c);
		if (--num == 0) break;
		a += 4;
		r += 4;
		}
	return c;
	}
#endif /* BN_LLONG */



int BN_mont_red(BIGNUM *y, BN_MONTGOMERY *mont)
/* yR^{-1} (mod p) */
	{
	BIGNUM *p;
	BN_ULONG c;
	int i, max;

	assert(y != NULL && mont != NULL);
	assert(mont->p != NULL);
	assert(BN_cmp(y, mont->p) < 0);
	assert(!y->neg);


	if (BN_is_zero(y)) return 1;

	p = mont->p;
	max = mont->p_num_bytes;

	if (bn_wexpand(y, max) == NULL) return 0;
	for (i = y->top; i < max; i++) y->d[i] = 0;
	y->top = max;

	/* r = [r + (y_0 * p') * p] / b */
	for (i = 0; i < max; i++)
		{
		c = BN_mul_add_rshift(y->d, p->d, max, ((y->d[0]) * mont->p_inv_b_neg) & BN_MASK2); 
		y->d[max - 1] = c;
		}

	while (y->d[y->top - 1] == 0) y->top--;

	if (BN_cmp(y, p) >= 0) 
		{
		if (!BN_sub(y, y, p)) return 0;
		}

	return 1;
	}


int BN_mont_mod_mul(BIGNUM *r_, BIGNUM *x, BIGNUM *y, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* r = x * y mod p */
/* r != x && r! = y !!! */
	{
	BN_ULONG c;
	BIGNUM *p;
	int i, j, max;
	BIGNUM *r;

	assert(r_!= NULL && x != NULL  && y != NULL && mont != NULL);
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

	if (r_ == x || r_ == y)
		{
		BN_CTX_start(ctx);
		r = BN_CTX_get(ctx);
		}
	else
		r = r_;

	p = mont->p;
	max = mont->p_num_bytes;

	/* for multiplication we need at most max + 2 words
		the last one --- max + 3 --- is only as a backstop
		for incorrect input 
	*/
	if (bn_wexpand(r, max + 3) == NULL) goto err;
	for (i = 0; i < max + 3; i++) r->d[i] = 0;
	r->top = max + 2;

	for (i = 0; i < x->top; i++)
		{
		/* r = r + (r_0 + x_i * y_0) * p' * p */
		c = bn_mul_add_words(r->d, p->d, max, \
			((r->d[0] + x->d[i] * y->d[0]) * mont->p_inv_b_neg) & BN_MASK2);
		if (c)
			{
			if (((r->d[max] += c) & BN_MASK2) < c)
				if (((r->d[max + 1] ++) & BN_MASK2) == 0) goto err;
			}
		
		/* r = (r + x_i * y) / b */
		c = BN_mul_add_rshift(r->d, y->d, y->top, x->d[i]); 
		for(j = y->top; j <= max + 1; j++) r->d[j - 1] = r->d[j];
		if (c)
			{
			if (((r->d[y->top - 1] += c) & BN_MASK2) < c)
				{
				j = y->top;
				while (((++ (r->d[j]) ) & BN_MASK2) == 0) 
					j++;
				if (j > max) goto err;
				}
			}
		r->d[max + 1] = 0;
		}

	for (i = x->top; i < max; i++)
		{
		/* r = (r + r_0 * p' * p) / b */
		c = BN_mul_add_rshift(r->d, p->d, max, ((r->d[0]) * mont->p_inv_b_neg) & BN_MASK2); 
		j = max - 1;
		r->d[j] = c + r->d[max];
		if (r->d[j++] < c) r->d[j] = r->d[++j] + 1;
		else r->d[j] = r->d[++j];
		r->d[max + 1] = 0;
		}

	while (r->d[r->top - 1] == 0) r->top--;

	if (BN_cmp(r, mont->p) >= 0) 
		{
		if (!BN_sub(r, r, mont->p)) goto err;
		}

	if (r != r_)
		{
		if (!BN_copy(r_, r)) goto err;
		BN_CTX_end(ctx);
		}

	return 1;

 err:
	if (r != r_)
		BN_CTX_end(ctx);
	return 0;
	}
