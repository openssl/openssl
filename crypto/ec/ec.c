/*
 *
 *	ec.c
 *
 *	Elliptic Curve Arithmetic Functions
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include "ec.h"
#include "bn_modfs.h"



EC *EC_new()
{
	EC *ret;

	ret=(EC *)malloc(sizeof(EC));
	if (ret == NULL) return NULL;
	ret->A = BN_new();
	ret->B = BN_new();
	ret->p = BN_new();
	ret->h = BN_new();
	ret->is_in_mont = 0;

	if (ret->A == NULL || ret->B == NULL || ret->p == NULL || ret->h == NULL)
	{
		if (ret->A != NULL) BN_free(ret->A);
		if (ret->B != NULL) BN_free(ret->B);
		if (ret->p != NULL) BN_free(ret->p);
		if (ret->h != NULL) BN_free(ret->h);
		free(ret);
		return(NULL);
	}
	return(ret);
}


void EC_clear_free(EC *E)
{
	if (E == NULL) return;

	if (E->A != NULL) BN_clear_free(E->A);
	if (E->B != NULL) BN_clear_free(E->B);
	if (E->p != NULL) BN_clear_free(E->p);
	if (E->h != NULL) BN_clear_free(E->h);
	E->is_in_mont = 0;
	free(E);
}


#ifdef MONTGOMERY
int EC_to_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (E->is_in_mont) return 1;

	if (!BN_lshift(E->A, E->A, mont->R_num_bits)) return 0;
	if (!BN_mod(E->A, E->A, mont->p, ctx)) return 0;

	if (!BN_lshift(E->B, E->B, mont->R_num_bits)) return 0;
	if (!BN_mod(E->B, E->B, mont->p, ctx)) return 0;

	if (!BN_lshift(E->h, E->h, mont->R_num_bits)) return 0;
	if (!BN_mod(E->h, E->h, mont->p, ctx)) return 0;

	E->is_in_mont = 1;
	return 1;

}


int EC_from_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (!E->is_in_mont) return 1;

	if (!BN_mont_red(E->A, mont, ctx)) return 0;
	if (!BN_mont_red(E->B, mont, ctx)) return 0;
	if (!BN_mont_red(E->h, mont, ctx)) return 0;

	E->is_in_mont = 0;
	return 1;
}
#endif /* MONTGOMERY */

int EC_set_half(EC *E)
/* h <- 1/2 mod p = (p + 1)/2 */
{
	assert(E != NULL);
	assert(E->p != NULL);
	assert(E->h != NULL);
	assert(!E->is_in_mont);

	if (BN_copy(E->h, E->p) == NULL) return 0; 
	if (!BN_add_word(E->h, 1)) return 0;
	if (!BN_rshift1(E->h, E->h)) return 0; 
	return 1;
}
