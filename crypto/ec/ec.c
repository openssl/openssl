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



EC *EC_new()
{
	EC *ret;

	ret=(EC *)malloc(sizeof(EC));
	if (ret == NULL) return NULL;
	ret->A = BN_new();
	ret->B = BN_new();
	ret->p = BN_new();
	ret->is_in_mont = 0;

	if (ret->A == NULL || ret->B == NULL || ret->p == NULL)
	{
		if (ret->A != NULL) BN_free(ret->A);
		if (ret->B != NULL) BN_free(ret->B);
		if (ret->p != NULL) BN_free(ret->p);
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
	E->is_in_mont = 0;
	free(E);
}


#ifdef MONTGOMERY
int EC_to_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (E->is_in_mont) return 1;

	if (!BN_lshift(E->A, E->A, mont->R_num_bits)) return 0;
	if (!BN_mod(E->A, E->A, mont->p, ctx)) return 0;

	if (!BN_lshift(E->B, E->B, mont->R_num_bits)) return 0;
	if (!BN_mod(E->B, E->B, mont->p, ctx)) return 0;

	E->is_in_mont = 1;
	return 1;

}


int EC_from_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (!E->is_in_mont) return 1;

	if (!BN_mont_red(E->A, mont)) return 0;
	if (!BN_mont_red(E->B, mont)) return 0;

	E->is_in_mont = 0;
	return 1;
}
#endif /* MONTGOMERY */
