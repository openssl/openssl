/*
 *
 *	ec_point.c
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
#include <memory.h>

#include <openssl/bn.h>

#include "bn_modfs.h"
#include "bn_mont2.h"
#include "ec.h"

EC_POINT *ECP_new()
{
	EC_POINT *ret;

	ret=(EC_POINT *)malloc(sizeof(EC_POINT));
	if (ret == NULL) return NULL;
	ret->X = BN_new();
	ret->Y = BN_new();
	ret->Z = BN_new();
	ret->is_in_mont = 0;

	if (ret->X == NULL || ret->Y == NULL || ret->Z == NULL) 
	{
		if (ret->X != NULL) BN_free(ret->X);
		if (ret->Y != NULL) BN_free(ret->Y);
		if (ret->Z != NULL) BN_free(ret->Z);
		free(ret);
		return(NULL);
	}
	return(ret);
}

void ECP_clear_free(EC_POINT *P)
{
	if (P == NULL) return;
	
	P->is_in_mont = 0;
	if (P->X != NULL) BN_clear_free(P->X);
	if (P->Y != NULL) BN_clear_free(P->Y);
	if (P->Z != NULL) BN_clear_free(P->Z);
	free(P);
}

void ECP_clear_free_precompute(ECP_PRECOMPUTE *prec)
{
	int i;
	int max;

	if (prec == NULL) return;
	if (prec->Pi != NULL)
	{
		max = 1;
		max <<= (prec->r - 1);

		for (i = 0; i < max; i++)
		{
			if (prec->Pi[i] != NULL) ECP_clear_free(prec->Pi[i]);
		}
	}
	free(prec);
}

int ECP_is_on_ec(EC_POINT *P, EC *E, BN_CTX *ctx)
{
	BIGNUM *n0, *n1, *n2, *p;
	int Pnorm;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL);

	assert(ctx != NULL);

	assert(!P->is_in_mont);

	if (ECP_is_infty(P)) return 1;
	
	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	ctx->tos += 3;


	p = E->p;

	Pnorm = (ECP_is_norm(P));

	if (!Pnorm)
	{
		if (!BN_mod_mul(n0, P->Z, P->Z, p, ctx)) goto err;
		if (!BN_mod_mul(n1, n0, n0, p, ctx)) goto err;
		if (!BN_mod_mul(n2, n0, n1, p, ctx)) goto err;
	}

	if (!BN_mod_mul(n0, P->X, P->X, p, ctx)) goto err;
	if (!BN_mod_mul(n0, n0, P->X, p, ctx)) goto err;

	if (Pnorm)
	{
		if (!BN_mod_mul(n1, P->X, E->A, p, ctx)) goto err;
	}
	else
	{
		if (!BN_mod_mul(n1, n1, P->X, p, ctx)) goto err;
		if (!BN_mod_mul(n1, n1, E->A, p, ctx)) goto err;
	}
	if (!BN_mod_add(n0, n0, n1, p, ctx)) goto err;

	if (Pnorm)
	{
		if (!BN_mod_add(n0, n0, E->B, p, ctx)) goto err;
	}
	else
	{
		if (!BN_mod_mul(n2, n2, E->B,  p, ctx)) goto err;
		if (!BN_mod_add(n0, n0, n2, p, ctx)) goto err;
	}

	if (!BN_mod_mul(n1, P->Y, P->Y, p, ctx)) goto err;

	if (BN_cmp(n0, n1)) 
	{ 
		ctx->tos -= 3;
		return 0;
	}

	ctx->tos -= 3;
	return 1;
	
err:
	ctx->tos -= 3;
	return -1;
}


EC_POINT *ECP_generate(BIGNUM *x, BIGNUM *z,EC *E, BN_CTX *ctx)
/* x == NULL || z = 0  -> point of infinity	*/
/* z == NULL || z = 1  -> normalized		*/
{
	BIGNUM *n0, *n1;
	EC_POINT *ret;
	int Pnorm, Pinfty, X0, A0;

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(ctx != NULL);

	Pinfty = (x == NULL);
	Pnorm = (z == NULL);
	if (!Pnorm) 
	{
		Pnorm = BN_is_one(z);
		Pinfty = (Pinfty || BN_is_zero(z));
	}

	if (Pinfty) 
	{
		if ((ret = ECP_new()) == NULL) return NULL;
		if (!BN_zero(ret->Z)) 
		{ 
			ECP_clear_free(ret);
			return NULL;
		}
		return ret;
	}

	X0 = BN_is_zero(x);
	A0 = BN_is_zero(E->A);

	if ((ret = ECP_new()) == NULL) return NULL;

	ret->is_in_mont = 0;

	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	if (!BN_zero(n0)) return NULL;
	if (!BN_zero(n1)) return NULL;

	ctx->tos += 2;

	if (!X0)
	{
		if (!BN_mod_sqr(n0, x, E->p, ctx)) goto err;
		if (!BN_mod_mul(n0, n0, x, E->p, ctx)) goto err;	/* x^3 */
	}

	if (!X0 && !A0)
	{
		if (!BN_mod_mul(n1, E->A, x, E->p, ctx)) goto err;	/* Ax */
		if (!BN_mod_add(n0, n0, n1, E->p, ctx)) goto err;	/* x^3 + Ax */
	}

	if (!BN_is_zero(E->B))
		if (!BN_mod_add(n0, n0, E->B, E->p, ctx)) goto err;	/* x^3 + Ax +B */

	if (!BN_mod_sqrt(ret->Y, n0, E->p, ctx)) goto err;
	if (BN_copy(ret->X, x) == NULL) goto err;
	
	if (Pnorm)
	{
		if (!BN_one(ret->Z)) goto err;
	}
	else
	{
		if (BN_copy(ret->Z, z) == NULL) goto err;
		if (!BN_mod_sqr(n0, z, E->p, ctx)) goto err;
		if (!BN_mod_mul(ret->X, ret->X, n0, E->p, ctx)) goto err;
		if (!BN_mod_mul(n0, n0, z, E->p, ctx)) goto err;
		if (!BN_mod_mul(ret->Y, ret->Y, n0, E->p, ctx)) goto err;
	}

#ifdef TEST
	if (!ECP_is_on_ec(ret, E, ctx)) goto err;
#endif
	
	ctx->tos -= 2;
	return ret;

err:
	if (ret != NULL) ECP_clear_free(ret);
	ctx->tos -= 2;
	return NULL;
}

int ECP_ecp2bin(EC_POINT *P, unsigned char *to, int form)
/* form =	1 ... compressed
			2 ... uncompressed
			3 ... hybrid */
{
	int bytes, bx, by;

	assert (P != NULL);
	assert (P->X != NULL && P->Y != NULL && P->Z != NULL);
	assert (!P->is_in_mont);
	assert (ECP_is_norm(P) || ECP_is_infty(P));
	assert (to != NULL);
	assert (form > 0 && form < 4);

	if (BN_is_zero(P->Z))
	{
		to[0] = 0;
		return 1;
	}

	bx = BN_num_bytes(P->X);
	if (form == 1 ) bytes = bx + 1;
	else 
	{
		by = BN_num_bytes(P->Y);
		bytes = (bx > by ? bx : by);
		bytes = bytes * 2 + 1;
	}
	memset(to, 0, bytes);

	switch (form)
	{
	case 1: to[0] = 2;	break;
	case 2: to[0] = 4;	break;
	case 3: to[0] = 6;	break;
	}
	if (form != 2) to[0] += BN_is_bit_set(P->Y, 0);

	
	if ((BN_bn2bin(P->X, to + 1)) != bx) return 0;
	if (form != 1)
	{
		if ((BN_bn2bin(P->Y, to + bx + 1)) != by) return 0;
	}

	return bytes;
}

int ECP_bin2ecp(unsigned char *from, int len, EC_POINT *P, EC *E, BN_CTX *ctx)
{
	int y;
	BIGNUM *x;
	EC_POINT *pp;

	assert (E != NULL);
	assert (E->A != NULL && E->B != NULL && E->p != NULL);
	assert (!E->is_in_mont);

	assert (ctx != NULL);
	assert (from != NULL);
	assert (P != NULL);
	assert (P->X != NULL && P->Y != NULL && P->Z != NULL);

	if (len == 1 && from[0] != 0) return 0;

	if (len == 0 || len == 1)
	{ 
		if (!BN_zero(P->Z)) return 0;
		return 1;
	}

	switch (from[0])
	{
	case 2:
	case 3:
		y = from[0] - 2;
		if ((x = BN_new()) == NULL) return 0;
		if (BN_bin2bn(from + 1, len - 1, x) == NULL) return 0;

		pp = ECP_generate(x, NULL, E, ctx);
		BN_clear_free(x);
		if (pp == NULL) return 0;

		ECP_copy(P, pp);
		ECP_clear_free(pp);

		if (BN_is_bit_set(P->Y, 0) != y)
			if (!BN_sub(P->Y, E->p, P->Y)) return 0;
		break;

	case 4:
	case 6:
	case 7:
		y = (len - 1)/2;
		if (BN_bin2bn(from + 1, y, P->X) == NULL) return 0;
		if (BN_bin2bn(from + y + 1, y, P->Y) == NULL) return 0;
		if (!BN_set_word(P->Z, 1)) return 0;
		break;

	default:
		assert(0);

	}

	if (!ECP_is_on_ec(P, E, ctx)) return 0;
	return 1;
}

int ECP_normalize(EC_POINT *P, EC *E, BN_CTX *ctx)
{
	BIGNUM *z, *zm;

	assert (P != NULL);
	assert (P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert (E != NULL);
	assert (E->A != NULL && E->B != NULL && E->p != NULL);

	assert (ctx != NULL);

	if (ECP_is_norm(P)) return 1;
	if (ECP_is_infty(P)) return 0;

	if ((zm = BN_mod_inverse(P->Z, P->Z, E->p, ctx)) == NULL) return 0;

	assert(!P->is_in_mont);


	z = ctx->bn[ctx->tos]; 
	ctx->tos++;

	if (!BN_mod_mul(z, zm, zm, E->p, ctx)) goto err;
	if (!BN_mod_mul(P->X, P->X, z, E->p, ctx)) goto err;

	if (!BN_mod_mul(z, z, zm, E->p, ctx)) goto err;
	if (!BN_mod_mul(P->Y, P->Y, z, E->p, ctx)) goto err;

	if (!BN_one(P->Z)) goto err;

	if (zm != NULL) BN_clear_free(zm);

	ctx->tos--;
	return 1;

err:
	if (zm != NULL) BN_clear_free(zm);
	ctx->tos--;
	return 0;
}

int ECP_copy(EC_POINT *R, EC_POINT *P)
{
	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	if (BN_copy(R->X, P->X) == NULL) return 0;
	if (BN_copy(R->Y, P->Y) == NULL) return 0;
	if (BN_copy(R->Z, P->Z) == NULL) return 0;
	R->is_in_mont = P->is_in_mont;

	return 1;
}

EC_POINT *ECP_dup(EC_POINT *P)
{
	EC_POINT *ret;

	ret = ECP_new();
	if (ret == NULL) return NULL;

	if (!ECP_copy(ret, P))
	{
		ECP_clear_free(ret);
		return(NULL);
	}

	return(ret);
}


EC_POINT *ECP_minus(EC_POINT *P, BIGNUM *p) /* mont || non-mont */
{
	EC_POINT *ret;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(p != NULL);

	assert(BN_cmp(P->Y, p) < 0);

	ret = ECP_dup(P);
	if (ret == NULL) return NULL;

	if (BN_is_zero(ret->Y)) return ret;

	if (!BN_sub(ret->Y, p, ret->Y))
	{
		ECP_clear_free(ret);
		return NULL;
	}

	return ret;
}


#ifdef SIMPLE
int ECP_cmp(EC_POINT *P, EC_POINT *Q, BIGNUM *p, BN_CTX *ctx)
/* return values: 
	-2 ... error
	 0 ... P = Q 
	-1 ... P = -Q
	 1 ... else
*/
{
	BIGNUM *n0, *n1, *n2, *n3, *n4;
	int Pnorm, Qnorm;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(Q != NULL);
	assert(Q->X != NULL && Q->Y != NULL && Q->Z != NULL);

	assert(p != NULL);
	assert(ctx != NULL);

	assert(!P->is_in_mont);
	assert(!Q->is_in_mont);

	if (ECP_is_infty(P) && ECP_is_infty(Q)) return 0;
	if (ECP_is_infty(P) || ECP_is_infty(Q)) return 1;

	
	Pnorm = (ECP_is_norm(P));
	Qnorm = (ECP_is_norm(Q));
	
	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 
	n4 = ctx->bn[ctx->tos + 4]; 
	ctx->tos += 5;
	
	if (Qnorm)
	{
		if (BN_copy(n1, P->X) == NULL) goto err;			/* L1 = x_p */
		if (BN_copy(n2, P->Y) == NULL) goto err;			/* L2 = y_p */
	}
	else
	{
		if (!BN_sqr(n0, Q->Z, ctx)) goto err;
		if (!BN_mod_mul(n1, P->X, n0, p, ctx)) goto err;	/* L1 = x_p * z_q^2 */

		if (!BN_mod_mul(n0, n0, Q->Z, p, ctx)) goto err; 
		if (!BN_mod_mul(n2, P->Y, n0, p, ctx)) goto err;	/* L2 = y_p * z_q^3 */
	}

	if (Pnorm)
	{
		if (BN_copy(n3, Q->X) == NULL) goto err;			/* L3 = x_q */
		if (BN_copy(n4, Q->Y) == NULL) goto err;			/* L4 = y_q */
	}
	else
	{
		if (!BN_sqr(n0, P->Z, ctx)) goto err;
		if (!BN_mod_mul(n3, Q->X, n0, p, ctx)) goto err;	/* L3 = x_q * z_p^2 */

		if (!BN_mod_mul(n0, n0, P->Z, p, ctx)) goto err; 
		if (!BN_mod_mul(n4, Q->Y, n0, p, ctx)) goto err;	/* L4 = y_q * z_p^3 */
	}

	if (!BN_mod_sub(n0, n1, n3, p, ctx)) goto err;			/* L5 = L1 - L3 */

	if (!BN_is_zero(n0))
	{
		ctx->tos -= 5;
		return 1;
	}
	
	if (!BN_mod_sub(n0, n2, n4, p, ctx)) goto err;			/* L6 = L2 - L4 */

	if (!BN_is_zero(n0))
	{
		ctx->tos -= 5;
		return -1;
	}

	ctx->tos -= 5;
	return 0;

err:
	ctx->tos -= 5;
	return -2;
}

int ECP_double(EC_POINT *R, EC_POINT *P, EC *E, BN_CTX *ctx)
/* R <- 2P (on E) */
{
	BIGNUM *n0, *n1, *n2, *n3, *p;
	int Pnorm, A0;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(ctx != NULL);

	assert(!P->is_in_mont);

	if (ECP_is_infty(P))
	{
		if (!BN_zero(R->Z)) return 0;
		return 1;
	}

	Pnorm = (ECP_is_norm(P));
	A0 = (BN_is_zero(E->A));

	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 
	ctx->tos += 4;

	p = E->p;

	/* L1 */
	if (Pnorm || A0)
	{
		if (!BN_mod_sqr(n1, P->X, p, ctx)) goto err;
		if (!BN_mul_word(n1, 3)) goto err;  
		if (!A0)                                   /* if A = 0: L1 = 3 * x^2 + a * z^4 = 3 * x ^2    */
			if (!BN_mod_add(n1, n1, E->A, p, ctx)) goto err; /* L1 = 3 * x^2 + a * z^4 = 3 * x^2 + a */
	}
	else
	{
		if (!BN_mod_sqr(n0, P->Z, p, ctx)) goto err;
		if (!BN_mod_mul(n0, n0, n0, p, ctx)) goto err;
		if (!BN_mod_mul(n0, n0, E->A, p, ctx)) goto err; 
		if (!BN_mod_sqr(n1, P->X, p, ctx)) goto err;
		if (!BN_mul_word(n1, 3)) goto err;  
		if (!BN_mod_add(n1, n1, n0, p, ctx)) goto err;		/* L1 = 3 * x^2 + a * z^4 */
	}

	/* Z */
	if (Pnorm)
	{
		if (BN_copy(n0, P->Y) == NULL) goto err;
	}
	else
	{
		if (!BN_mod_mul(n0, P->Y, P->Z, p, ctx)) goto err; 
	}
	if (!BN_lshift1(n0, n0)) goto err; 
	if (!BN_smod(R->Z, n0, p, ctx)) goto err;				/* Z = 2 * y * z */

	/* L2 */
	if (!BN_mod_sqr(n3, P->Y, p, ctx)) goto err;
	if (!BN_mod_mul(n2, P->X, n3, p, ctx)) goto err; 
	if (!BN_lshift(n2, n2, 2)) goto err; 
	if (!BN_smod(n2, n2, p, ctx)) goto err;					/* L2 = 4 * x * y^2 */

	/* X */
	if (!BN_lshift1(n0, n2)) goto err; 
	if (!BN_mod_sqr(R->X, n1, p, ctx)) goto err;
	if (!BN_mod_sub(R->X, R->X, n0, p, ctx)) goto err;		/* X = L1^2 - 2 * L2 */
	
	/* L3 */
	if (!BN_mod_sqr(n0, n3, p, ctx)) goto err;
	if (!BN_lshift(n3, n0, 3)) goto err; 
	if (!BN_smod(n3, n3, p, ctx)) goto err;					/* L3 = 8 * y^4 */
	
	/* Y */
	if (!BN_mod_sub(n0, n2, R->X, p, ctx)) goto err; 
	if (!BN_mod_mul(n0, n1, n0, p, ctx)) goto err; 
	if (!BN_mod_sub(R->Y, n0, n3, p, ctx)) goto err;		/* Y = L1 * (L2 - X) - L3 */


#ifdef TEST
	if (!ECP_is_on_ec(R, E, ctx)) return 0;
#endif

	ctx->tos -= 4;
	return 1;

err:
	ctx->tos -= 4;
	return 0;
}

int ECP_add(EC_POINT *R, EC_POINT *P, EC_POINT *Q, EC *E, BN_CTX *ctx)
/* R <- P + Q (on E) */
{
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5, *n6, *p;
	int Pnorm, Qnorm;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(Q != NULL);
	assert(Q->X != NULL && Q->Y != NULL && Q->Z != NULL);

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);
	assert(!BN_is_zero(E->h));;

	assert(ctx != NULL);

	assert(!P->is_in_mont);
	assert(!Q->is_in_mont);

	if (P == Q) return ECP_double(R, P, E, ctx);

	if (ECP_is_infty(P)) return ECP_copy(R, Q);
	if (ECP_is_infty(Q)) return ECP_copy(R, P);
	
	Pnorm = (ECP_is_norm(P));
	Qnorm = (ECP_is_norm(Q));
	
	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 
	n4 = ctx->bn[ctx->tos + 4]; 
	n5 = ctx->bn[ctx->tos + 5]; 
	n6 = ctx->bn[ctx->tos + 6]; 
	ctx->tos += 7;
	p = E->p;
	
	/* L1; L2 */
	if (Qnorm)
	{
		if (BN_copy(n1, P->X) == NULL) goto err;         /* L1 = x_p */
		if (BN_copy(n2, P->Y) == NULL) goto err;         /* L2 = y_p */
	}
	else
	{
		if (!BN_sqr(n0, Q->Z, ctx)) goto err;
		if (!BN_mod_mul(n1, P->X, n0, p, ctx)) goto err; /* L1 = x_p * z_q^2 */

		if (!BN_mod_mul(n0, n0, Q->Z, p, ctx)) goto err; 
		if (!BN_mod_mul(n2, P->Y, n0, p, ctx)) goto err; /* L2 = y_p * z_q^3 */
	}

	/* L3; L4 */
	if (Pnorm)
	{
		if (BN_copy(n3, Q->X) == NULL) goto err;         /* L3 = x_q */
		if (BN_copy(n4, Q->Y) == NULL) goto err;         /* L4 = y_q */
	}
	else
	{
		if (!BN_sqr(n0, P->Z, ctx)) goto err;
		if (!BN_mod_mul(n3, Q->X, n0, p, ctx)) goto err; /* L3 = x_q * z_p^2 */

		if (!BN_mod_mul(n0, n0, P->Z, p, ctx)) goto err; 
		if (!BN_mod_mul(n4, Q->Y, n0, p, ctx)) goto err; /* L4 = y_q * z_p^3 */
	}

	/* L5; L6 */
	if (!BN_mod_sub(n5, n1, n3, p, ctx)) goto err;		/* L5 = L1 - L3 */
	if (!BN_mod_sub(n6, n2, n4, p, ctx)) goto err;		/* L6 = L2 - L4 */

	/* pata */
	if (BN_is_zero(n5))
	{
		if (BN_is_zero(n6))	/* P = Q => P + Q = 2P */
		{
			ctx->tos -= 7;
			return ECP_double(R, P, E, ctx);
		}
		else				 /* P = -Q => P + Q = \infty */
		{ 
			ctx->tos -= 7;
			if (!BN_zero(R->Z)) return 0;
			return 1;
		}
	}

	/* L7; L8 */
	if (!BN_mod_add(n1, n1, n3, p, ctx)) goto err;		/* L7 = L1 + L3 */
	if (!BN_mod_add(n2, n2, n4, p, ctx)) goto err;		/* L8 = L2 + L4 */

	/* Z */
	if (Pnorm) 
	{
		if (BN_copy(n0, Q->Z) == NULL) goto err;
	}
	else
	{
		if (!BN_mod_mul(n0, P->Z, Q->Z, p, ctx)) goto err;
	}
	if (!BN_mod_mul(R->Z, n0, n5, p, ctx)) goto err;	/* Z = z_p * z_q * L_5 */

	/* X */
	if (!BN_mod_sqr(n0, n6, p, ctx)) goto err;
	if (!BN_mod_sqr(n4, n5, p, ctx)) goto err;
	if (!BN_mod_mul(n3, n1, n4, p, ctx)) goto err; 
	if (!BN_mod_sub(R->X, n0, n3, p, ctx)) goto err;	/* X = L6^2 - L5^2 * L7 */
	
	/* L9 */
	if (!BN_lshift1(n0, R->X)) goto err;
	if (!BN_mod_sub(n0, n3, n0, p, ctx)) goto err;		/* L9 = L5^2 * L7 - 2X */

	/* Y */
	if (!BN_mod_mul(n0, n0, n6, p, ctx)) goto err; 
	if (!BN_mod_mul(n5, n4, n5, p, ctx)) goto err; 
	if (!BN_mod_mul(n1, n2, n5, p, ctx)) goto err; 
	if (!BN_mod_sub(n0, n0, n1, p, ctx)) goto err;   
	if (!BN_mod_mul(R->Y, n0, E->h, p, ctx)) goto err;	/* Y = (L6 * L9 - L8 * L5^3) / 2 */



#ifdef TEST
	if (!ECP_is_on_ec(R, E, ctx)) return 0;
#endif

	ctx->tos -= 7;
	return 1;

err:
	ctx->tos -= 7;
	return 0;
}


ECP_PRECOMPUTE *ECP_precompute(int r, EC_POINT *P, EC *E, BN_CTX *ctx)
{
	ECP_PRECOMPUTE *ret;
	EC_POINT *P2;
	int i, max;

	assert(r > 2);
	assert(!P->is_in_mont);
	assert(!E->is_in_mont);

	ret=(ECP_PRECOMPUTE *)malloc(sizeof(ECP_PRECOMPUTE));
	if (ret == NULL) return NULL;

	max = 1;
	max <<= (r - 1);

	ret->r = 0;

	ret->Pi=(EC_POINT **)malloc(sizeof(EC_POINT *) * max);
	if (ret->Pi == NULL) goto err;

	
	/* P2 = [2]P */
	if ((P2 = ECP_new()) == NULL) goto err;
	if (!ECP_double(P2, P, E, ctx)) goto err;

	/* P_0 = P */
	if((ret->Pi[0] = ECP_dup(P)) == NULL) goto err;


	/* P_i = P_(i-1) + P2 */
	for (i = 1; i < max; i++)
	{
		if ((ret->Pi[i] = ECP_new()) == NULL) goto err;
		
		if (!ECP_add(ret->Pi[i], P2, ret->Pi[i - 1], E, ctx)) goto err;
	}

	ret->r = r;
	ECP_clear_free(P2);

	return ret;

err:
	ECP_clear_free(P2);
	ECP_clear_free_precompute(ret);
	return NULL;
}

int ECP_multiply(EC_POINT *R, BIGNUM *k, ECP_PRECOMPUTE *prec, EC *E, BN_CTX *ctx)
/* R = [k]P */
{
	int j;
	int t, nextw, h, r;

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(k != NULL);
	assert(!k->neg);

	assert(ctx != NULL);
	assert(prec != NULL);

	assert(!E->is_in_mont);

	if (BN_is_zero(k))
	{
		if (!BN_zero(R->Z)) return 0;
		R->is_in_mont = 0;
		return 1;
	}


	j = BN_num_bits(k);
	j--;

	r = prec->r;

	if (!BN_zero(R->Z)) return 0;
	R->is_in_mont = 0;

	while(j >= 0)
	{
		if (!BN_is_bit_set(k, j))
		{
			if (!ECP_double(R, R, E, ctx)) return 0;
			j--;
		}
		else
		{
			nextw = j - r;
			if (nextw < -1) nextw = -1;
			t = nextw + 1;			
			while(!BN_is_bit_set(k, t))
			{
				t++;
			}

			if (!ECP_double(R, R, E, ctx)) return 0;

			j--;
			if (j < t) h = 0;
			else 
			{
				h = 1;
				for(; j > t; j--)
				{
					h <<= 1;
					if (BN_is_bit_set(k, j)) h++;
					if (!ECP_double(R, R, E, ctx)) return 0;
				}
				if (!ECP_double(R, R, E, ctx)) return 0;
				j--;
			}

			if (!ECP_add(R, R, prec->Pi[h], E, ctx)) return 0;

			for (; j > nextw; j--)
			{
				if (!ECP_double(R, R, E, ctx)) return 0;
			}

		}
	}

	return 1;
}

#endif /* SIMPLE */

#ifdef MONTGOMERY

int ECP_to_montgomery(EC_POINT *P, BN_MONTGOMERY *mont, BN_CTX *ctx)
{

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (P->is_in_mont) return 1;

	if (!BN_lshift(P->X, P->X, mont->R_num_bits)) return 0;
	if (!BN_mod(P->X, P->X, mont->p, ctx)) return 0;

	if (!BN_lshift(P->Y, P->Y, mont->R_num_bits)) return 0;
	if (!BN_mod(P->Y, P->Y, mont->p, ctx)) return 0;

	if (!BN_lshift(P->Z, P->Z, mont->R_num_bits)) return 0;
	if (!BN_mod(P->Z, P->Z, mont->p, ctx)) return 0;

	P->is_in_mont = 1;
	return 1;
}


int ECP_from_montgomery(EC_POINT *P, BN_MONTGOMERY *mont, BN_CTX *ctx)
{

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (!P->is_in_mont) return 1;

	if (!BN_mont_red(P->X, mont, ctx)) return 0;
	if (!BN_mont_red(P->Y, mont, ctx)) return 0;
	if (!BN_mont_red(P->Z, mont, ctx)) return 0;

	P->is_in_mont = 0;
	return 1;
}

int ECP_mont_cmp(EC_POINT *P, EC_POINT *Q, BN_MONTGOMERY *mont, BN_CTX *ctx) 
/* return values: 
	-2 ... error
	 0 ... P = Q 
	-1 ... P = -Q
	 1 ... else
*/
{
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5, *p;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(Q != NULL);
	assert(Q->X != NULL && Q->Y != NULL && Q->Z != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	assert(ctx != NULL);

	if (!P->is_in_mont)
		if (!ECP_to_montgomery(P, mont, ctx)) return 0;

	if (!Q->is_in_mont)
		if (!ECP_to_montgomery(Q, mont, ctx)) return 0;


	if (ECP_is_infty(P) && ECP_is_infty(Q)) return 0;
	if (ECP_is_infty(P) || ECP_is_infty(Q)) return 1;

	
	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 
	n4 = ctx->bn[ctx->tos + 4]; 
	n5 = ctx->bn[ctx->tos + 5]; 
	ctx->tos += 6;

	p = mont->p;
	

	if (!BN_mont_mod_mul(n5, Q->Z, Q->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n1, P->X, n5, mont, ctx)) goto err;	/* L1 = x_p * z_q^2 */

	if (!BN_mont_mod_mul(n0, n5, Q->Z, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n2, P->Y, n0, mont, ctx)) goto err;	/* L2 = y_p * z_q^3 */

	if (!BN_mont_mod_mul(n5, P->Z, P->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n3, Q->X, n5, mont, ctx)) goto err;	/* L3 = x_q * z_p^2 */

	if (!BN_mont_mod_mul(n0, n5, P->Z, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n4, Q->Y, n0, mont, ctx)) goto err;	/* L4 = y_q * z_p^3 */


	if (!BN_mod_sub_quick(n0, n1, n3, p)) goto err;			/* L5 = L1 - L3 */

	if (!BN_is_zero(n0))
	{
		ctx->tos -= 6;
		return 1;
	}
	
	if (!BN_mod_sub_quick(n0, n2, n4, p)) goto err;			/* L6 = L2 - L4 */

	if (!BN_is_zero(n0))
	{
		ctx->tos -= 6;
		return -1;
	}

	ctx->tos -= 6;
	return 0;

err:
	ctx->tos -= 6;
	return -2;
}


int ECP_mont_double(EC_POINT *R, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* R <- 2P (on E) */
{
	BIGNUM *n0, *n1, *n2, *n3, *p;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(ctx != NULL);
	
	if (!P->is_in_mont)
		if (!ECP_to_montgomery(P, mont, ctx)) return 0;

	if (!E->is_in_mont) 
		if (!EC_to_montgomery(E, mont, ctx)) return 0;

	R->is_in_mont = 1;

	if (ECP_is_infty(P))
	{
		if (!BN_zero(R->Z)) return 0;
		return 1;
	}


	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 

	ctx->tos += 4;

	p = E->p;

	/* L1 */
	if (!BN_mont_mod_mul(n0, P->Z, P->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n2, n0, n0, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n0, n2, E->A, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n1, P->X, P->X, mont, ctx)) goto err;
	if (!BN_mod_lshift1_quick(n2, n1, p)) goto err;
	if (!BN_mod_add_quick(n1, n1, n2, p)) goto err;
	if (!BN_mod_add_quick(n1, n1, n0, p)) goto err;		/* L1 = 3 * x^2 + a * z^4 */

	/* Z */
	if (!BN_mont_mod_mul(n0, P->Y, P->Z, mont, ctx)) goto err; 
	if (!BN_mod_lshift1_quick(R->Z, n0, p)) goto err;		/* Z = 2 * y * z */

	/* L2 */
	if (!BN_mont_mod_mul(n3, P->Y, P->Y, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n2, P->X, n3, mont, ctx)) goto err; 
	if (!BN_mod_lshift_quick(n2, n2, 2, p)) goto err;		/* L2 = 4 * x * y^2 */

	/* X */
	if (!BN_mod_lshift1_quick(n0, n2, p)) goto err; 
	if (!BN_mont_mod_mul(R->X, n1, n1, mont, ctx)) goto err;
	if (!BN_mod_sub_quick(R->X, R->X, n0, p)) goto err;	/* X = L1^2 - 2 * L2 */
	
	/* L3 */
	if (!BN_mont_mod_mul(n0, n3, n3, mont, ctx)) goto err;
	if (!BN_mod_lshift_quick(n3, n0, 3, p)) goto err;		/* L3 = 8 * y^4 */

	
	/* Y */
	if (!BN_mod_sub_quick(n2, n2, R->X, p)) goto err; 
	if (!BN_mont_mod_mul(n0, n1, n2, mont, ctx)) goto err; 
	if (!BN_mod_sub_quick(R->Y, n0, n3, p)) goto err;		/* Y = L1 * (L2 - X) - L3 */

	ctx->tos -= 4;
	return 1;

err:
	ctx->tos -= 4;
	return 0;
}


int ECP_mont_add(EC_POINT *R, EC_POINT *P, EC_POINT *Q, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* R <- P + Q (on E) */
{
	BIGNUM *n0, *n1, *n2, *n3, *n4, *n5, *n6, *p;

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(Q != NULL);
	assert(Q->X != NULL && Q->Y != NULL && Q->Z != NULL);

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);
	assert(!BN_is_zero(E->h));;

	assert(ctx != NULL);

	if (!Q->is_in_mont)
		if (!ECP_to_montgomery(Q, mont, ctx)) return 0;

	if (!P->is_in_mont)
		if (!ECP_to_montgomery(P, mont, ctx)) return 0;

	if (!E->is_in_mont) 
		if (!EC_to_montgomery(E, mont, ctx)) return 0;

	if (P == Q) return ECP_mont_double(R, P, E, mont, ctx);

	if (ECP_is_infty(P)) return ECP_copy(R, Q);
	if (ECP_is_infty(Q)) return ECP_copy(R, P);
	

	n0 = ctx->bn[ctx->tos]; 
	n1 = ctx->bn[ctx->tos + 1]; 
	n2 = ctx->bn[ctx->tos + 2]; 
	n3 = ctx->bn[ctx->tos + 3]; 
	n4 = ctx->bn[ctx->tos + 4]; 
	n5 = ctx->bn[ctx->tos + 5]; 
	n6 = ctx->bn[ctx->tos + 6]; 
	ctx->tos += 7;


	p = E->p;

	R->is_in_mont = 1;
	
	/* L1; L2 */
	if (!BN_mont_mod_mul(n6, Q->Z, Q->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n1, P->X, n6, mont, ctx)) goto err;	/* L1 = x_p * z_q^2 */

	if (!BN_mont_mod_mul(n0, n6, Q->Z, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n2, P->Y, n0, mont, ctx)) goto err;	/* L2 = y_p * z_q^3 */


	/* L3; L4 */
	if (!BN_mont_mod_mul(n6, P->Z, P->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n3, Q->X, n6, mont, ctx)) goto err;	/* L3 = x_q * z_p^2 */

	if (!BN_mont_mod_mul(n0, n6, P->Z, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n4, Q->Y, n0, mont, ctx)) goto err;	/* L4 = y_q * z_p^3 */


	/* L5; L6 */
	if (!BN_mod_sub_quick(n5, n1, n3, p)) goto err;			/* L5 = L1 - L3 */
	if (!BN_mod_sub_quick(n6, n2, n4, p)) goto err;			/*L6 = L2 - L4 */


	/* pata */
	if (BN_is_zero(n5))
	{
		if (BN_is_zero(n6))  /* P = Q => P + Q = 2P */
		{
			ctx->tos -= 7;
			return ECP_mont_double(R, P, E, mont, ctx);
		}
		else				 /* P = -Q => P + Q = \infty */
		{ 
			ctx->tos -= 7;
			if (!BN_zero(R->Z)) return 0;
			return 1;
		}
	}

	/* L7; L8 */
	if (!BN_mod_add_quick(n1, n1, n3, p)) goto err;			/* L7 = L1 + L3 */
	if (!BN_mod_add_quick(n2, n2, n4, p)) goto err;			/* L8 = L2 + L4 */


	/* Z */
	if (!BN_mont_mod_mul(n0, P->Z, Q->Z, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(R->Z, n0, n5, mont, ctx)) goto err;	/* Z = z_p * z_q * L_5 */


	/* X */
	if (!BN_mont_mod_mul(n0, n6, n6, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n4, n5, n5, mont, ctx)) goto err;
	if (!BN_mont_mod_mul(n3, n1, n4, mont, ctx)) goto err; 
	if (!BN_mod_sub_quick(R->X, n0, n3, p)) goto err;			/* X = L6^2 - L5^2 * L7 */

	
	/* L9 */
	if (!BN_mod_lshift1_quick(n0, R->X, p)) goto err;
	if (!BN_mod_sub_quick(n3, n3, n0, p)) goto err;			/* L9 = L5^2 * L7 - 2X */


	/* Y */
	if (!BN_mont_mod_mul(n0, n3, n6, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n6, n4, n5, mont, ctx)) goto err; 
	if (!BN_mont_mod_mul(n1, n2, n6, mont, ctx)) goto err; 
	if (!BN_mod_sub_quick(n0, n0, n1, p)) goto err;   
	if (!BN_mont_mod_mul(R->Y, n0, E->h, mont, ctx)) goto err;	/* Y = (L6 * L9 - L8 * L5^3) / 2 */


	ctx->tos -= 7;
	return 1;

err:
	ctx->tos -= 7;
	return 0;
}


ECP_PRECOMPUTE *ECP_mont_precompute(int r, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
{
	ECP_PRECOMPUTE *ret;
	EC_POINT *P2;
	int i, max;

	assert(r > 2);
	assert(r < sizeof(unsigned int) * 8 - 1);

	assert(mont != NULL);
	assert(mont->p != NULL);
	
	if (!P->is_in_mont)
		if (!ECP_to_montgomery(P, mont, ctx)) return 0;

	if (!E->is_in_mont) 
		if (!EC_to_montgomery(E, mont, ctx)) return 0;

	ret=(ECP_PRECOMPUTE *)malloc(sizeof(ECP_PRECOMPUTE));
	if (ret == NULL) return NULL;

	max = 1;
	max <<= (r - 1);

	ret->r = 0;

	ret->Pi=(EC_POINT **)malloc(sizeof(EC_POINT *) * max);
	if (ret->Pi == NULL) goto err;

	
	/* P2 = [2]P */
	if ((P2 = ECP_new()) == NULL) goto err;
	if (!ECP_mont_double(P2, P, E, mont, ctx)) goto err;

	/* P_0 = P */
	if((ret->Pi[0] = ECP_dup(P)) == NULL) goto err;


	/* P_i = P_(i-1) + P2 */
	for (i = 1; i < max; i++)
	{
		if ((ret->Pi[i] = ECP_new()) == NULL) goto err;
		if (!ECP_mont_add(ret->Pi[i], P2, ret->Pi[i - 1], E, mont, ctx)) goto err;
	}

	ret->r = r;
	ECP_clear_free(P2);

	return ret;

err:
	ECP_clear_free(P2);
	ECP_clear_free_precompute(ret);
	return NULL;
}

int ECP_mont_multiply(EC_POINT *R, BIGNUM *k, ECP_PRECOMPUTE *prec, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* R = [k]P   P = prec->Pi[0]*/
{
	int j;
	int t, nextw, h, r;

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(k != NULL);
	assert(!k->neg);

	assert(ctx != NULL);
	assert(prec != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	if (!E->is_in_mont) 
		if (!EC_to_montgomery(E, mont, ctx)) return 0;


	if (BN_is_zero(k))
	{
		if (!BN_zero(R->Z)) return 0;
		R->is_in_mont = 1;
		return 1;
	}

	j = BN_num_bits(k);
	j--;

	r = prec->r;

	if (!BN_zero(R->Z)) return 0;
	R->is_in_mont = 1;

	while(j >= 0)
	{
		if (!BN_is_bit_set(k, j))
		{
			if (!ECP_mont_double(R, R, E, mont, ctx)) return 0;
			j--;
		}
		else
		{
			nextw = j - r;
			if (nextw < -1) nextw = -1;
			t = nextw + 1;			
			while(!BN_is_bit_set(k, t))
			{
				t++;
			}

			if (!ECP_mont_double(R, R, E, mont, ctx)) return 0;

			j--;
			if (j < t) h = 0;
			else 
			{
				h = 1;
				for(; j > t; j--)
				{
					h <<= 1;
					if (BN_is_bit_set(k, j)) h++;
					if (!ECP_mont_double(R, R, E, mont, ctx)) return 0;
				}
				if (!ECP_mont_double(R, R, E, mont, ctx)) return 0;
				j--;
			}

			if (!ECP_mont_add(R, R, prec->Pi[h], E, mont, ctx)) return 0;

			for (; j > nextw; j--)
			{
				if (!ECP_mont_double(R, R, E, mont, ctx)) return 0;
			}

		}
	}

	return 1;
}


int ECP_mont_multiply2(EC_POINT *R, BIGNUM *k, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx)
/* R = [k]P */
{
	int j, hj, kj;
	BIGNUM *h;
	EC_POINT *mP;

	assert(R != NULL);
	assert(R->X != NULL && R->Y != NULL && R->Z != NULL);

	assert(P != NULL);
	assert(P->X != NULL && P->Y != NULL && P->Z != NULL);

	assert(E != NULL);
	assert(E->A != NULL && E->B != NULL && E->p != NULL && E->h != NULL);

	assert(k != NULL);
	assert(!k->neg);

	assert(ctx != NULL);

	assert(mont != NULL);
	assert(mont->p != NULL);

	if (!E->is_in_mont) 
		if (!EC_to_montgomery(E, mont, ctx)) return 0;

	if (!P->is_in_mont) 
		if (!ECP_to_montgomery(P, mont, ctx)) return 0;


	if (BN_is_zero(k))
	{
		if (!BN_zero(R->Z)) return 0;
		R->is_in_mont = 1;
		return 1;
	}

	if ((h = BN_dup(k)) == NULL) return 0;
	
	if (!BN_lshift1(h, h)) goto err;
	if (!BN_add(h, h, k)) goto err;

	if (!ECP_copy(R, P)) goto err;
	if ((mP = ECP_mont_minus(P, mont)) == NULL) goto err;

	for(j = BN_num_bits(h) - 2; j > 0; j--)
	{
		if (!ECP_mont_double(R, R, E, mont, ctx)) goto err;
		kj = BN_is_bit_set(k, j);
		hj = BN_is_bit_set(h, j);
		if (hj == 1 && kj == 0)
			if (!ECP_mont_add(R, R, P, E, mont, ctx)) goto err;
		if (hj == 0 && kj == 1)
			if (!ECP_mont_add(R, R, mP, E, mont, ctx)) goto err;
	}

	if (h != NULL) BN_free(h);
	if (mP != NULL) ECP_clear_free(mP);
	return 1;

err:
	if (h != NULL) BN_free(h);
	if (mP != NULL) ECP_clear_free(mP);
	return 0;
}

#endif /* MONTGOMERY */
