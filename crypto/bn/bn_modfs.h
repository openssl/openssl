/*
 *
 *	bn_modfs.h
 *
 *	Some Modular Arithmetic Functions.
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */

#ifndef HEADER_BN_MODFS_H
#define HEADER_BN_MODFS_H


#include "bn.h"

#ifdef BN_is_zero
#undef BN_is_zero
#define BN_is_zero(a)	(((a)->top == 0) || (((a)->top == 1) && ((a)->d[0] == (BN_ULONG)0)))
#endif /*BN_is_zero(a)*/


int BN_smod(BIGNUM *rem, BIGNUM *m, BIGNUM *d, BN_CTX *ctx);
int BN_mod_sub(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *m, BN_CTX *ctx);
int BN_mod_add(BIGNUM *r, BIGNUM *a, BIGNUM *b, BIGNUM *m, BN_CTX *ctx); 
int BN_mod_sqr(BIGNUM *r, BIGNUM *a, BIGNUM *p, BN_CTX *ctx);
int BN_swap(BIGNUM *x, BIGNUM *y);
int BN_legendre(BIGNUM *a, BIGNUM *p, BN_CTX *ctx);
int BN_mod_sqrt(BIGNUM *x, BIGNUM *a, BIGNUM *p, BN_CTX *ctx);

#endif