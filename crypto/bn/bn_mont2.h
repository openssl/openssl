/*
 *
 *	bn_mont2.h
 *
 *	Montgomery Modular Arithmetic Functions.
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */

#ifndef HEADER_MONT2_H
#define HEADER_MONT2_H

#define MONTGOMERY

#include <openssl/bn.h>

typedef struct bn_mont_st{
	int R_num_bits;
	int p_num_bytes;
	BIGNUM *p;
	BN_ULONG p_inv_b_neg;	/* p' = p^{-1} mod b; b = 2^BN_BITS */
} BN_MONTGOMERY;

#define BN_from_mont(x, mont) (BN_mont_red((x), (mont)))


BN_MONTGOMERY *BN_mont_new();
int BN_to_mont(BIGNUM *x, BN_MONTGOMERY *mont, BN_CTX *ctx); 
void BN_mont_clear_free(BN_MONTGOMERY *mont);
int BN_mont_set(BIGNUM *p, BN_MONTGOMERY *mont, BN_CTX *ctx);
int BN_mont_red(BIGNUM *y, BN_MONTGOMERY *mont);
int BN_mont_mod_mul(BIGNUM *r, BIGNUM *x, BIGNUM *y, BN_MONTGOMERY *mont, BN_CTX *);

#endif
