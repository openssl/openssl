/*
 *
 *	ec.h
 *
 *	Elliptic Curve Arithmetic Functions
 *
 *	Copyright (C) Lenka Fibikova 2000
 *
 *
 */


#ifndef HEADER_EC_H
#define HEADER_EC_H


#include "bn.h"
#include "bn_mont2.h"

typedef struct bn_ec_struct		/* E: y^2 = x^3 + Ax + B  (mod p) */
{
	BIGNUM	*A, *B, *p, *h;		/* h = 1/2 mod p = (p + 1)/2 */
	int is_in_mont;
} EC;

typedef struct bn_ec_point_struct /* P = [X, Y, Z] */
{
	BIGNUM	*X, *Y, *Z;
	int is_in_mont;
} EC_POINT;

typedef struct bn_ecp_precompute_struct /* Pi[i] = [2i + 1]P	i = 0..2^{r-1} - 1 */
{
	int r;
	EC_POINT **Pi;
} ECP_PRECOMPUTE;


#define ECP_is_infty(P) (BN_is_zero(P->Z))
#define ECP_is_norm(P) (BN_is_one(P->Z))

#define ECP_mont_minus(P, mont) (ECP_minus((P), (mont)->p))


EC *EC_new();
void EC_clear_free(EC *E);
int EC_set_half(EC *E);
#ifdef MONTGOMERY
int EC_to_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
int EC_from_montgomery(EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
#endif /* MONTGOMERY */


EC_POINT *ECP_new();
void ECP_clear_free(EC_POINT *P);
void ECP_clear_free_precompute(ECP_PRECOMPUTE *prec);

EC_POINT *ECP_generate(BIGNUM *x, BIGNUM *z, EC *E, BN_CTX *ctx);
EC_POINT *ECP_dup(EC_POINT *P);
int ECP_copy(EC_POINT *R, EC_POINT *P);
int ECP_normalize(EC_POINT *P, EC *E, BN_CTX *ctx);
EC_POINT *ECP_minus(EC_POINT *P, BIGNUM *p);
int ECP_is_on_ec(EC_POINT *P, EC *E, BN_CTX *ctx);
int ECP_ecp2bin(EC_POINT *P, unsigned char *to, int form); /* form(ANSI 9.62): 1-compressed; 2-uncompressed; 3-hybrid */
int ECP_bin2ecp(unsigned char *from, int len, EC_POINT *P, EC *E, BN_CTX *ctx);

#ifdef SIMPLE
int ECP_cmp(EC_POINT *P, EC_POINT *Q, BIGNUM *p, BN_CTX *ctx);
int ECP_double(EC_POINT *R, EC_POINT *P, EC *E, BN_CTX *ctx);
int ECP_add(EC_POINT *R, EC_POINT *P, EC_POINT *Q, EC *E, BN_CTX *ctx);
ECP_PRECOMPUTE *ECP_precompute(int r, EC_POINT *P, EC *E, BN_CTX *ctx);
int ECP_multiply(EC_POINT *R, BIGNUM *k, ECP_PRECOMPUTE *prec, EC *E, BN_CTX *ctx);
#endif /* SIMPLE */

#ifdef MONTGOMERY
int ECP_to_montgomery(EC_POINT *P, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_from_montgomery(EC_POINT *P, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_mont_cmp(EC_POINT *P, EC_POINT *Q, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_mont_double(EC_POINT *R, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_mont_add(EC_POINT *R, EC_POINT *P, EC_POINT *Q, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
ECP_PRECOMPUTE *ECP_mont_precompute(int r, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_mont_multiply(EC_POINT *R, BIGNUM *k, ECP_PRECOMPUTE *prec, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
int ECP_mont_multiply2(EC_POINT *R, BIGNUM *k, EC_POINT *P, EC *E, BN_MONTGOMERY *mont, BN_CTX *ctx);
#endif /* MONTGOMERY */

#endif