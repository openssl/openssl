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


int BN_legendre(BIGNUM *a, BIGNUM *p, BN_CTX *ctx);
int BN_mod_sqrt(BIGNUM *x, BIGNUM *a, BIGNUM *p, BN_CTX *ctx);

#endif
