/*
 * Written by Diego F. Aranha (d@miracl.com) and contributed to the
 * the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2016 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.OpenSSL.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    licensing@OpenSSL.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.OpenSSL.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/*
 * ====================================================================
 * Copyright 2016 MIRACL UK Ltd., All Rights Reserved. Portions of the
 * attached software ("Contribution") are developed by MIRACL UK LTD., and
 * are contributed to the OpenSSL project. The Contribution is licensed
 * pursuant to the OpenSSL open source license provided above.
 */

#include <stdlib.h>

#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/bp.h>

/********************************************************************/
/*               Internal types for bilinear groups                 */
/********************************************************************/

/*
 * Opaque type for quadratic extension field element
 */
typedef struct bp_fp2_elem_st FP2;

/*
 * Opaque type for sextic extension field element
 */
typedef struct bp_fp6_elem_st FP6;

/*
 * Opaque type for dodecic extension field element
 */
typedef struct bp_fp12_elem_st FP12;

/*
 * G2 precomputation data
 */
typedef struct g2_pre_comp_st G2_PRE_COMP;

/*
 * Bilinear groups
 */
struct bp_group_st {
    /*
     * Group of points for curve defined over the base field (G1).
     */
    EC_GROUP *ec;
    /*
     * Convenient copy of the prime field modulus.
     */
    BIGNUM *field;
    /*
     * Montgomery data to handle extension field arithmetic.
     */
    BN_MONT_CTX *mont;
    /*
     * Convenient copy of one converted to Montgomery representation.
     */
    BIGNUM *one;
    /*
     * Curve parameter.
     */
    BIGNUM *param;
    /*
     * Generator for G_2.
     */
    G2_ELEM *gen2;
    /*
     * Precomputed data for G_2.
     */
    G2_PRE_COMP *g2_pre_comp;
    /*
     * Constants to help with Frobenius map.
     */
    FP2 *frb;
};

/*
 * G1 element
 */
struct bp_g1_elem_st {
    /*
     * Point in the curve defined over the base field
     */
    EC_POINT *p;
};

/*
 * G2 element
 */
struct bp_g2_elem_st {
    /**
     * X-coordinate of point defined over the twist
     */
    FP2 *X;
    /**
     * Y-coordinate of point defined over the twist
     */
    FP2 *Y;
    /**
     * Z-coordinate of point defined over the twist
     */
    FP2 *Z;
    /**
     * Flag to indicate if point in affine coordinates
     */
    int Z_is_one;
};

/**
 * Quadratic extension field element.
 */
struct bp_fp2_elem_st {
    /**
     * Vector of multiprecision integers.
     */
    BIGNUM *f[2];
};

/**
 * Sextic extension field element.
 */
struct bp_fp6_elem_st {
    /**
     * Vector of quadratic extension field elements.
     */
    FP2 *f[3];
};

/**
 * Dodecic extension field element.
 */
struct bp_fp12_elem_st {
    /**
     * Vector of sextic extension field elements.
     */
    FP6 *f[2];
};

/**
 * GT element.
 */
struct bp_gt_elem_st {
    /**
     * Underlying dodecic extension field element.
     */
    FP12 *f;
};

/********************************************************************/
/*               Functions for managing Fp^2 elements               */
/********************************************************************/

FP2 *FP2_new(void);
void FP2_init(FP2 *a);
void FP2_clear(FP2 *a);
void FP2_free(FP2 *a);
void FP2_clear_free(FP2 *a);

/********************************************************************/
/*               Functions for arithmetic in Fp^2                   */
/********************************************************************/

int FP2_rand(const BP_GROUP *group, FP2 *a);
void FP2_print(const FP2 *a);
int FP2_zero(FP2 *a);
int FP2_cmp(const FP2 *a, const FP2 *b);
int FP2_copy(FP2 *a, const FP2 *b);
int FP2_is_zero(const FP2 *a);
int FP2_add(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b);
int FP2_sub(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b);
int FP2_neg(const BP_GROUP *group, FP2 *r, const FP2 *a);
int FP2_dbl(const BP_GROUP *group, FP2 *r, const FP2 *a);
int FP2_mul(const BP_GROUP *group, FP2 *r, const FP2 *a, const FP2 *b,
            BN_CTX *ctx);
int FP2_mul_frb(const BP_GROUP *group, FP2 *r, const FP2 *a, int i,
                BN_CTX *ctx);
int FP2_mul_art(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_mul_nor(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_sqr(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_inv(const BP_GROUP *group, FP2 *r, const FP2 *a, BN_CTX *ctx);
int FP2_conj(const BP_GROUP *group, FP2 *r, const FP2 *a);
int FP2_inv_sim(const BP_GROUP *group, FP2 *r[], FP2 *a[], int num,
                BN_CTX *ctx);
int FP2_exp(const BP_GROUP *group, FP2 *r, const FP2 *a, const BIGNUM *b,
            BN_CTX *ctx);

/********************************************************************/
/*               Functions for managing Fp^6 elements               */
/********************************************************************/

FP6 *FP6_new(void);
void FP6_init(FP6 *a);
void FP6_clear(FP6 *a);
void FP6_free(FP6 *a);
void FP6_clear_free(FP6 *a);

/********************************************************************/
/*               Functions for arithmetic in Fp^6                   */
/********************************************************************/

int FP6_rand(const BP_GROUP *group, FP6 *a);
void FP6_print(const FP6 *a);
int FP6_zero(FP6 *a);
int FP6_cmp(const FP6 *a, const FP6 *b);
int FP6_copy(FP6 *a, const FP6 *b);
int FP6_is_zero(const FP6 *a);
int FP6_add(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b);
int FP6_sub(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b);
int FP6_neg(const BP_GROUP *group, FP6 *r, const FP6 *a);
int FP6_mul(const BP_GROUP *group, FP6 *r, const FP6 *a, const FP6 *b,
            BN_CTX *ctx);
int FP6_mul_sparse(const BP_GROUP *group, FP6 *r, const FP6 *a,
                   const FP6 *b, BN_CTX *ctx);
int FP6_mul_art(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_sqr(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);
int FP6_inv(const BP_GROUP *group, FP6 *r, const FP6 *a, BN_CTX *ctx);

/********************************************************************/
/*               Functions for managing Fp^12 elements               */
/********************************************************************/

FP12 *FP12_new(void);
void FP12_init(FP12 *a);
void FP12_clear(FP12 *a);
void FP12_free(FP12 *a);
void FP12_clear_free(FP12 *a);

/********************************************************************/
/*               Functions for arithmetic in Fp^12                   */
/********************************************************************/
int FP12_rand(const BP_GROUP *group, FP12 *a);
void FP12_print(const FP12 *a);
int FP12_zero(FP12 *a);
int FP12_cmp(const FP12 *a, const FP12 *b);
int FP12_copy(FP12 *a, const FP12 *b);
int FP12_is_zero(const FP12 *a);
int FP12_add(const BP_GROUP *group, FP12 *r, const FP12 *a, const FP12 *b);
int FP12_sub(const BP_GROUP *group, FP12 *r, const FP12 *a, const FP12 *b);
int FP12_neg(const BP_GROUP *group, FP12 *r, const FP12 *a);
int FP12_mul(const BP_GROUP *group, FP12 *r, const FP12 *a,
             const FP12 *b, BN_CTX *ctx);
int FP12_mul_sparse(const BP_GROUP *group, FP12 *r, const FP12 *a,
                    const FP12 *b, BN_CTX *ctx);
int FP12_sqr(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_sqr_cyc(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_sqr_pck(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_inv(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_conj(const BP_GROUP *group, FP12 *r, const FP12 *a);
int FP12_cyc(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_back(const BP_GROUP *group, FP12 *r[], const FP12 *a[], int num,
              BN_CTX *ctx);
int FP12_frb(const BP_GROUP *group, FP12 *r, const FP12 *a, BN_CTX *ctx);
int FP12_exp_cyc(const BP_GROUP *group, FP12 *r, const FP12 *a,
				 const BIGNUM *b, BN_CTX *ctx);
int FP12_exp_pck(const BP_GROUP *group, FP12 *r, const FP12 *a,
				 const BIGNUM *b, BN_CTX *ctx);

/********************************************************************/
/*              Functions for precomputation in G2                  */
/********************************************************************/

G2_PRE_COMP *g2_pre_comp_dup(G2_PRE_COMP *pre);
void g2_pre_comp_free(G2_PRE_COMP *pre);
int g2_wNAF_precompute_mult(BP_GROUP *group, BN_CTX *ctx);
