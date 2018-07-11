/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ecjpake_struct.h"

/**
 * Initialize the context for a JPAKE session with elliptic curves.
 */
static int EC_JPAKE_CTX_init(EC_JPAKE_CTX *ctx,
        const char *name,
        const char *curve_name,
        const BIGNUM *secret) 
{

    if (ctx == NULL) {
        return 1;
    }

    if((ctx->name = OPENSSL_strdup(name)) == NULL ||
     (ctx->secret = BN_dup(secret)) == NULL ||
      (ctx->group = EC_GROUP_new_by_curve_name(EC_curve_nist2nid(curve_name))) == NULL ||
        (ctx->gx1 = EC_POINT_new(ctx->group)) == NULL ||
        (ctx->gx2 = EC_POINT_new(ctx->group)) == NULL ||
        (ctx->gx3 = EC_POINT_new(ctx->group)) == NULL ||
        (ctx->gx4 = EC_POINT_new(ctx->group)) == NULL ||
          (ctx->b = EC_POINT_new(ctx->group)) == NULL ||
         (ctx->x1 = BN_new()) == NULL ||
         (ctx->x2 = BN_new()) == NULL ||
        (ctx->x2s = BN_new()) == NULL ||
      (ctx->bnCtx = BN_CTX_new()) == NULL) {
          return 1;
      }

    return 0;
}

/**
 * Fields to clear after calculating the shared key
 */
void EC_JPAKE_CTX_clear_private_fields(EC_JPAKE_CTX *ctx) 
{
    if (ctx == NULL) {
        return;
    }
    
    BN_clear(ctx->secret);
    BN_clear(ctx->x1);
    BN_clear(ctx->x2);
    BN_clear(ctx->x2s);
}

/**
 * Free the JPAKE context
 */
void EC_JPAKE_CTX_free(EC_JPAKE_CTX *ctx) 
{

    if (ctx == NULL) {
        return;
    }

    BN_clear_free(ctx->secret);
    EC_POINT_clear_free(ctx->b);
    BN_clear_free(ctx->x1);
    BN_clear_free(ctx->x2);
    BN_clear_free(ctx->x2s);

    EC_GROUP_free(ctx->group);
    OPENSSL_free(ctx->name);
    OPENSSL_free(ctx->peer_name);
    EC_POINT_free(ctx->gx1);
    EC_POINT_free(ctx->gx2);
    EC_POINT_free(ctx->gx3);
    EC_POINT_free(ctx->gx4);
    BN_CTX_free(ctx->bnCtx);
}

/**
 * Setup the context for an EC JPAKE session.
 */
EC_JPAKE_CTX *EC_JPAKE_CTX_new(const char *name,
        const char *curve_name,
        const BIGNUM *secret) 
{

    EC_JPAKE_CTX *ctx = OPENSSL_malloc(sizeof *ctx);

    if (ctx == NULL) {
        return NULL;
    }

    if(EC_JPAKE_CTX_init(ctx, name, curve_name, secret) == 1) {
        return NULL;
    }

    return ctx;
}

/**
 * Initializes a partial structure
 */
int EC_JPAKE_STEP_PART_init(EC_JPAKE_STEP_PART *p)
{
    p->gx = BN_new();
    if(p->gx == NULL ||
    !EC_JPAKE_ZKP_init(&p->zkpx)) {
        return 0;
    }
    return 1;
}

/**
 * Releases a partial structure
 */
void EC_JPAKE_STEP_PART_release(EC_JPAKE_STEP_PART *p)
{
    EC_JPAKE_ZKP_release(&p->zkpx);
    BN_free(p->gx);
}

/**
 * Initializes a first round structure
 */
int EC_JPAKE_STEP1_init(EC_JPAKE_STEP1 *s1)
{
    if(!EC_JPAKE_STEP_PART_init(&s1->p1) ||
    !EC_JPAKE_STEP_PART_init(&s1->p2)) {
        return 0;
    }
    return 1;
}

/**
 * Releases a first round structure
 */
void EC_JPAKE_STEP1_release(EC_JPAKE_STEP1 *s1)
{
    EC_JPAKE_STEP_PART_release(&s1->p2);
    EC_JPAKE_STEP_PART_release(&s1->p1);
}

/**
 * Initializes the third round JPAKE structure
 */
int EC_JPAKE_STEP3_init(EC_JPAKE_STEP3 *s3, const EVP_MD *method) 
{
    s3->method = method;
    s3->hmac = OPENSSL_malloc(EVP_MD_size(method));

    if(s3->method == NULL || s3->hmac == NULL) {
        return 0;
    }
    return 1;
}

/**
 * Frees memory for the third step structure
 */
void EC_JPAKE_STEP3_release(EC_JPAKE_STEP3 *s3) 
{
    BN_clear_free(s3->hmac);
    s3->method = NULL;
}

/**
 *  Initializes a zero knowledge proof for JPAKE
 */
int EC_JPAKE_ZKP_init(EC_JPAKE_ZKP *zkp) {
    
    zkp->gr = BN_new();
    zkp->b = BN_new();
    
    if(zkp->gr == NULL || zkp->b == NULL) {
        return 0;
    }
    return 1;
}

/**
 *  Rekeases a zero knowledge proof
 */
void EC_JPAKE_ZKP_release(EC_JPAKE_ZKP *zkp) {
    BN_clear_free(zkp->gr);
    BN_clear_free(zkp->b);
}


