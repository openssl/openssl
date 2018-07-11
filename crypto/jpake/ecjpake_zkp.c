/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#import "ecjpake_zkp.h"
#import "string.h"

/**
 * Find a random BIGNUM given an order of an EC Curve.
 * 
 *     bn - The BIGNUM to store the number
 *  order - The order of a curve
 * returns The random BIGNUm
 */
BIGNUM *random_big_num_for_curve_order(BIGNUM *bn, const BIGNUM *order) 
{
    if (!bn) {
        bn = BN_new();
        if(bn == NULL) {
            return NULL;
        }
    }

    if(!BN_rand_range(bn, order)) {
        BN_clear_free(bn);
        return NULL;
    }

    if(BN_is_zero(bn)) {
        if(!BN_add(bn, bn, BN_value_one())) {
            BN_clear_free(bn);
            return NULL;
        }
    }
    return bn;
}

/**
 * Gets a hash of the curve's G, a random element Gv on the curve, and a point
 * given from the participant (Gx).  The lengths of each, as well as the points,
 * are encoded then hashed to provide a challenge in some zero-knowledge proof.
 *
 *  userId - The participant's id
 *   group - The elliptic curve group
 *       G - The base point of the elliptic curve
 *      Gv - A random eleemnt, v, on the EC curve
 *      Gx - The public key (x1 or x2) of a participant
 *     btx - BIGNUM context helper
 *  returns a hash of the encoded lengths and points in the format of:
 *  length(G) | G | length(Gv) | Gv | length(Gx) | Gx | length(userId) | userId
 *  or returns NULL on error.
 */
BIGNUM *get_hash(const char *userId,
        const EC_GROUP *group,
        const EC_POINT *G,
        const EC_POINT *Gv,
        const EC_POINT *Gx,
        const EVP_MD *hashMethod,
        BN_CTX *btx)
{

    /* Initialize our return value */
    BIGNUM *bnHash = BN_new();

    /**
     * BN_bn2mpi() converts a Big Number in to a multi-precision integer
     * which encodes the length as a 4-byte array followed by the binary
     * data of the Big Number (EC Point). This function also returns the
     * length of the character array we'll hash below.
     */
    BIGNUM *gBn = EC_POINT_point2bn(group, G, POINT_CONVERSION_UNCOMPRESSED, NULL, btx);
    BIGNUM *gvBn = EC_POINT_point2bn(group, Gv, POINT_CONVERSION_UNCOMPRESSED, NULL, btx);
    BIGNUM *gxBn = EC_POINT_point2bn(group, Gx, POINT_CONVERSION_UNCOMPRESSED, NULL, btx);

    if(gBn == NULL || gvBn == NULL || gxBn == NULL) {
        goto bnErr;
    }

    unsigned char *gBytes = OPENSSL_malloc(BN_bn2mpi(gBn, NULL));
    unsigned char *gvBytes = OPENSSL_malloc(BN_bn2mpi(gvBn, NULL));
    unsigned char *gxBytes = OPENSSL_malloc(BN_bn2mpi(gxBn, NULL));

    if(gBn == NULL || gvBn == NULL || gxBn == NULL) {
        goto mallocErr;
    }

    int gLength = BN_bn2mpi(gBn, gBytes);
    int gvLength = BN_bn2mpi(gvBn, gvBytes);
    int gxLength = BN_bn2mpi(gxBn, gxBytes);

    /**
     * Write the length, as one byte, in a padded, 4 byte character array 
     * for the user Id string. This satisfies the format of the hash 
     * described in the comment above.
     */
    unsigned long idlen = strlen((const char *) userId);
    char idLengthBytes[4] = {0, 0, 0, idlen};

    unsigned int mdLength = 0;
    unsigned char *md = OPENSSL_malloc(EVP_MD_size(hashMethod));
    EVP_MD_CTX *context = EVP_MD_CTX_create();

    if(md == NULL || context == NULL) {
        goto err;
    }
    
    if(!EVP_DigestInit_ex(context, hashMethod, NULL) ||
        !EVP_DigestUpdate(context, gBytes, (size_t) gLength) ||
        !EVP_DigestUpdate(context, gvBytes, (size_t) gvLength) ||
        !EVP_DigestUpdate(context, gxBytes, (size_t) gxLength) ||
        !EVP_DigestUpdate(context, idLengthBytes, sizeof(idLengthBytes)) ||
        !EVP_DigestUpdate(context, userId, idlen) ||
        !EVP_DigestFinal_ex(context, md, &mdLength)) {
            goto err;
        }

    BN_bin2bn(md, EVP_MD_size(hashMethod), bnHash);

    /* Free resources */    
err:
    EVP_MD_CTX_destroy(context);
    OPENSSL_free(md);
mallocErr:
    OPENSSL_free(gBytes);
    OPENSSL_free(gvBytes);
    OPENSSL_free(gxBytes);
bnErr:
    BN_clear_free(gBn);
    BN_clear_free(gvBn);
    BN_clear_free(gxBn);

    return bnHash;
}

/**
 * Creates a zero-knowledge proof for a particular point on an elliptic curve.
 * Our partner can use this to validate that we created a point Gx
 * for some generator G on a particular curve.
 *
 *  step_part - The part of a JPAKE step we're finding values for.
 *      group - The elliptic curve group.
 *          G - The generator point for some curve. Is derived for round 2 payload.
 *          x - The private key of the participant
 *         Gx - The base point multiplied by the private key, x
 *          N - The order of the elliptic curve
 * hashMethod - The message digest method
 *      bnCtx - The context for BIGNUM operations
 *       name - The participant name
 * 1 is returned for success, 0 on error.
 */
int ec_generate_zkp(EC_JPAKE_STEP_PART *step_part,
        const EC_GROUP *group,
        const EC_POINT *G,
        const BIGNUM *x,
        const EC_POINT *Gx,
        const BIGNUM *N,
        const EVP_MD *hashMethod,
        BN_CTX *bnCtx,
        const char *name) 
{
    
    /* Assume failure */
    int ret = 0;

    /* Save Gx to the step */
    if(EC_POINT_point2bn(group, Gx, POINT_CONVERSION_UNCOMPRESSED, step_part->gx, bnCtx) == NULL) {
        return ret;
    }

    /* Create a new, random EC point Gv */
    EC_POINT *Gv = EC_POINT_new(group);
    BIGNUM *v = BN_new();

    if( Gv == NULL || v == NULL) {
        goto ecErr;
    }

    /* Find a random number (v) between [1, p) and compute G*v */
    if((v = random_big_num_for_curve_order(v, N)) == NULL ||
            !EC_POINT_mul(group, Gv, NULL, G, v, bnCtx)) {
        goto ecErr;
    }

    /* Save result to the zero-knowledge proof's gr */
    if((EC_POINT_point2bn(group, Gv, POINT_CONVERSION_UNCOMPRESSED, step_part->zkpx.gr, bnCtx)) == NULL) {
        goto ecErr;
    }

    /**
     * Find r where 'r = v-x*h mod n'
     * 'v' is a random element of the curve
     * 'x' is another element of the curve (the generator multiplied by some 'x', e.g the payload's x1, x2, etc.)
     * 'h' is a hash of 'g', 'g*v', 'g*x', and the userId
     * 'n' is the max range of the curve
     */
    BIGNUM *hash;
    if((hash = get_hash(name, group, G, Gv, Gx, hashMethod, bnCtx)) == NULL) {
        goto ecErr;
    }
    
    BIGNUM *r = BN_new();

    if (r == NULL) {
        BN_clear_free(hash);
        goto ecErr;
    }

    if(!BN_mul(r, x, hash, bnCtx)) {
        goto err;
    }

    /* Store 'r' in the zero-knowledge proof */
    if(!BN_mod_sub(step_part->zkpx.b, v, r, N, bnCtx)) {
        goto err;
    }

    /* Success */
    ret = 1;

    /* Free resources */
err:
    BN_clear_free(r);
    BN_clear_free(hash);
ecErr:
    BN_clear_free(v);
    EC_POINT_free(Gv);

    return ret;
}

/**
 * Preliminary checks to perform before verifying a zero-knowledge proof
 *
 * group - The group of the elliptic curve.
 *    Gx - Some point on an elliptic curve.
 * bnCtx - The operation context for a BIGNUM.
 * 1 is returned for success, 0 on error.
 */
int ec_verify_zkp_prelim_checks(const EC_GROUP *group, const EC_POINT *Gx, BN_CTX *bnCtx) {

    // Assume failure
    int ret = 0;

    /* 1. Check that Gx is not infinity */
    if (EC_POINT_is_at_infinity(group, Gx)) {
        return ret;
    }

    /* 2. Check that the coordinate x and y are in the Fq, i.e of [1, q) */
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *zero = BN_new();
    BN_zero(zero);
    BIGNUM *Q = BN_new();

    BIGNUM *cofactor = BN_new();
    EC_POINT *nGx = EC_POINT_new(group);

    /* Get curve parameter Q */
    if(!EC_GROUP_get_curve_GFp(group, Q, NULL, NULL, bnCtx)) {
        goto err;
    }

    /* Get and check coordinates for Gx */
    if(!EC_POINT_get_affine_coordinates_GFp(group, Gx, x, y, bnCtx)) {
        goto err;
    }

    if (BN_cmp(x, zero) < 0 || 
        BN_cmp(y, zero) < 0 || 
        BN_cmp(x, Q) >= 0 || 
        BN_cmp(y, Q) >= 0) {
        /* x or y is not in the domain Q */
        goto err;
    }

    /* 3. Check that the point lies on the curve for the group we expect. */
    if (!EC_POINT_is_on_curve(group, Gx, bnCtx)) {
        /* Point is not on the curve we expect */
        goto err;
    }

    /* 4. Check that n*G*x is infinity (i.e., co-factor*G*x is not infinity). */
    if (!(EC_GROUP_get_cofactor(group, cofactor, bnCtx))) {
        goto err;
    }

    EC_POINT_mul(group, nGx, NULL, Gx, cofactor, bnCtx);
    if(EC_POINT_is_at_infinity(group, Gx)) {
        /* n*G*x is infinity */
        goto err;
    }

    /* Success */
    ret = 1;

err:
    /* Free resources */
    BN_clear_free(x);
    BN_clear_free(y);
    BN_clear_free(zero);
    BN_clear_free(Q);
    BN_clear_free(cofactor);
    EC_POINT_free(nGx);
    
    /* Checks pass */
    return ret;
}

/**
 * Verifies the zero-knowledge proof give by a partner.
 *
 *       group - The elliptic curve group in use.
 *           G - The generator point for some curve. Is derived for round 2 payload.
 *          Gx - A point on an elliptic curve.
 *         zkp - The zero-knowledge proof to validate.
 *  hashMethod - The message digest method to hash some data.
 *       bnCtx - The BIGNUM operation context
 *        name - The current participant's id
 * 1 is returned for success, 0 on error.
 */
int ec_verify_zkp(const EC_GROUP *group,
        const EC_POINT *G,
        const EC_POINT *Gx,
        const EC_JPAKE_ZKP *zkp,
        const EVP_MD *hashMethod,
        BN_CTX *bnCtx,
        const char *name) {

    /* Assume failure */
    int ret = 0;

    /* Perform some preliminary checks */
    if (!ec_verify_zkp_prelim_checks(group, Gx, bnCtx)) {
        return ret;
    }

    /* Get the order of the group 'N' */
    BIGNUM *n = BN_new();

    if(n == NULL) {
        return ret;
    }

    if(!EC_GROUP_get_order(group, n, bnCtx)) {
        BN_clear_free(n);
        return ret;
    }

    /* Create an EC_POINT from the proof's BIGNUM, gr */
    EC_POINT *Gv;
    if((Gv = EC_POINT_new(group)) == NULL) {
        goto ecErr;
    }

    if((Gv = EC_POINT_bn2point(group, zkp->gr, Gv, bnCtx)) == NULL) {
        goto ecErr;
    }

    /* Get the challenge (digest of G | G*x | G*v | ID). */
    BIGNUM *h;
    if((h = get_hash(name, group, G, Gv, Gx, hashMethod, bnCtx)) == NULL) {
        goto pointErr;
    }

    if(!BN_mod(h, h, n, bnCtx)) {
        goto pointErr;
    }

    /* Get G*r */
    EC_POINT *GrGx = EC_POINT_new(group);
    EC_POINT *Gr = EC_POINT_new(group);
    EC_POINT *Gxh = EC_POINT_new(group);

    if(GrGx == NULL || Gr == NULL || Gxh == NULL) {
        goto err;
    }

    /* G * r + Gx * h */
    if(!EC_POINT_mul(group, Gr, NULL, G, zkp->b, bnCtx) ||
       !EC_POINT_mul(group, Gxh, NULL, Gx, h, bnCtx) ||
       !EC_POINT_add(group, GrGx, Gr, Gxh, bnCtx)) {
           goto err;
       }

    /* Check that G*v = G*r + G*x*h. */
    int cmp = EC_POINT_cmp(group, Gv, GrGx, bnCtx);

    /* If points are equal then return success */
    ret = (cmp == 0) ? 1 : 0;

    /* Free resources */
err:
    EC_POINT_free(Gxh);
    EC_POINT_free(Gr);
    EC_POINT_free(GrGx);
pointErr:
    BN_clear_free(h);
ecErr:
    EC_POINT_free(Gv);
    BN_clear_free(n);

    return ret;
}
