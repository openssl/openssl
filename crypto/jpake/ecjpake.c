/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include "ecjpake.h"
#include "string.h"

/**
 * Generate the first round payload containing two random points
 * (Gx1, Gx2) and zero-knowledge proofs for both.
 *
 *  step1 - The structure to populate with first round data.
 *    ctx - The context of this JPAKE exchange.
 *  1 is returned for success, 0 on error.
 */
int EC_JPAKE_STEP1_generate(EC_JPAKE_STEP1 *step1, EC_JPAKE_CTX *ctx, const EVP_MD *digestMethod) 
{

    /* Error code for this step -- assume failure */
    EC_JPAKE_RET returnCode = JPAKE_RET_FAILURE;

    /* Get the generator point of the curve group */
    const EC_POINT *G = EC_GROUP_get0_generator(ctx->group);

    /* Get the order of the group 'N' */
    BIGNUM *n = BN_new();
    if(n == NULL ||
      !EC_GROUP_get_order(ctx->group, n, ctx->bnCtx)) {
        goto err;
    }

    /* Choose a random x1 and x2 in the range of [0, n). */
    ctx->x1 = random_big_num_for_curve_order(ctx->x1, n);
    ctx->x2 = random_big_num_for_curve_order(ctx->x2, n);

    if(ctx->x1 == NULL || ctx->x2 == NULL) {
        goto err;
    }

    /* Calculate the G*x1 and G*x2 */
    if(!EC_POINT_mul(ctx->group, ctx->gx1, NULL, G, ctx->x1, ctx->bnCtx) ||
       !EC_POINT_mul(ctx->group, ctx->gx2, NULL, G, ctx->x2, ctx->bnCtx)) {
        goto err;
    }

    /* Calculate the zero-knowledge proofs */
    if(!ec_generate_zkp(&step1->p1, ctx->group, G, ctx->x1, ctx->gx1, n, digestMethod, ctx->bnCtx, ctx->name) ||
       !ec_generate_zkp(&step1->p2, ctx->group, G, ctx->x2, ctx->gx2, n, digestMethod, ctx->bnCtx, ctx->name)) {
        goto err;
    }
    
    /* Success */
    returnCode = JPAKE_RET_SUCCESS;

    /* Free resources */
err:
    BN_clear_free(n);
    return returnCode;
}

/**
 * Checks that a given peer is still the same as the peer from round one,
 * and that the ids of each participant are different.
 *
 *     ctx - The JPAKE context
 *  peerId - The partner's participant id
 *  1 is returned for success, 0 on error.
 */
int validate_participants(EC_JPAKE_CTX *ctx, const char *peerId) 
{

    /* Check that the sender/receiver IDs differ */
    if (strcmp(ctx->name, peerId) == 0) {
        return 0;
    }

    /* Check that the peer Ids are the same */
    if (strcmp(ctx->peer_name, peerId) != 0) {
        return 0;
    }

    /* Checks Pass */
    return 1;
}

/**
 * Validate a first round payload. This also populates the Client's x3 and x4 (which,
 * if you noticed in the header comments, are the Server's x1 and x2).
 *
 *                   ctx - The context of this JPAKE exchange.
 *  partnerParticipantId - The peer's id.
 *              received - The partner's (Bob's) first round payload data.
 *          digestMethod - The digest method used in the exchange.
 *  Non-zero indicates error, 0 returned on success
 */
int EC_JPAKE_STEP1_process(EC_JPAKE_CTX *ctx, const char *partnerParticipantId, const EC_JPAKE_STEP1 *received, const EVP_MD *digestMethod) 
{

    /* Error code for this step */
    const EC_JPAKE_RET stepErrorCode = JPAKE_RET_FAILURE;

    /* Get the generator point of the curve group */
    const EC_POINT *G;
    
    if((G = EC_GROUP_get0_generator(ctx->group)) == NULL) {
        return stepErrorCode;
    }

    /* Save the partner Id */
    ctx->peer_name = OPENSSL_strdup(partnerParticipantId);

    /* Check that ids are different */
    if (G == NULL ||
        ctx->peer_name == NULL ||
        !validate_participants(ctx, partnerParticipantId)) {
        return stepErrorCode;
    }

    /* Save the the client's Gx3 and Gx4 from the server's Gx1 and Gx2 */
    ctx->gx3 = EC_POINT_bn2point(ctx->group, received->p1.gx, ctx->gx3, ctx->bnCtx);
    ctx->gx4 = EC_POINT_bn2point(ctx->group, received->p2.gx, ctx->gx4, ctx->bnCtx);

    if(ctx->gx3 == NULL || ctx->gx4 == NULL) {
        return stepErrorCode;
    }

    /* Verify the given ZKPs */
    if(!ec_verify_zkp(ctx->group, G, ctx->gx3, &received->p1.zkpx, digestMethod, ctx->bnCtx, ctx->peer_name) ||
       !ec_verify_zkp(ctx->group, G, ctx->gx4, &received->p2.zkpx, digestMethod, ctx->bnCtx, ctx->peer_name)) {
           return stepErrorCode;
       }

    return JPAKE_RET_SUCCESS;
}

/**
 * Generate the second round payload for a participant.  This includes a point
 * on the curve that was calculated from a random number, the secret, and
 * multiplied by a generator point G derived from Client's Gx1 and the Server's
 * Gx1 & Gx2.
 *
 * Reference:
 * Client:  GA = X1  + X3  + X4  | xs = x2  * secret | Xc = xc * GA
 * Server:  GB = X3  + X1  + X2  | xs = x4  * secret | Xs = xs * GB
 * Unified: G  = Xm1 + Xp1 + Xp2 | xm = xm2 * secret | Xm = xm * G
 *
 *        step2 - Structure for round 2 data
 *          ctx - The JPAKE context
 * digestMethod - The digest method used in the exchange.
 */
int EC_JPAKE_STEP2_generate(EC_JPAKE_STEP2 *step2, EC_JPAKE_CTX *ctx, const EVP_MD *digestMethod) 
{

    /* Error code for this step */
    EC_JPAKE_RET returnCode = JPAKE_RET_FAILURE;

    /* Get the order of the group 'N' */
    BIGNUM *n = BN_new();
    EC_POINT *GA = EC_POINT_new(ctx->group);
    EC_POINT *A = EC_POINT_new(ctx->group);

    if(n == NULL ||
      GA == NULL ||
       A == NULL ||
      !EC_GROUP_get_order(ctx->group, n, ctx->bnCtx)) {
        goto err;
    }

    /* Find x2s = x2 * secret % n */
    if(!BN_mod_mul(ctx->x2s, ctx->x2, ctx->secret, n, ctx->bnCtx)) {
        goto err;
    }

    /* Find the generator where G = Gx1 + Gx3 + Gx4 */
    if(!EC_POINT_add(ctx->group, GA, ctx->gx1, ctx->gx3, ctx->bnCtx) ||
       !EC_POINT_add(ctx->group, GA, GA, ctx->gx4, ctx->bnCtx)) {
           goto err;
       }

    /* Create a public key from the random number, secret, and derived generator */
    if(!EC_POINT_mul(ctx->group, A, NULL, GA, ctx->x2s, ctx->bnCtx)) {
        goto err;
    }

    /* Create the zero-knowledge for the public key */
    if(!ec_generate_zkp(step2, ctx->group, GA, ctx->x2s, A, n, digestMethod, ctx->bnCtx, ctx->name)) {
        goto err;
    }

    /* Success */
    returnCode = JPAKE_RET_SUCCESS;

err:
    /* Free resources */
    EC_POINT_free(A);
    EC_POINT_free(GA);
    BN_clear_free(n);

    return returnCode;
}

/**
 * Validates the round two data created by our peer.
 *
 *                   ctx - The JPAKE context
 *  partnerParticipantId - The peer's id (e.g 'server').
 *              received - Our peer's round two data
 * 1 is returned for success, 0 on error.
 */
int EC_JPAKE_STEP2_process(EC_JPAKE_CTX *ctx, const char *partnerParticipantId, const EC_JPAKE_STEP2 *received, const EVP_MD *digestMethod) 
{
    /* Error code for this step */
    EC_JPAKE_RET returnCode = JPAKE_RET_FAILURE;

    /* Check that ids are different */
    if (!validate_participants(ctx, partnerParticipantId)) {
        return returnCode;
    }

    /* Calculate the generator Gb which should be the same as     */
    /* the generator found in the peer's round two generate step. */
    EC_POINT *GA = EC_POINT_new(ctx->group);
    EC_POINT *Gx = EC_POINT_new(ctx->group);

    if(GA == NULL ||
       Gx == NULL ||
      !EC_POINT_add(ctx->group, GA, ctx->gx1, ctx->gx2, ctx->bnCtx) ||
      !EC_POINT_add(ctx->group, GA, GA, ctx->gx3, ctx->bnCtx)) {
          goto err;
      }

    /* Build the point (public key) given in the peer's round 2 payload data */
    Gx = EC_POINT_bn2point(ctx->group, received->gx, Gx, ctx->bnCtx);

    /* Save the partner's A as our B */
    ctx->b = EC_POINT_dup(Gx, ctx->group);

    if(Gx == NULL || ctx->b == NULL) {
        goto err;
    }

    /* Verify the proof */
    if(!ec_verify_zkp(ctx->group, GA, Gx, &received->zkpx, digestMethod, ctx->bnCtx, ctx->peer_name)) {
        goto err;
    }

    /* Success */
    returnCode = JPAKE_RET_SUCCESS;

    /* Free resources */
err:
    EC_POINT_free(GA);
    EC_POINT_free(Gx);

    return returnCode;
}

/**
 * Finds the shared key between two participants.  Reference:
 *
 * Client:  K = ( Xs - X4  * x2  * s ) * x2
 * Server:  K = ( Xc - X2  * x4  * s ) * x4
 * Unified: K = ( Xp - Xp2 * xm2 * s ) * xm2
 *
 * Where 'Xs' was the peer's public key we saved in the previous step.
 * Our partner performs the same operation, and using our key, should derive
 * an EC Point with the same 'X' coordinate as us.  That coordinate is
 * then hashed and saved to the context as a BIGNUM.
 *
 *         ctx - JPAKE context containing values found in earlier steps.
 *  hashMethod - The message digest method to use to hash the shared key.
 *  returns the shared key
 */
const BIGNUM *EC_JPAKE_get_shared_key(EC_JPAKE_CTX *ctx, const EVP_MD *hashMethod) 
{

    /* Assume error */
    BIGNUM *bnKey = NULL;

    EC_POINT *Ka = EC_POINT_new(ctx->group);

    /* K = ( Xp - Xp2 * xm2 * s ) * xm2 */
    if(Ka == NULL ||

    /* 1. Xp2 * xm2 * s */
    !EC_POINT_mul(ctx->group, Ka, NULL, ctx->gx4, ctx->x2s, ctx->bnCtx) ||

    /* 2. -1 * Xp2 * xm2 * s */
    !EC_POINT_invert(ctx->group, Ka, ctx->bnCtx) ||

    /* 3. Xp - Xp2 * xm2 * s */
    !EC_POINT_add(ctx->group, Ka, ctx->b, Ka, ctx->bnCtx) ||

    /* Finally, K = ( Xp - Xp2 * xm2 * s ) * xm2 */
    !EC_POINT_mul(ctx->group, Ka, NULL, Ka, ctx->x2, ctx->bnCtx)) {
        goto err;
    }

    /* Find and hash the x coordinate of Ka and return it */
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();

    if(x == NULL || 
       y == NULL ||
      !EC_POINT_get_affine_coordinates_GFp(ctx->group, Ka, x, y, NULL)) {
        goto bnErr;
    }

    /* Convert the BIGNUM of x in to a binary, c string */
    unsigned int length = 0;
    unsigned char *md = OPENSSL_malloc(EVP_MD_size(hashMethod));
    unsigned char *xBytes = OPENSSL_malloc(BN_num_bytes(x));
    
    if(md == NULL || xBytes == NULL) {
        goto charErr;
    }

    /* Create a digest context and hash the bytes */
    int xLen = BN_bn2bin(x, xBytes);
    EVP_MD_CTX *context = EVP_MD_CTX_new();

    if(context == NULL ||
    !EVP_DigestInit_ex(context, hashMethod, NULL) ||
    !EVP_DigestUpdate(context, xBytes, (size_t) xLen) ||
    !EVP_DigestFinal_ex(context, md, &length)) {
        goto evpErr;
    }

    /* Convert back to a BIGNUM representation and return */
    bnKey = BN_bin2bn(md, EVP_MD_size(hashMethod), NULL);

    /* Free the JPAKE context (clears the secret field) */
    EC_JPAKE_CTX_clear_private_fields(ctx);

    /* Free resources */
evpErr:
    EVP_MD_CTX_free(context);
charErr:
    OPENSSL_free(xBytes);
    OPENSSL_free(md);
bnErr:
    BN_clear_free(x);
    BN_clear_free(y);
err:
    EC_POINT_free(Ka);

    return bnKey;
}

/**
 * The HMAC's secret key is composed of the shared, symmetric key. This should ensure
 * the HMAC generated by both participants can be validated.
 * 
 * MacKey = H(K || "JPAKE_KC")
 */
unsigned char *calculate_mac_key(const BIGNUM *keyingMaterial, const EVP_MD *method) 
{

    const char *JPAKE_KC = "JPAKE_KC";
    unsigned char *keyBytes = OPENSSL_malloc(BN_num_bytes(keyingMaterial));

    if(keyBytes == NULL) {
        return NULL;
    }

    int len = BN_bn2bin(keyingMaterial, keyBytes);

    /* Create a digest context and hash the bytes */
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned char *message = OPENSSL_malloc(EVP_MD_size(method));
    unsigned int mdLength = 0;

    if(context == NULL ||
       message == NULL ||
       !EVP_DigestInit_ex(context, method, NULL) ||
       !EVP_DigestUpdate(context, keyBytes, len) ||
       !EVP_DigestUpdate(context, JPAKE_KC, strlen(JPAKE_KC)) ||
       !EVP_DigestFinal_ex(context, message, &mdLength)) {
          goto err;
    }

err:
    EVP_MD_CTX_free(context);
    OPENSSL_free(keyBytes);

    return message;
}

/**
 * Calculates the Hashed Message Authentication Code (HMAC). This is also
 * referred to as a mac or mac tag.
 *
 *         participantId - a session unique identifier of one participant
 *  partnerParticipantId - a session unique identifier of the partner
 *                   Gx1 - an EC Point, encoded in the mac tag
 *                   Gx2 - an EC Point, encoded in the mac tag
 *                   Gx3 - an EC Point, encoded in the mac tag
 *                   Gx4 - an EC Point, encoded in the mac tag
 *        keyingMaterial - a shared, common key between two parties
 *          digestMethod - An EVP_MD struct descriptive of the digest used
 *                 group - The elliptic curve group in use
 *                 bnCtx - The BIGNUM context
 *  returns a big integer containing the mac tag or NULL if there was an error.
 */
BIGNUM *calculate_mac_tag(const char *participantId,
        const char *partnerParticipantId,
        EC_POINT *Gx1,
        EC_POINT *Gx2,
        EC_POINT *Gx3,
        EC_POINT *Gx4,
        const BIGNUM *keyingMaterial,
        const EVP_MD *digestMethod,
        EC_GROUP *group,
        BN_CTX *bnCtx) 
{
    /* Return value */
    BIGNUM *bnHmac = BN_new();

    // Initialize the Hash Message Authentication Code (HMAC) Context with our shared secret and a SHA-256 digest
    HMAC_CTX *hmacCtx = HMAC_CTX_new();
    unsigned char *macKey = calculate_mac_key(keyingMaterial, digestMethod);
    unsigned char *hmac_value = OPENSSL_malloc(EVP_MD_size(digestMethod));

    if(bnHmac == NULL || 
      hmacCtx == NULL || 
       macKey == NULL ||
   hmac_value == NULL ||
      !HMAC_Init_ex(hmacCtx, macKey, EVP_MD_size(digestMethod), digestMethod, NULL)) {
        goto err;
    }

    /**
     * We'll use the same format as Bouncy Castle for HMAC, as described in:
     * https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Ar3.pdf
     * MacData = "KC_1_U" || participantId_Alice || participantId_Bob || gx1 || gx2 || gx3 || gx4.
     *
     * This format will allow us to validate with peers, using different crypto libraries, that
     * also implement to this specification.
     * 
     */
    const unsigned char *KC_1_U = (unsigned char *) "KC_1_U";

    /** Create BIGNUMs from the provided EC Points **/
    BIGNUM *bnGx1 = EC_POINT_point2bn(group, Gx1, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    BIGNUM *bnGx2 = EC_POINT_point2bn(group, Gx2, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    BIGNUM *bnGx3 = EC_POINT_point2bn(group, Gx3, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);
    BIGNUM *bnGx4 = EC_POINT_point2bn(group, Gx4, POINT_CONVERSION_UNCOMPRESSED, NULL, bnCtx);

    if(bnGx1 == NULL || bnGx2 == NULL || bnGx3 == NULL || bnGx4 == NULL) {
        goto bnErr;
    }
       
    /* Allocate memory to store BIGNUMs as unsigned character arrays (byte arrays) */
    unsigned char *charGx1 = OPENSSL_malloc(BN_num_bytes(bnGx1));
    unsigned char *charGx2 = OPENSSL_malloc(BN_num_bytes(bnGx2));
    unsigned char *charGx3 = OPENSSL_malloc(BN_num_bytes(bnGx3));
    unsigned char *charGx4 = OPENSSL_malloc(BN_num_bytes(bnGx4));

   if(charGx1 == NULL || charGx2 == NULL || charGx3 == NULL || charGx4 == NULL) {
        goto mallocErr;
    }

    /* This writes the BIGNUM bytes to the character arrays we created and returns the length */
    int Gx1Len = BN_bn2bin(bnGx1, charGx1);
    int Gx2Len = BN_bn2bin(bnGx2, charGx2);
    int Gx3Len = BN_bn2bin(bnGx3, charGx3);
    int Gx4Len = BN_bn2bin(bnGx4, charGx4);

    unsigned int hmac_length;

    if(hmac_value == NULL ||
       !HMAC_Update(hmacCtx, KC_1_U, strlen((char *) KC_1_U)) ||
       !HMAC_Update(hmacCtx, (const unsigned char *) participantId, strlen(participantId)) ||
       !HMAC_Update(hmacCtx, (const unsigned char *) partnerParticipantId, strlen(partnerParticipantId)) ||
       !HMAC_Update(hmacCtx, charGx1, Gx1Len) ||
       !HMAC_Update(hmacCtx, charGx2, Gx2Len) ||
       !HMAC_Update(hmacCtx, charGx3, Gx3Len) ||
       !HMAC_Update(hmacCtx, charGx4, Gx4Len) ||
       !HMAC_Final(hmacCtx, hmac_value, &hmac_length)) {
           goto mallocErr;
    }

    /* Save the HMAC */
    bnHmac = BN_bin2bn(hmac_value, hmac_length, NULL);

    /* Cleanup */
mallocErr:
    OPENSSL_free(charGx4);
    OPENSSL_free(charGx3);
    OPENSSL_free(charGx2);
    OPENSSL_free(charGx1);
bnErr:
    BN_clear_free(bnGx4);
    BN_clear_free(bnGx3);
    BN_clear_free(bnGx2);
    BN_clear_free(bnGx1);
err:
    OPENSSL_free(hmac_value);
    OPENSSL_free(macKey);
    HMAC_CTX_free(hmacCtx);

    return bnHmac;
}

/**
 * Generates an a Hashed Message Authentication Code comprised of the user Ids and EC Points
 * generated in the previous rounds. Our partner has the same information to generate an
 * HMAC which should match ours.  We do the same step in validation.
 *
 *   ctx - The JPAKE context
 *  send - The data (hmac) to send to our peer for validation
 *   key - The shared secret
 *  1 is returned for success, 0 on error.
 */
int EC_JPAKE_STEP3_generate(EC_JPAKE_CTX *ctx, EC_JPAKE_STEP3 *send, const BIGNUM *key) 
{

    if (key == NULL) {
        return JPAKE_RET_FAILURE;
    }

    send->hmac = calculate_mac_tag(ctx->name, ctx->peer_name, ctx->gx1, ctx->gx2,
            ctx->gx3, ctx->gx4, key, send->method, ctx->group, ctx->bnCtx);

    if (send->hmac == NULL) {
        return JPAKE_RET_FAILURE;
    }

    return JPAKE_RET_SUCCESS;
}

/**
 * This validates the partner Mac by calculating
 * the expected Mac using the parameters as the partner
 * would have used when the partner called calculateMacTag.
 *
 * i.e. basically all the parameters are reversed.
 * participantId <-> partnerParticipantId
 *            x1 <-> x3
 *            x2 <-> x4
 *
 *  1 is returned for success, 0 on error.
 */
int EC_JPAKE_STEP3_process(EC_JPAKE_CTX *ctx, const char *partnerParticipantId, EC_JPAKE_STEP3 *received, const BIGNUM *key) 
{

    /* Check that ids are different */
    if (!validate_participants(ctx, partnerParticipantId)) {
        return JPAKE_RET_FAILURE;
    }

    BIGNUM *partnerMac = calculate_mac_tag(ctx->peer_name, ctx->name, ctx->gx3, ctx->gx4,
            ctx->gx1, ctx->gx2, key, received->method, ctx->group, ctx->bnCtx);
    int cmp = BN_cmp(received->hmac, partnerMac);

    /* 0 = success; all non-zero values will be true (error) */
    return (cmp == 0) ? JPAKE_RET_SUCCESS : JPAKE_RET_FAILURE;
}



