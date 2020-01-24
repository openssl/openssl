/*
 * Copyright 2011-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "rand_local.h"

/*
 * Called twice by SP800-90Ar1 10.1.2.2 HMAC_DRBG_Update_Process.
 *
 * hmac is an object that holds the input/output Key and Value (K and V).
 * inbyte is 0x00 on the first call and 0x01 on the second call.
 * in1, in2, in3 are optional inputs that can be NULL.
 * in1len, in2len, in3len are the lengths of the input buffers.
 *
 * The returned K,V is:
 *   hmac->K = HMAC(hmac->K, hmac->V || inbyte || [in1] || [in2] || [in3])
 *   hmac->V = HMAC(hmac->K, hmac->V)
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int do_hmac(RAND_DRBG_HMAC *hmac, unsigned char inbyte,
                   const unsigned char *in1, size_t in1len,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len)
{
    HMAC_CTX *ctx = hmac->ctx;

    return HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
           /* K = HMAC(K, V || inbyte || [in1] || [in2] || [in3]) */
           && HMAC_Update(ctx, hmac->V, hmac->blocklen)
           && HMAC_Update(ctx, &inbyte, 1)
           && (in1 == NULL || in1len == 0 || HMAC_Update(ctx, in1, in1len))
           && (in2 == NULL || in2len == 0 || HMAC_Update(ctx, in2, in2len))
           && (in3 == NULL || in3len == 0 || HMAC_Update(ctx, in3, in3len))
           && HMAC_Final(ctx, hmac->K, NULL)
           /* V = HMAC(K, V) */
           && HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
           && HMAC_Update(ctx, hmac->V, hmac->blocklen)
           && HMAC_Final(ctx, hmac->V, NULL);
}

/*
 * SP800-90Ar1 10.1.2.2 HMAC_DRBG_Update_Process
 *
 *
 * Updates the drbg objects Key(K) and Value(V) using the following algorithm:
 *   K,V = do_hmac(hmac, 0, in1, in2, in3)
 *   if (any input is not NULL)
 *     K,V = do_hmac(hmac, 1, in1, in2, in3)
 *
 * where in1, in2, in3 are optional input buffers that can be NULL.
 *       in1len, in2len, in3len are the lengths of the input buffers.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hmac_update(RAND_DRBG *drbg,
                            const unsigned char *in1, size_t in1len,
                            const unsigned char *in2, size_t in2len,
                            const unsigned char *in3, size_t in3len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;

    /* (Steps 1-2) K = HMAC(K, V||0x00||provided_data). V = HMAC(K,V) */
    if (!do_hmac(hmac, 0x00, in1, in1len, in2, in2len, in3, in3len))
        return 0;
    /* (Step 3) If provided_data == NULL then return (K,V) */
    if (in1len == 0 && in2len == 0 && in3len == 0)
        return 1;
    /* (Steps 4-5) K = HMAC(K, V||0x01||provided_data). V = HMAC(K,V) */
    return do_hmac(hmac, 0x01, in1, in1len, in2, in2len, in3, in3len);
}

/*
 * SP800-90Ar1 10.1.2.3 HMAC_DRBG_Instantiate_Process:
 *
 * This sets the drbg Key (K) to all zeros, and Value (V) to all 1's.
 * and then calls (K,V) = drbg_hmac_update() with input parameters:
 *   ent = entropy data (Can be NULL) of length ent_len.
 *   nonce = nonce data (Can be NULL) of length nonce_len.
 *   pstr = personalization data (Can be NULL) of length pstr_len.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hmac_instantiate(RAND_DRBG *drbg,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;

    /* (Step 2) Key = 0x00 00...00 */
    memset(hmac->K, 0x00, hmac->blocklen);
    /* (Step 3) V = 0x01 01...01 */
    memset(hmac->V, 0x01, hmac->blocklen);
    /* (Step 4) (K,V) = HMAC_DRBG_Update(entropy||nonce||pers string, K, V) */
    return drbg_hmac_update(drbg, ent, ent_len, nonce, nonce_len, pstr,
                            pstr_len);
}

/*
 * SP800-90Ar1 10.1.2.4 HMAC_DRBG_Reseed_Process:
 *
 * Reseeds the drbg's Key (K) and Value (V) by calling
 * (K,V) = drbg_hmac_update() with the following input parameters:
 *   ent = entropy input data (Can be NULL) of length ent_len.
 *   adin = additional input data (Can be NULL) of length adin_len.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hmac_reseed(RAND_DRBG *drbg,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    /* (Step 2) (K,V) = HMAC_DRBG_Update(entropy||additional_input, K, V) */
    return drbg_hmac_update(drbg, ent, ent_len, adin, adin_len, NULL, 0);
}

/*
 * SP800-90Ar1 10.1.2.5 HMAC_DRBG_Generate_Process:
 *
 * Generates pseudo random bytes and updates the internal K,V for the drbg.
 * out is a buffer to fill with outlen bytes of pseudo random data.
 * adin is an additional_input string of size adin_len that may be NULL.
 *
 * Returns zero if an error occurs otherwise it returns 1.
 */
static int drbg_hmac_generate(RAND_DRBG *drbg,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;
    HMAC_CTX *ctx = hmac->ctx;
    const unsigned char *temp = hmac->V;

    /* (Step 2) if adin != NULL then (K,V) = HMAC_DRBG_Update(adin, K, V) */
    if (adin != NULL
            && adin_len > 0
            && !drbg_hmac_update(drbg, adin, adin_len, NULL, 0, NULL, 0))
        return 0;

    /*
     * (Steps 3-5) temp = NULL
     *             while (len(temp) < outlen) {
     *                 V = HMAC(K, V)
     *                 temp = temp || V
     *             }
     */
    for (;;) {
        if (!HMAC_Init_ex(ctx, hmac->K, hmac->blocklen, hmac->md, NULL)
                || !HMAC_Update(ctx, temp, hmac->blocklen))
            return 0;

        if (outlen > hmac->blocklen) {
            if (!HMAC_Final(ctx, out, NULL))
                return 0;
            temp = out;
        } else {
            if (!HMAC_Final(ctx, hmac->V, NULL))
                return 0;
            memcpy(out, hmac->V, outlen);
            break;
        }
        out += hmac->blocklen;
        outlen -= hmac->blocklen;
    }
    /* (Step 6) (K,V) = HMAC_DRBG_Update(adin, K, V) */
    if (!drbg_hmac_update(drbg, adin, adin_len, NULL, 0, NULL, 0))
        return 0;

    return 1;
}

static int drbg_hmac_uninstantiate(RAND_DRBG *drbg)
{
    EVP_MD_free(drbg->data.hmac.md);
    HMAC_CTX_free(drbg->data.hmac.ctx);
    OPENSSL_cleanse(&drbg->data.hmac, sizeof(drbg->data.hmac));
    return 1;
}

static RAND_DRBG_METHOD drbg_hmac_meth = {
    drbg_hmac_instantiate,
    drbg_hmac_reseed,
    drbg_hmac_generate,
    drbg_hmac_uninstantiate
};

int drbg_hmac_init(RAND_DRBG *drbg)
{
    EVP_MD *md = NULL;
    RAND_DRBG_HMAC *hmac = &drbg->data.hmac;

    /*
     * Confirm digest is allowed. We allow all digests that are not XOF
     * (such as SHAKE).  In FIPS mode, the fetch will fail for non-approved
     * digests.
     */
    md = EVP_MD_fetch(drbg->libctx, ossl_prov_util_nid_to_name(drbg->type), "");
    if (md == NULL)
        return 0;

    if ((EVP_MD_flags(md) & EVP_MD_FLAG_XOF) != 0)
        return 0;

    drbg->meth = &drbg_hmac_meth;

    if (hmac->ctx == NULL) {
        hmac->ctx = HMAC_CTX_new();
        if (hmac->ctx == NULL) {
            EVP_MD_free(md);
            return 0;
        }
    }

    /* These are taken from SP 800-90 10.1 Table 2 */
    EVP_MD_free(hmac->md);
    hmac->md = md;
    hmac->blocklen = EVP_MD_size(md);
    /* See SP800-57 Part1 Rev4 5.6.1 Table 3 */
    drbg->strength = 64 * (int)(hmac->blocklen >> 3);
    if (drbg->strength > 256)
        drbg->strength = 256;
    drbg->seedlen = hmac->blocklen;

    drbg->min_entropylen = drbg->strength / 8;
    drbg->max_entropylen = DRBG_MAX_LENGTH;

    drbg->min_noncelen = drbg->min_entropylen / 2;
    drbg->max_noncelen = DRBG_MAX_LENGTH;

    drbg->max_perslen = DRBG_MAX_LENGTH;
    drbg->max_adinlen = DRBG_MAX_LENGTH;

    /* Maximum number of bits per request = 2^19 = 2^16 bytes*/
    drbg->max_request = 1 << 16;

    return 1;
}
