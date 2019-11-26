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
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "internal/thread_once.h"
#include "prov/providercommon.h"
#include "drbg_local.h"

typedef struct rand_drbg_hmac_st {
    EVP_MAC_CTX *ctx;
    size_t blocklen;
    unsigned char K[EVP_MAX_MD_SIZE];
    unsigned char V[EVP_MAX_MD_SIZE];
} PROV_RAND_HMAC;


static OSSL_OP_rand_newctx_fn drbg_hmac_new_wrapper;
static OSSL_OP_rand_instantiate_fn drbg_hmac_instantiate;
static OSSL_OP_rand_uninstantiate_fn drbg_hmac_uninstantiate;
static OSSL_OP_rand_generate_fn drbg_hmac_generate;
static OSSL_OP_rand_reseed_fn drbg_hmac_reseed;
static OSSL_OP_rand_gettable_ctx_params_fn drbg_hmac_gettable_ctx_params;
static OSSL_OP_rand_get_ctx_params_fn drbg_hmac_get_ctx_params;
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
static int do_hmac(PROV_RAND_HMAC *hmac, unsigned char inbyte,
                   const unsigned char *in1, size_t in1len,
                   const unsigned char *in2, size_t in2len,
                   const unsigned char *in3, size_t in3len)
{
    EVP_MAC_CTX *ctx = hmac->ctx;

    return EVP_MAC_init(ctx)
           /* K = HMAC(K, V || inbyte || [in1] || [in2] || [in3]) */
           && EVP_MAC_update(ctx, hmac->V, hmac->blocklen)
           && EVP_MAC_update(ctx, &inbyte, 1)
           && (in1 == NULL || in1len == 0 || EVP_MAC_update(ctx, in1, in1len))
           && (in2 == NULL || in2len == 0 || EVP_MAC_update(ctx, in2, in2len))
           && (in3 == NULL || in3len == 0 || EVP_MAC_update(ctx, in3, in3len))
           && EVP_MAC_final(ctx, hmac->K, NULL, sizeof(hmac->K))
           /* V = HMAC(K, V) */
           && EVP_MAC_init(ctx)
           && EVP_MAC_update(ctx, hmac->V, hmac->blocklen)
           && EVP_MAC_final(ctx, hmac->V, NULL, sizeof(hmac->V));
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
static int drbg_hmac_update(PROV_RAND *drbg,
                            const unsigned char *in1, size_t in1len,
                            const unsigned char *in2, size_t in2len,
                            const unsigned char *in3, size_t in3len)
{
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;

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
static int drbg_hmac_instantiate(void *vdrbg,
                                 const unsigned char *ent, size_t ent_len,
                                 const unsigned char *nonce, size_t nonce_len,
                                 const unsigned char *pstr, size_t pstr_len)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;

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
static int drbg_hmac_reseed(void *vdrbg,
                            const unsigned char *ent, size_t ent_len,
                            const unsigned char *adin, size_t adin_len)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;

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
static int drbg_hmac_generate(void *vdrbg,
                              unsigned char *out, size_t outlen,
                              const unsigned char *adin, size_t adin_len)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;
    EVP_MAC_CTX *ctx = hmac->ctx;
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
        if (!EVP_MAC_init(ctx)
                || !EVP_MAC_update(ctx, temp, hmac->blocklen))
            return 0;

        if (outlen > hmac->blocklen) {
            if (!EVP_MAC_final(ctx, out, NULL, outlen))
                return 0;
            temp = out;
        } else {
            if (!EVP_MAC_final(ctx, hmac->V, NULL, sizeof(hmac->V)))
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

static int drbg_hmac_uninstantiate(void *vdrbg)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;

    EVP_MAC_CTX_free(hmac->ctx);
    if (drbg->secure)
        OPENSSL_secure_clear_free(hmac, sizeof(*hmac));
    else
        OPENSSL_clear_free(hmac, sizeof(*hmac));
    drbg->data = NULL;
    return 1;
}

/* Provider support from here down */
static int drbg_hmac_new(PROV_RAND *ctx, int df)
{
    PROV_RAND_HMAC *hmac;

    hmac = ctx->secure ? OPENSSL_secure_zalloc(sizeof(*hmac))
                       : OPENSSL_zalloc(sizeof(*hmac));
    if (hmac == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    ctx->data = hmac;
    ctx->seedlen = EVP_MAX_MD_SIZE;
    ctx->max_entropylen = DRBG_MAX_LENGTH;
    ctx->max_noncelen = DRBG_MAX_LENGTH;
    ctx->max_perslen = DRBG_MAX_LENGTH;
    ctx->max_adinlen = DRBG_MAX_LENGTH;

    /* Maximum number of bits per request = 2^19 = 2^16 bytes*/
    ctx->max_request = 1 << 16;
    return 1;
}

static void *drbg_hmac_new_wrapper(void *provctx, int secure, int df)
{
    return prov_rand_drbg_new(provctx, secure, df, &drbg_hmac_new);
}

static void drbg_hmac_free_wrapper(void *vdrbg)
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;

    if (drbg->secure)
        OPENSSL_secure_clear_free(hmac, sizeof(*hmac));
    else
        OPENSSL_clear_free(hmac, sizeof(*hmac));
    prov_rand_free(drbg);
}

static int drbg_hmac_get_ctx_params(void *vdrbg, OSSL_PARAM params[])
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;

    return drbg_get_ctx_params(drbg, params);
}

static const OSSL_PARAM *drbg_hmac_gettable_ctx_params(void)
{
    static const OSSL_PARAM known_gettable_ctx_params[] = {
        OSSL_PARAM_DRBG_GETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_gettable_ctx_params;
}

static int drbg_hmac_set_ctx_params(void *vdrbg, const OSSL_PARAM params[])
{
    PROV_RAND *drbg = (PROV_RAND *)vdrbg;
    PROV_RAND_HMAC *hmac = (PROV_RAND_HMAC *)drbg->data;
    OPENSSL_CTX *provctx = PROV_LIBRARY_CONTEXT_OF(drbg->provctx);

    if (!ossl_prov_macctx_load_from_params(&hmac->ctx, params, "HMAC", NULL,
                                           NULL, provctx))
        return 0;
    if (hmac->ctx != NULL) {
        /* These are taken from SP 800-90 10.1 Table 2 */
        hmac->blocklen = EVP_MAC_size(hmac->ctx);
        /* See SP800-57 Part1 Rev4 5.6.1 Table 3 */
        drbg->strength = 64 * (int)(hmac->blocklen >> 3);
        if (drbg->strength > 256)
            drbg->strength = 256;
        drbg->seedlen = hmac->blocklen;

        drbg->min_entropylen = drbg->strength / 8;
        drbg->min_noncelen = drbg->min_entropylen / 2;
    }
    return drbg_set_ctx_params(drbg, params);
}

static const OSSL_PARAM *drbg_hmac_settable_ctx_params(void)
{
    static const OSSL_PARAM known_settable_ctx_params[] = {
        OSSL_PARAM_utf8_string(OSSL_RAND_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_utf8_string(OSSL_RAND_PARAM_DIGEST, NULL, 0),
        OSSL_PARAM_DRBG_SETABLE_CTX_COMMON,
        OSSL_PARAM_END
    };
    return known_settable_ctx_params;
}

const OSSL_DISPATCH drbg_hmac_functions[] = {
    { OSSL_FUNC_RAND_NEWCTX, (void(*)(void))drbg_hmac_new_wrapper },
    { OSSL_FUNC_RAND_FREECTX, (void(*)(void))drbg_hmac_free_wrapper },
    { OSSL_FUNC_RAND_INSTANTIATE, (void(*)(void))drbg_hmac_instantiate },
    { OSSL_FUNC_RAND_UNINSTANTIATE, (void(*)(void))drbg_hmac_uninstantiate },
    { OSSL_FUNC_RAND_GENERATE, (void(*)(void))drbg_hmac_generate },
    { OSSL_FUNC_RAND_RESEED, (void(*)(void))drbg_hmac_reseed },
    { OSSL_FUNC_RAND_SETTABLE_CTX_PARAMS,
      (void(*)(void))drbg_hmac_settable_ctx_params },
    { OSSL_FUNC_RAND_SET_CTX_PARAMS, (void(*)(void))drbg_hmac_set_ctx_params },
    { OSSL_FUNC_RAND_GETTABLE_CTX_PARAMS,
      (void(*)(void))drbg_hmac_gettable_ctx_params },
    { OSSL_FUNC_RAND_GET_CTX_PARAMS, (void(*)(void))drbg_hmac_get_ctx_params },
    { 0, NULL }
};
