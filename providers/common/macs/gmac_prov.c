/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "internal/providercommonerr.h"
#include "internal/provider_algs.h"
#include "internal/provider_ctx.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_OP_mac_newctx_fn gmac_new;
static OSSL_OP_mac_dupctx_fn gmac_dup;
static OSSL_OP_mac_freectx_fn gmac_free;
static OSSL_OP_mac_gettable_params_fn gmac_gettable_params;
static OSSL_OP_mac_get_params_fn gmac_get_params;
static OSSL_OP_mac_settable_ctx_params_fn gmac_settable_ctx_params;
static OSSL_OP_mac_ctx_set_params_fn gmac_ctx_set_params;
static OSSL_OP_mac_init_fn gmac_init;
static OSSL_OP_mac_update_fn gmac_update;
static OSSL_OP_mac_final_fn gmac_final;

/* local GMAC pkey structure */

struct gmac_data_st {
    void *provctx;
    EVP_CIPHER_CTX *ctx;         /* Cipher context */

    /*
     * References to the underlying cipher implementation.  |cipher| caches
     * the cipher, always.  |alloc_cipher| only holds a reference to an
     * explicitly fetched cipher.
     * |cipher| is cleared after a CMAC_Init call.
     */
    const EVP_CIPHER *cipher;    /* Cache GCM cipher */
    EVP_CIPHER *alloc_cipher;    /* Fetched cipher */

    /*
     * Conditions for legacy EVP_CIPHER uses.
     */
    ENGINE *engine;              /* Engine implementing the algorithm */
};

static size_t gmac_size(void);

static void gmac_free(void *vmacctx)
{
    struct gmac_data_st *macctx = vmacctx;

    if (macctx != NULL) {
        EVP_CIPHER_CTX_free(macctx->ctx);
        EVP_CIPHER_meth_free(macctx->alloc_cipher);
        OPENSSL_free(macctx);
    }
}

static void *gmac_new(void *provctx)
{
    struct gmac_data_st *macctx;

    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL
        || (macctx->ctx = EVP_CIPHER_CTX_new()) == NULL) {
        gmac_free(macctx);
        return NULL;
    }
    macctx->provctx = provctx;

    return macctx;
}

static void *gmac_dup(void *vsrc)
{
    struct gmac_data_st *src = vsrc;
    struct gmac_data_st *dst = gmac_new(src->provctx);

    if (dst == NULL)
        return NULL;

    if (!EVP_CIPHER_CTX_copy(dst->ctx, src->ctx)
        || (src->alloc_cipher != NULL
            && !EVP_CIPHER_up_ref(src->alloc_cipher))) {
        gmac_free(dst);
        return NULL;
    }

    dst->cipher = src->cipher;
    dst->alloc_cipher = src->alloc_cipher;
    dst->engine = src->engine;
    return dst;
}

static int gmac_init(void *vmacctx)
{
    return 1;
}

static int gmac_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct gmac_data_st *macctx = vmacctx;
    EVP_CIPHER_CTX *ctx = macctx->ctx;
    int outlen;

    while (datalen > INT_MAX) {
        if (!EVP_EncryptUpdate(ctx, NULL, &outlen, data, INT_MAX))
            return 0;
        data += INT_MAX;
        datalen -= INT_MAX;
    }
    return EVP_EncryptUpdate(ctx, NULL, &outlen, data, datalen);
}

static int gmac_final(void *vmacctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    struct gmac_data_st *macctx = vmacctx;
    int hlen = 0;

    if (!EVP_EncryptFinal_ex(macctx->ctx, out, &hlen))
        return 0;

    /* TODO(3.0) Use params */
    hlen = gmac_size();
    if (!EVP_CIPHER_CTX_ctrl(macctx->ctx, EVP_CTRL_AEAD_GET_TAG,
                             hlen, out))
        return 0;

    *outl = hlen;
    return 1;
}

static size_t gmac_size(void)
{
    return EVP_GCM_TLS_TAG_LEN;
}

static const OSSL_PARAM known_gettable_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_OUTLEN, NULL),
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL), /* Same as "outlen" */
    OSSL_PARAM_END
};
static const OSSL_PARAM *gmac_gettable_params(void)
{
    return known_gettable_params;
}

static int gmac_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_OUTLEN)) != NULL
        || (p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, gmac_size());

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    /* "algorithm" and "cipher" are the same parameter */
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_ALGORITHM, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_CIPHER, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_ENGINE, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_IV, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *gmac_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int gmac_ctx_set_params(void *vmacctx, const OSSL_PARAM params[])
{
    struct gmac_data_st *macctx = vmacctx;
    EVP_CIPHER_CTX *ctx = macctx->ctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_CIPHER)) != NULL
        || (p = OSSL_PARAM_locate_const(params,
                                        OSSL_MAC_PARAM_ALGORITHM)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;

        {
            const char *algoname = p->data;
            const char *propquery = NULL;

#ifndef FIPS_MODE /* Inside the FIPS module, we don't support engines */
            ENGINE_finish(macctx->engine);
            macctx->engine = NULL;

            if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_ENGINE))
                != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                    return 0;

                macctx->engine = ENGINE_by_id(p->data);
                if (macctx->engine == NULL)
                    return 0;
            }
#endif
            if ((p = OSSL_PARAM_locate_const(params,
                                             OSSL_MAC_PARAM_PROPERTIES))
                != NULL) {
                if (p->data_type != OSSL_PARAM_UTF8_STRING)
                    return 0;

                propquery = p->data;
            }

            EVP_CIPHER_meth_free(macctx->alloc_cipher);
            macctx->cipher = macctx->alloc_cipher = NULL;

            macctx->cipher = macctx->alloc_cipher =
                EVP_CIPHER_fetch(PROV_LIBRARY_CONTEXT_OF(macctx->provctx),
                                 algoname, propquery);
#ifndef FIPS_MODE /* Inside the FIPS module, we don't support legacy ciphers */
            /* TODO(3.0) BEGIN legacy stuff, to be removed */
            if (macctx->cipher == NULL)
                macctx->cipher = EVP_get_cipherbyname(algoname);
            /* TODO(3.0) END of legacy stuff */
#endif

            if (macctx->cipher == NULL)
                return 0;

            if (EVP_CIPHER_mode(macctx->cipher) != EVP_CIPH_GCM_MODE) {
                ERR_raise(ERR_LIB_PROV, EVP_R_CIPHER_NOT_GCM_MODE);
                return 0;
            }
        }
        if (!EVP_EncryptInit_ex(ctx, macctx->cipher, macctx->engine,
                                NULL, NULL))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (p->data_size != (size_t)EVP_CIPHER_CTX_key_length(ctx)) {
            ERR_raise(ERR_LIB_PROV, EVP_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, p->data, NULL))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_IV)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 p->data_size, NULL)
            || !EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, p->data))
            return 0;
    }
    return 1;
}

const OSSL_DISPATCH gmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))gmac_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))gmac_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))gmac_free },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))gmac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))gmac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))gmac_final },
    { OSSL_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))gmac_gettable_params },
    { OSSL_FUNC_MAC_GET_PARAMS, (void (*)(void))gmac_get_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))gmac_settable_ctx_params },
    { OSSL_FUNC_MAC_CTX_SET_PARAMS, (void (*)(void))gmac_ctx_set_params },
    { 0, NULL }
};
