/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_OP_mac_newctx_fn hmac_new;
static OSSL_OP_mac_dupctx_fn hmac_dup;
static OSSL_OP_mac_freectx_fn hmac_free;
static OSSL_OP_mac_gettable_ctx_params_fn hmac_gettable_ctx_params;
static OSSL_OP_mac_get_ctx_params_fn hmac_get_ctx_params;
static OSSL_OP_mac_settable_ctx_params_fn hmac_settable_ctx_params;
static OSSL_OP_mac_set_ctx_params_fn hmac_set_ctx_params;
static OSSL_OP_mac_init_fn hmac_init;
static OSSL_OP_mac_update_fn hmac_update;
static OSSL_OP_mac_final_fn hmac_final;

/* local HMAC context structure */

/* typedef EVP_MAC_IMPL */
struct hmac_data_st {
    void *provctx;
    HMAC_CTX *ctx;               /* HMAC context */
    PROV_DIGEST digest;
};

static size_t hmac_size(void *vmacctx);

static void *hmac_new(void *provctx)
{
    struct hmac_data_st *macctx;

    if ((macctx = OPENSSL_zalloc(sizeof(*macctx))) == NULL
        || (macctx->ctx = HMAC_CTX_new()) == NULL) {
        OPENSSL_free(macctx);
        return NULL;
    }
    /* TODO(3.0) Should we do something more with that context? */
    macctx->provctx = provctx;

    return macctx;
}

static void hmac_free(void *vmacctx)
{
    struct hmac_data_st *macctx = vmacctx;

    if (macctx != NULL) {
        HMAC_CTX_free(macctx->ctx);
        ossl_prov_digest_reset(&macctx->digest);
        OPENSSL_free(macctx);
    }
}

static void *hmac_dup(void *vsrc)
{
    struct hmac_data_st *src = vsrc;
    struct hmac_data_st *dst = hmac_new(src->provctx);

    if (dst == NULL)
        return NULL;

    if (!HMAC_CTX_copy(dst->ctx, src->ctx)
        || !ossl_prov_digest_copy(&dst->digest, &src->digest)) {
        hmac_free(dst);
        return NULL;
    }
    return dst;
}

static size_t hmac_size(void *vmacctx)
{
    struct hmac_data_st *macctx = vmacctx;

    return HMAC_size(macctx->ctx);
}

static int hmac_init(void *vmacctx)
{
    struct hmac_data_st *macctx = vmacctx;
    const EVP_MD *digest = ossl_prov_digest_md(&macctx->digest);
    int rv = 1;

    /* HMAC_Init_ex doesn't tolerate all zero params, so we must be careful */
    if (digest != NULL)
        rv = HMAC_Init_ex(macctx->ctx, NULL, 0, digest,
                          ossl_prov_digest_engine(&macctx->digest));
    ossl_prov_digest_reset(&macctx->digest);
    return rv;
}

static int hmac_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct hmac_data_st *macctx = vmacctx;

    return HMAC_Update(macctx->ctx, data, datalen);
}

static int hmac_final(void *vmacctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    unsigned int hlen;
    struct hmac_data_st *macctx = vmacctx;

    if (!HMAC_Final(macctx->ctx, out, &hlen))
        return 0;
    if (outl != NULL)
        *outl = hlen;
    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_gettable_ctx_params(void)
{
    return known_gettable_ctx_params;
}

static int hmac_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, hmac_size(vmacctx));

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_MAC_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_int(OSSL_MAC_PARAM_FLAGS, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    struct hmac_data_st *macctx = vmacctx;
    OPENSSL_CTX *ctx = PROV_LIBRARY_CONTEXT_OF(macctx->provctx);
    const OSSL_PARAM *p;

    if (!ossl_prov_digest_load_from_params(&macctx->digest, params, ctx))
        return 0;

    /* TODO(3.0) formalize the meaning of "flags", perhaps as other params */
    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_MAC_PARAM_FLAGS)) != NULL) {
        int flags = 0;

        if (!OSSL_PARAM_get_int(p, &flags))
            return 0;
        HMAC_CTX_set_flags(macctx->ctx, flags);
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;

        if (!HMAC_Init_ex(macctx->ctx, p->data, p->data_size,
                          ossl_prov_digest_md(&macctx->digest),
                          NULL /* ENGINE */))
            return 0;

        ossl_prov_digest_reset(&macctx->digest);
    }
    return 1;
}

const OSSL_DISPATCH hmac_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))hmac_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))hmac_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))hmac_free },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))hmac_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))hmac_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))hmac_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))hmac_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))hmac_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))hmac_settable_ctx_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))hmac_set_ctx_params },
    { 0, NULL }
};
