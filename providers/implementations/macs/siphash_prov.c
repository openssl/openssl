/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include "crypto/siphash.h"
/*
 * TODO(3.0) when siphash has moved entirely to our providers, this
 * header should be moved to the provider include directory.  For the
 * moment, crypto/siphash/siphash_ameth.c has us stuck.
 */
#include "../../../crypto/siphash/siphash_local.h"

#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_mac_newctx_fn siphash_new;
static OSSL_FUNC_mac_dupctx_fn siphash_dup;
static OSSL_FUNC_mac_freectx_fn siphash_free;
static OSSL_FUNC_mac_gettable_ctx_params_fn siphash_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn siphash_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn siphash_settable_params;
static OSSL_FUNC_mac_set_ctx_params_fn siphash_set_params;
static OSSL_FUNC_mac_init_fn siphash_init;
static OSSL_FUNC_mac_update_fn siphash_update;
static OSSL_FUNC_mac_final_fn siphash_final;

struct siphash_data_st {
    void *provctx;
    SIPHASH siphash;             /* Siphash data */
};

static void *siphash_new(void *provctx)
{
    struct siphash_data_st *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void siphash_free(void *vmacctx)
{
    OPENSSL_free(vmacctx);
}

static void *siphash_dup(void *vsrc)
{
    struct siphash_data_st *ssrc = vsrc;
    struct siphash_data_st *sdst;

    if (!ossl_prov_is_running())
        return NULL;
    sdst = siphash_new(ssrc->provctx);
    if (sdst == NULL)
        return NULL;

    sdst->siphash = ssrc->siphash;
    return sdst;
}

static size_t siphash_size(void *vmacctx)
{
    struct siphash_data_st *ctx = vmacctx;

    return SipHash_hash_size(&ctx->siphash);
}

static int siphash_init(void *vmacctx)
{
    /* Not much to do here, actual initialization happens through controls */
    return ossl_prov_is_running();
}

static int siphash_update(void *vmacctx, const unsigned char *data,
                          size_t datalen)
{
    struct siphash_data_st *ctx = vmacctx;

    if (datalen == 0)
        return 1;

    SipHash_Update(&ctx->siphash, data, datalen);
    return 1;
}

static int siphash_final(void *vmacctx, unsigned char *out, size_t *outl,
                         size_t outsize)
{
    struct siphash_data_st *ctx = vmacctx;
    size_t hlen = siphash_size(ctx);

    if (!ossl_prov_is_running() || outsize < hlen)
        return 0;

    *outl = hlen;
    return SipHash_Final(&ctx->siphash, out, hlen);
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *siphash_gettable_ctx_params(ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int siphash_get_ctx_params(void *vmacctx, OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_MAC_PARAM_SIZE)) != NULL)
        return OSSL_PARAM_set_size_t(p, siphash_size(vmacctx));

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_MAC_PARAM_KEY, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *siphash_settable_params(void *provctx)
{
    return known_settable_ctx_params;
}

static int siphash_set_params(void *vmacctx, const OSSL_PARAM *params)
{
    struct siphash_data_st *ctx = vmacctx;
    const OSSL_PARAM *p = NULL;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_SIZE)) != NULL) {
        size_t size;

        if (!OSSL_PARAM_get_size_t(p, &size)
            || !SipHash_set_hash_size(&ctx->siphash, size))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_MAC_PARAM_KEY)) != NULL)
        if (p->data_type != OSSL_PARAM_OCTET_STRING
            || p->data_size != SIPHASH_KEY_SIZE
            || !SipHash_Init(&ctx->siphash, p->data, 0, 0))
            return 0;
    return 1;
}

const OSSL_DISPATCH ossl_siphash_functions[] = {
    { OSSL_FUNC_MAC_NEWCTX, (void (*)(void))siphash_new },
    { OSSL_FUNC_MAC_DUPCTX, (void (*)(void))siphash_dup },
    { OSSL_FUNC_MAC_FREECTX, (void (*)(void))siphash_free },
    { OSSL_FUNC_MAC_INIT, (void (*)(void))siphash_init },
    { OSSL_FUNC_MAC_UPDATE, (void (*)(void))siphash_update },
    { OSSL_FUNC_MAC_FINAL, (void (*)(void))siphash_final },
    { OSSL_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))siphash_gettable_ctx_params },
    { OSSL_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))siphash_get_ctx_params },
    { OSSL_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))siphash_settable_params },
    { OSSL_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))siphash_set_params },
    { 0, NULL }
};
