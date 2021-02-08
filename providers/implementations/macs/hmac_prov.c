/*
 * Copyright 2018-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * HMAC low level APIs are deprecated for public use, but still ok for internal
 * use.
 */
#include "internal/deprecated.h"

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"
#include "prov/providercommon.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static OSSL_FUNC_mac_newctx_fn hmac_new;
static OSSL_FUNC_mac_dupctx_fn hmac_dup;
static OSSL_FUNC_mac_freectx_fn hmac_free;
static OSSL_FUNC_mac_gettable_ctx_params_fn hmac_gettable_ctx_params;
static OSSL_FUNC_mac_get_ctx_params_fn hmac_get_ctx_params;
static OSSL_FUNC_mac_settable_ctx_params_fn hmac_settable_ctx_params;
static OSSL_FUNC_mac_set_ctx_params_fn hmac_set_ctx_params;
static OSSL_FUNC_mac_init_fn hmac_init;
static OSSL_FUNC_mac_update_fn hmac_update;
static OSSL_FUNC_mac_final_fn hmac_final;

/* local HMAC context structure */

/* typedef EVP_MAC_IMPL */
struct hmac_data_st {
    void *provctx;
    HMAC_CTX *ctx;               /* HMAC context */
    PROV_DIGEST digest;
    unsigned char *key;
    size_t keylen;
    /* Length of full TLS record including the MAC and any padding */
    size_t tls_data_size;
    unsigned char tls_header[13];
    int tls_header_set;
    unsigned char tls_mac_out[EVP_MAX_MD_SIZE];
    size_t tls_mac_out_size;
};

/* Defined in ssl/s3_cbc.c */
int ssl3_cbc_digest_record(const EVP_MD *md,
                           unsigned char *md_out,
                           size_t *md_out_size,
                           const unsigned char header[13],
                           const unsigned char *data,
                           size_t data_size,
                           size_t data_plus_mac_plus_padding_size,
                           const unsigned char *mac_secret,
                           size_t mac_secret_length, char is_sslv3);

static void *hmac_new(void *provctx)
{
    struct hmac_data_st *macctx;

    if (!ossl_prov_is_running())
        return NULL;

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
        OPENSSL_secure_clear_free(macctx->key, macctx->keylen);
        OPENSSL_free(macctx);
    }
}

static void *hmac_dup(void *vsrc)
{
    struct hmac_data_st *src = vsrc;
    struct hmac_data_st *dst;
    HMAC_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;
    dst = hmac_new(src->provctx);
    if (dst == NULL)
        return NULL;

    ctx = dst->ctx;
    *dst = *src;
    dst->ctx = ctx;
    dst->key = NULL;

    if (!HMAC_CTX_copy(dst->ctx, src->ctx)
        || !ossl_prov_digest_copy(&dst->digest, &src->digest)) {
        hmac_free(dst);
        return NULL;
    }
    if (src->key != NULL) {
        /* There is no "secure" OPENSSL_memdup */
        dst->key = OPENSSL_secure_malloc(src->keylen > 0 ? src->keylen : 1);
        if (dst->key == NULL) {
            hmac_free(dst);
            return 0;
        }
        memcpy(dst->key, src->key, src->keylen);
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
    const EVP_MD *digest;
    int rv = 1;

    if (!ossl_prov_is_running())
        return 0;

    digest = ossl_prov_digest_md(&macctx->digest);
    /* HMAC_Init_ex doesn't tolerate all zero params, so we must be careful */
    if (macctx->tls_data_size == 0 && digest != NULL)
        rv = HMAC_Init_ex(macctx->ctx, NULL, 0, digest,
                          ossl_prov_digest_engine(&macctx->digest));

    return rv;
}

static int hmac_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct hmac_data_st *macctx = vmacctx;

    if (macctx->tls_data_size > 0) {
        /* We're doing a TLS HMAC */
        if (!macctx->tls_header_set) {
            /* We expect the first update call to contain the TLS header */
            if (datalen != sizeof(macctx->tls_header))
                return 0;
            memcpy(macctx->tls_header, data, datalen);
            macctx->tls_header_set = 1;
            return 1;
        }
        /* macctx->tls_data_size is datalen plus the padding length */
        if (macctx->tls_data_size < datalen)
            return 0;

        return ssl3_cbc_digest_record(ossl_prov_digest_md(&macctx->digest),
                                      macctx->tls_mac_out,
                                      &macctx->tls_mac_out_size,
                                      macctx->tls_header,
                                      data,
                                      datalen,
                                      macctx->tls_data_size,
                                      macctx->key,
                                      macctx->keylen,
                                      0);
    }

    return HMAC_Update(macctx->ctx, data, datalen);
}

static int hmac_final(void *vmacctx, unsigned char *out, size_t *outl,
                      size_t outsize)
{
    unsigned int hlen;
    struct hmac_data_st *macctx = vmacctx;

    if (!ossl_prov_is_running())
        return 0;
    if (macctx->tls_data_size > 0) {
        if (macctx->tls_mac_out_size == 0)
            return 0;
        if (outl != NULL)
            *outl = macctx->tls_mac_out_size;
        memcpy(out, macctx->tls_mac_out, macctx->tls_mac_out_size);
        return 1;
    }
    if (!HMAC_Final(macctx->ctx, out, &hlen))
        return 0;
    *outl = hlen;
    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_gettable_ctx_params(ossl_unused void *provctx)
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
    OSSL_PARAM_size_t(OSSL_MAC_PARAM_TLS_DATA_SIZE, NULL),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hmac_settable_ctx_params(ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int hmac_set_ctx_params(void *vmacctx, const OSSL_PARAM params[])
{
    struct hmac_data_st *macctx = vmacctx;
    OSSL_LIB_CTX *ctx = PROV_LIBCTX_OF(macctx->provctx);
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

        if (macctx->keylen > 0)
            OPENSSL_secure_clear_free(macctx->key, macctx->keylen);
        /* Keep a copy of the key if we need it for TLS HMAC */
        macctx->key = OPENSSL_secure_malloc(p->data_size > 0 ? p->data_size : 1);
        if (macctx->key == NULL)
            return 0;
        memcpy(macctx->key, p->data, p->data_size);
        macctx->keylen = p->data_size;

        if (!HMAC_Init_ex(macctx->ctx, p->data, p->data_size,
                          ossl_prov_digest_md(&macctx->digest),
                          NULL /* ENGINE */))
            return 0;

    }
    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_MAC_PARAM_TLS_DATA_SIZE)) != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &macctx->tls_data_size))
            return 0;
    }
    return 1;
}

const OSSL_DISPATCH ossl_hmac_functions[] = {
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
