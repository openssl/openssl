/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdlib.h>
#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/params.h>
#include <opentls/engine.h>
#include <opentls/evp.h>
#include <opentls/err.h>

#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/provider_util.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static Otls_OP_mac_newctx_fn gmac_new;
static Otls_OP_mac_dupctx_fn gmac_dup;
static Otls_OP_mac_freectx_fn gmac_free;
static Otls_OP_mac_gettable_params_fn gmac_gettable_params;
static Otls_OP_mac_get_params_fn gmac_get_params;
static Otls_OP_mac_settable_ctx_params_fn gmac_settable_ctx_params;
static Otls_OP_mac_set_ctx_params_fn gmac_set_ctx_params;
static Otls_OP_mac_init_fn gmac_init;
static Otls_OP_mac_update_fn gmac_update;
static Otls_OP_mac_final_fn gmac_final;

/* local GMAC pkey structure */

struct gmac_data_st {
    void *provctx;
    EVP_CIPHER_CTX *ctx;         /* Cipher context */
    PROV_CIPHER cipher;
};

static size_t gmac_size(void);

static void gmac_free(void *vmacctx)
{
    struct gmac_data_st *macctx = vmacctx;

    if (macctx != NULL) {
        EVP_CIPHER_CTX_free(macctx->ctx);
        otls_prov_cipher_reset(&macctx->cipher);
        OPENtls_free(macctx);
    }
}

static void *gmac_new(void *provctx)
{
    struct gmac_data_st *macctx;

    if ((macctx = OPENtls_zalloc(sizeof(*macctx))) == NULL
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
        || !otls_prov_cipher_copy(&dst->cipher, &src->cipher)) {
        gmac_free(dst);
        return NULL;
    }
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

static const Otls_PARAM known_gettable_params[] = {
    Otls_PARAM_size_t(Otls_MAC_PARAM_SIZE, NULL),
    Otls_PARAM_END
};
static const Otls_PARAM *gmac_gettable_params(void)
{
    return known_gettable_params;
}

static int gmac_get_params(Otls_PARAM params[])
{
    Otls_PARAM *p;

    if ((p = Otls_PARAM_locate(params, Otls_MAC_PARAM_SIZE)) != NULL)
        return Otls_PARAM_set_size_t(p, gmac_size());

    return 1;
}

static const Otls_PARAM known_settable_ctx_params[] = {
    Otls_PARAM_utf8_string(Otls_MAC_PARAM_CIPHER, NULL, 0),
    Otls_PARAM_utf8_string(Otls_MAC_PARAM_PROPERTIES, NULL, 0),
    Otls_PARAM_octet_string(Otls_MAC_PARAM_KEY, NULL, 0),
    Otls_PARAM_octet_string(Otls_MAC_PARAM_IV, NULL, 0),
    Otls_PARAM_END
};
static const Otls_PARAM *gmac_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int gmac_set_ctx_params(void *vmacctx, const Otls_PARAM params[])
{
    struct gmac_data_st *macctx = vmacctx;
    EVP_CIPHER_CTX *ctx = macctx->ctx;
    OPENtls_CTX *provctx = PROV_LIBRARY_CONTEXT_OF(macctx->provctx);
    const Otls_PARAM *p;

   if (ctx == NULL
        || !otls_prov_cipher_load_from_params(&macctx->cipher, params, provctx))
        return 0;

    if (EVP_CIPHER_mode(otls_prov_cipher_cipher(&macctx->cipher))
        != EVP_CIPH_GCM_MODE) {
        ERR_raise(ERR_LIB_PROV, EVP_R_CIPHER_NOT_GCM_MODE);
        return 0;
    }
    if (!EVP_EncryptInit_ex(ctx, otls_prov_cipher_cipher(&macctx->cipher),
                            otls_prov_cipher_engine(&macctx->cipher), NULL,
                            NULL))
        return 0;

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING)
            return 0;

        if (p->data_size != (size_t)EVP_CIPHER_CTX_key_length(ctx)) {
            ERR_raise(ERR_LIB_PROV, EVP_R_INVALID_KEY_LENGTH);
            return 0;
        }
        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, p->data, NULL))
            return 0;
    }
    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_IV)) != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING)
            return 0;

        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                                 p->data_size, NULL)
            || !EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, p->data))
            return 0;
    }
    return 1;
}

const Otls_DISPATCH gmac_functions[] = {
    { Otls_FUNC_MAC_NEWCTX, (void (*)(void))gmac_new },
    { Otls_FUNC_MAC_DUPCTX, (void (*)(void))gmac_dup },
    { Otls_FUNC_MAC_FREECTX, (void (*)(void))gmac_free },
    { Otls_FUNC_MAC_INIT, (void (*)(void))gmac_init },
    { Otls_FUNC_MAC_UPDATE, (void (*)(void))gmac_update },
    { Otls_FUNC_MAC_FINAL, (void (*)(void))gmac_final },
    { Otls_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))gmac_gettable_params },
    { Otls_FUNC_MAC_GET_PARAMS, (void (*)(void))gmac_get_params },
    { Otls_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))gmac_settable_ctx_params },
    { Otls_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))gmac_set_ctx_params },
    { 0, NULL }
};
