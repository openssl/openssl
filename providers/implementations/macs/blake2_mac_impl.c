/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/params.h>

#include "prov/blake2.h"
#include "internal/cryptlib.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static Otls_OP_mac_newctx_fn blake2_mac_new;
static Otls_OP_mac_dupctx_fn blake2_mac_dup;
static Otls_OP_mac_freectx_fn blake2_mac_free;
static Otls_OP_mac_gettable_ctx_params_fn blake2_gettable_ctx_params;
static Otls_OP_mac_get_ctx_params_fn blake2_get_ctx_params;
static Otls_OP_mac_settable_ctx_params_fn blake2_mac_settable_ctx_params;
static Otls_OP_mac_set_ctx_params_fn blake2_mac_set_ctx_params;
static Otls_OP_mac_init_fn blake2_mac_init;
static Otls_OP_mac_update_fn blake2_mac_update;
static Otls_OP_mac_final_fn blake2_mac_final;

struct blake2_mac_data_st {
    BLAKE2_CTX ctx;
    BLAKE2_PARAM params;
    unsigned char key[BLAKE2_KEYBYTES];
};

static size_t blake2_mac_size(void *vmacctx);

static void *blake2_mac_new(void *unused_provctx)
{
    struct blake2_mac_data_st *macctx = OPENtls_zalloc(sizeof(*macctx));

    if (macctx != NULL) {
        BLAKE2_PARAM_INIT(&macctx->params);
        /* ctx initialization is deferred to BLAKE2b_Init() */
    }
    return macctx;
}

static void *blake2_mac_dup(void *vsrc)
{
    struct blake2_mac_data_st *dst;
    struct blake2_mac_data_st *src = vsrc;

    dst = OPENtls_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    *dst = *src;
    return dst;
}

static void blake2_mac_free(void *vmacctx)
{
    struct blake2_mac_data_st *macctx = vmacctx;

    if (macctx != NULL) {
        OPENtls_cleanse(macctx->key, sizeof(macctx->key));
        OPENtls_free(macctx);
    }
}

static int blake2_mac_init(void *vmacctx)
{
    struct blake2_mac_data_st *macctx = vmacctx;

    /* Check key has been set */
    if (macctx->params.key_length == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    return BLAKE2_INIT_KEY(&macctx->ctx, &macctx->params, macctx->key);
}

static int blake2_mac_update(void *vmacctx,
                             const unsigned char *data, size_t datalen)
{
    struct blake2_mac_data_st *macctx = vmacctx;

    return BLAKE2_UPDATE(&macctx->ctx, data, datalen);
}

static int blake2_mac_final(void *vmacctx,
                            unsigned char *out, size_t *outl,
                            size_t outsize)
{
    struct blake2_mac_data_st *macctx = vmacctx;

    return BLAKE2_FINAL(out, &macctx->ctx);
}

static const Otls_PARAM known_gettable_ctx_params[] = {
    Otls_PARAM_size_t(Otls_MAC_PARAM_SIZE, NULL),
    Otls_PARAM_END
};
static const Otls_PARAM *blake2_gettable_ctx_params(void)
{
    return known_gettable_ctx_params;
}

static int blake2_get_ctx_params(void *vmacctx, Otls_PARAM params[])
{
    Otls_PARAM *p;

    if ((p = Otls_PARAM_locate(params, Otls_MAC_PARAM_SIZE)) != NULL)
        return Otls_PARAM_set_size_t(p, blake2_mac_size(vmacctx));

    return 1;
}

static const Otls_PARAM known_settable_ctx_params[] = {
    Otls_PARAM_size_t(Otls_MAC_PARAM_SIZE, NULL),
    Otls_PARAM_octet_string(Otls_MAC_PARAM_KEY, NULL, 0),
    Otls_PARAM_octet_string(Otls_MAC_PARAM_CUSTOM, NULL, 0),
    Otls_PARAM_octet_string(Otls_MAC_PARAM_SALT, NULL, 0),
    Otls_PARAM_END
};
static const Otls_PARAM *blake2_mac_settable_ctx_params()
{
    return known_settable_ctx_params;
}

/*
 * ALL parameters should be set before init().
 */
static int blake2_mac_set_ctx_params(void *vmacctx, const Otls_PARAM params[])
{
    struct blake2_mac_data_st *macctx = vmacctx;
    const Otls_PARAM *p;

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_SIZE)) != NULL) {
        size_t size;

        if (!Otls_PARAM_get_size_t(p, &size)
            || size < 1
            || size > BLAKE2_OUTBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_NOT_XOF_OR_INVALID_LENGTH);
            return 0;
        }
        BLAKE2_PARAM_SET_DIGEST_LENGTH(&macctx->params, (uint8_t)size);
    }

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_KEY)) != NULL) {
        size_t len;
        void *key_p = macctx->key;

        if (!Otls_PARAM_get_octet_string(p, &key_p, BLAKE2_KEYBYTES, &len)) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        /* Pad with zeroes at the end */
        memset(macctx->key + len, 0, BLAKE2_KEYBYTES - len);

        BLAKE2_PARAM_SET_KEY_LENGTH(&macctx->params, (uint8_t)len);
    }

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_CUSTOM))
        != NULL) {
        /*
         * The Otls_PARAM API doesn't provide direct pointer use, so we
         * must handle the Otls_PARAM structure ourselves here
         */
        if (p->data_size > BLAKE2_PERSONALBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_CUSTOM_LENGTH);
            return 0;
        }
        BLAKE2_PARAM_SET_PERSONAL(&macctx->params, p->data, p->data_size);
    }

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_SALT)) != NULL) {
        /*
         * The Otls_PARAM API doesn't provide direct pointer use, so we
         * must handle the Otls_PARAM structure ourselves here as well
         */
        if (p->data_size > BLAKE2_SALTBYTES) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SALT_LENGTH);
            return 0;
        }
        BLAKE2_PARAM_SET_SALT(&macctx->params, p->data, p->data_size);
    }
    return 1;
}

static size_t blake2_mac_size(void *vmacctx)
{
    struct blake2_mac_data_st *macctx = vmacctx;

    return macctx->params.digest_length;
}

const Otls_DISPATCH BLAKE2_FUNCTIONS[] = {
    { Otls_FUNC_MAC_NEWCTX, (void (*)(void))blake2_mac_new },
    { Otls_FUNC_MAC_DUPCTX, (void (*)(void))blake2_mac_dup },
    { Otls_FUNC_MAC_FREECTX, (void (*)(void))blake2_mac_free },
    { Otls_FUNC_MAC_INIT, (void (*)(void))blake2_mac_init },
    { Otls_FUNC_MAC_UPDATE, (void (*)(void))blake2_mac_update },
    { Otls_FUNC_MAC_FINAL, (void (*)(void))blake2_mac_final },
    { Otls_FUNC_MAC_GETTABLE_CTX_PARAMS,
      (void (*)(void))blake2_gettable_ctx_params },
    { Otls_FUNC_MAC_GET_CTX_PARAMS, (void (*)(void))blake2_get_ctx_params },
    { Otls_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))blake2_mac_settable_ctx_params },
    { Otls_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))blake2_mac_set_ctx_params },
    { 0, NULL }
};
