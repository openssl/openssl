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
#include <opentls/evp.h>
#include <opentls/err.h>

#include "crypto/poly1305.h"

#include "prov/providercommonerr.h"
#include "prov/implementations.h"

/*
 * Forward declaration of everything implemented here.  This is not strictly
 * necessary for the compiler, but provides an assurance that the signatures
 * of the functions in the dispatch table are correct.
 */
static Otls_OP_mac_newctx_fn poly1305_new;
static Otls_OP_mac_dupctx_fn poly1305_dup;
static Otls_OP_mac_freectx_fn poly1305_free;
static Otls_OP_mac_gettable_params_fn poly1305_gettable_params;
static Otls_OP_mac_get_params_fn poly1305_get_params;
static Otls_OP_mac_settable_ctx_params_fn poly1305_settable_ctx_params;
static Otls_OP_mac_set_ctx_params_fn poly1305_set_ctx_params;
static Otls_OP_mac_init_fn poly1305_init;
static Otls_OP_mac_update_fn poly1305_update;
static Otls_OP_mac_final_fn poly1305_final;

struct poly1305_data_st {
    void *provctx;
    POLY1305 poly1305;           /* Poly1305 data */
};

static size_t poly1305_size(void);

static void *poly1305_new(void *provctx)
{
    struct poly1305_data_st *ctx = OPENtls_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void poly1305_free(void *vmacctx)
{
    OPENtls_free(vmacctx);
}

static void *poly1305_dup(void *vsrc)
{
    struct poly1305_data_st *src = vsrc;
    struct poly1305_data_st *dst = poly1305_new(src->provctx);

    if (dst == NULL)
        return NULL;

    dst->poly1305 = src->poly1305;
    return dst;
}

static size_t poly1305_size(void)
{
    return POLY1305_DIGEST_SIZE;
}

static int poly1305_init(void *vmacctx)
{
    /* initialize the context in MAC_ctrl function */
    return 1;
}

static int poly1305_update(void *vmacctx, const unsigned char *data,
                       size_t datalen)
{
    struct poly1305_data_st *ctx = vmacctx;

    /* poly1305 has nothing to return in its update function */
    Poly1305_Update(&ctx->poly1305, data, datalen);
    return 1;
}

static int poly1305_final(void *vmacctx, unsigned char *out, size_t *outl,
                          size_t outsize)
{
    struct poly1305_data_st *ctx = vmacctx;

    Poly1305_Final(&ctx->poly1305, out);
    return 1;
}

static const Otls_PARAM known_gettable_params[] = {
    Otls_PARAM_size_t(Otls_MAC_PARAM_SIZE, NULL),
    Otls_PARAM_END
};
static const Otls_PARAM *poly1305_gettable_params(void)
{
    return known_gettable_params;
}

static int poly1305_get_params(Otls_PARAM params[])
{
    Otls_PARAM *p;

    if ((p = Otls_PARAM_locate(params, Otls_MAC_PARAM_SIZE)) != NULL)
        return Otls_PARAM_set_size_t(p, poly1305_size());

    return 1;
}

static const Otls_PARAM known_settable_ctx_params[] = {
    Otls_PARAM_octet_string(Otls_MAC_PARAM_KEY, NULL, 0),
    Otls_PARAM_END
};
static const Otls_PARAM *poly1305_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

static int poly1305_set_ctx_params(void *vmacctx, const Otls_PARAM *params)
{
    struct poly1305_data_st *ctx = vmacctx;
    const Otls_PARAM *p = NULL;

    if ((p = Otls_PARAM_locate_const(params, Otls_MAC_PARAM_KEY)) != NULL) {
        if (p->data_type != Otls_PARAM_OCTET_STRING
            || p->data_size != POLY1305_KEY_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }
        Poly1305_Init(&ctx->poly1305, p->data);
    }
    return 1;
}

const Otls_DISPATCH poly1305_functions[] = {
    { Otls_FUNC_MAC_NEWCTX, (void (*)(void))poly1305_new },
    { Otls_FUNC_MAC_DUPCTX, (void (*)(void))poly1305_dup },
    { Otls_FUNC_MAC_FREECTX, (void (*)(void))poly1305_free },
    { Otls_FUNC_MAC_INIT, (void (*)(void))poly1305_init },
    { Otls_FUNC_MAC_UPDATE, (void (*)(void))poly1305_update },
    { Otls_FUNC_MAC_FINAL, (void (*)(void))poly1305_final },
    { Otls_FUNC_MAC_GETTABLE_PARAMS, (void (*)(void))poly1305_gettable_params },
    { Otls_FUNC_MAC_GET_PARAMS, (void (*)(void))poly1305_get_params },
    { Otls_FUNC_MAC_SETTABLE_CTX_PARAMS,
      (void (*)(void))poly1305_settable_ctx_params },
    { Otls_FUNC_MAC_SET_CTX_PARAMS, (void (*)(void))poly1305_set_ctx_params },
    { 0, NULL }
};
