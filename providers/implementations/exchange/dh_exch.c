/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/dh.h>
#include <opentls/params.h>
#include "prov/implementations.h"

static Otls_OP_keyexch_newctx_fn dh_newctx;
static Otls_OP_keyexch_init_fn dh_init;
static Otls_OP_keyexch_set_peer_fn dh_set_peer;
static Otls_OP_keyexch_derive_fn dh_derive;
static Otls_OP_keyexch_freectx_fn dh_freectx;
static Otls_OP_keyexch_dupctx_fn dh_dupctx;
static Otls_OP_keyexch_set_ctx_params_fn dh_set_ctx_params;
static Otls_OP_keyexch_settable_ctx_params_fn dh_settable_ctx_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DH structures, so
 * we use that here too.
 */

typedef struct {
    DH *dh;
    DH *dhpeer;
    unsigned int pad : 1;
} PROV_DH_CTX;

static void *dh_newctx(void *provctx)
{
    return OPENtls_zalloc(sizeof(PROV_DH_CTX));
}

static int dh_init(void *vpdhctx, void *vdh)
{
    PROV_DH_CTX *pdhctx = (PROV_DH_CTX *)vpdhctx;

    if (pdhctx == NULL || vdh == NULL || !DH_up_ref(vdh))
        return 0;
    DH_free(pdhctx->dh);
    pdhctx->dh = vdh;
    return 1;
}

static int dh_set_peer(void *vpdhctx, void *vdh)
{
    PROV_DH_CTX *pdhctx = (PROV_DH_CTX *)vpdhctx;

    if (pdhctx == NULL || vdh == NULL || !DH_up_ref(vdh))
        return 0;
    DH_free(pdhctx->dhpeer);
    pdhctx->dhpeer = vdh;
    return 1;
}

static int dh_derive(void *vpdhctx, unsigned char *secret, size_t *secretlen,
                     size_t outlen)
{
    PROV_DH_CTX *pdhctx = (PROV_DH_CTX *)vpdhctx;
    int ret;
    size_t dhsize;
    const BIGNUM *pub_key = NULL;

    /* TODO(3.0): Add errors to stack */
    if (pdhctx->dh == NULL || pdhctx->dhpeer == NULL)
        return 0;

    dhsize = (size_t)DH_size(pdhctx->dh);
    if (secret == NULL) {
        *secretlen = dhsize;
        return 1;
    }
    if (outlen < dhsize)
        return 0;

    DH_get0_key(pdhctx->dhpeer, &pub_key, NULL);
    ret = (pdhctx->pad) ? DH_compute_key_padded(secret, pub_key, pdhctx->dh)
                        : DH_compute_key(secret, pub_key, pdhctx->dh);
    if (ret <= 0)
        return 0;

    *secretlen = ret;
    return 1;
}

static void dh_freectx(void *vpdhctx)
{
    PROV_DH_CTX *pdhctx = (PROV_DH_CTX *)vpdhctx;

    DH_free(pdhctx->dh);
    DH_free(pdhctx->dhpeer);

    OPENtls_free(pdhctx);
}

static void *dh_dupctx(void *vpdhctx)
{
    PROV_DH_CTX *srcctx = (PROV_DH_CTX *)vpdhctx;
    PROV_DH_CTX *dstctx;

    dstctx = OPENtls_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->dh != NULL && !DH_up_ref(dstctx->dh)) {
        OPENtls_free(dstctx);
        return NULL;
    }

    if (dstctx->dhpeer != NULL && !DH_up_ref(dstctx->dhpeer)) {
        DH_free(dstctx->dh);
        OPENtls_free(dstctx);
        return NULL;
    }

    return dstctx;
}

static int dh_set_ctx_params(void *vpdhctx, const Otls_PARAM params[])
{
    PROV_DH_CTX *pdhctx = (PROV_DH_CTX *)vpdhctx;
    const Otls_PARAM *p;
    unsigned int pad;

    if (pdhctx == NULL || params == NULL)
        return 0;

    p = Otls_PARAM_locate_const(params, Otls_EXCHANGE_PARAM_PAD);
    if (p == NULL || !Otls_PARAM_get_uint(p, &pad))
        return 0;
    pdhctx->pad = pad ? 1 : 0;
    return 1;
}

static const Otls_PARAM known_settable_ctx_params[] = {
    Otls_PARAM_int(Otls_EXCHANGE_PARAM_PAD, NULL),
    Otls_PARAM_END
};

static const Otls_PARAM *dh_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

const Otls_DISPATCH dh_keyexch_functions[] = {
    { Otls_FUNC_KEYEXCH_NEWCTX, (void (*)(void))dh_newctx },
    { Otls_FUNC_KEYEXCH_INIT, (void (*)(void))dh_init },
    { Otls_FUNC_KEYEXCH_DERIVE, (void (*)(void))dh_derive },
    { Otls_FUNC_KEYEXCH_SET_PEER, (void (*)(void))dh_set_peer },
    { Otls_FUNC_KEYEXCH_FREECTX, (void (*)(void))dh_freectx },
    { Otls_FUNC_KEYEXCH_DUPCTX, (void (*)(void))dh_dupctx },
    { Otls_FUNC_KEYEXCH_SET_CTX_PARAMS, (void (*)(void))dh_set_ctx_params },
    { Otls_FUNC_KEYEXCH_SETTABLE_CTX_PARAMS,
      (void (*)(void))dh_settable_ctx_params },
    { 0, NULL }
};
