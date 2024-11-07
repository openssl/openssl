/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "crypto/slh_dsa.h"
#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_free_fn slh_dsa_free_key;
static OSSL_FUNC_keymgmt_has_fn slh_dsa_has;
static OSSL_FUNC_keymgmt_match_fn slh_dsa_match;
static OSSL_FUNC_keymgmt_import_fn slh_dsa_import;
static OSSL_FUNC_keymgmt_import_types_fn slh_dsa_imexport_types;
static OSSL_FUNC_keymgmt_get_params_fn slh_dsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn slh_dsa_gettable_params;
static OSSL_FUNC_keymgmt_gen_init_fn slh_dsa_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn slh_dsa_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn slh_dsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn slh_dsa_gen_settable_params;

#define SLH_DSA_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

struct slh_dsa_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    SLH_DSA_CTX *ctx;
};

static void *slh_dsa_new_key(void *provctx, const char *alg)
{
    if (!ossl_prov_is_running())
        return 0;

    return ossl_slh_dsa_key_new(PROV_LIBCTX_OF(provctx), alg);
}

static void slh_dsa_free_key(void *keydata)
{
    ossl_slh_dsa_key_free((SLH_DSA_KEY *)keydata);
}

static int slh_dsa_has(const void *keydata, int selection)
{
    const SLH_DSA_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    return ossl_slh_dsa_key_has(key, selection);
}

static int slh_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const SLH_DSA_KEY *key1 = keydata1;
    const SLH_DSA_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    return ossl_slh_dsa_key_equal(key1, key2, selection);
}

static int slh_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    SLH_DSA_KEY *key = keydata;
    int include_priv;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    include_priv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    return ossl_slh_dsa_key_fromdata(key, params, include_priv);
}

static const OSSL_PARAM slh_dsa_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *slh_dsa_imexport_types(int selection)
{
    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return NULL;
    return slh_dsa_key_types;
}

static const OSSL_PARAM *slh_dsa_gettable_params(void *provctx)
{
    return slh_dsa_key_types;
}

static int key_to_params(SLH_DSA_KEY *key, OSSL_PARAM_BLD *tmpl,
                         OSSL_PARAM params[], int include_private)
{
    if (key == NULL)
        return 0;

    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
                                           ossl_slh_dsa_key_get_pub(key),
                                           ossl_slh_dsa_key_get_len(key)))
        return 0;

    if (include_private
        && ossl_slh_dsa_key_is_private(key)
        && !ossl_param_build_set_octet_string(tmpl, params,
                                              OSSL_PKEY_PARAM_PRIV_KEY,
                                              ossl_slh_dsa_key_get_priv(key),
                                              ossl_slh_dsa_key_get_len(key)))
        return 0;

    return 1;
}

static int slh_dsa_get_params(void *keydata, OSSL_PARAM params[])
{
    SLH_DSA_KEY *key = keydata;

    return key_to_params(key, NULL, params, 1);
}

static void *slh_dsa_gen_init(void *provctx, int selection,
                              const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct slh_dsa_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        if (!slh_dsa_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *slh_dsa_gen(void *genctx, const char *alg)
{
    struct slh_dsa_gen_ctx *gctx = genctx;
    SLH_DSA_KEY *key = NULL;
    SLH_DSA_CTX *ctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;
    ctx = ossl_slh_dsa_ctx_new(alg, gctx->libctx, gctx->propq);
    if (ctx == NULL)
        return NULL;
    key = ossl_slh_dsa_key_new(gctx->libctx, alg);
    if (key == NULL)
        return NULL;
    if (!ossl_slh_dsa_generate_key(ctx, gctx->libctx, key))
        goto err;
    ossl_slh_dsa_ctx_free(ctx);
    return key;
 err:
    ossl_slh_dsa_ctx_free(ctx);
    ossl_slh_dsa_key_free(key);
    return NULL;
}

static int slh_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct slh_dsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *slh_dsa_gen_settable_params(ossl_unused void *genctx,
                                                     ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_KDF_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void slh_dsa_gen_cleanup(void *genctx)
{
    struct slh_dsa_gen_ctx *gctx = genctx;

    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

#define MAKE_KEYMGMT_FUNCTIONS(alg, fn)                                        \
static OSSL_FUNC_keymgmt_new_fn slh_dsa_##fn##_new_key;                        \
static OSSL_FUNC_keymgmt_gen_fn slh_dsa_##fn##_gen;                            \
static void *slh_dsa_##fn##_new_key(void *provctx)                             \
{                                                                              \
    return slh_dsa_new_key(provctx, alg);                                      \
}                                                                              \
static void *slh_dsa_##fn##_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)\
{                                                                              \
    return slh_dsa_gen(genctx, alg);                                           \
}                                                                              \
const OSSL_DISPATCH ossl_slh_dsa_##fn##_keymgmt_functions[] = {                \
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))slh_dsa_##fn##_new_key },         \
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))slh_dsa_free_key },              \
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))slh_dsa_has },                    \
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))slh_dsa_match },                \
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))slh_dsa_import },              \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))slh_dsa_imexport_types },\
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))slh_dsa_get_params },     \
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))slh_dsa_gettable_params }, \
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))slh_dsa_gen_init },          \
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))slh_dsa_##fn##_gen },             \
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))slh_dsa_gen_cleanup },    \
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                        \
      (void (*)(void))slh_dsa_gen_set_params },                                \
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                                   \
      (void (*)(void))slh_dsa_gen_settable_params },                           \
    OSSL_DISPATCH_END                                                          \
}

MAKE_KEYMGMT_FUNCTIONS("SLH-DSA-SHA2-128s", sha2_128s);
