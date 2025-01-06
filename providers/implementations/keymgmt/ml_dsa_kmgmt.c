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
#include <openssl/proverr.h>
#include <openssl/self_test.h>
#include "crypto/ml_dsa.h"
#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_free_fn ml_dsa_free_key;
static OSSL_FUNC_keymgmt_has_fn ml_dsa_has;
static OSSL_FUNC_keymgmt_match_fn ml_dsa_match;
static OSSL_FUNC_keymgmt_import_fn ml_dsa_import;
static OSSL_FUNC_keymgmt_export_fn ml_dsa_export;
static OSSL_FUNC_keymgmt_import_types_fn ml_dsa_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn ml_dsa_imexport_types;
static OSSL_FUNC_keymgmt_load_fn ml_dsa_load;
static OSSL_FUNC_keymgmt_get_params_fn ml_dsa_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ml_dsa_gettable_params;
static OSSL_FUNC_keymgmt_validate_fn ml_dsa_validate;
static OSSL_FUNC_keymgmt_gen_init_fn ml_dsa_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ml_dsa_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn ml_dsa_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ml_dsa_gen_settable_params;

struct ml_dsa_gen_ctx {
    OSSL_LIB_CTX *libctx;
    char *propq;
    uint8_t entropy[32];
    size_t entropy_len;
};

static void *ml_dsa_new_key(void *provctx, const char *alg)
{
    if (!ossl_prov_is_running())
        return 0;

    return ossl_ml_dsa_key_new(PROV_LIBCTX_OF(provctx), NULL, alg);
}

static void ml_dsa_free_key(void *keydata)
{
    ossl_ml_dsa_key_free((ML_DSA_KEY *)keydata);
}

static int ml_dsa_has(const void *keydata, int selection)
{
    const ML_DSA_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */

    return ossl_ml_dsa_key_has(key, selection);
}

static int ml_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const ML_DSA_KEY *key1 = keydata1;
    const ML_DSA_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    return ossl_ml_dsa_key_equal(key1, key2, selection);
}

static int ml_dsa_validate(const void *key_data, int selection, int check_type)
{
    const ML_DSA_KEY *key = key_data;

    if (!ml_dsa_has(key, selection))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == OSSL_KEYMGMT_SELECT_KEYPAIR)
        return ossl_ml_dsa_key_pairwise_check(key);
    return 1;
}

static int ml_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    ML_DSA_KEY *key = keydata;
    int include_priv;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_priv = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    return ossl_ml_dsa_key_fromdata(key, params, include_priv);
}

#define ML_DSA_IMEXPORTABLE_PARAMETERS \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0), \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)

static const OSSL_PARAM ml_dsa_key_types[] = {
    ML_DSA_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM *ml_dsa_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;
    return ml_dsa_key_types;
}

static const OSSL_PARAM ml_dsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    ML_DSA_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM *ml_dsa_gettable_params(void *provctx)
{
    return ml_dsa_params;
}

static int key_to_params(ML_DSA_KEY *key, OSSL_PARAM_BLD *tmpl,
                         int include_private)
{
    /* Error if there is no key or public key */
    if (key == NULL || ossl_ml_dsa_key_get_pub(key) == NULL)
        return 0;
    /*
     * Note that the private key always contains the public key elements so we
     * just save the one blob and return.
     */
    if (include_private && ossl_ml_dsa_key_get_priv(key) != NULL)
        return ossl_param_build_set_octet_string(tmpl, NULL,
                                                 OSSL_PKEY_PARAM_PRIV_KEY,
                                                 ossl_ml_dsa_key_get_priv(key),
                                                 ossl_ml_dsa_key_get_priv_len(key));
    /* Otherwise write out the public key element */
    return ossl_param_build_set_octet_string(tmpl, NULL,
                                             OSSL_PKEY_PARAM_PUB_KEY,
                                             ossl_ml_dsa_key_get_pub(key),
                                             ossl_ml_dsa_key_get_pub_len(key));
}

static int ml_dsa_get_params(void *keydata, OSSL_PARAM params[])
{
    ML_DSA_KEY *key = keydata;
    OSSL_PARAM *p;
    const uint8_t *pub, *priv;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
            && !OSSL_PARAM_set_int(p, 8 * ossl_ml_dsa_key_get_pub_len(key)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
            && !OSSL_PARAM_set_int(p, 8 * ossl_ml_dsa_key_get_collision_strength_bits(key)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
            && !OSSL_PARAM_set_int(p, ossl_ml_dsa_key_get_sig_len(key)))
        return 0;

    pub = ossl_ml_dsa_key_get_pub(key);
    priv = ossl_ml_dsa_key_get_priv(key);

    /* This just gets the private elements */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL) {
        if (priv == NULL
                || !OSSL_PARAM_set_octet_string(p, priv,
                                                ossl_ml_dsa_key_get_priv_len(key)))
            return 0;
    }
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (p != NULL) {
        if (pub == NULL
                || !OSSL_PARAM_set_octet_string(p, pub,
                                                ossl_ml_dsa_key_get_pub_len(key)))
            return 0;
    }
    return 1;
}

static int ml_dsa_export(void *keydata, int selection,
                         OSSL_CALLBACK *param_cb, void *cbarg)
{
    ML_DSA_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0, include_private;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;
    /* The public key is required for private keys */
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    include_private = ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0);
    if (!key_to_params(key, tmpl, include_private))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

static void *ml_dsa_load(const void *reference, size_t reference_sz)
{
    ML_DSA_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(ML_DSA_KEY **)reference;
        /* We grabbed, so we detach it */
        *(ML_DSA_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *ml_dsa_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct ml_dsa_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->libctx = libctx;
        if (!ml_dsa_gen_set_params(gctx, params)) {
            OPENSSL_free(gctx);
            gctx = NULL;
        }
    }
    return gctx;
}

static void *ml_dsa_gen(void *genctx, const char *alg)
{
    struct ml_dsa_gen_ctx *gctx = genctx;
    ML_DSA_KEY *key = NULL;

    if (!ossl_prov_is_running())
        return NULL;
    key = ossl_ml_dsa_key_new(gctx->libctx, gctx->propq, alg);
    if (key == NULL)
        return NULL;
    if (!ossl_ml_dsa_generate_key(gctx->libctx, gctx->entropy, gctx->entropy_len,
                                  key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_FAILED_TO_GENERATE_KEY);
        goto err;
    }
    return key;
 err:
    ossl_ml_dsa_key_free(key);
    return NULL;
}

static int ml_dsa_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct ml_dsa_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_DSA_SEED);
    if (p != NULL) {
        void *vp = gctx->entropy;
        size_t len = sizeof(gctx->entropy);

        if (!OSSL_PARAM_get_octet_string(p, &vp, len, &(gctx->entropy_len))) {
            gctx->entropy_len = 0;
            return 0;
        }
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        OPENSSL_free(gctx->propq);
        gctx->propq = NULL;
        if (!OSSL_PARAM_get_utf8_string(p, &gctx->propq, 0))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *ml_dsa_gen_settable_params(ossl_unused void *genctx,
                                                    ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_DSA_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void ml_dsa_gen_cleanup(void *genctx)
{
    struct ml_dsa_gen_ctx *gctx = genctx;

    OPENSSL_cleanse(gctx->entropy, gctx->entropy_len);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

#define MAKE_KEYMGMT_FUNCTIONS(alg, fn)                                        \
    static OSSL_FUNC_keymgmt_new_fn ml_dsa_##fn##_new_key;                     \
    static OSSL_FUNC_keymgmt_gen_fn ml_dsa_##fn##_gen;                         \
    static void *ml_dsa_##fn##_new_key(void *provctx)                          \
    {                                                                          \
        return ml_dsa_new_key(provctx, alg);                                   \
    }                                                                          \
    static void *ml_dsa_##fn##_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)\
    {                                                                          \
        return ml_dsa_gen(genctx, alg);                                        \
    }                                                                          \
    const OSSL_DISPATCH ossl_ml_dsa_##fn##_keymgmt_functions[] = {             \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ml_dsa_##fn##_new_key },      \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ml_dsa_free_key },           \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ml_dsa_has },                 \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ml_dsa_match },             \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ml_dsa_import },           \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ml_dsa_imexport_types },\
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ml_dsa_export },           \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ml_dsa_imexport_types },\
        { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))ml_dsa_load },               \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ml_dsa_get_params },  \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ml_dsa_gettable_params },\
        { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))ml_dsa_validate },       \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))ml_dsa_gen_init },       \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ml_dsa_##fn##_gen },          \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))ml_dsa_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS,                                    \
          (void (*)(void))ml_dsa_gen_set_params },                             \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,                               \
          (void (*)(void))ml_dsa_gen_settable_params },                        \
        OSSL_DISPATCH_END                                                      \
    }

MAKE_KEYMGMT_FUNCTIONS("ML-DSA-44", 44);
MAKE_KEYMGMT_FUNCTIONS("ML-DSA-65", 65);
MAKE_KEYMGMT_FUNCTIONS("ML-DSA-87", 87);
