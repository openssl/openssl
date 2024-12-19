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
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/self_test.h>
#include "crypto/ml_kem.h"
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"

static OSSL_FUNC_keymgmt_new_fn ml_kem_512_new;
static OSSL_FUNC_keymgmt_new_fn ml_kem_768_new;
static OSSL_FUNC_keymgmt_new_fn ml_kem_1024_new;
static OSSL_FUNC_keymgmt_gen_fn ml_kem_gen;
static OSSL_FUNC_keymgmt_gen_init_fn ml_kem_512_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ml_kem_768_gen_init;
static OSSL_FUNC_keymgmt_gen_init_fn ml_kem_1024_gen_init;
static OSSL_FUNC_keymgmt_gen_cleanup_fn ml_kem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn ml_kem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn ml_kem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn ml_kem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn ml_kem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn ml_kem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn ml_kem_settable_params;
static OSSL_FUNC_keymgmt_has_fn ml_kem_has;
static OSSL_FUNC_keymgmt_match_fn ml_kem_match;
static OSSL_FUNC_keymgmt_import_fn ml_kem_import;
static OSSL_FUNC_keymgmt_export_fn ml_kem_export;
static OSSL_FUNC_keymgmt_import_types_fn ml_kem_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn ml_kem_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn ml_kem_dup;

typedef struct ml_kem_gen_ctx_st {
    OSSL_LIB_CTX *libctx;
    char *propq;
    int selection;
    int variant;
    uint8_t seedbuf[ML_KEM_SEED_BYTES];
    uint8_t *seed;
} PROV_ML_KEM_GEN_CTX;

static void *ml_kem_new(OSSL_LIB_CTX *libctx, char *propq, int variant)
{
    if (!ossl_prov_is_running())
        return NULL;
    return ossl_ml_kem_key_new(libctx, propq, variant);
}

static int ml_kem_has(const void *vkey, int selection)
{
    const ML_KEM_KEY *key = vkey;

    /* A NULL key MUST fail to have anything */
    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    switch (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) {
    case 0:
        return 1;
    case OSSL_KEYMGMT_SELECT_PUBLIC_KEY:
        return ossl_ml_kem_have_pubkey(key);
    default:
        return ossl_ml_kem_have_prvkey(key);
    }
}

static int ml_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    const ML_KEM_KEY *key1 = vkey1;
    const ML_KEM_KEY *key2 = vkey2;

    if (!ossl_prov_is_running())
        return 0;

    /* All we have that can be compared is key material */
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;

    return ossl_ml_kem_pubkey_cmp(key1, key2);
}

static int ml_kem_export(void *vkey, int selection, OSSL_CALLBACK *param_cb,
                         void *cbarg)
{
    ML_KEM_KEY *key = vkey;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    uint8_t *pubenc = NULL;
    uint8_t *prvenc = NULL;
    const ML_KEM_VINFO *v;
    int ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    /* Fail when no key material has yet been provided */
    if (!ossl_ml_kem_have_pubkey(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    v = ossl_ml_kem_key_vinfo(key);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pubenc = OPENSSL_malloc(v->pubkey_bytes);
        if (pubenc == NULL)
            goto err;
    }

    if (ossl_ml_kem_have_prvkey(key)
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        /*
         * Allocated on the secure heap if configured, this is detected in
         * ossl_param_build_set_octet_string(), which will then also use the
         * secure heap.
         */
        prvenc = OPENSSL_secure_zalloc(v->prvkey_bytes);
        if (prvenc == NULL)
            goto err;
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        goto err;

    /* The public key on request; it is always available when either is */
    if (pubenc != NULL)
        if (!ossl_ml_kem_encode_public_key(pubenc, v->pubkey_bytes, key)
            || !ossl_param_build_set_octet_string(
                   tmpl, params, OSSL_PKEY_PARAM_PUB_KEY,
                   pubenc, v->pubkey_bytes))
            goto err;

    /* The private key on request */
    if (prvenc != NULL && ossl_ml_kem_have_prvkey(key))
        if (!ossl_ml_kem_encode_private_key(prvenc, v->prvkey_bytes, key)
            || !ossl_param_build_set_octet_string(
                    tmpl, params, OSSL_PKEY_PARAM_PRIV_KEY,
                    prvenc, v->prvkey_bytes))
            goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);

err:
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_secure_clear_free(prvenc, v->prvkey_bytes);
    OPENSSL_free(pubenc);
    return ret;
}

static const OSSL_PARAM *ml_kem_imexport_types(int selection)
{
    static const OSSL_PARAM key_types[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        return key_types;
    return NULL;
}

static int ml_kem_key_fromdata(ML_KEM_KEY *key,
                               const OSSL_PARAM params[],
                               int include_private)
{
    const OSSL_PARAM *param_prv_key = NULL, *param_pub_key;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    const ML_KEM_VINFO *v;

    /* Invalid attempt to mutate a key, what is the right error to report? */
    if (key == NULL || ossl_ml_kem_have_pubkey(key))
        return 0;
    v = ossl_ml_kem_key_vinfo(key);

    /* What does the caller want to set? */
    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param_pub_key != NULL &&
        OSSL_PARAM_get_octet_string_ptr(param_pub_key, &pubenc, &publen) != 1)
        return 0;
    if (include_private)
        param_prv_key = OSSL_PARAM_locate_const(params,
                                                OSSL_PKEY_PARAM_PRIV_KEY);
    if (param_prv_key != NULL &&
        OSSL_PARAM_get_octet_string_ptr(param_prv_key, &prvenc, &prvlen) != 1)
        return 0;

    /* The caller MUST specify at least one of the public or private keys. */
    if (publen == 0 && prvlen == 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }

    /*
     * When a pubkey is provided, its length MUST be correct, if a private key
     * is also provided, the public key will be otherwise ignored.  We could
     * look for a matching encoded block, but unclear this is useful.
     */
    if (publen != 0 && publen != v->pubkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    if (prvlen != 0 && prvlen != v->prvkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    /*
     * If the private key is given, we'll ignore the public key data, taking
     * the embedded public key as authoritative.
     */
    if (prvlen != 0)
        return ossl_ml_kem_parse_private_key(prvenc, prvlen, key);
    return ossl_ml_kem_parse_public_key(pubenc, publen, key);
}

static int ml_kem_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    ML_KEM_KEY *key = vkey;
    int include_private;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    return ml_kem_key_fromdata(key, params, include_private);
}

static const OSSL_PARAM *ml_kem_gettable_params(void *provctx)
{
    static const OSSL_PARAM arr[] = {
        OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
        OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return arr;
}

/*
 * It is assumed the key is guaranteed non-NULL here, and is from this provider
 */
static int ml_kem_get_params(void *vkey, OSSL_PARAM params[])
{
    ML_KEM_KEY *key = vkey;
    const ML_KEM_VINFO *v = ossl_ml_kem_key_vinfo(key);
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
    if (p != NULL)
        if (!OSSL_PARAM_set_int(p, v->bits))
            return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
    if (p != NULL)
        if (!OSSL_PARAM_set_int(p, v->secbits))
            return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
    if (p != NULL)
        if (!OSSL_PARAM_set_int(p, v->ctext_bytes))
            return 0;

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL && ossl_ml_kem_have_pubkey(key)) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = v->pubkey_bytes;
        if (p->data != NULL) {
            if (p->data_size < p->return_size)
                return 0;
            if (!ossl_ml_kem_encode_public_key(p->data, p->return_size, key))
                return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL && ossl_ml_kem_have_prvkey(key)) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = v->prvkey_bytes;
        if (p->data != NULL) {
            if (p->data_size < p->return_size)
                return 0;
            if (!ossl_ml_kem_encode_private_key(p->data, p->return_size, key))
                return 0;
        }
    }
    return 1;
}

static const OSSL_PARAM *ml_kem_settable_params(void *provctx)
{
    static const OSSL_PARAM arr[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
        OSSL_PARAM_END
    };

    return arr;
}

static int ml_kem_set_params(void *vkey, const OSSL_PARAM params[])
{
    ML_KEM_KEY *key = vkey;
    const ML_KEM_VINFO *v = ossl_ml_kem_key_vinfo(key);
    const OSSL_PARAM *p;
    const void *pubenc = NULL;
    size_t publen = 0;

    if (ossl_param_is_empty(params))
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p == NULL)
        return 1;

    /* Key mutation is reportedly generally not allowed */
    if (ossl_ml_kem_have_pubkey(key)) {
        ERR_raise_data(ERR_LIB_PROV,
                       PROV_R_OPERATION_NOT_SUPPORTED_FOR_THIS_KEYTYPE,
                       "ML-KEM keys cannot be mutated");
        return 0;
    }
    /* An unlikely failure mode is the parameter having some unexpected type */
    if (!OSSL_PARAM_get_octet_string_ptr(p, &pubenc, &publen))
        return 0;

    if (publen != v->pubkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    return ossl_ml_kem_parse_public_key(pubenc, publen, key);
}

static int ml_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    PROV_ML_KEM_GEN_CTX *gctx = vgctx;
    const OSSL_PARAM *p;

    if (gctx == NULL)
        return 0;
    if (ossl_param_is_empty(params))
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        OPENSSL_free(gctx->propq);
        if ((gctx->propq = OPENSSL_strdup(p->data)) == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
    if (p != NULL) {
        size_t len = ML_KEM_SEED_BYTES;

        gctx->seed = gctx->seedbuf;
        if (OSSL_PARAM_get_octet_string(p, (void **)&gctx->seed, len, &len)
            && len == ML_KEM_SEED_BYTES)
            return 1;

        /* Possibly, but less likely wrong data type */
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        gctx->seed = NULL;
        return 0;
    }
    return 1;
}

static void *ml_kem_gen_init(void *provctx, int selection,
                             const OSSL_PARAM params[], int variant)
{
    static const int minimal =
        OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS
        | OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    PROV_ML_KEM_GEN_CTX *gctx = NULL;

    /*
     * We can only generate private keys, check that the selection is
     * appropriate.
     */
    if (!ossl_prov_is_running()
        || (selection & minimal) == 0
        || (gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL)
        return NULL;

    gctx->selection = selection;
    gctx->variant = variant;
    if (provctx != NULL)
        gctx->libctx = PROV_LIBCTX_OF(provctx);
    if (ml_kem_gen_set_params(gctx, params))
        return gctx;

    ml_kem_gen_cleanup(gctx);
    return NULL;
}

static const OSSL_PARAM *ml_kem_gen_settable_params(ossl_unused void *vgctx,
                                                    ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, NULL, 0),
        OSSL_PARAM_END
    };
    return settable;
}

static void *ml_kem_gen(void *vgctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    PROV_ML_KEM_GEN_CTX *gctx = vgctx;
    ML_KEM_KEY *key;
    uint8_t *nopub = NULL;
    uint8_t *seed = gctx->seed;
    size_t slen = seed == NULL ? 0 : ML_KEM_SEED_BYTES;
    int genok = 0;

    if (gctx == NULL
        || (gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) ==
            OSSL_KEYMGMT_SELECT_PUBLIC_KEY
        || (key = ml_kem_new(gctx->libctx, gctx->propq, gctx->variant)) == NULL)
        return NULL;

    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    genok = seed != NULL
        ? ossl_ml_kem_genkey_seed(seed, slen, nopub, 0, key)
        : ossl_ml_kem_genkey_rand(NULL, slen, nopub, 0, key);

    /* Erase the single-use seed */
    if (seed != NULL)
        OPENSSL_cleanse(seed, ML_KEM_SEED_BYTES);
    gctx->seed = NULL;

    if (genok)
        return key;

    ossl_ml_kem_key_free(key);
    return NULL;
}

static void ml_kem_gen_cleanup(void *vgctx)
{
    PROV_ML_KEM_GEN_CTX *gctx = vgctx;

    if (gctx->seed != NULL)
        OPENSSL_cleanse(gctx->seed, ML_KEM_RANDOM_BYTES);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(gctx);
}

static void *ml_kem_dup(const void *vkey, int selection)
{
    const ML_KEM_KEY *key = vkey;

    if (!ossl_prov_is_running())
        return NULL;

    return ossl_ml_kem_key_dup(key, selection);
}

typedef void (*func_ptr_t)(void);

#define DECLARE_VARIANT(bits) \
    static void *ml_kem_##bits##_new(void *provctx) \
    { \
        return ml_kem_new(provctx == NULL ? NULL : PROV_LIBCTX_OF(provctx), \
                          NULL, ML_KEM_##bits); \
    } \
    static void *ml_kem_##bits##_gen_init(void *provctx, int selection, \
                                          const OSSL_PARAM params[]) \
    { \
        return ml_kem_gen_init(provctx, selection, params, ML_KEM_##bits); \
    } \
    const OSSL_DISPATCH ossl_ml_kem_##bits##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (func_ptr_t) ml_kem_##bits##_new }, \
        { OSSL_FUNC_KEYMGMT_FREE, (func_ptr_t) ossl_ml_kem_key_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (func_ptr_t) ml_kem_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (func_ptr_t) ml_kem_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (func_ptr_t) ml_kem_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (func_ptr_t) ml_kem_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (func_ptr_t) ml_kem_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (func_ptr_t) ml_kem_match }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, (func_ptr_t) ml_kem_##bits##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (func_ptr_t) ml_kem_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, (func_ptr_t) ml_kem_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (func_ptr_t) ml_kem_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (func_ptr_t) ml_kem_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_DUP, (func_ptr_t) ml_kem_dup }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (func_ptr_t) ml_kem_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (func_ptr_t) ml_kem_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (func_ptr_t) ml_kem_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (func_ptr_t) ml_kem_imexport_types }, \
        OSSL_DISPATCH_END \
    }
DECLARE_VARIANT(512);
DECLARE_VARIANT(768);
DECLARE_VARIANT(1024);
