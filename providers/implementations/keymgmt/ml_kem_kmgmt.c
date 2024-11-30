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
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include "prov/ml_kem.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include <assert.h>

static OSSL_FUNC_keymgmt_free_fn ml_kem_free;
static OSSL_FUNC_keymgmt_gen_fn ml_kem_gen;
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

typedef const ossl_ml_kem_vinfo *vinfo_t;

struct ml_kem_gen_ctx {
    void *provctx;
    char *propq;
    vinfo_t vinfo;
    uint8_t seedbuf[ML_KEM_SEED_BYTES];
    uint8_t *seed;
    int selection;
};

static void *ml_kem_new(void *provctx, vinfo_t v, char *propq)
{
    OSSL_LIB_CTX *libctx = NULL;
    ML_KEM_PROVIDER_KEYPAIR *key;

    if (!ossl_prov_is_running() || v == NULL)
        return 0;
    if (provctx != NULL)
        libctx = PROV_LIBCTX_OF(provctx);

    key = OPENSSL_zalloc(sizeof(ML_KEM_PROVIDER_KEYPAIR));
    if (key != NULL) {
        key->provctx = provctx;
        key->vinfo = v;
        key->ctx = ossl_ml_kem_newctx(libctx, propq);
        if (key->ctx == NULL) {
            OPENSSL_free(key);
            return NULL;
        }
    }
    return key;
}

static void ml_kem_free(void *vkey)
{
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;

    if (key == NULL)
        return;

    /* Free all key material, zeroing any private parts. */
    OPENSSL_free(key->pubkey);
    ossl_ml_kem_vcleanse_prvkey(key->vinfo, &key->prvkey);
    ossl_ml_kem_ctx_free(key->ctx);
    OPENSSL_free(key);
}

static int ml_kem_has(const void *vkey, int selection)
{
    static int selectable =
        OSSL_KEYMGMT_SELECT_PUBLIC_KEY |
        OSSL_KEYMGMT_SELECT_PRIVATE_KEY;
    const ML_KEM_PROVIDER_KEYPAIR *key = vkey;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & selectable) == 0)
        return 1;

    /*
     * Fail if the public key (or if requested the private key) is unavailable.
     * The public key is available when either was provided.
     */
    if (!have_keys(key)
        || ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && key->prvkey == NULL))
        return 0;

    return 1;
}

static int ml_kem_match(const void *vkey1, const void *vkey2, int selection)
{
    const ML_KEM_PROVIDER_KEYPAIR *k1 = vkey1;
    const ML_KEM_PROVIDER_KEYPAIR *k2 = vkey2;

    if (!ossl_prov_is_running())
        return 0;

    /* All we have that can be compared is key material */
    if (!(selection & OSSL_KEYMGMT_SELECT_KEYPAIR))
        return 1;

    return ossl_ml_kem_vcompare_pubkeys(k1->vinfo, k1->pubkey, k1->prvkey,
                                        k2->vinfo, k2->pubkey, k2->prvkey);
}

static int ml_kem_export(void *vkey, int selection, OSSL_CALLBACK *param_cb,
                         void *cbarg)
{
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;
    vinfo_t v;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    uint8_t *pubenc = NULL;
    uint8_t *prvenc = NULL;
    int ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    /* Fail when no key material has yet been provided */
    if (key == NULL || !have_keys(key)) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_KEY);
        return 0;
    }
    v = key->vinfo;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        pubenc = OPENSSL_malloc(v->pubkey_bytes);
        if (pubenc == NULL)
            goto err;
    }

    if (key->prvkey != NULL
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
        if (!ossl_ml_kem_vencode_public_key(v, pubenc, v->pubkey_bytes,
                                            key->pubkey, key->prvkey)
            || !ossl_param_build_set_octet_string(
                   tmpl, params, OSSL_PKEY_PARAM_PUB_KEY,
                   pubenc, key->vinfo->pubkey_bytes))
            goto err;

    /* The private key on request */
    if (prvenc != NULL && key->prvkey != NULL)
        if (!ossl_ml_kem_vencode_private_key(v, prvenc, v->prvkey_bytes,
                                             key->prvkey)
            || !ossl_param_build_set_octet_string(
                    tmpl, params, OSSL_PKEY_PARAM_PRIV_KEY,
                    prvenc, key->vinfo->prvkey_bytes))
            goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_free(params);

err:
    OSSL_PARAM_BLD_free(tmpl);
    OPENSSL_secure_clear_free(prvenc, key->vinfo->prvkey_bytes);
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

static int ossl_ml_kem_key_fromdata(ML_KEM_PROVIDER_KEYPAIR *key,
                                    const OSSL_PARAM params[],
                                    int include_private)
{
    const OSSL_PARAM *param_prv_key = NULL, *param_pub_key;
    const void *pubenc = NULL, *prvenc = NULL;
    size_t publen = 0, prvlen = 0;
    vinfo_t v;

    if (key == NULL)
        return 0;
    v = key->vinfo;

    /* Invalid attempt to mutate a key, what is the right error to report? */
    if (have_keys(key))
        return 0;

    /* What does the caller want to set? */
    param_pub_key = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (param_pub_key &&
        OSSL_PARAM_get_octet_string_ptr(param_pub_key, &pubenc, &publen) != 1)
        return 0;
    if (include_private)
        param_prv_key = OSSL_PARAM_locate_const(params,
                                                OSSL_PKEY_PARAM_PRIV_KEY);
    if (param_prv_key &&
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
    if (publen != 0 && publen != key->vinfo->pubkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }
    if (prvlen != 0 && prvlen != key->vinfo->prvkey_bytes) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
        return 0;
    }

    /*
     * If the private key is given, we'll ignore the public key data, taking
     * the embedded public key as authoritative.
     */
    if (prvlen != 0) {
        if (ossl_ml_kem_vparse_private_key(v, &key->prvkey, prvenc, prvlen,
                                           key->ctx) == 1)
            return 1;
        ossl_ml_kem_vcleanse_prvkey(v, &key->prvkey);
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
        return 0;
    }

    if (ossl_ml_kem_vparse_public_key(v, &key->pubkey, pubenc, publen,
                                      key->ctx) == 1)
        return 1;
    OPENSSL_free(key->pubkey);
    key->pubkey = NULL;
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
    return 0;
}

static int ml_kem_import(void *vkey, int selection, const OSSL_PARAM params[])
{
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;
    int include_private;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    include_private = selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;
    return ossl_ml_kem_key_fromdata(key, params, include_private);
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
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;
    vinfo_t v = key->vinfo;
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
    if (p != NULL && have_keys(key)) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = key->vinfo->pubkey_bytes;
        if (p->data != NULL) {
            if (p->data_size < p->return_size)
                return 0;
            if (!ossl_ml_kem_vencode_public_key(v, p->data, p->return_size,
                                                key->pubkey, key->prvkey))
                return 0;
        }
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_PRIV_KEY);
    if (p != NULL && key->prvkey != NULL) {
        if (p->data_type != OSSL_PARAM_OCTET_STRING)
            return 0;
        p->return_size = key->vinfo->prvkey_bytes;
        if (p->data != NULL) {
            if (p->data_size < p->return_size)
                return 0;
            if (!ossl_ml_kem_vencode_private_key(v, p->data, p->return_size,
                                                 key->prvkey))
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
    ML_KEM_PROVIDER_KEYPAIR *key = vkey;
    vinfo_t v = key->vinfo;
    const OSSL_PARAM *p;
    const void *pubenc = NULL;
    size_t publen = 0;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p == NULL)
        return 1;

    /* Key mutation is reported generally not allowed */
    if (have_keys(key)) {
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
    if (ossl_ml_kem_vparse_public_key(v, &key->pubkey, pubenc, publen,
                                      key->ctx) == 1)
        return 1;

    OPENSSL_free(key->pubkey);
    key->pubkey = NULL;
    ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY);
    return 0;
}

static int ml_kem_gen_set_params(void *vgctx, const OSSL_PARAM params[])
{
    struct ml_kem_gen_ctx *gctx = vgctx;
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
        gctx->propq = OPENSSL_strdup(p->data);
        if (gctx->propq == NULL)
            return 0;
    }

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ML_KEM_SEED);
    if (p == NULL)
        return 1;

    /* Treat wrong data type as promised, but missing */
    if (p->data_type != OSSL_PARAM_OCTET_STRING) {
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_SEED);
        return 0;
    }
    if (p->data_size != ML_KEM_SEED_BYTES) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_SEED_LENGTH);
        return 0;
    }

    gctx->seed = gctx->seedbuf;
    memcpy(gctx->seed, p->data, ML_KEM_SEED_BYTES);

    return 1;
}

static void *ml_kem_gen_init(void *provctx, vinfo_t v,
                             int selection, const OSSL_PARAM params[])
{
    struct ml_kem_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) == NULL)
        return NULL;

    gctx->provctx = provctx;
    gctx->vinfo = v;
    gctx->selection = selection;

    if (!ml_kem_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx->propq);
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    return gctx;
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
    struct ml_kem_gen_ctx *gctx = vgctx;
    ML_KEM_PROVIDER_KEYPAIR *key;
    uint8_t *nopub = NULL;
    size_t seedlen = ML_KEM_SEED_BYTES;
    vinfo_t v = gctx->vinfo;
    int genok = 0;

    if (gctx == NULL)
        return NULL;

    key = ml_kem_new(gctx->provctx, gctx->vinfo, gctx->propq);
    if (key == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /* Actual keypair generation may optionally be deferred */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return key;

    genok = gctx->seed != NULL ?
        ossl_ml_kem_vgenkey_seed(v, gctx->seed, seedlen, nopub, 0, &key->prvkey,
                                 key->ctx) :
        ossl_ml_kem_vgenkey_rand(v, NULL, 0, nopub, 0, &key->prvkey, key->ctx);

    /* Single-use seeds */
    if (gctx->seed)
        OPENSSL_cleanse(gctx->seed, ML_KEM_SEED_BYTES);
    gctx->seed = NULL;

    if (genok)
        return key;

    /* The pubkey is always NULL in a generated key */
    ossl_ml_kem_vcleanse_prvkey(v, &key->prvkey);
    OPENSSL_free(key);
    return NULL;
}

static void ml_kem_gen_cleanup(void *vgctx)
{
    struct ml_kem_gen_ctx *gctx = vgctx;

    if (gctx->seed != NULL)
        OPENSSL_cleanse(gctx->seed, ML_KEM_RANDOM_BYTES);
    OPENSSL_free(gctx->propq);
    OPENSSL_free(vgctx);
}

static void *ml_kem_dup(const void *vkey, int selection)
{
    const ML_KEM_PROVIDER_KEYPAIR *key = vkey;
    vinfo_t v = key->vinfo;
    ML_KEM_PROVIDER_KEYPAIR *newkey;

    if (!ossl_prov_is_running())
        return NULL;

    if ((newkey = OPENSSL_zalloc(sizeof(*key))) == NULL)
        return NULL;
    if ((newkey->ctx = ossl_ml_kem_ctx_dup(key->ctx)) == NULL)
        goto err;
    newkey->provctx = key->provctx;
    newkey->vinfo = v;

    /* If key material is requested, clone the entire structure */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return newkey;

    if (key->prvkey != NULL
        && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        newkey->prvkey = OPENSSL_memdup(key->prvkey, v->prvalloc);
        if (newkey->prvkey != NULL)
            return newkey;
        goto err;
    }

    if (key->pubkey != NULL) {
        newkey->pubkey = OPENSSL_memdup(key->pubkey, v->puballoc);
        if (newkey->pubkey != NULL)
            return newkey;
    }

  err:
    ml_kem_free(newkey);
    return NULL;
}

#define DECLARE_VARIANT(bits) \
    static void *ml_kem_##bits##_new(void *provctx) \
    { \
        return ml_kem_new(provctx, ossl_ml_kem_##bits##_get_vinfo(), NULL); \
    } \
    static void *ml_kem_##bits##_gen_init(void *provctx, int selection, \
                                        const OSSL_PARAM params[]) \
    { \
        return ml_kem_gen_init(provctx, ossl_ml_kem_##bits##_get_vinfo(), \
                              selection, params); \
    } \
    const OSSL_DISPATCH ossl_ml_kem_##bits##_keymgmt_functions[] = { \
        { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ml_kem_##bits##_new }, \
        { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ml_kem_free }, \
        { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ml_kem_get_params }, \
        { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, \
            (void (*) (void))ml_kem_gettable_params }, \
        { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))ml_kem_set_params }, \
        { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, \
            (void (*) (void))ml_kem_settable_params }, \
        { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ml_kem_has }, \
        { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))ml_kem_match }, \
        { OSSL_FUNC_KEYMGMT_GEN_INIT, \
            (void (*)(void))ml_kem_##bits##_gen_init }, \
        { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, \
            (void (*)(void))ml_kem_gen_set_params }, \
        { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS, \
          (void (*)(void))ml_kem_gen_settable_params }, \
        { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))ml_kem_gen }, \
        { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, \
            (void (*)(void))ml_kem_gen_cleanup }, \
        { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))ml_kem_dup }, \
        { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ml_kem_import }, \
        { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, \
            (void (*)(void))ml_kem_imexport_types }, \
        { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ml_kem_export }, \
        { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, \
            (void (*)(void))ml_kem_imexport_types }, \
        OSSL_DISPATCH_END \
    }
DECLARE_VARIANT(512);
DECLARE_VARIANT(768);
DECLARE_VARIANT(1024);
