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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/self_test.h>
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include "internal/mlkem.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"


static OSSL_FUNC_keymgmt_new_fn mlkem_new;
static OSSL_FUNC_keymgmt_free_fn mlkem_free;
static OSSL_FUNC_keymgmt_gen_init_fn mlkem_gen_init;
static OSSL_FUNC_keymgmt_gen_fn mlkem_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn mlkem_gen_cleanup;
static OSSL_FUNC_keymgmt_gen_set_params_fn mlkem_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn mlkem_gen_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn mlkem_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn mlkem_gettable_params;
static OSSL_FUNC_keymgmt_set_params_fn mlkem_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn mlkem_settable_params;
static OSSL_FUNC_keymgmt_has_fn mlkem_has;
static OSSL_FUNC_keymgmt_match_fn mlkem_match;
static OSSL_FUNC_keymgmt_dup_fn mlkem_dup;

#define ECX_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

struct mlkem_gen_ctx {
    void *provctx;
    int selection;
};

static void *mlkem_new(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return OPENSSL_zalloc(sizeof(MLKEM_KEY));
}

static void mlkem_free(void *vkey)
{
    MLKEM_KEY *mkey = (MLKEM_KEY *)vkey;

    if (mkey == NULL)
        return;
    OPENSSL_free(mkey->pubkey);
    OPENSSL_free(mkey->seckey);
    OPENSSL_free(mkey);
}

static int mlkem_has(const void *keydata, int selection)
{
    const MLKEM_KEY *key = keydata;
    int ok = 0;

    if (ossl_prov_is_running() && key != NULL) {
        /*
         * ML-KEM keys always have all the parameters they need (i.e. none).
         * Therefore we always return with 1, if asked about parameters.
         */
        ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && key->pubkey != NULL;

        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && key->seckey != NULL;
    }
    return ok;
}

static int mlkem_match(const void *keydata1, const void *keydata2, int selection)
{
    const MLKEM_KEY *key1 = keydata1;
    const MLKEM_KEY *key2 = keydata2;
    int ok = 1;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && key1->keytype == key2->keytype;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int key_checked = 0;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
            const uint8_t *pa = key1->pubkey;
            const uint8_t *pb = key2->pubkey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_PUBLICKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        if (!key_checked
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
            const uint8_t *pa = key1->seckey;
            const uint8_t *pb = key2->seckey;

            if (pa != NULL && pb != NULL) {
                ok = ok
                    && key1->keytype == key2->keytype
                    && CRYPTO_memcmp(pa, pb, MLKEM768_SECRETKEYBYTES) == 0;
                key_checked = 1;
            }
        }
        ok = ok && key_checked;
    }
    return ok;
}

static int mlkem_get_params(void *key, OSSL_PARAM params[])
{
    MLKEM_KEY *mkey = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_SECRETKEYBYTES * 8))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_SECURITY_BITS))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, MLKEM768_CIPHERTEXTBYTES))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY)) != NULL) {
        if (!OSSL_PARAM_set_octet_string(p, mkey->pubkey, MLKEM768_PUBLICKEYBYTES))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM mlkem_gettable_params_arr[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_gettable_params(void *provctx)
{
    return mlkem_gettable_params_arr;
}

static int mlkem_set_params(void *key, const OSSL_PARAM params[])
{
    MLKEM_KEY *mkey = key;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY);
    if (p != NULL) {
        void *buf;

        if (mkey->pubkey == NULL)
            mkey->pubkey = OPENSSL_malloc(MLKEM768_PUBLICKEYBYTES);

        buf = mkey->pubkey;
        if (buf == NULL)
            return 0;

        if (p->data_size != MLKEM768_PUBLICKEYBYTES
                || !OSSL_PARAM_get_octet_string(p, &buf, MLKEM768_PUBLICKEYBYTES,
                                                NULL))
            return 0;
        OPENSSL_clear_free(mkey->seckey, MLKEM768_SECRETKEYBYTES);
        mkey->seckey = NULL;
    }

    return 1;
}

static const OSSL_PARAM mlkem_settable_params_arr[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_settable_params(void *provctx)
{
    return mlkem_settable_params_arr;
}

static void *mlkem_gen_init(void *provctx, int selection,
                            const OSSL_PARAM params[])
{
    struct mlkem_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((gctx = OPENSSL_zalloc(sizeof(*gctx))) != NULL) {
        gctx->provctx = provctx;
        gctx->selection = selection;
    }
    if (!mlkem_gen_set_params(gctx, params)) {
        OPENSSL_free(gctx);
        gctx = NULL;
    }
    return gctx;
}

static int mlkem_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct ecx_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return 0;

    return 1;
}

static const OSSL_PARAM *mlkem_gen_settable_params(ossl_unused void *genctx,
                                                   ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_END
    };
    return settable;
}

static void *mlkem_gen(void *vctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct mlkem_gen_ctx *gctx = (struct mlkem_gen_ctx *)vctx;
    MLKEM_KEY *mkey;

    if (gctx == NULL)
        return NULL;

    if ((mkey = mlkem_new(NULL)) == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_INTERNAL_ERROR);
        return NULL;
    }

    /* If we're doing parameter generation then we just return a blank key */
    if ((gctx->selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return mkey;

    mkey->keytype = MLKEM_KEY_TYPE_768;
    mkey->pubkey = OPENSSL_malloc(MLKEM768_PUBLICKEYBYTES);
    mkey->seckey = OPENSSL_malloc(MLKEM768_SECRETKEYBYTES);
    if (mkey->pubkey == NULL || mkey->seckey == NULL)
        goto err;

    if (!mlkem768_ref_keypair(mkey->pubkey, mkey->seckey))
        goto err;

    return mkey;
err:
    mlkem_free(mkey);
    return NULL;
}

static void mlkem_gen_cleanup(void *genctx)
{
    struct ecx_gen_ctx *gctx = genctx;

    OPENSSL_free(gctx);
}

static void *mlkem_dup(const void *vsrckey, int selection)
{
    const MLKEM_KEY *srckey = (const MLKEM_KEY *)vsrckey;
    MLKEM_KEY *dstkey;

    if (!ossl_prov_is_running())
        return NULL;

    dstkey = mlkem_new(NULL);
    if (dstkey == NULL)
        return NULL;

    dstkey->keytype = srckey->keytype;
    if (srckey->pubkey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        dstkey->pubkey = OPENSSL_memdup(srckey->pubkey, MLKEM768_PUBLICKEYBYTES);
        if (dstkey->pubkey == NULL) {
            goto err;
        }
    }
    if (srckey->seckey != NULL
            && (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        dstkey->seckey = OPENSSL_memdup(srckey->seckey, MLKEM768_SECRETKEYBYTES);
        if (dstkey->seckey == NULL) {
            goto err;
        }
    }

    return dstkey;
 err:
    mlkem_free(dstkey);
    return NULL;
}

const OSSL_DISPATCH ossl_mlkem_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))mlkem_new },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))mlkem_free },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))mlkem_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))mlkem_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))mlkem_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))mlkem_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))mlkem_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))mlkem_match },
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))mlkem_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))mlkem_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
        (void (*)(void))mlkem_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))mlkem_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))mlkem_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))mlkem_dup },
    OSSL_DISPATCH_END
};
