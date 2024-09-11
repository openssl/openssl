/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <assert.h>
#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "internal/param_build_set.h"
#include <openssl/param_build.h>
#include <openssl/hss.h>
#include "crypto/hss.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_new_fn hss_new_key;
static OSSL_FUNC_keymgmt_free_fn hss_free_key;
static OSSL_FUNC_keymgmt_load_fn hss_load;
static OSSL_FUNC_keymgmt_set_params_fn hss_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn hss_settable_params;
static OSSL_FUNC_keymgmt_get_params_fn hss_get_params;
static OSSL_FUNC_keymgmt_gettable_params_fn hss_gettable_params;
static OSSL_FUNC_keymgmt_has_fn hss_has;
static OSSL_FUNC_keymgmt_match_fn hss_match;
static OSSL_FUNC_keymgmt_validate_fn hss_validate;
static OSSL_FUNC_keymgmt_import_fn hss_import;
static OSSL_FUNC_keymgmt_export_fn hss_export;
static OSSL_FUNC_keymgmt_import_types_fn hss_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn hss_imexport_types;

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
static OSSL_FUNC_keymgmt_gen_init_fn hss_gen_init;
static OSSL_FUNC_keymgmt_gen_set_params_fn hss_gen_set_params;
static OSSL_FUNC_keymgmt_gen_settable_params_fn hss_gen_settable_params;
static OSSL_FUNC_keymgmt_gen_fn hss_gen;
static OSSL_FUNC_keymgmt_gen_cleanup_fn hss_gen_cleanup;
static OSSL_FUNC_keymgmt_reserve_fn hss_reserve;
#endif

#define HSS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_KEYPAIR)

static void *hss_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return ossl_hss_key_new(PROV_LIBCTX_OF(provctx), NULL);
}

static void hss_free_key(void *keydata)
{
    HSS_KEY *key = keydata;

    ossl_hss_key_free(key);
}

static int hss_has(const void *keydata, int selection)
{
    const HSS_KEY *hsskey = keydata;
    int ok = 1;
    LMS_KEY *key;

    if (!ossl_prov_is_running() || hsskey == NULL)
        return 0;
    if ((selection & HSS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    key = sk_LMS_KEY_value(hsskey->lmskeys, 0);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = (key != NULL && key->pub.K != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = (key != NULL && key->priv.data != NULL);
    return ok;
}

static int hss_match(const void *keydata1, const void *keydata2, int selection)
{
    const HSS_KEY *hsskey1 = keydata1;
    const HSS_KEY *hsskey2 = keydata2;
    LMS_KEY *key1, *key2;
    int ok = 1;

    if (!ossl_prov_is_running())
        return 0;
    if (hsskey1 == NULL || hsskey2 == NULL)
        return 0;

    key1 = sk_LMS_KEY_value(hsskey1->lmskeys, 0);
    key2 = sk_LMS_KEY_value(hsskey2->lmskeys, 0);
    if (key1 == NULL || key2 == NULL)
        return 0;

    ok = (hsskey1->L == hsskey2->L
          && key1->q == key2->q
          && key1->lms_params == key2->lms_params
          && key1->ots_params == key2->ots_params);
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        ok = ok
            && key1->pub.encodedlen == key2->pub.encodedlen
            && (memcmp(key1->pub.encoded, key2->pub.encoded,
                       key1->pub.encodedlen) == 0);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0) {
        ok = ok && (memcmp(key1->priv.seed, key2->priv.seed,
                           key1->ots_params->n) == 0);
    }
    return ok;
}

static int hss_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    HSS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    return ossl_hss_pubkey_from_params(params, key);
}

static int hss_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    HSS_KEY *hsskey = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0, L;
    LMS_KEY *lmskey;

    if (!ossl_prov_is_running() || hsskey == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    lmskey = sk_LMS_KEY_value(hsskey->lmskeys, 0);

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    L = hsskey->L;
    if (!ossl_param_build_set_int(tmpl, params, OSSL_PKEY_PARAM_HSS_L, L))
        goto err;
    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                           lmskey->pub.encoded,
                                           lmskey->pub.encodedlen))
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

#define LMS_KEY_TYPES()                                                        \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),      \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0)

#define HSS_KEY_TYPES()                                                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_HSS_L, NULL),                               \
    LMS_KEY_TYPES()

static const OSSL_PARAM hss_key_types[] = {
    HSS_KEY_TYPES(),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hss_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return hss_key_types;
    return NULL;
}

static const OSSL_PARAM *hss_settable_params(void *provctx)
{
    static const OSSL_PARAM hss_settable_params_table[] = {
        LMS_KEY_TYPES(),
        OSSL_PARAM_END
    };

    return hss_settable_params_table;
}

static int hss_set_params(void *key, const OSSL_PARAM params[])
{
    HSS_KEY *hsskey = key;

    if (params == NULL)
        return 1;
    return ossl_hss_pubkey_from_params(params, hsskey);
}

static const OSSL_PARAM *hss_gettable_params(ossl_unused void *ctx)
{
    static const OSSL_PARAM hss_gettable_params_table[] = {
        OSSL_PARAM_uint64(OSSL_PKEY_PARAM_HSS_KEYS_REMAINING, NULL),
        OSSL_PARAM_END
    };

    return hss_gettable_params_table;
}

static int hss_get_params(void *key, OSSL_PARAM *params)
{
#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
    HSS_KEY *hsskey = key;
    OSSL_PARAM *p;
#endif

    if (key == NULL)
        return 0;
    if (params == NULL)
        return 1;

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_HSS_KEYS_REMAINING);
    if (p != NULL) {
        uint64_t sz = ossl_hss_keys_remaining(hsskey);

        if (!OSSL_PARAM_set_uint64(p, sz))
            return 0;
    }
#endif
    return 1;
}

static void *hss_load(const void *reference, size_t reference_sz)
{
    HSS_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(HSS_KEY **)reference;
        /* We grabbed, so we detach it */
        *(HSS_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static int hss_validate(const void *keydata, int selection, int checktype)
{
    const HSS_KEY *hsskey = keydata;
    LMS_KEY *lmskey;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & HSS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    lmskey = sk_LMS_KEY_value(hsskey->lmskeys, 0);
    return (lmskey->pub.encoded != NULL && lmskey->pub.encodedlen > 0);
}

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
struct hss_gen_ctx {
    OSSL_LIB_CTX *libctx;
    const char *propq;
    uint32_t levels;
    uint32_t lms_types[8];
    uint32_t ots_types[8];
};

static const char *ossl_hss_lms_type_names[] = {
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L1,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L2,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L3,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L4,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L5,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L6,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L7,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L8,
    NULL
};

static const char *ossl_hss_ots_type_names[] = {
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L1,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L2,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L3,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L4,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L5,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L6,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L7,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L8,
    NULL
};

static void *hss_gen_init(void *provctx, int selection,
                          const OSSL_PARAM params[])
{
    OSSL_LIB_CTX *libctx = PROV_LIBCTX_OF(provctx);
    struct hss_gen_ctx *gctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return NULL;

    gctx = OPENSSL_zalloc(sizeof(*gctx));
    if (gctx == NULL)
        goto err;

    gctx->libctx = libctx;
    if (!hss_gen_set_params(gctx, params))
        goto err;
    return gctx;

err:
    if (gctx != NULL) {
    }
    OPENSSL_free(gctx);
    return NULL;
}

static int hss_gen_set_params(void *genctx, const OSSL_PARAM params[])
{
    struct hss_gen_ctx *gctx = genctx;
    const OSSL_PARAM *p;
    int i;

    if (params == NULL)
        return 1;
    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_HSS_LEVELS);
    if (p != NULL) {
        if (!OSSL_PARAM_get_uint32(p, &gctx->levels))
            return 0;
        if (gctx->levels == 0 || gctx->levels > 8)
            return 0;
    }
    for (i = 0; i < 8; ++i) {
        p = OSSL_PARAM_locate_const(params, ossl_hss_lms_type_names[i]);
        if (p != NULL && !OSSL_PARAM_get_uint32(p, &gctx->lms_types[i]))
            return 0;
        p = OSSL_PARAM_locate_const(params, ossl_hss_ots_type_names[i]);
        if (p != NULL && !OSSL_PARAM_get_uint32(p, &gctx->ots_types[i]))
            return 0;
    }
    return 1;
}

static const OSSL_PARAM *hss_gen_settable_params(ossl_unused void *genctx,
                                                 ossl_unused void *provctx)
{
    static OSSL_PARAM settable[] = {
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LEVELS, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L1, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L2, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L3, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L4, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L5, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L6, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L7, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_LMS_TYPE_L8, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L1, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L2, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L3, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L4, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L5, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L6, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L7, NULL),
        OSSL_PARAM_uint32(OSSL_PKEY_PARAM_HSS_OTS_TYPE_L8, NULL),
        OSSL_PARAM_END
    };
    return settable;
}

static void *hss_gen(void *genctx, OSSL_CALLBACK *osslcb, void *cbarg)
{
    struct hss_gen_ctx *gctx = genctx;
    HSS_KEY *key = NULL;
    uint32_t i;

    if (!ossl_prov_is_running() || gctx == NULL)
        return NULL;

    for (i = 0; i < gctx->levels; ++i) {
        if (gctx->lms_types[i] == 0)
            return NULL;
        if (gctx->ots_types[i] == 0)
            return NULL;
    }
    while (i < 8) {
        if (gctx->lms_types[i] != 0)
            return NULL;
        if (gctx->ots_types[i] != 0)
            return NULL;
        ++i;
    }
    key = ossl_hss_key_new(gctx->libctx, gctx->propq);
    if (key == NULL)
        return NULL;
    if (!ossl_hss_generate_key(key, gctx->levels,
                               gctx->lms_types, gctx->ots_types)) {
        ossl_hss_key_free(key);
        key = NULL;
    }
    return key;
}

static void hss_gen_cleanup(void *genctx)
{
    struct hss_gen_ctx *gctx = genctx;

    if (gctx == NULL)
        return;
    OPENSSL_free(gctx);
}

static void *hss_reserve(void *keydata, uint64_t count)
{
    HSS_KEY *curkey = (HSS_KEY *)keydata;
    HSS_KEY *newkey = NULL;

    if (count == 0)
        return NULL;
    if (count > ossl_hss_keys_remaining(curkey))
        return NULL;

    newkey = ossl_hss_key_reserve(curkey, count);
    if (newkey == NULL)
        return NULL;

    if (!ossl_hss_key_advance(curkey, count)) {
        ossl_hss_key_free(newkey);
        return NULL;
    }
    return newkey;
}
#endif

const OSSL_DISPATCH ossl_hss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hss_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hss_free_key },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))hss_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))hss_settable_params },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))hss_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))hss_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hss_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hss_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))hss_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hss_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hss_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))hss_load },

#if !defined(OPENSSL_NO_HSS_GEN) && !defined(FIPS_MODULE)
    { OSSL_FUNC_KEYMGMT_GEN_INIT, (void (*)(void))hss_gen_init },
    { OSSL_FUNC_KEYMGMT_GEN_SET_PARAMS, (void (*)(void))hss_gen_set_params },
    { OSSL_FUNC_KEYMGMT_GEN_SETTABLE_PARAMS,
      (void (*)(void))hss_gen_settable_params },
    { OSSL_FUNC_KEYMGMT_GEN, (void (*)(void))hss_gen },
    { OSSL_FUNC_KEYMGMT_GEN_CLEANUP, (void (*)(void))hss_gen_cleanup },
    { OSSL_FUNC_KEYMGMT_RESERVE, (void (*)(void))hss_reserve },
#endif
    OSSL_DISPATCH_END
};
