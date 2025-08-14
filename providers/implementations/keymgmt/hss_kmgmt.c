/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "crypto/hss.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/param_build_set.h"

static OSSL_FUNC_keymgmt_new_fn hss_new_key;
static OSSL_FUNC_keymgmt_free_fn hss_free_key;
static OSSL_FUNC_keymgmt_dup_fn hss_dup_key;
static OSSL_FUNC_keymgmt_has_fn hss_has;
static OSSL_FUNC_keymgmt_match_fn hss_match;
static OSSL_FUNC_keymgmt_validate_fn hss_validate;
static OSSL_FUNC_keymgmt_import_fn hss_import;
static OSSL_FUNC_keymgmt_export_fn hss_export;
static OSSL_FUNC_keymgmt_import_types_fn hss_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn hss_imexport_types;
static OSSL_FUNC_keymgmt_load_fn hss_load;

#define HSS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

static void *hss_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return ossl_hss_key_new(PROV_LIBCTX_OF(provctx), NULL);
}

static void hss_free_key(void *keydata)
{
    ossl_hss_key_free((HSS_KEY *)keydata);
}

static int hss_has(const void *keydata, int selection)
{
    const HSS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */

    return ossl_hss_key_has(key, selection);
}

static int hss_match(const void *keydata1, const void *keydata2, int selection)
{
    const HSS_KEY *key1 = keydata1;
    const HSS_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    return ossl_hss_key_equal(key1, key2, selection);
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

static void *hss_dup_key(const void *keydata_from, int selection)
{
    if (ossl_prov_is_running())
        return ossl_hss_key_dup(keydata_from, selection);
    return NULL;
}

static const OSSL_PARAM hss_key_types[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_HSS_L, NULL),
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *hss_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return hss_key_types;
    return NULL;
}

static int hss_validate(const void *keydata, int selection, int checktype)
{
    const HSS_KEY *hsskey = keydata;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & HSS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    return ossl_hss_key_valid(hsskey, selection);
}

static int hss_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    LMS_KEY *lmskey;
    HSS_KEY *hsskey = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!ossl_prov_is_running() || hsskey == NULL)
        return 0;

    lmskey = hsskey->public;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0
            || lmskey == NULL || lmskey->pub.encoded == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if (!ossl_param_build_set_int(tmpl, params, OSSL_PKEY_PARAM_HSS_L, hsskey->L))
        goto err;
    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_PUB_KEY,
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

static const OSSL_PARAM hss_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_MANDATORY_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hss_gettable_params(void *provctx)
{
    return hss_params;
}

static int hss_get_params(void *keydata, OSSL_PARAM params[])
{
    HSS_KEY *key = keydata;
    OSSL_PARAM *p;
    LMS_KEY *lms = key->public;
    size_t n = lms->lms_params->n;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
            && !OSSL_PARAM_set_size_t(p, 8 * n))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
            && !OSSL_PARAM_set_size_t(p, 8 * n))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
            && !OSSL_PARAM_set_size_t(p, 80 * 1024))
        return 0;

    /*
     * This allows apps to use an empty digest, so that the old API
     * for digest signing can be used.
     */
    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MANDATORY_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ""))
        return 0;
    return 1;
}

const OSSL_DISPATCH ossl_hss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hss_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hss_free_key },
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
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))hss_dup_key },
    OSSL_DISPATCH_END
};
