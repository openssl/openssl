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
#include "crypto/hss.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_new_fn hss_new_key;
static OSSL_FUNC_keymgmt_free_fn hss_free_key;
static OSSL_FUNC_keymgmt_load_fn hss_load;
static OSSL_FUNC_keymgmt_set_params_fn hss_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn hss_settable_params;
static OSSL_FUNC_keymgmt_has_fn hss_has;
static OSSL_FUNC_keymgmt_match_fn hss_match;
static OSSL_FUNC_keymgmt_validate_fn hss_validate;
static OSSL_FUNC_keymgmt_import_fn hss_import;
static OSSL_FUNC_keymgmt_export_fn hss_export;
static OSSL_FUNC_keymgmt_import_types_fn hss_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn hss_imexport_types;

#define HSS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

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
    const HSS_KEY *key = keydata;
    int ok = 1;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & HSS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = (key->lms_pub.pub != NULL && key->lms_pub.publen > 0);

    return ok;
}

static int hss_match(const void *keydata1, const void *keydata2, int selection)
{
    const HSS_KEY *key1 = keydata1;
    const HSS_KEY *key2 = keydata2;
    int ok = 1;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        ok = (key1->L == key2->L
              && key1->lms_pub.publen == key2->lms_pub.publen
              && memcmp(key1->lms_pub.pub, key2->lms_pub.pub,
                        key1->lms_pub.publen) == 0);
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
    HSS_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0, L;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    L = key->L;
    if (!ossl_param_build_set_int(tmpl, params, OSSL_PKEY_PARAM_HSS_L, L))
        goto err;;
    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                           key->lms_pub.pub, key->lms_pub.publen))
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

static int set_property_query(HSS_KEY *key, const char *propq)
{
    OPENSSL_free(key->lms_pub.propq);
    key->lms_pub.propq = NULL;
    if (propq != NULL) {
        key->lms_pub.propq = OPENSSL_strdup(propq);
        if (key->lms_pub.propq == NULL)
            return 0;
    }
    return 1;
}

static int hss_set_params(void *key, const OSSL_PARAM params[])
{
    HSS_KEY *hsskey = key;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || !set_property_query(hsskey, p->data))
            return 0;
    }
    return ossl_hss_pubkey_from_params(params, hsskey);
}

static const OSSL_PARAM hss_settable_params_table[] = {
    LMS_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *hss_settable_params(void *provctx)
{
    return hss_settable_params_table;
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
    const HSS_KEY *key = keydata;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & HSS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    return (key->lms_pub.pub != NULL && key->lms_pub.publen > 0);
}

const OSSL_DISPATCH ossl_hss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hss_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hss_free_key },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))hss_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))hss_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hss_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hss_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))hss_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hss_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hss_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))hss_load },
    OSSL_DISPATCH_END
};
