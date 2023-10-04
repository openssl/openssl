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
#include "crypto/lms.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_new_fn lms_new_key;
static OSSL_FUNC_keymgmt_load_fn lms_load;
static OSSL_FUNC_keymgmt_set_params_fn lms_set_params;
static OSSL_FUNC_keymgmt_settable_params_fn lms_settable_params;
static OSSL_FUNC_keymgmt_has_fn lms_has;
static OSSL_FUNC_keymgmt_match_fn lms_match;
static OSSL_FUNC_keymgmt_validate_fn lms_validate;
static OSSL_FUNC_keymgmt_import_fn lms_import;
static OSSL_FUNC_keymgmt_export_fn lms_export;
static OSSL_FUNC_keymgmt_import_fn hss_import;
static OSSL_FUNC_keymgmt_export_fn hss_export;
static OSSL_FUNC_keymgmt_import_types_fn lms_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn lms_imexport_types;
static OSSL_FUNC_keymgmt_dup_fn lms_dup;

#define LMS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

static void *lms_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return ossl_lms_key_new(PROV_LIBCTX_OF(provctx), NULL);
}

static int lms_has(const void *keydata, int selection)
{
    const LMS_KEY *key = keydata;
    int ok = 1;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = (key->pub != NULL && key->publen > 0);

    return ok;
}

static int lms_match(const void *keydata1, const void *keydata2, int selection)
{
    const LMS_KEY *key1 = keydata1;
    const LMS_KEY *key2 = keydata2;
    int ok = 1;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0) {
        ok = (key1->L == key2->L
              && key1->publen == key2->publen
              && memcmp(key1->pub, key2->pub, key1->publen) == 0);
    }
    return ok;
}

static int hss_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    return ossl_hss_key_fromdata(params, key);
}

static int lms_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    return ossl_lms_key_fromdata(params, key);
}

static int lms_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    LMS_KEY *key = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if (!ossl_param_build_set_octet_string(tmpl, params,
                                           OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                           key->pub, key->publen))
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

static int hss_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    LMS_KEY *key = keydata;
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
                                           key->pub, key->publen))
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
    LMS_KEY_TYPES(),                                                           \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_HSS_L, NULL)

static const OSSL_PARAM lms_key_types[] = {
    LMS_KEY_TYPES(),
    OSSL_PARAM_END
};
static const OSSL_PARAM *lms_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return lms_key_types;
    return NULL;
}

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

static int set_property_query(LMS_KEY *key, const char *propq)
{
    OPENSSL_free(key->propq);
    key->propq = NULL;
    if (propq != NULL) {
        key->propq = OPENSSL_strdup(propq);
        if (key->propq == NULL)
            return 0;
    }
    return 1;
}

static int lms_set_params(void *key, const OSSL_PARAM params[])
{
    LMS_KEY *lmskey = key;
    const OSSL_PARAM *p;

    if (params == NULL)
        return 1;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING
            || !set_property_query(lmskey, p->data))
            return 0;
    }
    return ossl_lms_key_fromdata(params, lmskey);
}

static const OSSL_PARAM lms_settable_params_table[] = {
    LMS_KEY_TYPES(),
    OSSL_PARAM_END
};

static const OSSL_PARAM *lms_settable_params(void *provctx)
{
    return lms_settable_params_table;
}

void *lms_load(const void *reference, size_t reference_sz)
{
    LMS_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(LMS_KEY **)reference;
        /* We grabbed, so we detach it */
        *(LMS_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static void *lms_dup(const void *keydata_from, int selection)
{
    if (ossl_prov_is_running())
        return ossl_lms_key_dup(keydata_from, selection);
    return NULL;
}

static int lms_validate(const void *keydata, int selection, int checktype)
{
    const LMS_KEY *key = keydata;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    return (key->pub != NULL && key->publen > 0);
}

const OSSL_DISPATCH ossl_lms_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))lms_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ossl_lms_key_free },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))lms_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))lms_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))lms_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))lms_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))lms_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))lms_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))lms_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))lms_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))lms_imexport_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))lms_load },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))lms_dup },
    OSSL_DISPATCH_END
};

const OSSL_DISPATCH ossl_hss_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))lms_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ossl_lms_key_free },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))lms_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))lms_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))lms_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))lms_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))lms_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hss_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hss_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))hss_imexport_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))lms_load },
    { OSSL_FUNC_KEYMGMT_DUP, (void (*)(void))lms_dup },
    OSSL_DISPATCH_END
};
