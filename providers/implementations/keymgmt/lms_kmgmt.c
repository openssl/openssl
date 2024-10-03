/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "crypto/lms.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_new_fn lms_new_key;
static OSSL_FUNC_keymgmt_free_fn lms_free_key;
static OSSL_FUNC_keymgmt_has_fn lms_has;
static OSSL_FUNC_keymgmt_match_fn lms_match;
static OSSL_FUNC_keymgmt_validate_fn lms_validate;
static OSSL_FUNC_keymgmt_import_fn lms_import;
static OSSL_FUNC_keymgmt_import_types_fn lms_imexport_types;

#define LMS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

static void *lms_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return ossl_lms_key_new(PROV_LIBCTX_OF(provctx));
}

static void lms_free_key(void *keydata)
{
    ossl_lms_key_free((LMS_KEY *)keydata);
}

static int lms_has(const void *keydata, int selection)
{
    const LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    return ossl_lms_key_has(key, selection);
}

static int lms_match(const void *keydata1, const void *keydata2, int selection)
{
    const LMS_KEY *key1 = keydata1;
    const LMS_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    return ossl_lms_key_equal(key1, key2, selection);
}

static int lms_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    return ossl_lms_pubkey_from_params(params, key);
}

static const OSSL_PARAM lms_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY, NULL, 0),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_PROPERTIES, NULL, 0),
    OSSL_PARAM_END
};
static const OSSL_PARAM *lms_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return lms_key_types;
    return NULL;
}

static int lms_validate(const void *keydata, int selection, int checktype)
{
    const LMS_KEY *lmskey = keydata;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    return ossl_lms_key_valid(lmskey, selection);
}

const OSSL_DISPATCH ossl_lms_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))lms_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))lms_free_key },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))lms_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))lms_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))lms_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))lms_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))lms_imexport_types },
    OSSL_DISPATCH_END
};
