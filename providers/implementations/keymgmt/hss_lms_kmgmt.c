/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/lms.h"
#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "providers/implementations/keymgmt/hss_lms_kmgmt.inc"

static OSSL_FUNC_keymgmt_new_fn hss_lms_new_key;
static OSSL_FUNC_keymgmt_free_fn hss_lms_free_key;
static OSSL_FUNC_keymgmt_has_fn hss_lms_has;
static OSSL_FUNC_keymgmt_match_fn hss_lms_match;
static OSSL_FUNC_keymgmt_validate_fn hss_lms_validate;
static OSSL_FUNC_keymgmt_import_fn hss_lms_import;
static OSSL_FUNC_keymgmt_export_fn hss_lms_export;
static OSSL_FUNC_keymgmt_import_types_fn hss_lms_imexport_types;
static OSSL_FUNC_keymgmt_export_types_fn hss_lms_imexport_types;
static OSSL_FUNC_keymgmt_load_fn hss_lms_load;
static OSSL_FUNC_keymgmt_gettable_params_fn hss_lms_gettable_params;
static OSSL_FUNC_keymgmt_get_params_fn hss_lms_get_params;

#define LMS_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

static void *hss_lms_new_key(void *provctx)
{
    if (!ossl_prov_is_running())
        return 0;
    return ossl_hss_lms_key_new(PROV_LIBCTX_OF(provctx), NULL);
}

static void hss_lms_free_key(void *keydata)
{
    ossl_hss_lms_key_free((HSS_LMS_KEY *)keydata);
}

static int hss_lms_has(const void *keydata, int selection)
{
    const HSS_LMS_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 1; /* the selection is not missing */

    return ossl_lms_key_has(&key->public, selection);
}

static int hss_lms_match(const void *keydata1, const void *keydata2, int selection)
{
    const HSS_LMS_KEY *key1 = keydata1;
    const HSS_LMS_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    return ossl_hss_lms_key_equal(key1, key2, selection);
}

static int hss_lms_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    HSS_LMS_KEY *hss = keydata;
    struct hss_lms_import_st p;

    if (!ossl_prov_is_running()
        || hss == NULL
        || !hss_lms_import_decoder(params, &p))
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;

    return ossl_hss_lms_pubkey_from_params(p.pub, p.l, hss);
}

static const OSSL_PARAM *hss_lms_imexport_types(int selection)
{
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        return hss_lms_import_list;
    return NULL;
}

static int hss_lms_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
    void *cbarg)
{
    HSS_LMS_KEY *hsskey = keydata;
    LMS_KEY *lmskey;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!ossl_prov_is_running() || hsskey == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    lmskey = &hsskey->public;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if (!ossl_param_build_set_int(tmpl, params, OSSL_PKEY_PARAM_HSS_LMS_L, hsskey->L)
        || !ossl_param_build_set_octet_string(tmpl, params,
            OSSL_PKEY_PARAM_PUB_KEY,
            lmskey->pub.encoded,
            lmskey->pub.encodedlen))
        goto err;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto err;

    ret = param_cb(params, cbarg);
    OSSL_PARAM_clear_free(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
    return ret;
}

static int hss_lms_validate(const void *keydata, int selection, int checktype)
{
    const HSS_LMS_KEY *hsskey = keydata;

    if (!ossl_prov_is_running())
        return 0;

    if ((selection & LMS_POSSIBLE_SELECTIONS) == 0)
        return 1; /* nothing to validate */

    return ossl_hss_lms_key_valid(hsskey, selection);
}

static void *hss_lms_load(const void *reference, size_t reference_sz)
{
    HSS_LMS_KEY *key = NULL;

    if (ossl_prov_is_running() && reference_sz == sizeof(key)) {
        /* The contents of the reference is the address to our object */
        key = *(HSS_LMS_KEY **)reference;
        /* We grabbed, so we detach it */
        *(HSS_LMS_KEY **)reference = NULL;
        return key;
    }
    return NULL;
}

static const OSSL_PARAM *hss_lms_gettable_params(void *provctx)
{
    return hss_lms_get_params_list;
}

static int hss_lms_get_params(void *keydata, OSSL_PARAM params[])
{
    HSS_LMS_KEY *hss = keydata;
    LMS_KEY *key;
    const uint8_t *d;
    size_t len;
    struct hss_lms_get_params_st p;

    if (hss == NULL || !hss_lms_get_params_decoder(params, &p))
        return 0;
    key = &hss->public;

    if (p.bits != NULL
        && !OSSL_PARAM_set_size_t(p.bits, 8 * ossl_lms_key_get_pub_len(key)))
        return 0;

    if (p.secbits != NULL
        && !OSSL_PARAM_set_size_t(p.secbits, ossl_lms_key_get_collision_strength_bits(key)))
        return 0;

    if (p.maxsize != NULL
        && !OSSL_PARAM_set_size_t(p.maxsize, ossl_lms_key_get_sig_len(key)))
        return 0;

    if (p.pubkey != NULL) {
        d = ossl_lms_key_get_pub(key);
        if (d != NULL) {
            len = ossl_lms_key_get_pub_len(key);
            if (!OSSL_PARAM_set_octet_string(p.pubkey, d, len))
                return 0;
        }
    }
    if (p.l != NULL
        && !OSSL_PARAM_set_uint32(p.l, hss->L))
        return 0;

    /*
     * This allows apps to use an empty digest, so that the old API
     * for digest signing can be used.
     */
    if (p.dgstp != NULL && !OSSL_PARAM_set_utf8_string(p.dgstp, ""))
        return 0;
    return 1;
}

const OSSL_DISPATCH ossl_hss_lms_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))hss_lms_new_key },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))hss_lms_free_key },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))hss_lms_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))hss_lms_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))hss_lms_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))hss_lms_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))hss_lms_imexport_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))hss_lms_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))hss_lms_imexport_types },
    { OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))hss_lms_load },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))hss_lms_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))hss_lms_gettable_params },
    OSSL_DISPATCH_END
};
