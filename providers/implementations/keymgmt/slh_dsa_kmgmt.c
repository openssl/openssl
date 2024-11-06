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
#include "crypto/slh_dsa.h"
#include "internal/param_build_set.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"

static OSSL_FUNC_keymgmt_free_fn slh_dsa_free_key;
static OSSL_FUNC_keymgmt_has_fn slh_dsa_has;
static OSSL_FUNC_keymgmt_match_fn slh_dsa_match;
static OSSL_FUNC_keymgmt_import_fn slh_dsa_import;
static OSSL_FUNC_keymgmt_import_types_fn slh_dsa_imexport_types;

#define SLH_DSA_POSSIBLE_SELECTIONS (OSSL_KEYMGMT_SELECT_PUBLIC_KEY)

static void *slh_dsa_new_key(void *provctx, const char *alg)
{
    if (!ossl_prov_is_running())
        return 0;

    return ossl_slh_dsa_key_new(PROV_LIBCTX_OF(provctx), alg);
}

static void slh_dsa_free_key(void *keydata)
{
    ossl_slh_dsa_key_free((SLH_DSA_KEY *)keydata);
}

static int slh_dsa_has(const void *keydata, int selection)
{
    const SLH_DSA_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;
    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return 1; /* the selection is not missing */

    return ossl_slh_dsa_key_has(key, selection);
}

static int slh_dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const SLH_DSA_KEY *key1 = keydata1;
    const SLH_DSA_KEY *key2 = keydata2;

    if (!ossl_prov_is_running())
        return 0;
    if (key1 == NULL || key2 == NULL)
        return 0;
    return ossl_slh_dsa_key_equal(key1, key2, selection);
}

static int slh_dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    SLH_DSA_KEY *key = keydata;

    if (!ossl_prov_is_running() || key == NULL)
        return 0;

    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return 0;

    return ossl_slh_dsa_key_fromdata(key, params);
}

static const OSSL_PARAM slh_dsa_key_types[] = {
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *slh_dsa_imexport_types(int selection)
{
    if ((selection & SLH_DSA_POSSIBLE_SELECTIONS) == 0)
        return NULL;
    return slh_dsa_key_types;
}

#define MAKE_KEYMGMT_FUNCTIONS(alg, fn)                                        \
static OSSL_FUNC_keymgmt_new_fn slh_dsa_##fn##_new_key;                        \
static void *slh_dsa_##fn##_new_key(void *provctx)                             \
{                                                                              \
    return slh_dsa_new_key(provctx, alg);                                      \
}                                                                              \
const OSSL_DISPATCH ossl_slh_dsa_##fn##_keymgmt_functions[] = {                \
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))slh_dsa_##fn##_new_key },         \
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))slh_dsa_free_key },              \
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))slh_dsa_has },                    \
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))slh_dsa_match },                \
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))slh_dsa_import },              \
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))slh_dsa_imexport_types },\
    OSSL_DISPATCH_END                                                          \
}

MAKE_KEYMGMT_FUNCTIONS("SLH-DSA-SHA2-128s", sha2_128s);
