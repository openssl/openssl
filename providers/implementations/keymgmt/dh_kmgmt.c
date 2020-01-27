/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "crypto/dh.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static OSSL_OP_keymgmt_new_fn dh_newdata;
static OSSL_OP_keymgmt_free_fn dh_freedata;
static OSSL_OP_keymgmt_get_params_fn dh_get_params;
static OSSL_OP_keymgmt_gettable_params_fn dh_gettable_params;
static OSSL_OP_keymgmt_has_fn dh_has;
static OSSL_OP_keymgmt_import_fn dh_import;
static OSSL_OP_keymgmt_import_types_fn dh_import_types;
static OSSL_OP_keymgmt_export_fn dh_export;
static OSSL_OP_keymgmt_export_types_fn dh_export_types;

#define DH_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

static int params_to_domparams(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_g;
    BIGNUM *p = NULL, *g = NULL;

    if (dh == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_g != NULL && !OSSL_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DH_set0_pqg(dh, p, NULL, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DH *dh, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dh_p = NULL, *dh_g = NULL;

    if (dh == NULL)
        return 0;

    DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
    if (dh_p != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dh_p))
        return 0;
    if (dh_g != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dh_g))
        return 0;

    return 1;
}

static int params_to_key(DH *dh, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;

    if (!params_to_domparams(dh, params))
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /*
     * DH documentation says that a public key must be present if a
     * private key is present.
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || !OSSL_PARAM_get_BN(param_pub_key, &pub_key))
        goto err;

    if (!DH_set0_key(dh, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DH *dh, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dh == NULL)
        return 0;
    if (!domparams_to_params(dh, tmpl))
        return 0;

    DH_get0_key(dh, &pub_key, &priv_key);
    if (priv_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dh_newdata(void *provctx)
{
    return DH_new();
}

static void dh_freedata(void *keydata)
{
    DH_free(keydata);
}

static int dh_has(void *keydata, int selection)
{
    DH *dh = keydata;
    int ok = 0;

    if ((selection & DH_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (DH_get0_pub_key(dh) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (DH_get0_priv_key(dh) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (DH_get0_p(dh) != NULL && DH_get0_g(dh) != NULL);
    return ok;
}

static int dh_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DH *dh = keydata;
    int ok = 0;

    if (dh == NULL)
        return 0;

    if ((selection & DH_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && params_to_domparams(dh, params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && params_to_key(dh, params);

    return ok;
}

static int dh_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                     void *cbarg)
{
    DH *dh = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (dh == NULL)
        return 0;

    ossl_param_bld_init(&tmpl);

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && domparams_to_params(dh, &tmpl);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(dh, &tmpl);

    if (!ok
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;

    ok = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ok;
}

/* IMEXPORT = IMPORT + EXPORT */

# define DH_IMEXPORTABLE_PARAMETERS                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),      \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0)
# define DH_IMEXPORTABLE_PUBLIC_KEY                     \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define DH_IMEXPORTABLE_PRIVATE_KEY                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
static const OSSL_PARAM dh_all_types[] = {
    DH_IMEXPORTABLE_PARAMETERS,
    DH_IMEXPORTABLE_PUBLIC_KEY,
    DH_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM dh_parameter_types[] = {
    DH_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM dh_key_types[] = {
    DH_IMEXPORTABLE_PUBLIC_KEY,
    DH_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM *dh_types[] = {
    NULL,                        /* Index 0 = none of them */
    dh_parameter_types,          /* Index 1 = parameter types */
    dh_key_types,                /* Index 2 = key types */
    dh_all_types                 /* Index 3 = 1 + 2 */
};

static const OSSL_PARAM *dh_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        type_select += 2;
    return dh_types[type_select];
}

static const OSSL_PARAM *dh_import_types(int selection)
{
    return dh_imexport_types(selection);
}

static const OSSL_PARAM *dh_export_types(int selection)
{
    return dh_imexport_types(selection);
}

static ossl_inline int dh_get_params(void *key, OSSL_PARAM params[])
{
    DH *dh = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DH_security_bits(dh)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DH_size(dh)))
        return 0;
    return 1;
}

static const OSSL_PARAM dh_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dh_gettable_params(void)
{
    return dh_params;
}

const OSSL_DISPATCH dh_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dh_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dh_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dh_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))dh_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dh_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dh_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dh_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dh_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dh_export_types },
    { 0, NULL }
};
