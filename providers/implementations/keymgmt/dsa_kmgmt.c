/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/params.h>
#include "internal/param_build.h"
#include "crypto/dsa.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"

static OSSL_OP_keymgmt_new_fn dsa_newdata;
static OSSL_OP_keymgmt_free_fn dsa_freedata;
static OSSL_OP_keymgmt_get_params_fn dsa_get_params;
static OSSL_OP_keymgmt_gettable_params_fn dsa_gettable_params;
static OSSL_OP_keymgmt_has_fn dsa_has;
static OSSL_OP_keymgmt_import_fn dsa_import;
static OSSL_OP_keymgmt_import_types_fn dsa_import_types;
static OSSL_OP_keymgmt_export_fn dsa_export;
static OSSL_OP_keymgmt_export_types_fn dsa_export_types;

#define DSA_DEFAULT_MD "SHA256"
#define DSA_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

static int params_to_domparams(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_p, *param_q, *param_g;
    BIGNUM *p = NULL, *q = NULL, *g = NULL;

    if (dsa == NULL)
        return 0;

    param_p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_P);
    param_q = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_Q);
    param_g = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_FFC_G);

    if ((param_p != NULL && !OSSL_PARAM_get_BN(param_p, &p))
        || (param_q != NULL && !OSSL_PARAM_get_BN(param_q, &q))
        || (param_g != NULL && !OSSL_PARAM_get_BN(param_g, &g)))
        goto err;

    if (!DSA_set0_pqg(dsa, p, q, g))
        goto err;

    return 1;

 err:
    BN_free(p);
    BN_free(q);
    BN_free(g);
    return 0;
}

static int domparams_to_params(DSA *dsa, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);
    if (dsa_p != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dsa_p))
        return 0;
    if (dsa_q != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, dsa_q))
        return 0;
    if (dsa_g != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dsa_g))
        return 0;

    return 1;
}

static int params_to_key(DSA *dsa, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;

    if (!params_to_domparams(dsa, params))
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /*
     * DSA documentation says that a public key must be present if a private key
     * is.
     */
    if (param_priv_key != NULL && param_pub_key == NULL)
        return 0;

    if ((param_priv_key != NULL
         && !OSSL_PARAM_get_BN(param_priv_key, &priv_key))
        || (param_pub_key != NULL
            && !OSSL_PARAM_get_BN(param_pub_key, &pub_key)))
        goto err;

    if (pub_key != NULL && !DSA_set0_key(dsa, pub_key, priv_key))
        goto err;

    return 1;

 err:
    BN_free(priv_key);
    BN_free(pub_key);
    return 0;
}

static int key_to_params(DSA *dsa, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *priv_key = NULL, *pub_key = NULL;

    if (dsa == NULL)
        return 0;
    if (!domparams_to_params(dsa, tmpl))
        return 0;

    DSA_get0_key(dsa, &pub_key, &priv_key);
    if (priv_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !ossl_param_bld_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dsa_newdata(void *provctx)
{
    return DSA_new();
}

static void dsa_freedata(void *keydata)
{
    DSA_free(keydata);
}

static int dsa_has(void *keydata, int selection)
{
    DSA *dsa = keydata;
    int ok = 0;

    if ((selection & DSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (DSA_get0_pub_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (DSA_get0_priv_key(dsa) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (DSA_get0_p(dsa) != NULL && DSA_get0_g(dsa) != NULL);
    return ok;
}

static int dsa_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    DSA *dsa = keydata;
    int ok = 0;

    if (dsa == NULL)
        return 0;

    if ((selection & DSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && params_to_domparams(dsa, params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && params_to_key(dsa, params);

    return ok;
}

static int dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    DSA *dsa = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (dsa == NULL)
        return 0;

    ossl_param_bld_init(&tmpl);

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && domparams_to_params(dsa, &tmpl);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(dsa, &tmpl);

    if (!ok
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;

    ok = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ok;
}

/* IMEXPORT = IMPORT + EXPORT */

# define DSA_IMEXPORTABLE_PARAMETERS                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_P, NULL, 0),      \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_Q, NULL, 0),      \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_FFC_G, NULL, 0)
# define DSA_IMEXPORTABLE_PUBLIC_KEY                    \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define DSA_IMEXPORTABLE_PRIVATE_KEY                   \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
static const OSSL_PARAM dsa_all_types[] = {
    DSA_IMEXPORTABLE_PARAMETERS,
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM dsa_parameter_types[] = {
    DSA_IMEXPORTABLE_PARAMETERS,
    OSSL_PARAM_END
};
static const OSSL_PARAM dsa_key_types[] = {
    DSA_IMEXPORTABLE_PUBLIC_KEY,
    DSA_IMEXPORTABLE_PRIVATE_KEY,
    OSSL_PARAM_END
};
static const OSSL_PARAM *dsa_types[] = {
    NULL,                        /* Index 0 = none of them */
    dsa_parameter_types,          /* Index 1 = parameter types */
    dsa_key_types,                /* Index 2 = key types */
    dsa_all_types                 /* Index 3 = 1 + 2 */
};

static const OSSL_PARAM *dsa_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        type_select += 2;
    return dsa_types[type_select];
}

static const OSSL_PARAM *dsa_import_types(int selection)
{
    return dsa_imexport_types(selection);
}

static const OSSL_PARAM *dsa_export_types(int selection)
{
    return dsa_imexport_types(selection);
}

static ossl_inline int dsa_get_params(void *key, OSSL_PARAM params[])
{
    DSA *dsa = key;
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_security_bits(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, DSA_size(dsa)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_DEFAULT_DIGEST)) != NULL
        && !OSSL_PARAM_set_utf8_string(p, DSA_DEFAULT_MD))
        return 0;
    return 1;
}

static const OSSL_PARAM dsa_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_DEFAULT_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsa_gettable_params(void)
{
    return dsa_params;
}

const OSSL_DISPATCH dsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))dsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dsa_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dsa_export_types },
    { 0, NULL }
};
