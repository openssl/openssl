/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"
#include "openssl/param_build.h"

static OSSL_OP_keymgmt_new_fn dsa_newdata;
static OSSL_OP_keymgmt_free_fn dsa_freedata;
static OSSL_OP_keymgmt_get_params_fn dsa_get_params;
static OSSL_OP_keymgmt_gettable_params_fn dsa_gettable_params;
static OSSL_OP_keymgmt_has_fn dsa_has;
static OSSL_OP_keymgmt_match_fn dsa_match;
static OSSL_OP_keymgmt_validate_fn dsa_validate;
static OSSL_OP_keymgmt_import_fn dsa_import;
static OSSL_OP_keymgmt_import_types_fn dsa_import_types;
static OSSL_OP_keymgmt_export_fn dsa_export;
static OSSL_OP_keymgmt_export_types_fn dsa_export_types;

#define DSA_DEFAULT_MD "SHA256"
#define DSA_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

static int domparams_to_params(DSA *dsa, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dsa_p = NULL, *dsa_q = NULL, *dsa_g = NULL;

    if (dsa == NULL)
        return 0;

    DSA_get0_pqg(dsa, &dsa_p, &dsa_q, &dsa_g);
    if (dsa_p != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dsa_p))
        return 0;
    if (dsa_q != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, dsa_q))
        return 0;
    if (dsa_g != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dsa_g))
        return 0;

    return 1;
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
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dsa_newdata(void *provctx)
{
    return dsa_new_with_ctx(PROV_LIBRARY_CONTEXT_OF(provctx));
}

static void dsa_freedata(void *keydata)
{
    DSA_free(keydata);
}

static int dsa_has(void *keydata, int selection)
{
    DSA *dsa = keydata;
    int ok = 0;

    if (dsa != NULL) {
        if ((selection & DSA_POSSIBLE_SELECTIONS) != 0)
            ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (DSA_get0_pub_key(dsa) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (DSA_get0_priv_key(dsa) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
            ok = ok && (DSA_get0_p(dsa) != NULL && DSA_get0_g(dsa) != NULL);
    }
    return ok;
}

static int dsa_match(const void *keydata1, const void *keydata2, int selection)
{
    const DSA *dsa1 = keydata1;
    const DSA *dsa2 = keydata2;
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok
            && BN_cmp(DSA_get0_pub_key(dsa1), DSA_get0_pub_key(dsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok
            && BN_cmp(DSA_get0_priv_key(dsa1), DSA_get0_priv_key(dsa2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        FFC_PARAMS *dsaparams1 = dsa_get0_params((DSA *)dsa1);
        FFC_PARAMS *dsaparams2 = dsa_get0_params((DSA *)dsa2);

        ok = ok && ffc_params_cmp(dsaparams1, dsaparams2, 1);
    }
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
        ok = ok && ffc_fromdata(dsa_get0_params(dsa), params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && dsa_key_fromdata(dsa, params);

    return ok;
}

static int dsa_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                      void *cbarg)
{
    DSA *dsa = keydata;
    OSSL_PARAM_BLD *tmpl = OSSL_PARAM_BLD_new();
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (dsa == NULL)
        goto err;;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && domparams_to_params(dsa, tmpl);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(dsa, tmpl);

    if (!ok
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL)
        goto err;;

    ok = param_cb(params, cbarg);
    OSSL_PARAM_BLD_free_params(params);
err:
    OSSL_PARAM_BLD_free(tmpl);
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

static int dsa_validate_domparams(DSA *dsa)
{
    int status = 0;

    return dsa_check_params(dsa, &status);
}

static int dsa_validate_public(DSA *dsa)
{
    int status = 0;
    const BIGNUM *pub_key = NULL;

    DSA_get0_key(dsa, &pub_key, NULL);
    return dsa_check_pub_key(dsa, pub_key, &status);
}

static int dsa_validate_private(DSA *dsa)
{
    int status = 0;
    const BIGNUM *priv_key = NULL;

    DSA_get0_key(dsa, NULL, &priv_key);
    return dsa_check_priv_key(dsa, priv_key, &status);
}

static int dsa_validate(void *keydata, int selection)
{
    DSA *dsa = keydata;
    int ok = 0;

    if ((selection & DSA_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && dsa_validate_domparams(dsa);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && dsa_validate_public(dsa);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && dsa_validate_private(dsa);

    /* If the whole key is selected, we do a pairwise validation */
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
        == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && dsa_check_pairwise(dsa);
    return ok;
}

const OSSL_DISPATCH dsa_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dsa_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dsa_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dsa_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))dsa_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dsa_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dsa_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dsa_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dsa_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dsa_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dsa_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dsa_export_types },
    { 0, NULL }
};
