/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/params.h>
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "crypto/dh.h"
#include "openssl/param_build.h"

static OSSL_OP_keymgmt_new_fn dh_newdata;
static OSSL_OP_keymgmt_free_fn dh_freedata;
static OSSL_OP_keymgmt_get_params_fn dh_get_params;
static OSSL_OP_keymgmt_gettable_params_fn dh_gettable_params;
static OSSL_OP_keymgmt_has_fn dh_has;
static OSSL_OP_keymgmt_match_fn dh_match;
static OSSL_OP_keymgmt_validate_fn dh_validate;
static OSSL_OP_keymgmt_import_fn dh_import;
static OSSL_OP_keymgmt_import_types_fn dh_import_types;
static OSSL_OP_keymgmt_export_fn dh_export;
static OSSL_OP_keymgmt_export_types_fn dh_export_types;

#define DH_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS)

static int domparams_to_params(DH *dh, OSSL_PARAM_BLD *tmpl)
{
    const BIGNUM *dh_p = NULL, *dh_g = NULL;

    if (dh == NULL)
        return 0;

    DH_get0_pqg(dh, &dh_p, NULL, &dh_g);
    if (dh_p != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, dh_p))
        return 0;
    if (dh_g != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, dh_g))
        return 0;

    return 1;
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
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, priv_key))
        return 0;
    if (pub_key != NULL
        && !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, pub_key))
        return 0;

    return 1;
}

static void *dh_newdata(void *provctx)
{
    return dh_new_with_ctx(PROV_LIBRARY_CONTEXT_OF(provctx));
}

static void dh_freedata(void *keydata)
{
    DH_free(keydata);
}

static int dh_has(void *keydata, int selection)
{
    DH *dh = keydata;
    int ok = 0;

    if (dh != NULL) {
        if ((selection & DH_POSSIBLE_SELECTIONS) != 0)
            ok = 1;

        if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
            ok = ok && (DH_get0_pub_key(dh) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
            ok = ok && (DH_get0_priv_key(dh) != NULL);
        if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
            ok = ok && (DH_get0_p(dh) != NULL && DH_get0_g(dh) != NULL);
    }
    return ok;
}

static int dh_match(const void *keydata1, const void *keydata2, int selection)
{
    const DH *dh1 = keydata1;
    const DH *dh2 = keydata2;
    int ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && BN_cmp(DH_get0_pub_key(dh1), DH_get0_pub_key(dh2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && BN_cmp(DH_get0_priv_key(dh1), DH_get0_priv_key(dh2)) == 0;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0) {
        FFC_PARAMS *dhparams1 = dh_get0_params((DH *)dh1);
        FFC_PARAMS *dhparams2 = dh_get0_params((DH *)dh2);

        ok = ok && ffc_params_cmp(dhparams1, dhparams2, 1);
    }
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
        ok = ok && ffc_fromdata(dh_get0_params(dh), params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && dh_key_fromdata(dh, params);

    return ok;
}

static int dh_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
                     void *cbarg)
{
    DH *dh = keydata;
    OSSL_PARAM_BLD *tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (dh == NULL)
        return 0;

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_ALL_PARAMETERS) != 0)
        ok = ok && domparams_to_params(dh, tmpl);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0)
        ok = ok && key_to_params(dh, tmpl);

    if (!ok
        || (params = OSSL_PARAM_BLD_to_param(tmpl)) == NULL) {
        OSSL_PARAM_BLD_free(tmpl);
        return 0;
    }
    OSSL_PARAM_BLD_free(tmpl);

    ok = param_cb(params, cbarg);
    OSSL_PARAM_BLD_free_params(params);
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

static int dh_validate_public(DH *dh)
{
    const BIGNUM *pub_key = NULL;

    DH_get0_key(dh, &pub_key, NULL);
    return DH_check_pub_key_ex(dh, pub_key);
}

static int dh_validate_private(DH *dh)
{
    int status = 0;
    const BIGNUM *priv_key = NULL;

    DH_get0_key(dh, NULL, &priv_key);
    return dh_check_priv_key(dh, priv_key, &status);;
}

static int dh_validate(void *keydata, int selection)
{
    DH *dh = keydata;
    int ok = 0;

    if ((selection & DH_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && DH_check_params_ex(dh);

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && dh_validate_public(dh);

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && dh_validate_private(dh);

    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR)
            == OSSL_KEYMGMT_SELECT_KEYPAIR)
        ok = ok && dh_check_pairwise(dh);
    return ok;
}

const OSSL_DISPATCH dh_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))dh_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))dh_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))dh_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))dh_gettable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))dh_has },
    { OSSL_FUNC_KEYMGMT_MATCH, (void (*)(void))dh_match },
    { OSSL_FUNC_KEYMGMT_VALIDATE, (void (*)(void))dh_validate },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))dh_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))dh_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))dh_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))dh_export_types },
    { 0, NULL }
};
