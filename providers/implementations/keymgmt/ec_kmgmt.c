/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDH/ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include "crypto/bn.h"
#include "internal/param_build.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"

static OSSL_OP_keymgmt_new_fn ec_newdata;
static OSSL_OP_keymgmt_free_fn ec_freedata;
static OSSL_OP_keymgmt_get_params_fn ec_get_params;
static OSSL_OP_keymgmt_gettable_params_fn ec_gettable_params;
static OSSL_OP_keymgmt_set_params_fn ec_set_params;
static OSSL_OP_keymgmt_settable_params_fn ec_settable_params;
static OSSL_OP_keymgmt_has_fn ec_has;
static OSSL_OP_keymgmt_import_fn ec_import;
static OSSL_OP_keymgmt_import_types_fn ec_import_types;
static OSSL_OP_keymgmt_export_fn ec_export;
static OSSL_OP_keymgmt_export_types_fn ec_export_types;
static OSSL_OP_keymgmt_query_operation_name_fn ec_query_operation_name;

#define EC_POSSIBLE_SELECTIONS                 \
    (OSSL_KEYMGMT_SELECT_KEYPAIR | OSSL_KEYMGMT_SELECT_ALL_PARAMETERS )

static
const char *ec_query_operation_name(int operation_id)
{
    switch (operation_id) {
    case OSSL_OP_KEYEXCH:
        return "ECDH";
#if 0
    case OSSL_OP_SIGNATURE:
        return deflt_signature;
#endif
    }
    return NULL;
}

static ossl_inline
int params_to_domparams(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *param_ec_name;
    EC_GROUP *ecg = NULL;
    char *curve_name = NULL;
    int ok = 0;

    if (ec == NULL)
        return 0;

    param_ec_name = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_EC_NAME);
    if (param_ec_name == NULL) {
        /* explicit parameters */

        /*
         * TODO(3.0): should we support explicit parameters curves?
         */
        return 0;
    } else {
        /* named curve */
        int curve_nid;

        if (!OSSL_PARAM_get_utf8_string(param_ec_name, &curve_name, 0)
                || curve_name == NULL
                || (curve_nid = OBJ_sn2nid(curve_name)) == NID_undef)
            goto err;

        if ((ecg = EC_GROUP_new_by_curve_name(curve_nid)) == NULL)
            goto err;
    }

    if (!EC_KEY_set_group(ec, ecg))
        goto err;

    /*
     * TODO(3.0): if the group has changed, should we invalidate the private and
     * public key?
     */

    ok = 1;

 err:
    OPENSSL_free(curve_name);
    EC_GROUP_free(ecg);
    return ok;
}

static ossl_inline
int domparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl)
{
    const EC_GROUP *ecg;
    int curve_nid;

    if (ec == NULL)
        return 0;

    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    curve_nid = EC_GROUP_get_curve_name(ecg);

    if (curve_nid == NID_undef) {
        /* explicit parameters */

        /*
         * TODO(3.0): should we support explicit parameters curves?
         */
        return 0;
    } else {
        /* named curve */
        const char *curve_name = NULL;

        if ((curve_name = OBJ_nid2sn(curve_nid)) == NULL)
            return 0;

        if (!ossl_param_bld_push_utf8_string(tmpl, OSSL_PKEY_PARAM_EC_NAME, curve_name, 0))
            return 0;
    }

    return 1;
}

/*
 * Callers of params_to_key MUST make sure that params_to_domparams has been
 * called before!
 *
 * This function only imports the bare keypair, domain parameters and other
 * parameters are imported separately, and domain parameters are required to
 * define a keypair.
 */
static ossl_inline
int params_to_key(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *param_priv_key, *param_pub_key;
    BIGNUM *priv_key = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len;
    const EC_GROUP *ecg = NULL;
    EC_POINT *pub_point = NULL;
    int ok = 0;

    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    param_priv_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);
    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);

    /*
     * We want to have at least a public key either way, so we end up
     * requiring it unconditionally.
     */
    if (param_pub_key == NULL
            || !OSSL_PARAM_get_octet_string(param_pub_key,
                                            (void **)&pub_key, 0, &pub_key_len)
            || (pub_point = EC_POINT_new(ecg)) == NULL
            || !EC_POINT_oct2point(ecg, pub_point,
                                   pub_key, pub_key_len, NULL))
        goto err;

    if (param_priv_key != NULL && include_private) {
        int fixed_top;
        const BIGNUM *order;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
         *
         * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
         * to preallocate the BIGNUM internal buffer to a fixed public size big
         * enough that operations performed during the processing never trigger
         * a realloc which would leak the size of the scalar through memory
         * accesses.
         *
         * Fixed Length
         * ------------
         *
         * The order of the large prime subgroup of the curve is our choice for
         * a fixed public size, as that is generally the upper bound for
         * generating a private key in EC cryptosystems and should fit all valid
         * secret scalars.
         *
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of "words"
         * required for the internal representation of the order, and we
         * preallocate 2 extra "words" in case any of the subsequent processing
         * might temporarily overflow the order length.
         */
        order = EC_GROUP_get0_order(ecg);
        if (order == NULL || BN_is_zero(order))
            goto err;

        fixed_top = bn_get_top(order) + 2;

        if ((priv_key = BN_new()) == NULL)
            goto err;
        if (bn_wexpand(priv_key, fixed_top) == NULL)
            goto err;
        BN_set_flags(priv_key, BN_FLG_CONSTTIME);

        if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
            goto err;
    }

    if (priv_key != NULL
            && !EC_KEY_set_private_key(ec, priv_key))
        goto err;

    if (!EC_KEY_set_public_key(ec, pub_point))
        goto err;

    ok = 1;

 err:
    BN_clear_free(priv_key);
    OPENSSL_free(pub_key);
    EC_POINT_free(pub_point);
    return ok;
}

/*
 * Callers of key_to_params MUST make sure that domparams_to_params is also
 * called!
 *
 * This function only exports the bare keypair, domain parameters and other
 * parameters are exported separately.
 */
static ossl_inline
int key_to_params(const EC_KEY *eckey, OSSL_PARAM_BLD *tmpl, int include_private)
{
    const BIGNUM *priv_key = NULL;
    const EC_POINT *pub_point = NULL;
    const EC_GROUP *ecg = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len = 0;
    int ret = 0;

    if (eckey == NULL)
        return 0;

    ecg = EC_KEY_get0_group(eckey);
    priv_key = EC_KEY_get0_private_key(eckey);
    pub_point = EC_KEY_get0_public_key(eckey);

    /* group and public_key must be present, priv_key is optional */
    if (ecg == NULL || pub_point == NULL)
        return 0;
    if ((pub_key_len = EC_POINT_point2buf(ecg, pub_point,
                                          POINT_CONVERSION_COMPRESSED,
                                          &pub_key, NULL)) == 0)
        return 0;

    if (!ossl_param_bld_push_octet_string(tmpl,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, pub_key_len))
        goto err;

    if (priv_key != NULL && include_private) {
        size_t sz;
        int ecbits;

        /*
         * Key import/export should never leak the bit length of the secret
         * scalar in the key.
         *
         * For this reason, on export we use padded BIGNUMs with fixed length.
         *
         * When importing we also should make sure that, even if short lived,
         * the newly created BIGNUM is marked with the BN_FLG_CONSTTIME flag as
         * soon as possible, so that any processing of this BIGNUM might opt for
         * constant time implementations in the backend.
         *
         * Setting the BN_FLG_CONSTTIME flag alone is never enough, we also have
         * to preallocate the BIGNUM internal buffer to a fixed public size big
         * enough that operations performed during the processing never trigger
         * a realloc which would leak the size of the scalar through memory
         * accesses.
         *
         * Fixed Length
         * ------------
         *
         * The order of the large prime subgroup of the curve is our choice for
         * a fixed public size, as that is generally the upper bound for
         * generating a private key in EC cryptosystems and should fit all valid
         * secret scalars.
         *
         * For padding on export we just use the bit length of the order
         * converted to bytes (rounding up).
         *
         * For preallocating the BIGNUM storage we look at the number of "words"
         * required for the internal representation of the order, and we
         * preallocate 2 extra "words" in case any of the subsequent processing
         * might temporarily overflow the order length.
         */
        ecbits = EC_GROUP_order_bits(ecg);
        if (ecbits <= 0)
            goto err;
        sz = (ecbits + 7 ) / 8;
        if (!ossl_param_bld_push_BN_pad(tmpl,
                                        OSSL_PKEY_PARAM_PRIV_KEY,
                                        priv_key, sz))
            goto err;
    }

    ret = 1;

 err:
    OPENSSL_free(pub_key);
    return ret;
}

static ossl_inline
int ec_set_param_ecdh_cofactor_mode(EC_KEY *ec, const OSSL_PARAM *p)
{
    const EC_GROUP *ecg = EC_KEY_get0_group(ec);
    const BIGNUM *cofactor;
    int mode;

    if (!OSSL_PARAM_get_int(p, &mode))
        return 0;

    /*
     * mode can be only 0 for disable, or 1 for enable here.
     *
     * This is in contrast with the same parameter on an ECDH EVP_PKEY_CTX that
     * also supports mode == -1 with the meaning of "reset to the default for
     * the associated key".
     */
    if (mode < 0 || mode > 1)
        return 0;

    if ((cofactor = EC_GROUP_get0_cofactor(ecg)) == NULL )
        return 0;

    /* ECDH cofactor mode has no effect if cofactor is 1 */
    if (BN_is_one(cofactor))
        return 1;

    if (mode == 1)
        EC_KEY_set_flags(ec, EC_FLAG_COFACTOR_ECDH);
    else if (mode == 0)
        EC_KEY_clear_flags(ec, EC_FLAG_COFACTOR_ECDH);

    return 1;
}

static ossl_inline
int params_to_otherparams(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (ec == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL && !ec_set_param_ecdh_cofactor_mode(ec, p))
        return 0;

    return 1;
}

static ossl_inline
int otherparams_to_params(const EC_KEY *ec, OSSL_PARAM_BLD *tmpl)
{
    int ecdh_cofactor_mode = 0;

    if (ec == NULL)
        return 0;

    ecdh_cofactor_mode =
        (EC_KEY_get_flags(ec) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;
    if (!ossl_param_bld_push_int(tmpl,
                OSSL_PKEY_PARAM_USE_COFACTOR_ECDH,
                ecdh_cofactor_mode))
        return 0;

    return 1;
}

static
void *ec_newdata(void *provctx)
{
    return EC_KEY_new();
}

static
void ec_freedata(void *keydata)
{
    EC_KEY_free(keydata);
}

static
int ec_has(void *keydata, int selection)
{
    EC_KEY *ec = keydata;
    int ok = 0;

    if ((selection & EC_POSSIBLE_SELECTIONS) != 0)
        ok = 1;

    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        ok = ok && (EC_KEY_get0_public_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        ok = ok && (EC_KEY_get0_private_key(ec) != NULL);
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && (EC_KEY_get0_group(ec) != NULL);
    /*
     * We consider OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS to always be available,
     * so no extra check is needed other than the previous one against
     * EC_POSSIBLE_SELECTIONS.
     */

    return ok;
}

static
int ec_import(void *keydata, int selection, const OSSL_PARAM params[])
{
    EC_KEY *ec = keydata;
    int ok = 0;

    if (ec == NULL)
        return 0;

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters only
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters must be requested only alongside a key
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && params_to_domparams(ec, params);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && params_to_key(ec, params, include_private);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && params_to_otherparams(ec, params);

    return ok;
}

static
int ec_export(void *keydata, int selection, OSSL_CALLBACK *param_cb,
              void *cbarg)
{
    EC_KEY *ec = keydata;
    OSSL_PARAM_BLD tmpl;
    OSSL_PARAM *params = NULL;
    int ok = 1;

    if (ec == NULL)
        return 0;

    /*
     * In this implementation, we can export/import only keydata in the
     * following combinations:
     *   - domain parameters only
     *   - public key with associated domain parameters (+optional other params)
     *   - private key with associated public key and domain parameters
     *         (+optional other params)
     *
     * This means:
     *   - domain parameters must always be requested
     *   - private key must be requested alongside public key
     *   - other parameters must be requested only alongside a key
     */
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0
            && (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
        return 0;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0
            && (selection & OSSL_KEYMGMT_SELECT_KEYPAIR) == 0)
        return 0;

    ossl_param_bld_init(&tmpl);

    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        ok = ok && domparams_to_params(ec, &tmpl);
    if ((selection & OSSL_KEYMGMT_SELECT_KEYPAIR) != 0) {
        int include_private =
            selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY ? 1 : 0;

        ok = ok && key_to_params(ec, &tmpl, include_private);
    }
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        ok = ok && otherparams_to_params(ec, &tmpl);

    if (!ok
        || (params = ossl_param_bld_to_param(&tmpl)) == NULL)
        return 0;

    ok = param_cb(params, cbarg);
    ossl_param_bld_free(params);
    return ok;
}

/* IMEXPORT = IMPORT + EXPORT */

# define EC_IMEXPORTABLE_DOM_PARAMETERS                          \
    OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_EC_NAME, NULL, 0)
# define EC_IMEXPORTABLE_PUBLIC_KEY                              \
    OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY, NULL, 0)
# define EC_IMEXPORTABLE_PRIVATE_KEY                             \
    OSSL_PARAM_BN(OSSL_PKEY_PARAM_PRIV_KEY, NULL, 0)
# define EC_IMEXPORTABLE_OTHER_PARAMETERS                        \
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL)

/*
 * Include all the possible combinations of OSSL_PARAM arrays for
 * ec_imexport_types().
 *
 * They are in a separate file as it is ~100 lines of unreadable and
 * uninteresting machine generated stuff.
 *
 * TODO(3.0): the generated list looks quite ugly, as to cover all possible
 * combinations of the bits in `selection`, it also includes combinations that
 * are not really useful: we might want to consider alternatives to this
 * solution.
 */
#include "ec_kmgmt_imexport.inc"

static ossl_inline
const OSSL_PARAM *ec_imexport_types(int selection)
{
    int type_select = 0;

    if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) != 0)
        type_select += 1;
    if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) != 0)
        type_select += 2;
    if ((selection & OSSL_KEYMGMT_SELECT_DOMAIN_PARAMETERS) != 0)
        type_select += 4;
    if ((selection & OSSL_KEYMGMT_SELECT_OTHER_PARAMETERS) != 0)
        type_select += 8;
    return ec_types[type_select];
}

static
const OSSL_PARAM *ec_import_types(int selection)
{
    return ec_imexport_types(selection);
}

static
const OSSL_PARAM *ec_export_types(int selection)
{
    return ec_imexport_types(selection);
}

static
int ec_get_params(void *key, OSSL_PARAM params[])
{
    EC_KEY *eck = key;
    const EC_GROUP *ecg = NULL;
    OSSL_PARAM *p;

    ecg = EC_KEY_get0_group(eck);
    if (ecg == NULL)
        return 0;

    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE)) != NULL
        && !OSSL_PARAM_set_int(p, ECDSA_size(eck)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS)) != NULL
        && !OSSL_PARAM_set_int(p, EC_GROUP_order_bits(ecg)))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS)) != NULL) {
        int ecbits, sec_bits;

        ecbits = EC_GROUP_order_bits(ecg);

        /*
         * The following estimates are based on the values published
         * in Table 2 of "NIST Special Publication 800-57 Part 1 Revision 4"
         * at http://dx.doi.org/10.6028/NIST.SP.800-57pt1r4 .
         *
         * Note that the above reference explicitly categorizes algorithms in a
         * discrete set of values {80, 112, 128, 192, 256}, and that it is
         * relevant only for NIST approved Elliptic Curves, while OpenSSL
         * applies the same logic also to other curves.
         *
         * Classifications produced by other standardazing bodies might differ,
         * so the results provided for "bits of security" by this provider are
         * to be considered merely indicative, and it is the users'
         * responsibility to compare these values against the normative
         * references that may be relevant for their intent and purposes.
         */
        if (ecbits >= 512)
            sec_bits = 256;
        else if (ecbits >= 384)
            sec_bits = 192;
        else if (ecbits >= 256)
            sec_bits = 128;
        else if (ecbits >= 224)
            sec_bits = 112;
        else if (ecbits >= 160)
            sec_bits = 80;
        else
            sec_bits = ecbits / 2;

        if (!OSSL_PARAM_set_int(p, sec_bits))
            return 0;
    }

    p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL) {
        int ecdh_cofactor_mode = 0;

        ecdh_cofactor_mode =
            (EC_KEY_get_flags(eck) & EC_FLAG_COFACTOR_ECDH) ? 1 : 0;

        if (!OSSL_PARAM_set_int(p, ecdh_cofactor_mode))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM ec_known_gettable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *ec_gettable_params(void)
{
    return ec_known_gettable_params;
}

static const OSSL_PARAM ec_known_settable_params[] = {
    OSSL_PARAM_int(OSSL_PKEY_PARAM_USE_COFACTOR_ECDH, NULL),
    OSSL_PARAM_END
};

static
const OSSL_PARAM *ec_settable_params(void)
{
    return ec_known_settable_params;
}

static
int ec_set_params(void *key, const OSSL_PARAM params[])
{
    EC_KEY *eck = key;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL && !ec_set_param_ecdh_cofactor_mode(eck, p))
        return 0;

    return 1;
}

const OSSL_DISPATCH ec_keymgmt_functions[] = {
    { OSSL_FUNC_KEYMGMT_NEW, (void (*)(void))ec_newdata },
    { OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))ec_freedata },
    { OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*) (void))ec_get_params },
    { OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*) (void))ec_gettable_params },
    { OSSL_FUNC_KEYMGMT_SET_PARAMS, (void (*) (void))ec_set_params },
    { OSSL_FUNC_KEYMGMT_SETTABLE_PARAMS, (void (*) (void))ec_settable_params },
    { OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))ec_has },
    { OSSL_FUNC_KEYMGMT_IMPORT, (void (*)(void))ec_import },
    { OSSL_FUNC_KEYMGMT_IMPORT_TYPES, (void (*)(void))ec_import_types },
    { OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))ec_export },
    { OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))ec_export_types },
    { OSSL_FUNC_KEYMGMT_QUERY_OPERATION_NAME,
        (void (*)(void))ec_query_operation_name },
    { 0, NULL }
};
