/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/objects.h>
#include <openssl/params.h>
#include "crypto/bn.h"
#include "crypto/ec.h"

/*
 * The intention with the "backend" source file is to offer backend support
 * for legacy backends (EVP_PKEY_ASN1_METHOD and EVP_PKEY_METHOD) and provider
 * implementations alike.
 */

int ec_set_ecdh_cofactor_mode(EC_KEY *ec, int mode)
{
    const EC_GROUP *ecg = EC_KEY_get0_group(ec);
    const BIGNUM *cofactor;
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

/*
 * Callers of ec_key_fromdata MUST make sure that ec_key_params_fromdata has
 * been called before!
 *
 * This function only gets the bare keypair, domain parameters and other
 * parameters are treated separately, and domain parameters are required to
 * define a keypair.
 */
int ec_key_fromdata(EC_KEY *ec, const OSSL_PARAM params[], int include_private)
{
    const OSSL_PARAM *param_priv_key = NULL, *param_pub_key = NULL;
    BN_CTX *ctx = NULL;
    BIGNUM *priv_key = NULL;
    unsigned char *pub_key = NULL;
    size_t pub_key_len;
    const EC_GROUP *ecg = NULL;
    EC_POINT *pub_point = NULL;
    int ok = 0;

    ecg = EC_KEY_get0_group(ec);
    if (ecg == NULL)
        return 0;

    param_pub_key =
        OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PUB_KEY);
    if (include_private)
        param_priv_key =
            OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_PRIV_KEY);

    ctx = BN_CTX_new_ex(ec_key_get_libctx(ec));
    if (ctx == NULL)
        goto err;

    /* OpenSSL decree: If there's a private key, there must be a public key */
    if (param_priv_key != NULL && param_pub_key == NULL)
        goto err;

    if (param_pub_key != NULL)
        if (!OSSL_PARAM_get_octet_string(param_pub_key,
                                         (void **)&pub_key, 0, &pub_key_len)
            || (pub_point = EC_POINT_new(ecg)) == NULL
            || !EC_POINT_oct2point(ecg, pub_point, pub_key, pub_key_len, ctx))
        goto err;

    if (param_priv_key != NULL && include_private) {
        int fixed_words;
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

        fixed_words = bn_get_top(order) + 2;

        if ((priv_key = BN_secure_new()) == NULL)
            goto err;
        if (bn_wexpand(priv_key, fixed_words) == NULL)
            goto err;
        BN_set_flags(priv_key, BN_FLG_CONSTTIME);

        if (!OSSL_PARAM_get_BN(param_priv_key, &priv_key))
            goto err;
    }

    if (priv_key != NULL
        && !EC_KEY_set_private_key(ec, priv_key))
        goto err;

    if (pub_point != NULL
        && !EC_KEY_set_public_key(ec, pub_point))
        goto err;

    ok = 1;

 err:
    BN_CTX_free(ctx);
    BN_clear_free(priv_key);
    OPENSSL_free(pub_key);
    EC_POINT_free(pub_point);
    return ok;
}

int ec_key_domparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
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
                || (curve_nid = ec_curve_name2nid(curve_name)) == NID_undef)
            goto err;

        if ((ecg = EC_GROUP_new_by_curve_name_ex(ec_key_get_libctx(ec),
                                                 curve_nid)) == NULL)
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

int ec_key_otherparams_fromdata(EC_KEY *ec, const OSSL_PARAM params[])
{
    const OSSL_PARAM *p;

    if (ec == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_USE_COFACTOR_ECDH);
    if (p != NULL) {
        int mode;

        if (!OSSL_PARAM_get_int(p, &mode)
            || !ec_set_ecdh_cofactor_mode(ec, mode))
            return 0;
    }
    return 1;
}
