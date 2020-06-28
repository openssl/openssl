/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include "crypto/ec.h"
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* ec_keymgmt_functions */
#include "prov/providercommonerr.h" /* PROV_R_MISSING_OID */
#include "serializer_local.h"

void ec_get_new_free_import(OSSL_FUNC_keymgmt_new_fn **ec_new,
                            OSSL_FUNC_keymgmt_free_fn **ec_free,
                            OSSL_FUNC_keymgmt_import_fn **ec_import)
{
    *ec_new = ossl_prov_get_keymgmt_new(ec_keymgmt_functions);
    *ec_free = ossl_prov_get_keymgmt_free(ec_keymgmt_functions);
    *ec_import = ossl_prov_get_keymgmt_import(ec_keymgmt_functions);
}

static int ossl_prov_print_ec_param(BIO *out, const EC_GROUP *group)
{
    const char *curve_name;
    int curve_nid = EC_GROUP_get_curve_name(group);

    /* TODO(3.0): Explicit parameters are currently not supported */
    if (curve_nid == NID_undef)
        return 0;

    if (BIO_printf(out, "%s: %s\n", "ASN1 OID", OBJ_nid2sn(curve_nid)) <= 0)
        return 0;

    /* TODO(3.0): Only named curves are currently supported */
    curve_name = EC_curve_nid2nist(curve_nid);
    return (curve_name == NULL
            || BIO_printf(out, "%s: %s\n", "NIST CURVE", curve_name) > 0);
}

int ossl_prov_print_eckey(BIO *out, EC_KEY *eckey, enum ec_print_type type)
{
    int ret = 0;
    const char *type_label = NULL;
    unsigned char *priv = NULL, *pub = NULL;
    size_t priv_len = 0, pub_len = 0;
    const EC_GROUP *group;

    if (eckey == NULL || (group = EC_KEY_get0_group(eckey)) == NULL)
        goto null_err;

    switch (type) {
    case ec_print_priv:
        type_label = "Private-Key";
        break;
    case ec_print_pub:
        type_label = "Public-Key";
        break;
    case ec_print_params:
        type_label = "EC-Parameters";
        break;
    }

    if (type == ec_print_priv) {
        const BIGNUM *priv_key = EC_KEY_get0_private_key(eckey);

        if (priv_key == NULL)
            goto null_err;
        priv_len = EC_KEY_priv2buf(eckey, &priv);
        if (priv_len == 0)
            goto err;
    }

    if (type == ec_print_priv || type == ec_print_pub) {
        const EC_POINT *pub_pt = EC_KEY_get0_public_key(eckey);

        if (pub_pt == NULL)
            goto null_err;

        pub_len = EC_KEY_key2buf(eckey, EC_KEY_get_conv_form(eckey), &pub, NULL);
        if (pub_len == 0)
            goto err;
    }

    if (BIO_printf(out, "%s: (%d bit)\n", type_label,
                   EC_GROUP_order_bits(group)) <= 0)
        goto err;
    if (priv != NULL
        && !ossl_prov_print_labeled_buf(out, "priv:", priv, priv_len))
        goto err;
    if (pub != NULL
        && !ossl_prov_print_labeled_buf(out, "pub:", pub, pub_len))
        goto err;
    ret = ossl_prov_print_ec_param(out, group);
err:
    OPENSSL_clear_free(priv, priv_len);
    OPENSSL_free(pub);
    return ret;
null_err:
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    goto err;
}

int ossl_prov_prepare_ec_params(const void *eckey, int nid,
                                void **pstr, int *pstrtype)
{
    int curve_nid;
    const EC_GROUP *group = EC_KEY_get0_group(eckey);
    ASN1_OBJECT *params;

    if (group == NULL
        || ((curve_nid = EC_GROUP_get_curve_name(group)) == NID_undef)
        || ((params = OBJ_nid2obj(curve_nid)) == NULL)) {
        /* TODO(3.0): Explicit curves are not supported */
        return 0;
    }

    if (OBJ_length(params) == 0) {
        /* Some curves might not have an associated OID */
        ERR_raise(ERR_LIB_PROV, PROV_R_MISSING_OID);
        ASN1_OBJECT_free(params);
        return 0;
    }

    *pstr = params;
    *pstrtype = V_ASN1_OBJECT;
    return 1;
}

int ossl_prov_ec_pub_to_der(const void *eckey, unsigned char **pder)
{
    return i2o_ECPublicKey(eckey, pder);
}

int ossl_prov_ec_priv_to_der(const void *veckey, unsigned char **pder)
{
    EC_KEY *eckey = (EC_KEY *)veckey;
    unsigned int old_flags;
    int ret = 0;

    /*
     * For PKCS8 the curve name appears in the PKCS8_PRIV_KEY_INFO object
     * as the pkeyalg->parameter field. (For a named curve this is an OID)
     * The pkey field is an octet string that holds the encoded
     * ECPrivateKey SEQUENCE with the optional parameters field omitted.
     * We omit this by setting the EC_PKEY_NO_PARAMETERS flag.
     */
    old_flags = EC_KEY_get_enc_flags(eckey); /* save old flags */
    EC_KEY_set_enc_flags(eckey, old_flags | EC_PKEY_NO_PARAMETERS);
    ret = i2d_ECPrivateKey(eckey, pder);
    EC_KEY_set_enc_flags(eckey, old_flags); /* restore old flags */
    return ret; /* return the length of the der encoded data */
}
