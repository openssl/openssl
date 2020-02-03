/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/dh.h>
#include <openssl/err.h>
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* rsa_keymgmt_functions */
#include "prov/providercommonerr.h" /* PROV_R_BN_ERROR */
#include "serializer_local.h"

OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_dh_new(void)
{
    return ossl_prov_get_keymgmt_new(dh_keymgmt_functions);
}

OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_dh_free(void)
{
    return ossl_prov_get_keymgmt_free(dh_keymgmt_functions);
}

OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_dh_import(void)
{
    return ossl_prov_get_keymgmt_import(dh_keymgmt_functions);
}

int ossl_prov_print_dh(BIO *out, DH *dh, enum dh_print_type type)
{
    const char *type_label = NULL;
    const BIGNUM *priv_key = NULL, *pub_key = NULL;
    const BIGNUM *p = NULL, *g = NULL;


    switch (type) {
    case dh_print_priv:
        type_label = "DH Private-Key";
        break;
    case dh_print_pub:
        type_label = "DH Public-Key";
        break;
    case dh_print_params:
        type_label = "DH Parameters";
        break;
    }

    if (type == dh_print_priv) {
        priv_key = DH_get0_priv_key(dh);
        if (priv_key == NULL)
            goto null_err;
    }

    if (type == dh_print_priv || type == dh_print_pub) {
        pub_key = DH_get0_pub_key(dh);
        if (pub_key == NULL)
            goto null_err;
    }

    p = DH_get0_p(dh);
    g = DH_get0_g(dh);
    if (p == NULL || g == NULL)
        goto null_err;

    /*
     * TODO(3.0): add printing of:
     *
     * - q (label "subgroup order:")
     * - j (label "subgroup factor:")
     * - seed (label "seed:")
     * - counter (label "counter:")
     *
     * This can happen as soon as there are DH_get0_ functions for them.
     */

    if (ossl_prov_bio_printf(out, "%s: (%d bit)\n", type_label, BN_num_bits(p))
        <= 0)
        goto err;
    if (priv_key != NULL
        && !ossl_prov_print_labeled_bignum(out, "    private-key:", priv_key))
        goto err;
    if (pub_key != NULL
        && !ossl_prov_print_labeled_bignum(out, "    public-key:", pub_key))
        goto err;
    if (p != NULL
        && !ossl_prov_print_labeled_bignum(out, "    prime:", p))
        goto err;
    if (g != NULL
        && !ossl_prov_print_labeled_bignum(out, "    generator:", g))
        goto err;

    return 1;
 err:
    return 0;
 null_err:
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    goto err;
}

int ossl_prov_prepare_dh_params(const void *dh, int nid,
                                ASN1_STRING **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (nid == EVP_PKEY_DHX)
        params->length = i2d_DHxparams(dh, &params->data);
    else
        params->length = i2d_DHparams(dh, &params->data);

    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }
    params->type = V_ASN1_SEQUENCE;

    *pstr = params;
    *pstrtype = V_ASN1_SEQUENCE;
    return 1;
}

int ossl_prov_dh_pub_to_der(const void *dh, unsigned char **pder)
{
    ASN1_INTEGER *pub_key = BN_to_ASN1_INTEGER(DH_get0_pub_key(dh), NULL);
    int ret;

    if (pub_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(pub_key, pder);

    ASN1_STRING_clear_free(pub_key);
    return ret;
}

int ossl_prov_dh_priv_to_der(const void *dh, unsigned char **pder)
{
    ASN1_INTEGER *priv_key = BN_to_ASN1_INTEGER(DH_get0_priv_key(dh), NULL);
    int ret;

    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(priv_key, pder);

    ASN1_STRING_clear_free(priv_key);
    return ret;
}

