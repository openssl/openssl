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

#include <openssl/dsa.h>
#include <openssl/err.h>
#include "prov/bio.h"             /* ossl_prov_bio_printf() */
#include "prov/implementations.h" /* rsa_keymgmt_functions */
#include "prov/providercommonerr.h" /* PROV_R_BN_ERROR */
#include "serializer_local.h"

OSSL_OP_keymgmt_new_fn *ossl_prov_get_keymgmt_dsa_new(void)
{
    return ossl_prov_get_keymgmt_new(dsa_keymgmt_functions);
}

OSSL_OP_keymgmt_free_fn *ossl_prov_get_keymgmt_dsa_free(void)
{
    return ossl_prov_get_keymgmt_free(dsa_keymgmt_functions);
}

OSSL_OP_keymgmt_import_fn *ossl_prov_get_keymgmt_dsa_import(void)
{
    return ossl_prov_get_keymgmt_import(dsa_keymgmt_functions);
}

int ossl_prov_print_dsa(BIO *out, DSA *dsa, enum dsa_print_type type)
{
    const char *type_label = NULL;
    const BIGNUM *priv_key = NULL, *pub_key = NULL;
    const BIGNUM *p = NULL, *q = NULL, *g = NULL;


    switch (type) {
    case dsa_print_priv:
        type_label = "Private-Key";
        break;
    case dsa_print_pub:
        type_label = "Public-Key";
        break;
    case dsa_print_params:
        type_label = "DSA-Parameters";
        break;
    }

    if (type == dsa_print_priv) {
        priv_key = DSA_get0_priv_key(dsa);
        if (priv_key == NULL)
            goto null_err;
    }

    if (type == dsa_print_priv || type == dsa_print_pub) {
        pub_key = DSA_get0_pub_key(dsa);
        if (pub_key == NULL)
            goto null_err;
    }

    p = DSA_get0_p(dsa);
    q = DSA_get0_q(dsa);
    g = DSA_get0_p(dsa);

    if (p == NULL || q == NULL || g == NULL)
        goto null_err;

    if (ossl_prov_bio_printf(out, "%s: (%d bit)\n", type_label, BN_num_bits(p))
        <= 0)
        goto err;
    if (priv_key != NULL
        && !ossl_prov_print_labeled_bignum(out, "priv:", priv_key))
        goto err;
    if (pub_key != NULL
        && !ossl_prov_print_labeled_bignum(out, "pub: ", pub_key))
        goto err;
    if (!ossl_prov_print_labeled_bignum(out, "P:   ", p))
        goto err;
    if (!ossl_prov_print_labeled_bignum(out, "Q:   ", q))
        goto err;
    if (!ossl_prov_print_labeled_bignum(out, "G:   ", g))
        goto err;

    return 1;
 err:
    return 0;
 null_err:
    ERR_raise(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER);
    goto err;
}

int ossl_prov_prepare_dsa_params(const void *dsa, int nid,
                                ASN1_STRING **pstr, int *pstrtype)
{
    ASN1_STRING *params = ASN1_STRING_new();

    if (params == NULL) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    params->length = i2d_DSAparams(dsa, &params->data);

    if (params->length <= 0) {
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
        ASN1_STRING_free(params);
        return 0;
    }

    *pstrtype = V_ASN1_SEQUENCE;
    *pstr = params;
    return 1;
}

int ossl_prov_prepare_all_dsa_params(const void *dsa, int nid,
                                     ASN1_STRING **pstr, int *pstrtype)
{
    const BIGNUM *p = DSA_get0_p(dsa);
    const BIGNUM *q = DSA_get0_q(dsa);
    const BIGNUM *g = DSA_get0_g(dsa);

    if (p != NULL && q != NULL && g != NULL)
        return ossl_prov_prepare_dsa_params(dsa, nid, pstr, pstrtype);

    *pstr = NULL;
    *pstrtype = V_ASN1_UNDEF;
    return 1;
}

int ossl_prov_dsa_pub_to_der(const void *dsa, unsigned char **pder)
{
    ASN1_INTEGER *pub_key = BN_to_ASN1_INTEGER(DSA_get0_pub_key(dsa), NULL);
    int ret;

    if (pub_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(pub_key, pder);

    ASN1_STRING_clear_free(pub_key);
    return ret;
}

int ossl_prov_dsa_priv_to_der(const void *dsa, unsigned char **pder)
{
    ASN1_INTEGER *priv_key = BN_to_ASN1_INTEGER(DSA_get0_priv_key(dsa), NULL);
    int ret;

    if (priv_key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_BN_ERROR);
        return 0;
    }

    ret = i2d_ASN1_INTEGER(priv_key, pder);

    ASN1_STRING_clear_free(priv_key);
    return ret;
}
