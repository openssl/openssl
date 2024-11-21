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
#include <openssl/params.h>
#include <openssl/x509.h>
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"

SLH_DSA_KEY *ossl_slh_dsa_key_from_pkcs8(const PKCS8_PRIV_KEY_INFO *p8_info,
                                         OSSL_LIB_CTX *lib_ctx, const char *propq)
{
    SLH_DSA_KEY *key = NULL;
    const X509_ALGOR *alg;
    const uint8_t *p;
    int nid, p_len, alg_param_type = 0;
    ASN1_OCTET_STRING *oct = NULL;
    const char *alg_name = NULL;

    if (!PKCS8_pkey_get0(NULL, &p, &p_len, &alg, p8_info))
        return 0;

    X509_ALGOR_get0(NULL, &alg_param_type, NULL, alg);
    if (alg_param_type != V_ASN1_UNDEF)
        return 0;

    oct = d2i_ASN1_OCTET_STRING(NULL, &p, p_len);
    if (oct == NULL) {
        p = NULL;
        p_len = 0;
    } else {
        p = ASN1_STRING_get0_data(oct);
        p_len = ASN1_STRING_length(oct);
    }
    if (p == NULL)
        goto err;

    nid = OBJ_obj2nid(alg->algorithm);
    if (nid == NID_undef)
        goto err;
    alg_name = OBJ_nid2ln(nid);
    if (alg_name == NULL)
        goto err;

    key = ossl_slh_dsa_key_new(lib_ctx, alg_name);
    if (key == NULL
            || !ossl_slh_dsa_set_priv(key, p, p_len))
        goto err;
    ASN1_OCTET_STRING_free(oct);
    return key;
err:
    ossl_slh_dsa_key_free(key);
    ASN1_OCTET_STRING_free(oct);
    return NULL;
}
