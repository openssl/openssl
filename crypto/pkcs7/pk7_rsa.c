/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/pkcs7.h>
#include "crypto/asn1.h"
#include "pk7_local.h"

int pkcs7_rsa_sign(PKCS7_SIGNER_INFO *si, int verify)
{
    if (verify == 0) {
        X509_ALGOR *alg = NULL;

        PKCS7_SIGNER_INFO_get0_algs(si, NULL, NULL, &alg);
        if (alg != NULL)
            X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
    }
    return 1;
}

int pkcs7_rsa_encrypt(PKCS7_RECIP_INFO *ri, int decrypt)
{
    X509_ALGOR *alg = NULL;

    if (decrypt == 0) {
        PKCS7_RECIP_INFO_get0_alg(ri, &alg);
        if (alg != NULL)
            X509_ALGOR_set0(alg, OBJ_nid2obj(NID_rsaEncryption), V_ASN1_NULL, 0);
    }
    return 1;
}
