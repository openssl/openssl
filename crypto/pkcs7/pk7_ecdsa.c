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

int pkcs7_ecdsa_dsa_sign(PKCS7_SIGNER_INFO *si, int verify)
{
    if (verify == 0) {
        int snid, hnid;
        X509_ALGOR *alg1, *alg2;
        EVP_PKEY *pkey = si->pkey;

        PKCS7_SIGNER_INFO_get0_algs(si, NULL, &alg1, &alg2);
        if (alg1 == NULL || alg1->algorithm == NULL)
            return -1;
        hnid = OBJ_obj2nid(alg1->algorithm);
        if (hnid == NID_undef)
            return -1;
        if (!OBJ_find_sigid_by_algs(&snid, hnid, EVP_PKEY_id(pkey)))
            return -1;
        X509_ALGOR_set0(alg2, OBJ_nid2obj(snid), V_ASN1_UNDEF, 0);
    }
    return 1;
}
