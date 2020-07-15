/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <oqs/oqs.h>

int X509_certificate_type(const X509 *x, const EVP_PKEY *pkey)
{
    const EVP_PKEY *pk;
    int ret = 0, i;

    if (x == NULL)
        return 0;

    if (pkey == NULL)
        pk = X509_get0_pubkey(x);
    else
        pk = pkey;

    if (pk == NULL)
        return 0;

    switch (EVP_PKEY_id(pk)) {
    case EVP_PKEY_RSA:
        ret = EVP_PK_RSA | EVP_PKT_SIGN;
/*              if (!sign only extension) */
        ret |= EVP_PKT_ENC;
        break;
    case EVP_PKEY_RSA_PSS:
        ret = EVP_PK_RSA | EVP_PKT_SIGN;
        break;
    case EVP_PKEY_DSA:
        ret = EVP_PK_DSA | EVP_PKT_SIGN;
        break;
    case EVP_PKEY_EC:
        ret = EVP_PK_EC | EVP_PKT_SIGN | EVP_PKT_EXCH;
        break;
    case EVP_PKEY_ED448:
    case EVP_PKEY_ED25519:
///// OQS_TEMPLATE_FRAGMENT_LIST_SIG_SWITCH_CASES_START
    case EVP_PKEY_OQS_SIG_DEFAULT:
    case EVP_PKEY_P256_OQS_SIG_DEFAULT:
    case EVP_PKEY_RSA3072_OQS_SIG_DEFAULT:
    case EVP_PKEY_DILITHIUM2:
    case EVP_PKEY_P256_DILITHIUM2:
    case EVP_PKEY_RSA3072_DILITHIUM2:
    case EVP_PKEY_DILITHIUM3:
    case EVP_PKEY_P256_DILITHIUM3:
    case EVP_PKEY_RSA3072_DILITHIUM3:
    case EVP_PKEY_DILITHIUM4:
    case EVP_PKEY_P384_DILITHIUM4:
    case EVP_PKEY_FALCON512:
    case EVP_PKEY_P256_FALCON512:
    case EVP_PKEY_RSA3072_FALCON512:
    case EVP_PKEY_FALCON1024:
    case EVP_PKEY_P521_FALCON1024:
    case EVP_PKEY_MQDSS3148:
    case EVP_PKEY_P256_MQDSS3148:
    case EVP_PKEY_RSA3072_MQDSS3148:
    case EVP_PKEY_PICNICL1FS:
    case EVP_PKEY_P256_PICNICL1FS:
    case EVP_PKEY_RSA3072_PICNICL1FS:
    case EVP_PKEY_PICNIC3L1:
    case EVP_PKEY_P256_PICNIC3L1:
    case EVP_PKEY_RSA3072_PICNIC3L1:
    case EVP_PKEY_QTESLAPI:
    case EVP_PKEY_P256_QTESLAPI:
    case EVP_PKEY_RSA3072_QTESLAPI:
    case EVP_PKEY_QTESLAPIII:
    case EVP_PKEY_P384_QTESLAPIII:
    case EVP_PKEY_RAINBOWIACLASSIC:
    case EVP_PKEY_P256_RAINBOWIACLASSIC:
    case EVP_PKEY_RSA3072_RAINBOWIACLASSIC:
    case EVP_PKEY_RAINBOWVCCLASSIC:
    case EVP_PKEY_P521_RAINBOWVCCLASSIC:
    case EVP_PKEY_SPHINCSHARAKA128FROBUST:
    case EVP_PKEY_P256_SPHINCSHARAKA128FROBUST:
    case EVP_PKEY_RSA3072_SPHINCSHARAKA128FROBUST:
///// OQS_TEMPLATE_FRAGMENT_LIST_SIG_SWITCH_CASES_END
        ret = EVP_PKT_SIGN;
        break;
    case EVP_PKEY_DH:
        ret = EVP_PK_DH | EVP_PKT_EXCH;
        break;
    case NID_id_GostR3410_2001:
    case NID_id_GostR3410_2012_256:
    case NID_id_GostR3410_2012_512:
        ret = EVP_PKT_EXCH | EVP_PKT_SIGN;
        break;
    default:
        break;
    }

    i = X509_get_signature_nid(x);
    if (i && OBJ_find_sigid_algs(i, NULL, &i)) {

        switch (i) {
        case NID_rsaEncryption:
        case NID_rsa:
            ret |= EVP_PKS_RSA;
            break;
        case NID_dsa:
        case NID_dsa_2:
            ret |= EVP_PKS_DSA;
            break;
        case NID_X9_62_id_ecPublicKey:
            ret |= EVP_PKS_EC;
            break;
        default:
            break;
        }
    }

    return ret;
}
