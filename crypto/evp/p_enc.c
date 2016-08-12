/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

int EVP_PKEY_encrypt_old(unsigned char *ek, const unsigned char *key,
                         int key_len, EVP_PKEY *pubk)
{
    int ret = 0;
#ifndef OPENSSL_NO_RSA
    RSA *rsa;

    if (EVP_PKEY_id(pubk) != EVP_PKEY_RSA) {
#endif
        EVPerr(EVP_F_EVP_PKEY_ENCRYPT_OLD, EVP_R_PUBLIC_KEY_NOT_RSA);
#ifndef OPENSSL_NO_RSA
        goto err;
    }

    rsa = EVP_PKEY_get1_RSA(pubk);
    if (rsa == NULL)
        /* Error already raised by EVP_PKEY_get1_rsa() */
        goto err;

    ret =
        RSA_public_encrypt(key_len, key, ek, rsa, RSA_PKCS1_PADDING);

    RSA_free(rsa);
 err:
#endif
    return ret;
}
