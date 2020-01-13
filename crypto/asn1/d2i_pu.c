/*
 * Copyright 1995-2016 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <opentls/bn.h>
#include <opentls/evp.h>
#include <opentls/objects.h>
#include <opentls/asn1.h>
#include <opentls/rsa.h>
#include <opentls/dsa.h>
#include <opentls/ec.h>

#include "crypto/evp.h"

EVP_PKEY *d2i_PublicKey(int type, EVP_PKEY **a, const unsigned char **pp,
                        long length)
{
    EVP_PKEY *ret;

    if ((a == NULL) || (*a == NULL)) {
        if ((ret = EVP_PKEY_new()) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
            return NULL;
        }
    } else
        ret = *a;

    if (type != EVP_PKEY_id(ret) && !EVP_PKEY_set_type(ret, type)) {
        ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_EVP_LIB);
        goto err;
    }

    switch (EVP_PKEY_id(ret)) {
#ifndef OPENtls_NO_RSA
    case EVP_PKEY_RSA:
        if ((ret->pkey.rsa = d2i_RSAPublicKey(NULL, pp, length)) == NULL) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENtls_NO_DSA
    case EVP_PKEY_DSA:
        /* TMP UGLY CAST */
        if (!d2i_DSAPublicKey(&ret->pkey.dsa, pp, length)) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
#ifndef OPENtls_NO_EC
    case EVP_PKEY_EC:
        if (!o2i_ECPublicKey(&ret->pkey.ec, pp, length)) {
            ASN1err(ASN1_F_D2I_PUBLICKEY, ERR_R_ASN1_LIB);
            goto err;
        }
        break;
#endif
    default:
        ASN1err(ASN1_F_D2I_PUBLICKEY, ASN1_R_UNKNOWN_PUBLIC_KEY_TYPE);
        goto err;
    }
    if (a != NULL)
        (*a) = ret;
    return ret;
 err:
    if (a == NULL || *a != ret)
        EVP_PKEY_free(ret);
    return NULL;
}
