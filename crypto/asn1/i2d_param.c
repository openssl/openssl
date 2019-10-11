/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/asn1.h>
#include "crypto/asn1.h"
#include "crypto/evp.h"

int i2d_KeyParams(const EVP_PKEY *a, unsigned char **pp)
{
    if (a->ameth != NULL && a->ameth->param_encode != NULL)
        return a->ameth->param_encode(a, pp);
    ASN1err(ASN1_F_I2D_KEYPARAMS, ASN1_R_UNSUPPORTED_TYPE);
    return -1;
}

int i2d_KeyParams_bio(BIO *bp, const EVP_PKEY *pkey)
{
    return ASN1_i2d_bio_of(EVP_PKEY, i2d_KeyParams, bp, pkey);
}

