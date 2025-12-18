/*
 * Copyright 1995-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"

#ifndef OPENSSL_NO_DES

#include <openssl/evp.h>
#include <openssl/objects.h>
#include "crypto/evp.h"
#include <openssl/des.h>
#include "evp_local.h"

static const EVP_CIPHER d_xcbc_cipher = {
    NID_desx_cbc,
    8, 24, 8,
    EVP_CIPH_CBC_MODE,
    EVP_ORIG_GLOBAL,
    NULL,
    NULL,
    NULL,
    0,
    NULL,
    NULL,
    NULL,
    NULL
};

const EVP_CIPHER *EVP_desx_cbc(void)
{
    return &d_xcbc_cipher;
}
#endif
