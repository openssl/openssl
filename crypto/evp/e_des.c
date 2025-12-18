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
#include <openssl/rand.h>
#include "evp_local.h"

BLOCK_CIPHER_defs(des, EVP_DES_KEY, NID_des, 8, 8, 8, 64,
    EVP_CIPH_RAND_KEY, NULL, NULL,
    NULL, NULL, NULL)

BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 1,
    EVP_CIPH_RAND_KEY, NULL, NULL,
    NULL, NULL, NULL)

BLOCK_CIPHER_def_cfb(des, EVP_DES_KEY, NID_des, 8, 8, 8,
    EVP_CIPH_RAND_KEY, NULL, NULL,
    NULL, NULL, NULL)

#endif
