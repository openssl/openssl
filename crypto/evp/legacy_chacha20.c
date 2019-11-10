/*
 * Copyright 2015-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"
#include "crypto/chacha.h"

static const EVP_CIPHER chacha20 = {
    NID_chacha20,
    1,                      /* block_size */
    CHACHA_KEY_SIZE,        /* key_len */
    CHACHA_CTR_SIZE,        /* iv_len, 128-bit counter in the context */
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT
};

const EVP_CIPHER *EVP_chacha20(void)
{
    return &chacha20;
}
