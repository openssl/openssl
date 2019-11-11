/*
 * Copyright 2013-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/aes.h>
#include "crypto/evp.h"
#include "evp_local.h"

static EVP_CIPHER aesni_128_cbc_hmac_sha256_cipher = {
#ifdef NID_aes_128_cbc_hmac_sha256
    NID_aes_128_cbc_hmac_sha256,
#else
    NID_undef,
#endif
    AES_BLOCK_SIZE, 16, AES_BLOCK_SIZE,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
    | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
};

static EVP_CIPHER aesni_256_cbc_hmac_sha256_cipher = {
#ifdef NID_aes_256_cbc_hmac_sha256
    NID_aes_256_cbc_hmac_sha256,
#else
    NID_undef,
#endif
    AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1
    | EVP_CIPH_FLAG_AEAD_CIPHER | EVP_CIPH_FLAG_TLS1_1_MULTIBLOCK
};

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256(void)
{
    return &aesni_128_cbc_hmac_sha256_cipher;
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256(void)
{
    return &aesni_256_cbc_hmac_sha256_cipher;
}
