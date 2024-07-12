/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "internal/deprecated.h"

#include "crypto/evp.h"
#include "prov/ciphercommon.h"
#include "crypto/aes_platform.h"

#if defined(__aarch64__) && defined(AES_CBC_HMAC_SHA_ETM_CAPABLE)

# include "arm_arch.h"

static EVP_CIPHER hwaes_128_cbc_hmac_sha256_etm_cipher = {
# ifdef NID_aes_128_cbc_hmac_sha256_etm
    NID_aes_128_cbc_hmac_sha256_etm,
# else
    NID_undef,
# endif
    AES_BLOCK_SIZE, 16, AES_BLOCK_SIZE,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_ENC_THEN_MAC,
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

static EVP_CIPHER hwaes_192_cbc_hmac_sha256_etm_cipher = {
# ifdef NID_aes_192_cbc_hmac_sha256_etm
    NID_aes_192_cbc_hmac_sha256_etm,
# else
    NID_undef,
# endif
    AES_BLOCK_SIZE, 24, AES_BLOCK_SIZE,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_ENC_THEN_MAC,
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

static EVP_CIPHER hwaes_256_cbc_hmac_sha256_etm_cipher = {
# ifdef NID_aes_256_cbc_hmac_sha256_etm
    NID_aes_256_cbc_hmac_sha256_etm,
# else
    NID_undef,
# endif
    AES_BLOCK_SIZE, 32, AES_BLOCK_SIZE,
    EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_ENC_THEN_MAC,
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

const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256_etm(void)
{
    return ((OPENSSL_armcap_P & ARMV8_AES) &&
            (OPENSSL_armcap_P & ARMV8_SHA256) ?
            &hwaes_128_cbc_hmac_sha256_etm_cipher : NULL);
}

const EVP_CIPHER *EVP_aes_192_cbc_hmac_sha256_etm(void)
{
    return ((OPENSSL_armcap_P & ARMV8_AES) &&
            (OPENSSL_armcap_P & ARMV8_SHA256) ?
            &hwaes_192_cbc_hmac_sha256_etm_cipher : NULL);
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256_etm(void)
{
    return ((OPENSSL_armcap_P & ARMV8_AES) &&
            (OPENSSL_armcap_P & ARMV8_SHA256) ?
            &hwaes_256_cbc_hmac_sha256_etm_cipher : NULL);
}
#else
const EVP_CIPHER *EVP_aes_128_cbc_hmac_sha256_etm(void)
{
    return NULL;
}

const EVP_CIPHER *EVP_aes_192_cbc_hmac_sha256_etm(void)
{
    return NULL;
}

const EVP_CIPHER *EVP_aes_256_cbc_hmac_sha256_etm(void)
{
    return NULL;
}
#endif
