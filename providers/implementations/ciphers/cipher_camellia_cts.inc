/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for CAMELLIA CBC CTS ciphers */

#include "cipher_cts.h"

#define CTS_FLAGS PROV_CIPHER_FLAG_CTS

static OSSL_FUNC_cipher_encrypt_init_fn camellia_cbc_cts_einit;
static OSSL_FUNC_cipher_decrypt_init_fn camellia_cbc_cts_dinit;

static int camellia_cbc_cts_einit(void *ctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[])
{
    if (!ossl_cipher_generic_einit(ctx, key, keylen, iv, ivlen, NULL))
        return 0;
    return ossl_cipher_cbc_cts_set_ctx_params(ctx, params);
}

static int camellia_cbc_cts_dinit(void *ctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[])
{
    if (!ossl_cipher_generic_dinit(ctx, key, keylen, iv, ivlen, NULL))
        return 0;
    return ossl_cipher_cbc_cts_set_ctx_params(ctx, params);
}

/* ossl_camellia256cbc_cts_functions */
IMPLEMENT_cts_cipher(camellia, CAMELLIA, cbc, CBC, CTS_FLAGS, 256, 128, 128, block)
/* ossl_camellia192cbc_cts_functions */
IMPLEMENT_cts_cipher(camellia, CAMELLIA, cbc, CBC, CTS_FLAGS, 192, 128, 128, block)
/* ossl_camellia128cbc_cts_functions */
IMPLEMENT_cts_cipher(camellia, CAMELLIA, cbc, CBC, CTS_FLAGS, 128, 128, 128, block)
