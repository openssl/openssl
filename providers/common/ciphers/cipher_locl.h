/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/ciphers/ciphercommon.h"

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_START(name)                         \
static const OSSL_PARAM name##_known_gettable_ctx_params[] = {                 \
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_KEYLEN, NULL),                            \
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_IVLEN, NULL),                             \
    OSSL_PARAM_int(OSSL_CIPHER_PARAM_PADDING, NULL),                           \
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_NUM, NULL),                            \
    OSSL_PARAM_octet_string(OSSL_CIPHER_PARAM_IV, NULL, 0),

#define CIPHER_DEFAULT_GETTABLE_CTX_PARAMS_END(name)                           \
    OSSL_PARAM_END                                                             \
};                                                                             \
const OSSL_PARAM * name##_gettable_ctx_params(void)                            \
{                                                                              \
    return name##_known_gettable_ctx_params;                                   \
}

size_t fillblock(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
int trailingdata(unsigned char *buf, size_t *buflen, size_t blocksize,
                 const unsigned char **in, size_t *inlen);
void padblock(unsigned char *buf, size_t *buflen, size_t blocksize);
int unpadblock(unsigned char *buf, size_t *buflen, size_t blocksize);
