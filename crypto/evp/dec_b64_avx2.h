/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_EVP_DEC_B64_AVX2_H
#define OSSL_CRYPTO_EVP_DEC_B64_AVX2_H

#include <openssl/evp.h>

#include "b64_avx2_common.h"

#ifdef HAVE_AVX2
int decode_base64_avx2(EVP_ENCODE_CTX *ctx, unsigned char *dst,
    const unsigned char *src, int srclen,
    int *consumed_out);
#endif

#endif
