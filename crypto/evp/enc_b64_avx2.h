/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_EVP_B64_AVX2_H
#define OSSL_CRYPTO_EVP_B64_AVX2_H

#include <openssl/evp.h>

#if defined(__x86_64) || defined(__x86_64__) || defined(_M_AMD64) || defined(_M_X64)
#if !defined(_M_ARM64EC)
int encode_base64_avx2(EVP_ENCODE_CTX *ctx,
    unsigned char *out, const unsigned char *src, int srclen,
    int newlines, int *wrap_cnt);

/*
 * Decode a complete block of base64 data (no padding in the chunk).
 * Returns number of bytes decoded (24 per 32 input bytes), or -1 on error.
 * use_srp: 1 for SRP alphabet, 0 for standard.
 */
__owur int decode_base64_avx2(int use_srp, unsigned char *restrict out,
    const unsigned char *restrict src, int srclen);
#endif /* !defined(_M_ARM64EC) */
#endif

#endif
