/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CMLL_PLATFORM_H
# define OSSL_CMLL_PLATFORM_H
# pragma once

# if defined(CMLL_ASM) && (defined(__sparc) || defined(__sparc__))

/* Fujitsu SPARC64 X support */
#  include "crypto/sparc_arch.h"

#  ifndef OPENSSL_NO_CAMELLIA
#   define SPARC_CMLL_CAPABLE      (OPENSSL_sparcv9cap_P[1] & CFR_CAMELLIA)
#   include <openssl/camellia.h>

void cmll_t4_set_key(const unsigned char *key, int bits, CAMELLIA_KEY *ks);
void cmll_t4_encrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);
void cmll_t4_decrypt(const unsigned char *in, unsigned char *out,
                     const CAMELLIA_KEY *key);

void cmll128_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll128_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll256_t4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll256_t4_cbc_decrypt(const unsigned char *in, unsigned char *out,
                            size_t len, const CAMELLIA_KEY *key,
                            unsigned char *ivec, int /*unused*/);
void cmll128_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);
void cmll256_t4_ctr32_encrypt(const unsigned char *in, unsigned char *out,
                              size_t blocks, const CAMELLIA_KEY *key,
                              unsigned char *ivec);
#  endif /* OPENSSL_NO_CAMELLIA */

# endif /* CMLL_ASM && sparc */

# if defined(CMLL_ASM) && (defined(__aarch64__) ||  defined (_M_ARM64))
#  include "crypto/arm_arch.h"

#  ifndef OPENSSL_NO_CAMELLIA
#   define CMLL_AES_CAPABLE (OPENSSL_armcap_P & ARMV7_NEON & ARMV8_AES)
#   include <openssl/camellia.h>
#   include <stdint.h>
struct camellia_simd_ctx {
    uint64_t key_table[34];
    int key_length;
};
extern void camellia_keysetup_neon(struct camellia_simd_ctx *ctx, 
                                     const void *vkey, unsigned int keylen);
extern void camellia_encrypt_1blk_armv8(struct camellia_simd_ctx *ctx, 
                                       void *vout, const void *vin);
extern void camellia_encrypt_1blk_aese(struct camellia_simd_ctx *ctx, 
                                       void *vout, const void *vin);
extern void camellia_decrypt_1blk_armv8(struct camellia_simd_ctx *ctx, 
                                       void *vout, const void *vin);
extern void camellia_encrypt_16blks_neon(struct camellia_simd_ctx *ctx, 
                                       void *vout, const void *vin);
extern void camellia_decrypt_16blks_neon(struct camellia_simd_ctx *ctx, 
                                       void *vout, const void *vin);
extern void camellia_cbc_encrypt_neon(const unsigned char *in, unsigned char *out,
                                      size_t len, const struct camellia_simd_ctx *ctx,
                                      unsigned char *ivec);
extern void camellia_cbc_decrypt_neon(const unsigned char *in, unsigned char *out,
                                      size_t len, const struct camellia_simd_ctx *ctx,
                                      unsigned char *ivec);
extern void camellia_ctr32_encrypt_blocks_neon(const unsigned char *in, unsigned char *out,
                                      size_t blocks, const struct camellia_simd_ctx *ctx,
                                      unsigned char *ivec);
#  endif /* OPENSSL_NO_CAMELLIA */
# endif /* CMLL_ASM && AARCH64*/

#endif /* OSSL_CRYPTO_CIPHERMODE_PLATFORM_H */
