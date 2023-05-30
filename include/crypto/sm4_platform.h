/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_SM4_PLATFORM_H
# define OSSL_SM4_PLATFORM_H
# pragma once

# if defined(OPENSSL_CPUID_OBJ)
#  if defined(__aarch64__)
#   include "arm_arch.h"
extern unsigned int OPENSSL_arm_midr;
static inline int vpsm4_capable(void)
{
    return (OPENSSL_armcap_P & ARMV8_CPUID) &&
            (MIDR_IS_CPU_MODEL(OPENSSL_arm_midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_V1) ||
             MIDR_IS_CPU_MODEL(OPENSSL_arm_midr, ARM_CPU_IMP_ARM, ARM_CPU_PART_N1));
}
#   if defined(VPSM4_ASM)
#    define VPSM4_CAPABLE vpsm4_capable()
#   endif
#   define HWSM4_CAPABLE (OPENSSL_armcap_P & ARMV8_SM4)
#   define HWSM4_set_encrypt_key sm4_v8_set_encrypt_key
#   define HWSM4_set_decrypt_key sm4_v8_set_decrypt_key
#   define HWSM4_encrypt sm4_v8_encrypt
#   define HWSM4_decrypt sm4_v8_decrypt
#   define HWSM4_cbc_encrypt sm4_v8_cbc_encrypt
#   define HWSM4_ecb_encrypt sm4_v8_ecb_encrypt
#   define HWSM4_ctr32_encrypt_blocks sm4_v8_ctr32_encrypt_blocks
#  endif
# endif /* OPENSSL_CPUID_OBJ */

# if defined(HWSM4_CAPABLE)
int HWSM4_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int HWSM4_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void HWSM4_encrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_decrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void HWSM4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       unsigned char *ivec, const int enc);
void HWSM4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       const int enc);
void HWSM4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
# endif /* HWSM4_CAPABLE */

#ifdef VPSM4_CAPABLE
int vpsm4_set_encrypt_key(const unsigned char *userKey, SM4_KEY *key);
int vpsm4_set_decrypt_key(const unsigned char *userKey, SM4_KEY *key);
void vpsm4_encrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void vpsm4_decrypt(const unsigned char *in, unsigned char *out,
                   const SM4_KEY *key);
void vpsm4_cbc_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       unsigned char *ivec, const int enc);
void vpsm4_ecb_encrypt(const unsigned char *in, unsigned char *out,
                       size_t length, const SM4_KEY *key,
                       const int enc);
void vpsm4_ctr32_encrypt_blocks(const unsigned char *in, unsigned char *out,
                                size_t len, const void *key,
                                const unsigned char ivec[16]);
# endif /* VPSM4_CAPABLE */


#endif /* OSSL_SM4_PLATFORM_H */
