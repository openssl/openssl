/*
 * Copyright 2019-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OSSL_PROVIDERS_IMPLEMENTATIONS_CIPHERS_CIPHER_AES_GCM_SIV_H)
#define OSSL_PROVIDERS_IMPLEMENTATIONS_CIPHERS_CIPHER_AES_GCM_SIV_H

#include <openssl/aes.h>
#include <openssl/modes.h>
#include "prov/ciphercommon.h"
#include "crypto/aes_platform.h"

#define BLOCK_SIZE 16
#define NONCE_SIZE 12
#define TAG_SIZE 16

/*
 * Scratch owned by the context, allocated on first use and cleared with the
 * context: POLYVAL stages its byte-reversed input here for the platform GHASH
 * kernel, and the generic CTR path builds and encrypts its counter blocks here.
 * 4 KiB runs: the GHASH and ECB kernels are flat from 4 KiB upward, and a run
 * this size stays in L1D beside the input and output on every CPU measured.
 */
#define GCM_SIV_SCRATCH (4 * 1024)

/* AAD manipulation macros */
#define UP16(x) (((x) + 15) & ~0x0F)
#define DOWN16(x) ((x) & ~0x0F)
#define REMAINDER16(x) ((x) & 0x0F)
#define IS16(x) (((x) & 0x0F) == 0)

typedef struct prov_cipher_hw_aes_gcm_siv_st {
    int (*initkey)(void *vctx);
    int (*cipher)(void *vctx, unsigned char *out, const unsigned char *in,
        size_t len);
    int (*dup_ctx)(void *vdst, void *vsrc);
    void (*clean_ctx)(void *vctx);
} PROV_CIPHER_HW_AES_GCM_SIV;

/* Arranged for alignment purposes */
typedef struct prov_aes_gcm_siv_ctx_st {
    const PROV_CIPHER_HW_AES_GCM_SIV *hw; /* maybe not used, yet? */
    uint8_t *aad; /* Allocated, rounded up to 16 bytes, from user */
    uint8_t *scratch; /* GCM_SIV_SCRATCH bytes, see above; NULL until first use */
    OSSL_LIB_CTX *libctx;
    OSSL_PROVIDER *provctx;
    size_t aad_len; /* actual AAD length */
    size_t key_len;
    AES_KEY ks; /* the message-encryption key schedule (msg_enc_key) */
    AES_KEY ks_bulk; /* a SECOND schedule of the same key for a bulk kernel that wants
                      * a different layout (x86 bitsliced ECB: the standard schedule) */
    const AES_KEY *ecb_key; /* the schedule `ecb` takes: &ks, or &ks_bulk */
    size_t ecb_min_blocks; /* runs shorter than this go through `block` instead of `ecb` */
    block128_f block; /* one-block AES encrypt under ks: aesni / aes_v8 / vpaes / AES_encrypt */
    ecb128_f ecb; /* multi-block ECB encrypt under *ecb_key, or NULL where the platform has none */
    int vaes; /* x86-64: the AVX-512/VAES keystream kernel is usable on this CPU */
    int aesni_ctr; /* x86-64: the 128-bit AES-NI keystream kernel is usable (AES-NI, no VAES) */
    int native_polyval; /* a native POLYVAL kernel is usable: x86-64 VPCLMULQDQ / PCLMULQDQ, aarch64 PMULL */
    int armv8_ctr; /* aarch64: the fused AESE/AESMC keystream kernel is usable (FEAT_AES) */
    uint8_t key_gen_key[32]; /* from user */
    uint8_t msg_enc_key[32]; /* depends on key size */
    uint8_t msg_auth_key[BLOCK_SIZE];
    uint8_t tag[TAG_SIZE]; /* generated tag, given to user or compared to user */
    uint8_t user_tag[TAG_SIZE]; /* from user */
    uint8_t nonce[NONCE_SIZE]; /* from user */
    u128 Htable[16]; /* Polyval calculations via ghash */
    unsigned int enc : 1; /* Set to 1 if we are encrypting or 0 otherwise */
    unsigned int have_user_tag : 1;
    unsigned int generated_tag : 1;
    unsigned int used_enc : 1;
    unsigned int used_dec : 1;
    unsigned int speed : 1;
} PROV_AES_GCM_SIV_CTX;

const PROV_CIPHER_HW_AES_GCM_SIV *ossl_prov_cipher_hw_aes_gcm_siv(size_t keybits);

void ossl_polyval_ghash_init(u128 Htable[16], const uint64_t H[2]);
/*
 * POLYVAL len bytes (a multiple of 16) into tag. scratch/scratch_len (may be NULL/0)
 * is staging space for the byte-reversed input: the larger it is, the longer each
 * GHASH kernel call.
 */
void ossl_polyval_ghash_hash(const u128 Htable[16], uint8_t *tag, const uint8_t *inp,
    size_t len, uint8_t *scratch, size_t scratch_len, const uint8_t *H);
/*
 * H (the 16-byte POLYVAL key, msg_auth_key) enables the native POLYVAL kernels on
 * x86-64 (VPCLMULQDQ, else PCLMULQDQ); pass NULL to take the GHASH route.
 */

/* Define GSWAP8/GSWAP4 - used for BOTH little and big endian architectures */
static ossl_inline uint32_t GSWAP4(uint32_t n)
{
    return (((n & 0x000000FF) << 24)
        | ((n & 0x0000FF00) << 8)
        | ((n & 0x00FF0000) >> 8)
        | ((n & 0xFF000000) >> 24));
}
static ossl_inline uint64_t GSWAP8(uint64_t n)
{
    uint64_t result;

    result = GSWAP4(n & 0x0FFFFFFFF);
    result <<= 32;
    return result | GSWAP4(n >> 32);
}

#endif /* !defined(OSSL_PROVIDERS_IMPLEMENTATIONS_CIPHERS_CIPHER_AES_GCM_SIV_H) */
