/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Cleanroom implementation of Ascon-AEAD128 (NIST SP 800-232).
 *
 * This is a cleanroom implementation based on the NIST SP 800-232 specification.
 */

#include "crypto/ascon.h"
#include <openssl/crypto.h>
#include <string.h>
#include <stdbool.h>
#include "internal/numbers.h"
#include "internal/common.h"

/* Rotate right 64-bit value */
#define ROR64(x, i) ((x << (64 - i)) | (x >> i))

/**
 * Constant addition layer, NIST SP 800-232 Table 5
 * 3c 2d 1e 0f f0 e1 d2 c3 b4 a5 96 87 78 69 5a 4b
 */
#define ASCONPC(x0, x1, x2, x3, x4, rcon) \
    do {                                  \
        x2 ^= rcon;                       \
    } while (0)

/**
 * Nonlinear layer, lifted from p43 of
 * https://csrc.nist.gov/CSRC/media/Projects/lightweight-cryptography/documents/finalist-round/updated-spec-doc/ascon-spec-final.pdf
 */
#define ASCONPS(x0, x1, x2, x3, x4) \
    do {                            \
        uint64_t q0, q1;            \
        x0 ^= x4;                   \
        x4 ^= x3;                   \
        x2 ^= x1;                   \
        q0 = x0 & (~x4);            \
        q1 = x2 & (~x1);            \
        x0 ^= q1;                   \
        q1 = x4 & (~x3);            \
        x2 ^= q1;                   \
        q1 = x1 & (~x0);            \
        x4 ^= q1;                   \
        q1 = x3 & (~x2);            \
        x1 ^= q1;                   \
        x3 ^= q0;                   \
        x1 ^= x0;                   \
        x3 ^= x2;                   \
        x0 ^= x4;                   \
        x2 = ~x2;                   \
    } while (0)

/* Linear layer, NIST SP 800-232 Figure 3 */
#define ASCONPL(x0, x1, x2, x3, x4)          \
    do {                                     \
        x0 ^= ROR64(x0, 19) ^ ROR64(x0, 28); \
        x1 ^= ROR64(x1, 61) ^ ROR64(x1, 39); \
        x2 ^= ROR64(x2, 1) ^ ROR64(x2, 6);   \
        x3 ^= ROR64(x3, 10) ^ ROR64(x3, 17); \
        x4 ^= ROR64(x4, 7) ^ ROR64(x4, 41);  \
    } while (0)

/* One round */
#define ASCONP1(x0, x1, x2, x3, x4, rcon)  \
    do {                                   \
        ASCONPC(x0, x1, x2, x3, x4, rcon); \
        ASCONPS(x0, x1, x2, x3, x4);       \
        ASCONPL(x0, x1, x2, x3, x4);       \
    } while (0)

/* 8 rounds */
#define ASCONP8(x0, x1, x2, x3, x4)           \
    do {                                      \
        ASCONP1(x0, x1, x2, x3, x4, 0xB4ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xA5ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x96ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x87ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x78ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x69ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x5AULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0x4BULL); \
    } while (0)

/* 12 rounds */
#define ASCONP12(x0, x1, x2, x3, x4)          \
    do {                                      \
        ASCONP1(x0, x1, x2, x3, x4, 0xF0ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xE1ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xD2ULL); \
        ASCONP1(x0, x1, x2, x3, x4, 0xC3ULL); \
        ASCONP8(x0, x1, x2, x3, x4);          \
    } while (0)

/* Internal flags for tracking state - stored in flags */
#define ASCONFLG_AAD 0x0000000000000001ULL /* has AAD inputs? */
#define ASCONFLG_DEC 0x0000000000000002ULL /* in decrypt mode? */
#define ASCONFLG_DOMAINSEP 0x8000000000000000ULL /* ready to absorb non-AAD? */
#define ASCONFLG_CLEANED 0xFFFFFFFFFFFFFFFFULL /* context cleaned? */

/* Internal update function */
static ossl_inline void
ascon_aead128_update_internal(ascon_aead_ctx_t* ctx, unsigned char* out,
                              const unsigned char* in, size_t len)
{
    uint64_t s0, s1, s2, s3, s4;
    unsigned char pad = 0x01;
    size_t offset = ctx->offset;
    uint64_t flags = ctx->flags;

    /* Handle domain separation if needed */
    if (flags & ASCONFLG_DOMAINSEP) {
        if (flags & ASCONFLG_AAD) {
            /* Finalize AAD processing */
            ctx->flags = 0;
            ascon_aead128_update_internal(ctx, NULL, &pad, 1);
            ASCONP8(ctx->state[0], ctx->state[1], ctx->state[2], ctx->state[3], ctx->state[4]);
            flags ^= ASCONFLG_AAD;
            offset = 0;
        }
        ctx->state[4] ^= ASCONFLG_DOMAINSEP;
        flags ^= ASCONFLG_DOMAINSEP;
        ctx->flags = flags;
    }

    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2];
    s3 = ctx->state[3];
    s4 = ctx->state[4];

    while (len--) {
        unsigned char ob, ib = *in++;

        if (offset >= 16) {
            ASCONP8(s0, s1, s2, s3, s4);
            offset = 0;
        }

        if (flags & ASCONFLG_DEC) {
            if (offset >= 8) {
                ob = (unsigned char)(s1 >> 8 * (offset & 0x7)) ^ ib;
                s1 ^= (uint64_t)(ob) << 8 * (offset & 0x7);
            } else {
                ob = (unsigned char)(s0 >> 8 * offset) ^ ib;
                s0 ^= (uint64_t)(ob) << 8 * offset;
            }
        } else {
            if (offset >= 8) {
                s1 ^= (uint64_t)(ib) << 8 * (offset & 0x7);
                ob = (unsigned char)(s1 >> 8 * (offset & 0x7));
            } else {
                s0 ^= (uint64_t)(ib) << 8 * offset;
                ob = (unsigned char)(s0 >> 8 * offset);
            }
        }

        if (out != NULL)
            *out++ = ob;
        offset++;
    }

    ctx->state[0] = s0;
    ctx->state[1] = s1;
    ctx->state[2] = s2;
    ctx->state[3] = s3;
    ctx->state[4] = s4;
    ctx->offset = offset;
}

/* One-shot encryption */
void
ascon_aead128_encrypt(uint8_t* ciphertext, uint8_t* tag,
                      const uint8_t key[ASCON_AEAD128_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data, const uint8_t* plaintext,
                      size_t assoc_data_len, size_t plaintext_len,
                      size_t tag_len)
{
    ossl_assert(plaintext_len == 0 || ciphertext != NULL);
    ossl_assert(tag_len != 0 || tag != NULL);
    ossl_assert(key != NULL);
    ossl_assert(nonce != NULL);
    ossl_assert(assoc_data_len == 0 || assoc_data != NULL);
    ossl_assert(plaintext_len == 0 || plaintext != NULL);
    ascon_aead_ctx_t ctx;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_ct_bytes = ascon_aead128_encrypt_update(&ctx, ciphertext,
                                                              plaintext,
                                                              plaintext_len);
    ascon_aead128_encrypt_final(&ctx, ciphertext + new_ct_bytes,
                                 tag, tag_len);
}

/* One-shot decryption */
bool
ascon_aead128_decrypt(uint8_t* plaintext,
                      const uint8_t key[ASCON_AEAD128_KEY_LEN],
                      const uint8_t nonce[ASCON_AEAD_NONCE_LEN],
                      const uint8_t* assoc_data, const uint8_t* ciphertext,
                      const uint8_t* expected_tag, size_t assoc_data_len,
                      size_t ciphertext_len, size_t expected_tag_len)
{
    ossl_assert(ciphertext_len == 0 || plaintext != NULL);
    ossl_assert(key != NULL);
    ossl_assert(nonce != NULL);
    ossl_assert(assoc_data_len == 0 || assoc_data != NULL);
    ossl_assert(ciphertext_len == 0 || ciphertext != NULL);
    ossl_assert(expected_tag_len != 0 || expected_tag != NULL);
    ascon_aead_ctx_t ctx;
    bool is_tag_valid;
    ascon_aead128_init(&ctx, key, nonce);
    ascon_aead128_assoc_data_update(&ctx, assoc_data, assoc_data_len);
    const size_t new_pt_bytes = ascon_aead128_decrypt_update(&ctx,
                                                              plaintext,
                                                              ciphertext,
                                                              ciphertext_len);
    ascon_aead128_decrypt_final(&ctx, plaintext + new_pt_bytes,
                                 &is_tag_valid, expected_tag, expected_tag_len);
    return is_tag_valid;
}

/* Initialize context */
void
ascon_aead128_init(ascon_aead_ctx_t* const ctx,
                    const uint8_t key[ASCON_AEAD128_KEY_LEN],
                    const uint8_t nonce[ASCON_AEAD_NONCE_LEN])
{
    /* Input validation */
    if (ctx == NULL || key == NULL || nonce == NULL)
        return;

    uint64_t s0, s1, s2, s3, s4, k0, k1;

    /* Load key and nonce */
    memcpy(&s1, key, 8);
    memcpy(&s2, key + 8, 8);
    memcpy(&s3, nonce, 8);
    memcpy(&s4, nonce + 8, 8);

    /* Store key for final step */
    ctx->key[0] = k0 = s1;
    ctx->key[1] = k1 = s2;

    /* Initialization vector for ASCON-AEAD128a */
    s0 = 0x80800c0800000000ULL;
    ASCONP12(s0, s1, s2, s3, s4);
    s3 ^= k0;
    s4 ^= k1;

    ctx->state[0] = s0;
    ctx->state[1] = s1;
    ctx->state[2] = s2;
    ctx->state[3] = s3;
    ctx->state[4] = s4;
    ctx->offset = 0;
    ctx->flags = ASCONFLG_DOMAINSEP;
}

/* Update associated data */
void
ascon_aead128_assoc_data_update(ascon_aead_ctx_t* const ctx,
                                 const uint8_t* assoc_data,
                                 size_t assoc_data_len)
{
    /* Input validation */
    if (ctx == NULL)
        return;
    if (assoc_data_len > 0 && assoc_data == NULL)
        return;

    uint64_t flags = ctx->flags;

    /* Set AAD flag */
    if (assoc_data_len > 0)
        flags |= ASCONFLG_AAD;

    ctx->flags = flags;

    /* Process AAD */
    if (assoc_data_len > 0) {
        while (assoc_data_len--) {
            unsigned char ib = *assoc_data++;
            ascon_aead128_update_internal(ctx, NULL, &ib, 1);
        }
    }
}

/* Encrypt update */
size_t
ascon_aead128_encrypt_update(ascon_aead_ctx_t* const ctx,
                              uint8_t* ciphertext,
                              const uint8_t* plaintext,
                              size_t plaintext_len)
{
    /* Input validation */
    if (ctx == NULL)
        return 0;
    if (plaintext_len > 0 && (plaintext == NULL || ciphertext == NULL))
        return 0;

    size_t processed = plaintext_len;
    ascon_aead128_update_internal(ctx, ciphertext, plaintext, plaintext_len);
    return processed;
}

/* Encrypt final */
size_t
ascon_aead128_encrypt_final(ascon_aead_ctx_t* const ctx,
                             uint8_t* const ciphertext,
                             uint8_t* tag,
                             size_t tag_len)
{
    /* Input validation */
    if (ctx == NULL || ciphertext == NULL)
        return 0;
    if (tag_len > 0 && tag == NULL)
        return 0;

    uint64_t s0, s1, s2, s3, s4, k0, k1;
    unsigned char pad = 0x01;

    /* Finalize any remaining data */
    ascon_aead128_update_internal(ctx, NULL, NULL, 0);
    ctx->flags = 0;
    ascon_aead128_update_internal(ctx, NULL, &pad, 1);

    k0 = ctx->key[0];
    k1 = ctx->key[1];
    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2];
    s3 = ctx->state[3];
    s4 = ctx->state[4];

    /* Finalize and generate tag */
    s2 ^= k0;
    s3 ^= k1;
    ASCONP12(s0, s1, s2, s3, s4);
    s3 ^= k0;
    s4 ^= k1;

    /* Generate tag */
    if (tag_len >= 8) {
        memcpy(tag, &s3, 8);
        if (tag_len >= 16) {
            memcpy(tag + 8, &s4, 8);
        }
    }

    /* Secure cleanup of sensitive local state */
    OPENSSL_cleanse(&s0, sizeof(s0));
    OPENSSL_cleanse(&s1, sizeof(s1));
    OPENSSL_cleanse(&s2, sizeof(s2));
    OPENSSL_cleanse(&s3, sizeof(s3));
    OPENSSL_cleanse(&s4, sizeof(s4));
    OPENSSL_cleanse(&k0, sizeof(k0));
    OPENSSL_cleanse(&k1, sizeof(k1));

    /* Cleanup context structure */
    ascon_aead_cleanup(ctx);

    return 0;
}

/* Decrypt update */
size_t
ascon_aead128_decrypt_update(ascon_aead_ctx_t* const ctx,
                              uint8_t* plaintext,
                              const uint8_t* ciphertext,
                              size_t ciphertext_len)
{
    /* Input validation */
    if (ctx == NULL)
        return 0;
    if (ciphertext_len > 0 && (ciphertext == NULL || plaintext == NULL))
        return 0;

    uint64_t flags = ctx->flags;
    flags |= ASCONFLG_DEC;
    ctx->flags = flags;

    size_t processed = ciphertext_len;
    ascon_aead128_update_internal(ctx, plaintext, ciphertext, ciphertext_len);
    return processed;
}

/* Decrypt final with tag verification */
size_t
ascon_aead128_decrypt_final(ascon_aead_ctx_t* const ctx,
                             uint8_t* plaintext,
                             bool* const is_tag_valid,
                             const uint8_t* const expected_tag,
                             const size_t expected_tag_len)
{
    /* Input validation */
    if (ctx == NULL || plaintext == NULL || is_tag_valid == NULL)
        return 0;
    if (expected_tag_len > 0 && expected_tag == NULL)
        return 0;

    uint64_t s0, s1, s2, s3, s4, k0, k1;
    unsigned char pad = 0x01;
    uint64_t computed_tag[2];
    uint64_t expected_tag_val[2];
    unsigned char diff = 0;
    size_t i;

    /* Finalize any remaining data */
    ascon_aead128_update_internal(ctx, NULL, NULL, 0);
    ctx->flags = 0;
    ascon_aead128_update_internal(ctx, NULL, &pad, 1);

    k0 = ctx->key[0];
    k1 = ctx->key[1];
    s0 = ctx->state[0];
    s1 = ctx->state[1];
    s2 = ctx->state[2];
    s3 = ctx->state[3];
    s4 = ctx->state[4];

    /* Finalize and generate tag */
    s2 ^= k0;
    s3 ^= k1;
    ASCONP12(s0, s1, s2, s3, s4);
    s3 ^= k0;
    s4 ^= k1;

    /* Generate tag for comparison */
    memcpy(computed_tag, &s3, 8);
    memcpy(computed_tag + 1, &s4, 8);
    
    /* Validate expected tag length */
    if (expected_tag_len != 16) {
        *is_tag_valid = false;
        OPENSSL_cleanse(computed_tag, sizeof(computed_tag));
        OPENSSL_cleanse(expected_tag_val, sizeof(expected_tag_val));
        OPENSSL_cleanse(&s0, sizeof(s0));
        OPENSSL_cleanse(&s1, sizeof(s1));
        OPENSSL_cleanse(&s2, sizeof(s2));
        OPENSSL_cleanse(&s3, sizeof(s3));
        OPENSSL_cleanse(&s4, sizeof(s4));
        OPENSSL_cleanse(&k0, sizeof(k0));
        OPENSSL_cleanse(&k1, sizeof(k1));
        ascon_aead_cleanup(ctx);
        return 0;
    }

    memcpy(expected_tag_val, expected_tag, 8);
    memcpy(expected_tag_val + 1, expected_tag + 8, 8);

    /* Constant-time tag comparison */
    for (i = 0; i < 16; i++) {
        diff |= ((unsigned char*)computed_tag)[i] ^ expected_tag[i];
    }
    *is_tag_valid = (diff == 0);

    /* Secure cleanup of sensitive local data */
    OPENSSL_cleanse(computed_tag, sizeof(computed_tag));
    OPENSSL_cleanse(expected_tag_val, sizeof(expected_tag_val));
    OPENSSL_cleanse(&s0, sizeof(s0));
    OPENSSL_cleanse(&s1, sizeof(s1));
    OPENSSL_cleanse(&s2, sizeof(s2));
    OPENSSL_cleanse(&s3, sizeof(s3));
    OPENSSL_cleanse(&s4, sizeof(s4));
    OPENSSL_cleanse(&k0, sizeof(k0));
    OPENSSL_cleanse(&k1, sizeof(k1));

    /* Cleanup context structure */
    ascon_aead_cleanup(ctx);

    return 0;
}

/* Cleanup function */
void
ascon_aead_cleanup(ascon_aead_ctx_t* const ctx)
{
    if (ctx == NULL)
        return;

    OPENSSL_cleanse(ctx->state, sizeof(ctx->state));
    OPENSSL_cleanse(ctx->key, sizeof(ctx->key));
    ctx->offset = 0;
    ctx->flags = ASCONFLG_CLEANED;
}
