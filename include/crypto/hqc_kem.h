/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OPENSSL_HEADER_HQC_KEM_H
#define OPENSSL_HEADER_HQC_KEM_H
#pragma once

typedef enum {
    EVP_PKEY_HQC_KEM_128 = 0,
    EVP_PKEY_HQC_KEM_192 = 1,
    EVP_PKEY_HQC_KEM_256 = 2,
    EVP_PKEY_HQC_KEM_MAX
} hqc_key_type;

typedef struct hqc_variant_info_st {
    hqc_key_type type;
    size_t ek_size;
    size_t dk_size;
    size_t seed_len;
    size_t security_bytes;
    uint32_t security_category;
    uint32_t secbits;
    uint32_t n;
    uint32_t n_mu;
    uint16_t omega;
    uint16_t omega_r;
    uint32_t rej_threshold;
} HQC_VARIANT_INFO;

/* Known as HQC_KEY via crypto/types.h */
typedef struct ossl_hqc_kem_key_st {
    const HQC_VARIANT_INFO *info; /* key size info */
    const void *ctx; /* provider context we came from */
    uint8_t *ek; /* encryption key */
    uint8_t *dk; /* decryption key */
    int selection; /* Presence status of key parts */
} HQC_KEY;

/*
 * Allocate a new empty key
 */
HQC_KEY *ossl_hqc_kem_key_new(const HQC_VARIANT_INFO *info, void *ctx);

/*
 * Free an HQC_KEY
 */
void ossl_hqc_kem_key_free(HQC_KEY *key);

#endif /* OPENSSL_HEADER_HQC_KEM_H */
