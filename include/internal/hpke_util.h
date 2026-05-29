/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_HPKE_UTIL_H
#define OSSL_INTERNAL_HPKE_UTIL_H
#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <openssl/hpke.h>
#include <openssl/types.h>

/* Constants from RFC 9180 Section 7.1 and 7.3 */
#define OSSL_HPKE_MAX_SECRET 64
#define OSSL_HPKE_MAX_PUBLIC 133 /* Currently only used by EC DHKEM */
#define OSSL_HPKE_MAX_PRIVATE 66 /* Currently only used by EC/ECX DHKEM */
#define OSSL_HPKE_MAX_KDF_INPUTLEN 64

/*
 * max length of a base-nonce (the Nn field from OSSL_HPKE_AEAD_INFO), this
 * is used for a local stack array size
 */
#define OSSL_HPKE_MAX_NONCELEN 12

/*
 * @brief info about a KEM
 * Used to store constants from Section 7.1 "Table 2 KEM IDs"
 * and the bitmask for EC curves described in Section 7.1.3 DeriveKeyPair
 */
typedef struct {
    uint16_t kem_id; /* code point for key encipherment method */
    const char *keytype; /* string form of algtype "EC"/"X25519"/"X448" */
    const char *groupname; /* string form of EC group for NIST curves  */
    const char *mdname; /* hash alg name for the HKDF */
    size_t Nsecret; /* size of secrets */
    size_t Nenc; /* length of encapsulated key */
    size_t Npk; /* length of public key */
    size_t Nsk; /* length of private key for EC and ECX */
    size_t derivekey_seedlen; /* length of seed for MLKEM & Hybrid MLKEM*/
    uint8_t bitmask;
    bool auth; /* Supports authentication */
    bool pq;
    size_t recommended_ikmlen;
} OSSL_HPKE_KEM_INFO;

/*
 * @brief info about a KDF
 */
typedef struct {
    uint16_t kdf_id; /* code point for KDF */
    const char *mdname; /* hash alg name for the HKDF */
    size_t Nh; /* length of hash/extract output */
} OSSL_HPKE_KDF_INFO;

/*
 * @brief info about an AEAD
 */
typedef struct {
    uint16_t aead_id; /* code point for aead alg */
    const char *name; /* alg name */
    size_t taglen; /* aead tag len */
    size_t Nk; /* size of a key for this aead */
    size_t Nn; /* length of a nonce for this aead */
} OSSL_HPKE_AEAD_INFO;

const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_curve(const char *curve);
const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_id(uint16_t kemid);
const OSSL_HPKE_KEM_INFO *ossl_HPKE_KEM_INFO_find_random(OSSL_LIB_CTX *ctx);
const OSSL_HPKE_KDF_INFO *ossl_HPKE_KDF_INFO_find_id(uint16_t kdfid);
const OSSL_HPKE_KDF_INFO *ossl_HPKE_KDF_INFO_find_random(OSSL_LIB_CTX *ctx);
const OSSL_HPKE_AEAD_INFO *ossl_HPKE_AEAD_INFO_find_id(uint16_t aeadid);
const OSSL_HPKE_AEAD_INFO *ossl_HPKE_AEAD_INFO_find_random(OSSL_LIB_CTX *ctx);

int ossl_hpke_kdf_extract(EVP_KDF_CTX *kctx,
    unsigned char *prk, size_t prklen,
    const unsigned char *salt, size_t saltlen,
    const unsigned char *ikm, size_t ikmlen);

int ossl_hpke_kdf_expand(EVP_KDF_CTX *kctx,
    unsigned char *okm, size_t okmlen,
    const unsigned char *prk, size_t prklen,
    const unsigned char *info, size_t infolen);

int ossl_hpke_labeled_extract(EVP_KDF_CTX *kctx,
    unsigned char *prk, size_t prklen,
    const unsigned char *salt, size_t saltlen,
    const char *protocol_label,
    const unsigned char *suiteid, size_t suiteidlen,
    const char *label,
    const unsigned char *ikm, size_t ikmlen);
int ossl_hpke_labeled_expand(EVP_KDF_CTX *kctx,
    unsigned char *okm, size_t okmlen,
    const unsigned char *prk, size_t prklen,
    const char *protocol_label,
    const unsigned char *suiteid, size_t suiteidlen,
    const char *label,
    const unsigned char *info, size_t infolen);

int ossl_hpke_labeled_derive_xof(uint8_t *out, size_t outlen, EVP_MD *md_xof,
    uint16_t kemid, const char *label, const uint8_t *ikm, size_t ikmlen,
    const uint8_t *context, size_t contextlen);
int ossl_hpke_keypair_derive_xof(uint8_t *out, size_t outlen,
    EVP_MD *md_xof, uint16_t kemid, const uint8_t *ikm, size_t ikmlen);

EVP_KDF_CTX *ossl_kdf_ctx_create(const char *kdfname, const char *mdname,
    OSSL_LIB_CTX *libctx, const char *propq);

int ossl_hpke_str2suite(const char *suitestr, OSSL_HPKE_SUITE *suite);
#endif
