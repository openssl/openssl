/*
 * Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h" /* PKCS1_MGF1() */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h> /* PKCS1_MGF1() */
#include <openssl/sha.h> /* PKCS1_MGF1() */
#include "slh_dsa_local.h"
#include "slh_dsa_key.h"

#define MAX_DIGEST_SIZE 64 /* SHA-512 is used for security category 3 & 5 */

static OSSL_SLH_HASHFUNC_HASH slh_hash_sha256;
static OSSL_SLH_HASHFUNC_HASH slh_hash_sha512;
static OSSL_SLH_HASHFUNC_HASH slh_hash_shake;
static OSSL_SLH_HASHFUNC_H_MSG slh_hmsg_shake;
#ifdef NORMAL
static OSSL_SLH_HASHFUNC_H_MSG slh_hmsg_sha256;
static OSSL_SLH_HASHFUNC_PRF_MSG slh_prf_msg_sha256;
#endif
static OSSL_SLH_HASHFUNC_H_MSG slh_hmsg_sha512;
static OSSL_SLH_HASHFUNC_PRF_MSG slh_prf_msg_sha512;
static OSSL_SLH_HASHFUNC_PRF_MSG slh_prf_msg_shake;
static OSSL_SLH_HASHFUNC_prehash_pk_seed slh_prehash_pk_seed_sha256;
static OSSL_SLH_HASHFUNC_prehash_pk_seed slh_prehash_pk_seed_shake;

static const uint8_t zeros[128] = { 0 };

/* See FIPS 205 Section 11.1 for SHAKE hash functions */

/*
 * Pre caches SHA256(pkseed) so that it can be used multiple times by
 * duping ctx->sha_ctx_pkseed.
 */
static int
slh_prehash_pk_seed_shake(SLH_DSA_HASH_CTX *hctx, const uint8_t *pkseed, size_t n)
{
    EVP_MD_CTX *ctx = hctx->sha_ctx_pkseed;

    return EVP_DigestUpdate(ctx, pkseed, n);
}

/* SHAKE256(pk_seed || ADRS || in, n) */
static int slh_hash_shake(SLH_DSA_HASH_CTX *hctx,
                          const uint8_t *pk_seed, const uint8_t *adrs,
                          const uint8_t *in, size_t in_len,
                          uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_dup(hctx->sha_ctx_pkseed);
    int ret = (ctx != NULL)
        && EVP_DigestUpdate(ctx, adrs, SLH_ADRS_SIZE)
        && EVP_DigestUpdate(ctx, in, in_len)
        && EVP_DigestFinalXOF(ctx, out, hctx->key->params->n);

    EVP_MD_CTX_free(ctx);
    return ret;
}

/* SHAKE256(r || pk_seed || pk_root || msg, m) */
static int
slh_hmsg_shake(SLH_DSA_HASH_CTX *hctx, const uint8_t *r,
               const uint8_t *pk_seed_and_root,
               const uint8_t *msg, size_t msg_len,
               uint8_t *out, size_t out_len)
{
    EVP_MD_CTX *ctx = hctx->sha_ctx;
    const SLH_DSA_PARAMS *params = hctx->key->params;
    size_t m = params->m;
    size_t n = params->n;

    return EVP_DigestInit_ex2(ctx, NULL, NULL)
        && EVP_DigestUpdate(ctx, r, n)
        && EVP_DigestUpdate(ctx, pk_seed_and_root, 2 * n)
        && EVP_DigestUpdate(ctx, msg, msg_len)
        && EVP_DigestFinalXOF(ctx, out, m);
}

/* SHAKE256(SK.prf || opt_rand || msg, n) */
static int
slh_prf_msg_shake(SLH_DSA_HASH_CTX *hctx, const uint8_t *sk_prf,
                  const uint8_t *opt_rand, const uint8_t *msg, size_t msg_len,
                  WPACKET *pkt)
{
    unsigned char out[SLH_MAX_N];
    EVP_MD_CTX *ctx = hctx->sha_ctx;
    size_t n = hctx->key->params->n;

    return EVP_DigestInit_ex2(ctx, NULL, NULL)
        && EVP_DigestUpdate(ctx, sk_prf, n)
        && EVP_DigestUpdate(ctx, opt_rand, n)
        && EVP_DigestUpdate(ctx, msg, msg_len)
        && EVP_DigestFinalXOF(ctx, out, n)
        && WPACKET_memcpy(pkt, out, n);
}

/* See FIPS 205 Section 11.2.1 and 11.2.2 for SHA256/SHA512 Hash Functions */

/* Trunc(SHA256(pk_seed || zeros(64 - n) || in), n) */
static int
slh_hash_sha256(SLH_DSA_HASH_CTX *hctx, const uint8_t *pk_seed, const uint8_t *adrs,
                const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    int ret;
    uint8_t digest[MAX_DIGEST_SIZE];
    EVP_MD_CTX *ctx = EVP_MD_CTX_dup(hctx->sha_ctx_pkseed);

    ret = (ctx != NULL)
        && EVP_DigestUpdate(ctx, adrs, SLH_ADRSC_SIZE)
        && EVP_DigestUpdate(ctx, in, inlen)
        && EVP_DigestFinal_ex(ctx, digest, NULL);
    if (ret)
        memcpy(out, digest, hctx->key->params->n); /* Truncated to n bytes */
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int
slh_hash_sha512(SLH_DSA_HASH_CTX *hctx, const uint8_t *pk_seed, const uint8_t *adrs,
                const uint8_t *in, size_t inlen, uint8_t *out, size_t outlen)
{
    int ret;
    uint8_t digest[MAX_DIGEST_SIZE];
    EVP_MD_CTX *ctx = hctx->sha512_ctx;
    size_t n = hctx->key->params->n;

    ret = EVP_DigestInit_ex2(ctx, NULL, NULL)
        && EVP_DigestUpdate(ctx, pk_seed, n)
        && EVP_DigestUpdate(ctx, zeros, 128 - n)
        && EVP_DigestUpdate(ctx, adrs, SLH_ADRSC_SIZE)
        && EVP_DigestUpdate(ctx, in, inlen)
        && EVP_DigestFinal_ex(ctx, digest, NULL);
    if (ret)
        memcpy(out, digest, n); /* Truncated to n bytes */
    return ret;
}

/*
 * Pre caches SHA256(pkseed || zeros(64 -n) so that it can be used multiple
 * times by duping ctx->sha_ctx_pkseed.
 */
static int
slh_prehash_pk_seed_sha256(SLH_DSA_HASH_CTX *hctx, const uint8_t *pkseed, size_t n)
{
    EVP_MD_CTX *ctx = hctx->sha_ctx_pkseed;

    return EVP_DigestUpdate(ctx, pkseed, n)
        && EVP_DigestUpdate(ctx, zeros, 64 - n);
}

/*
 * Either
 *  MGF1-SHA-256(r || pk_seed || SHA-256(r || pk_seed || pk_root || msg), m)
 * OR
 *  MGF1-SHA-512(r || pk_seed || SHA-512(r || pk_seed || pk_root || msg), m)
 */
static ossl_inline int
slh_hmsg(EVP_MD_CTX *ctx, EVP_MD *md, const SLH_DSA_PARAMS *params, size_t sz,
         const uint8_t *r, const uint8_t *pk_seed_and_root,
         const uint8_t *msg, size_t msg_len,
         uint8_t *out)
{
    size_t m = params->m;
    size_t n = params->n;
    /* Seed will contain r || PK.seed || SHA-XXX(r || PK.seed || PK.root || msg) */
    uint8_t seed[2 * SLH_MAX_N + MAX_DIGEST_SIZE];
    size_t seed_len = 2 * n + sz;

    memcpy(seed, r, n);
    memcpy(seed + n, pk_seed_and_root, n);
    return EVP_DigestInit_ex2(ctx, NULL, NULL)
        && EVP_DigestUpdate(ctx, r, n)
        && EVP_DigestUpdate(ctx, pk_seed_and_root, n * 2)
        && EVP_DigestUpdate(ctx, msg, msg_len)
        && EVP_DigestFinal_ex(ctx, seed + 2 * n, NULL)
        && (PKCS1_MGF1(out, (long)m, seed, (long)seed_len, md) == 0);
}

/* MGF1-SHA-256(r || pk_seed || SHA-256(r || pk_seed || pk_root || msg), m) */
static int
slh_hmsg_sha256(SLH_DSA_HASH_CTX *hctx, const uint8_t *r,
                const uint8_t *pk_seed_and_root,
                const uint8_t *msg, size_t msg_len,
                uint8_t *out, size_t out_len)
{
    return slh_hmsg(hctx->sha_ctx, hctx->key->md_sha, hctx->key->params,
                    SHA256_DIGEST_LENGTH, r, pk_seed_and_root, msg, msg_len, out);
}

/* MGF1-SHA-512(r || pk_seed || SHA-512(r || pk_seed || pk_root || msg), m) */
static int
slh_hmsg_sha512(SLH_DSA_HASH_CTX *hctx, const uint8_t *r,
                const uint8_t *pk_seed_and_root,
                const uint8_t *msg, size_t msg_len,
                uint8_t *out, size_t out_len)
{
    return slh_hmsg(hctx->sha512_ctx, hctx->key->md_sha512, hctx->key->params,
                    SHA512_DIGEST_LENGTH, r, pk_seed_and_root, msg, msg_len, out);
}

/* Trunc(n)(HMAC-SHA-XXX(SK.prf, opt_rand || msg) */
static int
slh_prf_msg_sha(SLH_DSA_HASH_CTX *hctx, EVP_MD *md,
                const uint8_t *sk_prf, const uint8_t *opt_rand,
                const uint8_t *msg, size_t msg_len, WPACKET *pkt)
{
    int ret;
    const SLH_DSA_KEY *key = hctx->key;
    EVP_MAC_CTX *mctx = hctx->hmac_ctx;
    const SLH_DSA_PARAMS *prms = key->params;
    size_t n = prms->n;
    uint8_t mac[MAX_DIGEST_SIZE] = {0};
    OSSL_PARAM *p = NULL;
    OSSL_PARAM params[3];

    /*
     * Due to the way HMAC works, it is not possible to do this code early
     * in hmac_ctx_new() since it requires a key in order to set the digest.
     * So we do a lazy update here on the first call.
     */
    if (hctx->hmac_digest_used == 0) {
        p = params;
        /* The underlying digest to be used */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                (char *)EVP_MD_get0_name(md), 0);
        if (key->propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                    (char *)key->propq, 0);
        *p = OSSL_PARAM_construct_end();
        p = params;
        hctx->hmac_digest_used = 1;
    }

    ret = EVP_MAC_init(mctx, sk_prf, n, p) == 1
        && EVP_MAC_update(mctx, opt_rand, n) == 1
        && EVP_MAC_update(mctx, msg, msg_len) == 1
        && EVP_MAC_final(mctx, mac, NULL, sizeof(mac)) == 1
        && WPACKET_memcpy(pkt, mac, n); /* Truncate output to n bytes */
    return ret;
}

/* Trunc(n)(HMAC-SHA-256(sk_prf, opt_rand || msg) */
static int
slh_prf_msg_sha256(SLH_DSA_HASH_CTX *hctx,
                   const uint8_t *sk_prf, const uint8_t *opt_rand,
                   const uint8_t *msg, size_t msg_len, WPACKET *pkt)
{
    return slh_prf_msg_sha(hctx, hctx->key->md_sha, sk_prf, opt_rand,
                           msg, msg_len, pkt);
}

/* Trunc(n)(HMAC-SHA-512(sk_prf, opt_rand || msg) */
static int
slh_prf_msg_sha512(SLH_DSA_HASH_CTX *hctx,
                   const uint8_t *sk_prf, const uint8_t *opt_rand,
                   const uint8_t *msg, size_t msg_len, WPACKET *pkt)
{
    return slh_prf_msg_sha(hctx, hctx->key->md_sha512, sk_prf, opt_rand,
                           msg, msg_len, pkt);
}

const SLH_HASH_FUNC *ossl_slh_get_hash_fn(int is_shake, int security_category)
{
    static const SLH_HASH_FUNC methods[] = {
        {
            slh_prehash_pk_seed_shake,
            slh_hash_shake, /* prf */
            slh_hash_shake, /* f */
            slh_hash_shake, /* h */
            slh_hash_shake, /* t */
            slh_hmsg_shake,
            slh_prf_msg_shake,
        },
        {
            slh_prehash_pk_seed_sha256,
            slh_hash_sha256,    /* prf */
            slh_hash_sha256,    /* f */
            slh_hash_sha256,    /* h */
            slh_hash_sha256,    /* t */
            slh_hmsg_sha256,
            slh_prf_msg_sha256,
        },
        {
            slh_prehash_pk_seed_sha256,
            slh_hash_sha256,    /* prf */
            slh_hash_sha256,    /* f */
            slh_hash_sha512,    /* h */
            slh_hash_sha512,    /* t */
            slh_hmsg_sha512,
            slh_prf_msg_sha512,
        },
    };
    return &methods[is_shake ? 0 : (security_category == 1 ? 1 : 2)];
}
