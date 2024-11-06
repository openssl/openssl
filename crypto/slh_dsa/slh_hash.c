/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/deprecated.h" /* PKCS1_MGF1() */

#include <assert.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/rsa.h> /* PKCS1_MGF1() */
#include "slh_dsa_local.h"

#define MAX_DIGEST_SIZE 64 /* SHA-512 is used for security category 3 & 5 */
/*
 * PRF(), F() use this value to calculate the number of zeros
 * H(), T() also use this for security cat 1
 */
#define SHA2_NUM_ZEROS_BOUND1 64
/* H(), T() use this to calculate the number of zeros for security cat 3 & 5 */
#define SHA2_NUM_ZEROS_BOUND2 128

static OSSL_SLH_HASHFUNC_H_MSG slh_hmsg_sha2;
static OSSL_SLH_HASHFUNC_PRF slh_prf_sha2;
static OSSL_SLH_HASHFUNC_PRF_MSG slh_prf_msg_sha2;
static OSSL_SLH_HASHFUNC_F slh_f_sha2;
static OSSL_SLH_HASHFUNC_H slh_h_sha2;
static OSSL_SLH_HASHFUNC_T slh_t_sha2;

static EVP_MAC_CTX *hmac_ctx_new(OSSL_LIB_CTX *lib_ctx, const char *propq)
{
    EVP_MAC_CTX *mctx = NULL;
    EVP_MAC *mac = EVP_MAC_fetch(lib_ctx, "HMAC", propq);

    if (mac == NULL)
        return NULL;
    mctx = EVP_MAC_CTX_new(mac);
    EVP_MAC_free(mac);
    return mctx;
}

static EVP_MD_CTX *md_ctx_new(EVP_MD *md)
{
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if (ctx == NULL)
        return NULL;

    if (EVP_DigestInit_ex2(ctx, md, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

int ossl_slh_hash_ctx_init(SLH_HASH_CTX *ctx, OSSL_LIB_CTX *lib_ctx,
                           const char *propq, int is_shake,
                           int security_category, size_t n, size_t m)
{
    const char *digest_alg = is_shake ? "SHAKE-256" : "SHA2-256";

    ctx->md = EVP_MD_fetch(lib_ctx, digest_alg, propq);
    if (ctx->md == NULL)
        return 0;
    /* For SHA2 all categories require a SHA2-256 digest */
    ctx->md_ctx = md_ctx_new(ctx->md);
    if (ctx->md_ctx == NULL)
        goto err;

    /*
     * SHA2 algorithm(s) require SHA256 + HMAC_SHA(X) & MGF1(SHAX)
     * SHAKE algorithm(s) use SHAKE for all functions.
     */
    if (is_shake == 0) {
        if (security_category == 1) {
            ctx->sha2_h_and_t_bound = SHA2_NUM_ZEROS_BOUND1;
            /* For category 1 SHA2-256 is used for all hash operations */
            ctx->md_big_ctx = ctx->md_ctx;
            ctx->hmac_digest = "SHA2-256";
        } else {
            /* Security categories 3 & 5 also need SHA-512 */
            EVP_MD_free(ctx->md);
            ctx->md = EVP_MD_fetch(lib_ctx, "SHA2-512", propq);
            if (ctx->md == NULL)
                goto err;
            ctx->sha2_h_and_t_bound = SHA2_NUM_ZEROS_BOUND2;
            /* Use HMAC-SHA2-512 for PRF_MSG */
            ctx->hmac_digest = "SHA2-512";
            /* use SHA2-512 in H_MSG, H and T */
            ctx->md_big_ctx = md_ctx_new(ctx->md);
            if (ctx->md_big_ctx == NULL)
                goto err;
            /* PRF & F use SHA2-256 via ctx->md_ctx */

        }
        /* This assumes that propq exists for the duration of the operation */
        ctx->hmac_propq = propq;
        ctx->hmac_ctx = hmac_ctx_new(lib_ctx, propq);
        if (ctx->hmac_ctx == NULL)
            goto err;
    }
    ctx->n = n;
    ctx->m = m;
    return 1;
 err:
    ossl_slh_hash_ctx_cleanup(ctx);
    return 0;
}

void ossl_slh_hash_ctx_cleanup(SLH_HASH_CTX *ctx)
{
    EVP_MD_free(ctx->md);
    EVP_MAC_CTX_free(ctx->hmac_ctx);
    if (ctx->md_big_ctx != ctx->md_ctx)
        EVP_MD_CTX_free(ctx->md_big_ctx);
    EVP_MD_CTX_free(ctx->md_ctx);
}

static ossl_inline int
digest_4(EVP_MD_CTX *ctx,
         const uint8_t *in1, size_t in1_len, const uint8_t *in2, size_t in2_len,
         const uint8_t *in3, size_t in3_len, const uint8_t *in4, size_t in4_len,
         uint8_t *out)
{
    return (EVP_DigestInit_ex2(ctx, NULL, NULL) == 1
            && EVP_DigestUpdate(ctx, in1, in1_len) == 1
            && EVP_DigestUpdate(ctx, in2, in2_len) == 1
            && EVP_DigestUpdate(ctx, in3, in3_len) == 1
            && EVP_DigestUpdate(ctx, in4, in4_len) == 1
            && EVP_DigestFinal_ex(ctx, out, NULL) == 1);
}

/* FIPS 205 Section 11.2.1 and 11.2.2 */

static void
slh_hmsg_sha2(SLH_HASH_CTX *hctx, const uint8_t *r, const uint8_t *pk_seed,
              const uint8_t *pk_root, const uint8_t *msg, size_t msg_len,
              uint8_t *out)
{
    size_t n = hctx->n;
    uint8_t seed[2 * SLH_MAX_N + MAX_DIGEST_SIZE];
    int sz = EVP_MD_get_size(hctx->md);
    size_t seed_len = (size_t)sz + 2 * n;

    assert(sz > 0);
    assert(seed_len <= sizeof(seed));

    memcpy(seed, r, n);
    memcpy(seed + n, pk_seed, n);
    digest_4(hctx->md_big_ctx, r, n, pk_seed, n, pk_root, n, msg, msg_len,
             seed + 2 * n);
    PKCS1_MGF1(out, hctx->m, seed, seed_len, hctx->md);
}

static void
slh_prf_msg_sha2(SLH_HASH_CTX *hctx,
                 const uint8_t *sk_prf, const uint8_t *opt_rand,
                 const uint8_t *msg, size_t msg_len, uint8_t *out)
{
    EVP_MAC_CTX *mctx = hctx->hmac_ctx;
    size_t n = hctx->n;
    uint8_t mac[MAX_DIGEST_SIZE];
    OSSL_PARAM *p = NULL;
    OSSL_PARAM params[3];

    /*
     * Due to the way HMAC works, it is not possible to do this code early
     * in hmac_ctx_new() since it requires a key in order to set the digest.
     */
    if (hctx->hmac_digest != NULL) {
        p = params;
        /* The underlying digest to be used */
        *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                (char *)hctx->hmac_digest, 0);
        if (hctx->hmac_propq != NULL)
            *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                    (char *)hctx->hmac_propq, 0);
        *p = OSSL_PARAM_construct_end();
        p = params;
        hctx->hmac_digest = NULL;
    }

    EVP_MAC_init(mctx, sk_prf, n, p);
    EVP_MAC_update(mctx, opt_rand, n);
    EVP_MAC_update(mctx, msg, msg_len);
    EVP_MAC_final(mctx, mac, NULL, sizeof(mac));
    memcpy(out, mac, n); /* Truncate output to n bytes */
}

static ossl_inline void
do_hash(EVP_MD_CTX *ctx, size_t n, const uint8_t *pk_seed, const SLH_ADRS adrs,
        const uint8_t *m, size_t m_len, size_t b, uint8_t *out)
{
    uint8_t zeros[128] = { 0 };
    uint8_t digest[MAX_DIGEST_SIZE];

    assert(b - n < sizeof(zeros));

    digest_4(ctx, pk_seed, n, zeros, b - n, adrs, SLH_ADRSC_SIZE, m, m_len,
             digest);
    /* Truncated returned value is n = 16 bytes */
    memcpy(out, digest, n);
}

static void
slh_prf_sha2(SLH_HASH_CTX *hctx, const uint8_t *pk_seed,
             const uint8_t *sk_seed, const SLH_ADRS adrs, uint8_t *out)
{
    size_t n = hctx->n;

    do_hash(hctx->md_ctx, n, pk_seed, adrs, sk_seed, n,
            SHA2_NUM_ZEROS_BOUND1, out);
}

static void
slh_f_sha2(SLH_HASH_CTX *hctx, const uint8_t *pk_seed, const SLH_ADRS adrs,
           const uint8_t *m1, size_t m1_len, uint8_t *out)
{
    do_hash(hctx->md_ctx, hctx->n, pk_seed, adrs, m1, m1_len,
            SHA2_NUM_ZEROS_BOUND1, out);
}

static void
slh_h_sha2(SLH_HASH_CTX *hctx, const uint8_t *pk_seed, const SLH_ADRS adrs,
           const uint8_t *m1, const uint8_t *m2, uint8_t *out)
{
    uint8_t m[SLH_MAX_N * 2];
    size_t n = hctx->n;

    memcpy(m, m1, n);
    memcpy(m + n, m2, n);
    do_hash(hctx->md_big_ctx, n, pk_seed, adrs, m, 2 * n,
            hctx->sha2_h_and_t_bound, out);
}

static void
slh_t_sha2(SLH_HASH_CTX *hctx, const uint8_t *pk_seed, const SLH_ADRS adrs,
           const uint8_t *ml, size_t ml_len, uint8_t *out)
{
    do_hash(hctx->md_big_ctx, hctx->n, pk_seed, adrs, ml, ml_len,
            hctx->sha2_h_and_t_bound, out);
}

const SLH_HASH_FUNC *ossl_slh_get_hash_fn(int is_shake)
{
    static const SLH_HASH_FUNC methods[] = {
        {
            slh_hmsg_sha2,
            slh_prf_sha2,
            slh_prf_msg_sha2,
            slh_f_sha2,
            slh_h_sha2,
            slh_t_sha2
        }
    };
    return &methods[0];
}
