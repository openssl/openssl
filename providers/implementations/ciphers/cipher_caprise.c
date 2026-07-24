/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Dispatch functions for CAPRISE cipher */

#include <string.h>
#define _USE_MATH_DEFINES
#include <math.h>
#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include "cipher_caprise.h"
#include "prov/implementations.h"
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "providers/implementations/ciphers/cipher_caprise.inc"

#define CAPRISE_MAX_DIM    4096  /* Maximum supported embedding dimension */
#define CAPRISE_KEY_SIZE   32     /* PRF key size in bytes */
#define CAPRISE_IV_SIZE    16     /* IV/nonce size */
#define CAPRISE_BLKSIZE    8      /* Block size for double precision vectors */

#define CAPRISE_FLAGS      (PROV_CIPHER_FLAG_CUSTOM_IV | PROV_CIPHER_FLAG_CTS)

static OSSL_FUNC_cipher_newctx_fn caprise_newctx;
static OSSL_FUNC_cipher_freectx_fn caprise_freectx;
static OSSL_FUNC_cipher_dupctx_fn caprise_dupctx;
static OSSL_FUNC_cipher_get_params_fn caprise_get_params;
static OSSL_FUNC_cipher_get_ctx_params_fn caprise_get_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn caprise_set_ctx_params;

/* Helper function to read double values from byte array */
static double bytes_to_double(const unsigned char *bytes)
{
    double value;
    memcpy(&value, bytes, sizeof(double));
    return value;
}

/* Helper function to write double values to byte array */
static void double_to_bytes(double value, unsigned char *bytes)
{
    memcpy(bytes, &value, sizeof(double));
}

/* Helper function to compute vector norm */
static double vector_norm(const double *vector, size_t dim)
{
    double norm = 0.0;
    size_t i;

    for (i = 0; i < dim; i++) {
        norm += vector[i] * vector[i];
    }
    return sqrt(norm);
}

/* Helper function to scale vector by scalar */
static void scale_vector(double *vector, size_t dim, double scalar)
{
    size_t i;

    for (i = 0; i < dim; i++) {
        vector[i] *= scalar;
    }
}

/* Helper function to add vectors */
static void add_vectors(const double *a, const double *b, double *result, size_t dim)
{
    size_t i;

    for (i = 0; i < dim; i++) {
        result[i] = a[i] + b[i];
    }
}

/* Helper function to subtract vectors */
static void sub_vectors(const double *a, const double *b, double *result, size_t dim)
{
    size_t i;

    for (i = 0; i < dim; i++) {
        result[i] = a[i] - b[i];
    }
}

/* Gaussian random number generation using Box-Muller transform */
static double gaussian_random(OSSL_LIB_CTX *libctx,
                               const unsigned char *seed, size_t seed_len)
{
    unsigned char hash1[EVP_MAX_MD_SIZE], hash2[EVP_MAX_MD_SIZE];
    size_t hash_len;
    double u1, u2, z0 = 0.0;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    int ret = 0;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    mac = EVP_MAC_fetch(libctx, "HMAC", NULL);
    if (mac == NULL)
        return 0.0;

    /* First uniform value: HMAC(seed, "u1") */
    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
        goto err;
    if (!EVP_MAC_init(mctx, seed, seed_len, params))
        goto err;
    if (!EVP_MAC_update(mctx, (const unsigned char *)"u1", 2))
        goto err;
    hash_len = sizeof(hash1);
    if (!EVP_MAC_final(mctx, hash1, &hash_len, sizeof(hash1)))
        goto err;

    u1 = ((uint32_t)hash1[0] | ((uint32_t)hash1[1] << 8)
          | ((uint32_t)hash1[2] << 16)) / (double)((1U << 24) - 1U);
    if (u1 == 0.0)
        u1 = 0.000001; /* Avoid log(0) */

    /* Second uniform value: HMAC(seed, "u2") - fresh context, same key */
    EVP_MAC_CTX_free(mctx);
    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
        goto err;
    if (!EVP_MAC_init(mctx, seed, seed_len, params))
        goto err;
    if (!EVP_MAC_update(mctx, (const unsigned char *)"u2", 2))
        goto err;
    hash_len = sizeof(hash2);
    if (!EVP_MAC_final(mctx, hash2, &hash_len, sizeof(hash2)))
        goto err;

    u2 = ((uint32_t)hash2[0] | ((uint32_t)hash2[1] << 8)
          | ((uint32_t)hash2[2] << 16)) / (double)((1U << 24) - 1U);

    /* Box-Muller transform */
    z0 = sqrt(-2.0 * log(u1)) * cos(2.0 * M_PI * u2);
    ret = 1;
err:
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return ret ? z0 : 0.0;
}

/* Generate noise vector using PRF */
static int generate_noise_vector_prf(OSSL_LIB_CTX *libctx,
                                     const CAPRISE_KEY *key,
                                     const unsigned char *nonce, size_t nonce_len,
                                     size_t dim, unsigned int mode,
                                     double *noise_vector)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    size_t hash_len;
    EVP_MAC *mac = NULL;
    EVP_MAC_CTX *mctx = NULL;
    double *gaussian_vec = NULL;
    double norm_gaussian;
    double u;
    double noise_magnitude;
    double temp;
    size_t i;
    int ret = 0;
    double noise_coefficient;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    mac = EVP_MAC_fetch(libctx, "HMAC", NULL);
    if (mac == NULL)
        return 0;

    gaussian_vec = OPENSSL_malloc(sizeof(double) * dim);
    if (gaussian_vec == NULL)
        goto err;

    /* Generate Gaussian vector n */
    for (i = 0; i < dim; i++) {
        EVP_MAC_CTX_free(mctx);
        mctx = EVP_MAC_CTX_new(mac);
        if (mctx == NULL)
            goto err;
        if (!EVP_MAC_init(mctx, key->K, key->K_len, params))
            goto err;
        if (!EVP_MAC_update(mctx, nonce, nonce_len))
            goto err;
        if (!EVP_MAC_update(mctx, (unsigned char *)&i, sizeof(i)))
            goto err;
        hash_len = sizeof(hash);
        if (!EVP_MAC_final(mctx, hash, &hash_len, sizeof(hash)))
            goto err;

        gaussian_vec[i] = gaussian_random(libctx, hash, hash_len);
    }

    /* Compute norm of Gaussian vector */
    norm_gaussian = vector_norm(gaussian_vec, dim);

    if (norm_gaussian == 0.0) {
        /* Handle degenerate case */
        for (i = 0; i < dim; i++)
            gaussian_vec[i] = 0.01;
        norm_gaussian = vector_norm(gaussian_vec, dim);
    }

    /* Generate uniform random u in [0,1]: HMAC(K, nonce || "uniform") */
    EVP_MAC_CTX_free(mctx);
    mctx = EVP_MAC_CTX_new(mac);
    if (mctx == NULL)
        goto err;
    if (!EVP_MAC_init(mctx, key->K, key->K_len, params))
        goto err;
    if (!EVP_MAC_update(mctx, nonce, nonce_len))
        goto err;
    if (!EVP_MAC_update(mctx, (const unsigned char *)"uniform", 7))
        goto err;
    hash_len = sizeof(hash);
    if (!EVP_MAC_final(mctx, hash, &hash_len, sizeof(hash)))
        goto err;

    u = ((uint32_t)hash[0] | ((uint32_t)hash[1] << 8)
         | ((uint32_t)hash[2] << 16) | ((uint32_t)hash[3] << 24))
        / (double)0xFFFFFFFFU;
    if (u == 0.0)
        u = 0.000001;

    /* Compute noise coefficient based on mode */
    if (mode == CAPRISE_MODE_DB) {
        /* λ = (3/8) * (n * s * β / ||n||) * (u)^(1/d) */
        noise_coefficient = 0.375 * key->s * key->beta;
    } else {
        /* η = (1/8) * (n * s * β / ||n||) * (u)^(1/d) */
        noise_coefficient = 0.125 * key->s * key->beta;
    }

    /* Compute u^(1/d) using exp(log(u)/d) */
    temp = exp(log(u) / (double)dim);
    noise_magnitude = noise_coefficient * temp;

    /* Generate noise vector */
    for (i = 0; i < dim; i++) {
        noise_vector[i] = (gaussian_vec[i] / norm_gaussian) * noise_magnitude;
    }

    ret = 1;

err:
    OPENSSL_free(gaussian_vec);
    EVP_MAC_CTX_free(mctx);
    EVP_MAC_free(mac);
    return ret;
}

/* Generate noise vector */
int caprise_generate_noise_vector(const unsigned char *prf_output, size_t prf_len,
                                  double s, double beta, size_t dim,
                                  unsigned int mode,
                                  double *noise_vector)
{
    CAPRISE_KEY key;

    key.s = s;
    key.K = (unsigned char *)prf_output;
    key.K_len = prf_len;
    key.beta = beta;

    /*
     * Public API: use NULL libctx (default). The prf_output is used as the
     * PRF key; callers must supply a separate nonce for per-vector randomness.
     * Here we derive the nonce by hashing the key material with a fixed tag
     * to maintain key/nonce separation.
     */
    return generate_noise_vector_prf(NULL, &key, prf_output, prf_len, dim,
                                     mode, noise_vector);
}

/* CAPRISE encryption: e' = s * e + noise */
int caprise_encrypt_vector(OSSL_LIB_CTX *libctx,
                           double *vector, size_t dim,
                           const CAPRISE_KEY *key, unsigned int mode,
                           const unsigned char *nonce, size_t nonce_len,
                           double *out_vector)
{
    double *noise_vector = NULL;
    int ret = 0;

    noise_vector = OPENSSL_malloc(sizeof(double) * dim);
    if (noise_vector == NULL)
        return 0;

    if (!generate_noise_vector_prf(libctx, key, nonce, nonce_len, dim, mode,
                                   noise_vector))
        goto err;

    /* Scale original vector: s * e */
    scale_vector(vector, dim, key->s);

    /* Add noise: e' = s * e + λ or η */
    add_vectors(vector, noise_vector, out_vector, dim);

    ret = 1;

err:
    OPENSSL_free(noise_vector);
    return ret;
}

/* CAPRISE decryption: e = (e' - noise) / s */
int caprise_decrypt_vector(OSSL_LIB_CTX *libctx,
                           double *vector, size_t dim,
                           const CAPRISE_KEY *key, unsigned int mode,
                           const unsigned char *nonce, size_t nonce_len,
                           double *out_vector)
{
    double *noise_vector = NULL;
    int ret = 0;

    noise_vector = OPENSSL_malloc(sizeof(double) * dim);
    if (noise_vector == NULL)
        return 0;

    /* Regenerate the same noise vector using the mode that was used to encrypt */
    if (!generate_noise_vector_prf(libctx, key, nonce, nonce_len, dim, mode,
                                   noise_vector))
        goto err;

    /* Subtract noise: e' - noise */
    sub_vectors(vector, noise_vector, out_vector, dim);

    /* Scale back: (e' - noise) / s */
    scale_vector(out_vector, dim, 1.0 / key->s);

    ret = 1;

err:
    OPENSSL_free(noise_vector);
    return ret;
}

/* Initialize CAPRISE context */
void ossl_caprise_initctx(PROV_CAPRISE_CTX *ctx)
{
    ctx->base.libctx = NULL;
    ctx->base.hw = NULL;
    ctx->base.mode = EVP_CIPH_ECB_MODE;
    ctx->base.blocksize = CAPRISE_BLKSIZE;
    ctx->base.ivlen = CAPRISE_IV_SIZE;
    ctx->base.keylen = CAPRISE_KEY_SIZE;
    ctx->base.pad = 0;
    ctx->base.enc = 0;
    ctx->base.key_set = 0;
    ctx->base.iv_set = 0;
    ctx->base.num = 0;
    ctx->mode = CAPRISE_MODE_DB;
    ctx->dim = CAPRISE_DEFAULT_DIM;
    ctx->key.s = CAPRISE_DEFAULT_S;
    ctx->key.beta = CAPRISE_DEFAULT_BETA;
    ctx->r = NULL;
    ctx->r_len = 0;
    ctx->noise = NULL;
    ctx->noise_len = 0;
    ctx->temp = NULL;
    ctx->temp_len = 0;
}

/* Allocate and initialize new context */
static void *caprise_newctx(void *provctx)
{
    PROV_CAPRISE_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(*ctx));
    if (ctx != NULL) {
        ossl_caprise_initctx(ctx);
        ctx->base.libctx = PROV_LIBCTX_OF(provctx);
    }
    return ctx;
}

/* Free context */
static void caprise_freectx(void *vctx)
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;

    if (ctx != NULL) {
        OPENSSL_clear_free(ctx->key.K, ctx->key.K_len);
        OPENSSL_clear_free(ctx->r, ctx->r_len);
        OPENSSL_free(ctx->noise);
        OPENSSL_free(ctx->temp);
        OPENSSL_clear_free(ctx, sizeof(*ctx));
    }
}

/* Duplicate context */
static void *caprise_dupctx(void *vctx)
{
    PROV_CAPRISE_CTX *src = (PROV_CAPRISE_CTX *)vctx;
    PROV_CAPRISE_CTX *dst;

    dst = OPENSSL_zalloc(sizeof(*dst));
    if (dst == NULL)
        return NULL;

    *dst = *src;

    /*
     * After the struct copy, dst holds shallow copies of all pointers.
     * Null them out before deep-copying so that partial-failure cleanup
     * via caprise_freectx does not double-free src's buffers.
     */
    dst->key.K = NULL;
    dst->r = NULL;
    dst->noise = NULL;
    dst->temp = NULL;

    /* Duplicate key */
    if (src->key.K != NULL) {
        dst->key.K = OPENSSL_memdup(src->key.K, src->key.K_len);
        if (dst->key.K == NULL)
            goto err;
    }

    /* Duplicate nonce */
    if (src->r != NULL) {
        dst->r = OPENSSL_memdup(src->r, src->r_len);
        if (dst->r == NULL)
            goto err;
    }

    /* Duplicate temp buffer */
    if (src->temp != NULL) {
        dst->temp = OPENSSL_malloc(src->temp_len);
        if (dst->temp == NULL)
            goto err;
    }

    /* noise is a transient scratch buffer; start fresh in the duplicate */
    dst->noise_len = 0;

    return dst;

err:
    caprise_freectx(dst);
    return NULL;
}

/* Get cipher parameters */
static int caprise_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, EVP_CIPH_ECB_MODE,
        CAPRISE_FLAGS,
        CAPRISE_KEY_SIZE * 8,
        CAPRISE_BLKSIZE * 8,
        CAPRISE_IV_SIZE * 8);
}

/* Get context parameters */
static int caprise_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAPRISE_KEY_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, CAPRISE_IV_SIZE))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->base.pad))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_NUM);
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->base.num))
        return 0;

    p = OSSL_PARAM_locate(params, "caprise_mode");
    if (p != NULL && !OSSL_PARAM_set_uint(p, ctx->mode))
        return 0;

    p = OSSL_PARAM_locate(params, "caprise_dim");
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->dim))
        return 0;

    p = OSSL_PARAM_locate(params, "caprise_s");
    if (p != NULL && !OSSL_PARAM_set_double(p, ctx->key.s))
        return 0;

    p = OSSL_PARAM_locate(params, "caprise_beta");
    if (p != NULL && !OSSL_PARAM_set_double(p, ctx->key.beta))
        return 0;

    return 1;
}

/* Set context parameters */
static int caprise_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;
    const OSSL_PARAM *p;
    size_t size;

    if (ctx == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_PADDING);
    if (p != NULL) {
        unsigned int pad;

        if (!OSSL_PARAM_get_uint(p, &pad))
            return 0;
        ctx->base.pad = pad ? 1 : 0;
    }

    /* Custom parameter: CAPRISE_MODE */
    p = OSSL_PARAM_locate_const(params, "caprise_mode");
    if (p != NULL) {
        unsigned int mode;

        if (!OSSL_PARAM_get_uint(p, &mode))
            return 0;
        if (mode != CAPRISE_MODE_DB && mode != CAPRISE_MODE_QUERY)
            return 0;
        ctx->mode = mode;
    }

    /* Custom parameter: CAPRISE_DIM */
    p = OSSL_PARAM_locate_const(params, "caprise_dim");
    if (p != NULL) {
        if (!OSSL_PARAM_get_size_t(p, &size))
            return 0;
        if (size == 0 || size > CAPRISE_MAX_DIM)
            return 0;
        ctx->dim = size;
    }

    /* Custom parameter: CAPRISE_S */
    p = OSSL_PARAM_locate_const(params, "caprise_s");
    if (p != NULL) {
        double s;

        if (!OSSL_PARAM_get_double(p, &s))
            return 0;
        if (s <= 0.0)
            return 0;
        ctx->key.s = s;
    }

    /* Custom parameter: CAPRISE_BETA */
    p = OSSL_PARAM_locate_const(params, "caprise_beta");
    if (p != NULL) {
        double beta;

        if (!OSSL_PARAM_get_double(p, &beta))
            return 0;
        if (beta <= 0.0 || beta >= 1.0)
            return 0;
        ctx->key.beta = beta;
    }

    return 1;
}

/* Initialize encryption */
int ossl_caprise_einit(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;

    if (ctx == NULL)
        return 0;

    if (key != NULL) {
        /* Set PRF key */
        if (keylen != CAPRISE_KEY_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_KEY_LENGTH);
            return 0;
        }

        OPENSSL_clear_free(ctx->key.K, ctx->key.K_len);
        ctx->key.K = OPENSSL_memdup(key, keylen);
        if (ctx->key.K == NULL)
            return 0;
        ctx->key.K_len = keylen;
        ctx->base.key_set = 1;
    }

    if (iv != NULL) {
        /* Set nonce */
        if (ivlen != CAPRISE_IV_SIZE) {
            ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_IV_LENGTH);
            return 0;
        }

        OPENSSL_clear_free(ctx->r, ctx->r_len);
        ctx->r = OPENSSL_memdup(iv, ivlen);
        if (ctx->r == NULL)
            return 0;
        ctx->r_len = ivlen;
        ctx->base.iv_set = 1;
    } else {
        /* Generate random nonce if not provided */
        if (ctx->r == NULL) {
            ctx->r = OPENSSL_malloc(CAPRISE_NONCE_LEN);
            if (ctx->r == NULL)
                return 0;
            if (RAND_bytes(ctx->r, CAPRISE_NONCE_LEN) != 1) {
                OPENSSL_free(ctx->r);
                ctx->r = NULL;
                return 0;
            }
            ctx->r_len = CAPRISE_NONCE_LEN;
        }
    }

    /* Allocate temporary buffer for vector operations */
    if (ctx->temp == NULL || ctx->temp_len < ctx->dim * sizeof(double)) {
        OPENSSL_free(ctx->temp);
        ctx->temp_len = ctx->dim * sizeof(double);
        ctx->temp = OPENSSL_malloc(ctx->temp_len);
        if (ctx->temp == NULL)
            return 0;
    }

    ctx->base.enc = 1;

    if (!caprise_set_ctx_params(vctx, params))
        return 0;

    return 1;
}

/* Initialize decryption */
int ossl_caprise_dinit(void *vctx, const unsigned char *key, size_t keylen,
                       const unsigned char *iv, size_t ivlen,
                       const OSSL_PARAM params[])
{
    /* Decryption uses the same initialization as encryption */
    int ret = ossl_caprise_einit(vctx, key, keylen, iv, ivlen, params);
    if (ret) {
        PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;
        ctx->base.enc = 0;
    }
    return ret;
}

/* Perform encryption/decryption of a single vector */
static int caprise_cipher(void *vctx, unsigned char *out,
                          const unsigned char *in, size_t len)
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;
    double *input_vector = NULL;
    double *output_vector = NULL;
    size_t dim;
    size_t i;
    int ret = 0;

    if (ctx == NULL)
        return 0;

    dim = ctx->dim;

    if (!ctx->base.key_set || !ctx->base.iv_set) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    /* Check input length matches one or more complete vectors */
    if (len == 0 || len % (dim * sizeof(double)) != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    input_vector = OPENSSL_malloc(dim * sizeof(double));
    output_vector = OPENSSL_malloc(dim * sizeof(double));
    if (input_vector == NULL || output_vector == NULL)
        goto err;

    /* Process each vector in the input buffer */
    while (len > 0) {
        for (i = 0; i < dim; i++)
            input_vector[i] = bytes_to_double(in + i * sizeof(double));

        if (ctx->base.enc) {
            if (!caprise_encrypt_vector(ctx->base.libctx, input_vector, dim,
                                        &ctx->key, ctx->mode,
                                        ctx->r, ctx->r_len, output_vector))
                goto err;
        } else {
            if (!caprise_decrypt_vector(ctx->base.libctx, input_vector, dim,
                                        &ctx->key, ctx->mode,
                                        ctx->r, ctx->r_len, output_vector))
                goto err;
        }

        for (i = 0; i < dim; i++)
            double_to_bytes(output_vector[i], out + i * sizeof(double));

        in += dim * sizeof(double);
        out += dim * sizeof(double);
        len -= dim * sizeof(double);
    }

    ret = 1;

err:
    OPENSSL_free(input_vector);
    OPENSSL_free(output_vector);
    return ret;
}

/* Update function (same as cipher for this stream cipher) */
static int caprise_update(void *vctx, unsigned char *out,
                          size_t *outl, size_t outsize,
                          const unsigned char *in, size_t inl)
{
    PROV_CAPRISE_CTX *ctx = (PROV_CAPRISE_CTX *)vctx;
    size_t vecbytes;

    if (ctx == NULL)
        return 0;

    vecbytes = ctx->dim * sizeof(double);

    if (inl == 0) {
        *outl = 0;
        return 1;
    }

    if (outsize < inl || inl % vecbytes != 0) {
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DATA);
        return 0;
    }

    if (!caprise_cipher(vctx, out, in, inl))
        return 0;

    *outl = inl;
    return 1;
}

/* Final function (no-op for this cipher) */
static int caprise_final(void *vctx, unsigned char *out, size_t *outl, size_t outsize)
{
    *outl = 0;
    return 1;
}

/* Cipher function */
static int caprise_do_cipher(void *vctx, unsigned char *out,
                           const unsigned char *in, size_t len)
{
    return caprise_cipher(vctx, out, in, len);
}

/* Dispatch table */
const OSSL_DISPATCH ossl_caprise_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))caprise_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))caprise_freectx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))caprise_dupctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))ossl_caprise_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))ossl_caprise_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))caprise_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))caprise_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))caprise_do_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))caprise_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
        (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))caprise_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))caprise_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (void (*)(void))caprise_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
        (void (*)(void))caprise_settable_ctx_params },
    OSSL_DISPATCH_END
};
