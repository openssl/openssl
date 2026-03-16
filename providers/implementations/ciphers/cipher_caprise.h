/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROV_CIPHER_CAPRISE_H
#define OSSL_PROV_CIPHER_CAPRISE_H

#include <openssl/params.h>
#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include "prov/ciphercommon.h"
#include "internal/refcount.h"

/* CAPRISE key structure */
typedef struct {
    double s;              /* Scaling factor */
    unsigned char *K;      /* PRF key */
    size_t K_len;          /* PRF key length */
    double beta;            /* Security parameter β */
} CAPRISE_KEY;

/* CAPRISE encryption context */
typedef struct {
    PROV_CIPHER_CTX base;   /* Base cipher context - must be first */
    CAPRISE_KEY key;       /* CAPRISE-specific key data */
    unsigned int mode;       /* Encryption mode: DB or QUERY */
    size_t dim;            /* Embedding dimension (d) */
    unsigned char *r;       /* Random nonce r */
    size_t r_len;          /* Length of random nonce */
    unsigned char *noise;    /* Noise vector buffer */
    size_t noise_len;      /* Length of noise vector */
    unsigned char *temp;    /* Temporary buffer for computations */
    size_t temp_len;       /* Length of temporary buffer */
} PROV_CAPRISE_CTX;

/* Encryption modes */
#define CAPRISE_MODE_DB    0  /* Database embedding encryption */
#define CAPRISE_MODE_QUERY 1  /* Query embedding encryption */

/* Default security parameters */
#define CAPRISE_DEFAULT_S       3.0
#define CAPRISE_DEFAULT_BETA   0.2
#define CAPRISE_DEFAULT_DIM    768  /* Default embedding dimension (e.g., GTR-T5-base) */

/* PRF output length */
#define CAPRISE_PRF_OUTPUT_LEN  32  /* HMAC-SHA256 output */

/* Random nonce length */
#define CAPRISE_NONCE_LEN        16

/* CAPRISE hardware structure */
typedef struct prov_cipher_hw_caprise_st {
    PROV_CIPHER_HW base;     /* Base structure - must be first */
    int (*init)(PROV_CIPHER_CTX *ctx, const uint8_t *key, size_t keylen);
    int (*encrypt)(PROV_CIPHER_CTX *ctx, unsigned char *out,
                  const unsigned char *in, size_t len);
    int (*decrypt)(PROV_CIPHER_CTX *ctx, unsigned char *out,
                  const unsigned char *in, size_t len);
} PROV_CIPHER_HW_CAPRISE;

/* Function declarations */
const PROV_CIPHER_HW *ossl_prov_cipher_hw_caprise(size_t keybits);

OSSL_FUNC_cipher_encrypt_init_fn ossl_caprise_einit;
OSSL_FUNC_cipher_decrypt_init_fn ossl_caprise_dinit;
void ossl_caprise_initctx(PROV_CAPRISE_CTX *ctx);

/* CAPRISE core functions */
int caprise_generate_noise_vector(const unsigned char *prf_output, size_t prf_len,
                                  double s, double beta, size_t dim,
                                  unsigned int mode,
                                  double *noise_vector);
int caprise_encrypt_vector(OSSL_LIB_CTX *libctx,
                           double *vector, size_t dim,
                           const CAPRISE_KEY *key, unsigned int mode,
                           const unsigned char *nonce, size_t nonce_len,
                           double *out_vector);
int caprise_decrypt_vector(OSSL_LIB_CTX *libctx,
                           double *vector, size_t dim,
                           const CAPRISE_KEY *key, unsigned int mode,
                           const unsigned char *nonce, size_t nonce_len,
                           double *out_vector);

#endif /* OSSL_PROV_CIPHER_CAPRISE_H */
