/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>
#include <openssl/engine.h>

typedef struct {
    /*
     * References to the underlying cipher implementation.  |cipher| caches
     * the cipher, always.  |alloc_cipher| only holds a reference to an
     * explicitly fetched cipher.
     */
    const EVP_CIPHER *cipher;   /* cipher */
    EVP_CIPHER *alloc_cipher;   /* fetched cipher */

    /* Conditions for legacy EVP_CIPHER uses */
    ENGINE *engine;             /* cipher engine */

    /* Name this was fetched by */
    char name[51];               /* A longer name would be unexpected */
} PROV_CIPHER;

typedef struct {
    /*
     * References to the underlying digest implementation.  |md| caches
     * the digest, always.  |alloc_md| only holds a reference to an explicitly
     * fetched digest.
     */
    const EVP_MD *md;           /* digest */
    EVP_MD *alloc_md;           /* fetched digest */

    /* Conditions for legacy EVP_MD uses */
    ENGINE *engine;             /* digest engine */

    /* Name this was fetched by */
    char name[51];               /* A longer name would be unexpected */
} PROV_DIGEST;

/* Cipher functions */
/*
 * Load a cipher from the specified parameters with the specified context.
 * The params "properties", "engine" and "cipher" are used to determine the
 * implementation used.  If a provider cannot be found, it falls back to trying
 * non-provider based implementations.
 */
int ossl_prov_cipher_load_from_params(PROV_CIPHER *pc,
                                      const OSSL_PARAM params[],
                                      OPENSSL_CTX *ctx);

/* Reset the PROV_CIPHER fields and free any allocated cipher reference */
void ossl_prov_cipher_reset(PROV_CIPHER *pc);

/* Clone a PROV_CIPHER structure into a second */
int ossl_prov_cipher_copy(PROV_CIPHER *dst, const PROV_CIPHER *src);

/* Query the cipher and associated engine (if any) */
const EVP_CIPHER *ossl_prov_cipher_cipher(const PROV_CIPHER *pc);
ENGINE *ossl_prov_cipher_engine(const PROV_CIPHER *pc);
const char *ossl_prov_cipher_name(const PROV_CIPHER *pc);

/* Digest functions */
/*
 * Load a digest from the specified parameters with the specified context.
 * The params "properties", "engine" and "digest" are used to determine the
 * implementation used.  If a provider cannot be found, it falls back to trying
 * non-provider based implementations.
 */
int ossl_prov_digest_load_from_params(PROV_DIGEST *pd,
                                      const OSSL_PARAM params[],
                                      OPENSSL_CTX *ctx);

/* Reset the PROV_DIGEST fields and free any allocated digest reference */
void ossl_prov_digest_reset(PROV_DIGEST *pd);

/* Clone a PROV_DIGEST structure into a second */
int ossl_prov_digest_copy(PROV_DIGEST *dst, const PROV_DIGEST *src);

/* Query the digest and associated engine (if any) */
const EVP_MD *ossl_prov_digest_md(const PROV_DIGEST *pd);
ENGINE *ossl_prov_digest_engine(const PROV_DIGEST *pd);
const char *ossl_prov_digest_name(const PROV_DIGEST *pd);
