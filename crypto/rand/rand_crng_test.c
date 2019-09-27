/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Implementation of the FIPS 140-2 section 4.9.2 Conditional Tests.
 */

#include <string.h>
#include <openssl/evp.h>
#include "crypto/rand.h"
#include "internal/thread_once.h"
#include "internal/cryptlib.h"
#include "rand_local.h"

typedef struct crng_test_global_st {
    unsigned char crngt_prev[EVP_MAX_MD_SIZE];
    RAND_POOL *crngt_pool;
} CRNG_TEST_GLOBAL;

int (*crngt_get_entropy)(OPENSSL_CTX *, RAND_POOL *, unsigned char *,
                         unsigned char *, unsigned int *)
    = &rand_crngt_get_entropy_cb;

static void rand_crng_ossl_ctx_free(void *vcrngt_glob)
{
    CRNG_TEST_GLOBAL *crngt_glob = vcrngt_glob;

    rand_pool_free(crngt_glob->crngt_pool);
    OPENSSL_free(crngt_glob);
}

static void *rand_crng_ossl_ctx_new(OPENSSL_CTX *ctx)
{
    unsigned char buf[CRNGT_BUFSIZ];
    CRNG_TEST_GLOBAL *crngt_glob = OPENSSL_zalloc(sizeof(*crngt_glob));

    if (crngt_glob == NULL)
        return NULL;

    if ((crngt_glob->crngt_pool
         = rand_pool_new(0, 1, CRNGT_BUFSIZ, CRNGT_BUFSIZ)) == NULL) {
        OPENSSL_free(crngt_glob);
        return NULL;
    }
    if (crngt_get_entropy(ctx, crngt_glob->crngt_pool, buf,
                          crngt_glob->crngt_prev, NULL)) {
        OPENSSL_cleanse(buf, sizeof(buf));
        return crngt_glob;
    }
    rand_pool_free(crngt_glob->crngt_pool);
    OPENSSL_free(crngt_glob);
    return NULL;
}

static const OPENSSL_CTX_METHOD rand_crng_ossl_ctx_method = {
    rand_crng_ossl_ctx_new,
    rand_crng_ossl_ctx_free,
};

int rand_crngt_get_entropy_cb(OPENSSL_CTX *ctx,
                              RAND_POOL *pool,
                              unsigned char *buf,
                              unsigned char *md,
                              unsigned int *md_size)
{
    int r;
    size_t n;
    unsigned char *p;

    if (pool == NULL)
        return 0;

    n = rand_pool_acquire_entropy(pool);
    if (n >= CRNGT_BUFSIZ) {
        EVP_MD *fmd = EVP_MD_fetch(ctx, "SHA256", "");
        if (fmd == NULL)
            return 0;
        p = rand_pool_detach(pool);
        r = EVP_Digest(p, CRNGT_BUFSIZ, md, md_size, fmd, NULL);
        if (r != 0)
            memcpy(buf, p, CRNGT_BUFSIZ);
        rand_pool_reattach(pool, p);
        EVP_MD_free(fmd);
        return r;
    }
    return 0;
}

size_t rand_crngt_get_entropy(RAND_DRBG *drbg,
                              unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance)
{
    unsigned char buf[CRNGT_BUFSIZ], md[EVP_MAX_MD_SIZE];
    unsigned int sz;
    RAND_POOL *pool;
    size_t q, r = 0, s, t = 0;
    int attempts = 3;
    CRNG_TEST_GLOBAL *crngt_glob
        = openssl_ctx_get_data(drbg->libctx, OPENSSL_CTX_RAND_CRNGT_INDEX,
                               &rand_crng_ossl_ctx_method);

    if (crngt_glob == NULL)
        return 0;

    if ((pool = rand_pool_new(entropy, 1, min_len, max_len)) == NULL)
        return 0;

    while ((q = rand_pool_bytes_needed(pool, 1)) > 0 && attempts-- > 0) {
        s = q > sizeof(buf) ? sizeof(buf) : q;
        if (!crngt_get_entropy(drbg->libctx, crngt_glob->crngt_pool, buf, md,
                               &sz)
            || memcmp(crngt_glob->crngt_prev, md, sz) == 0
            || !rand_pool_add(pool, buf, s, s * 8))
            goto err;
        memcpy(crngt_glob->crngt_prev, md, sz);
        t += s;
        attempts++;
    }
    r = t;
    *pout = rand_pool_detach(pool);
err:
    OPENSSL_cleanse(buf, sizeof(buf));
    rand_pool_free(pool);
    return r;
}

void rand_crngt_cleanup_entropy(RAND_DRBG *drbg,
                                unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}
