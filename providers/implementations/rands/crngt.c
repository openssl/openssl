/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/core_dispatch.h>
#include <openssl/params.h>
#include <openssl/self_test.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "internal/cryptlib.h"
#include "prov/rand_pool.h"
#include "drbg_local.h"
#include "prov/seeding.h"

typedef struct crng_test_global_st {
    unsigned char crngt_prev[EVP_MAX_MD_SIZE];
    RAND_POOL *crngt_pool;
} CRNG_TEST_GLOBAL;

static int crngt_get_entropy(OPENSSL_CTX *ctx, RAND_POOL *pool,
                             unsigned char *buf, unsigned char *md,
                             unsigned int *md_size)
{
    int r;
    size_t n;
    unsigned char *p;
    EVP_MD *fmd;

    if (pool == NULL)
        return 0;

    n = prov_pool_acquire_entropy(pool);
    if (n >= CRNGT_BUFSIZ) {
        fmd = EVP_MD_fetch(ctx, "SHA256", "");
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

static int prov_crngt_compare_previous(const unsigned char *prev,
                                       const unsigned char *cur,
                                       size_t sz)
{
    const int res = memcmp(prev, cur, sz) != 0;

    if (!res)
        ossl_set_error_state(OSSL_SELF_TEST_TYPE_CRNG);
    return res;
}

size_t prov_crngt_get_entropy(PROV_DRBG *drbg,
                              unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance)
{
    unsigned char buf[CRNGT_BUFSIZ], md[EVP_MAX_MD_SIZE];
    unsigned int sz;
    RAND_POOL *pool;
    size_t q, r = 0, s, t = 0;
    int attempts = 3, crng_test_pass = 1;
    OPENSSL_CTX *libctx = PROV_LIBRARY_CONTEXT_OF(drbg->provctx);
    CRNG_TEST_GLOBAL *crngt_glob
        = openssl_ctx_get_data(libctx, OPENSSL_CTX_RAND_CRNGT_INDEX,
                               &rand_crng_ossl_ctx_method);
    OSSL_CALLBACK *stcb = NULL;
    void *stcbarg = NULL;
    OSSL_SELF_TEST *st = NULL;

    if (crngt_glob == NULL)
        return 0;

    if ((pool = rand_pool_new(entropy, 1, min_len, max_len)) == NULL)
        return 0;

    OSSL_SELF_TEST_get_callback(libctx, &stcb, &stcbarg);
    if (stcb != NULL) {
        st = OSSL_SELF_TEST_new(stcb, stcbarg);
        if (st == NULL)
            goto err;
        OSSL_SELF_TEST_onbegin(st, OSSL_SELF_TEST_TYPE_CRNG,
                               OSSL_SELF_TEST_DESC_RNG);
    }

    while ((q = rand_pool_bytes_needed(pool, 1)) > 0 && attempts-- > 0) {
        s = q > sizeof(buf) ? sizeof(buf) : q;
        if (!crngt_get_entropy(libctx, crngt_glob->crngt_pool, buf, md, &sz))
            goto err;
        /* Force a failure here if the callback returns 1 */
        if (OSSL_SELF_TEST_oncorrupt_byte(st, md))
            memcpy(md, crngt_glob->crngt_prev, sz);
        if (!prov_crngt_compare_previous(crngt_glob->crngt_prev, md, sz)) {
            crng_test_pass = 0;
            goto err;
        }
        if (!rand_pool_add(pool, buf, s, s * 8))
            goto err;
        memcpy(crngt_glob->crngt_prev, md, sz);
        t += s;
        attempts++;
    }
    r = t;
    *pout = rand_pool_detach(pool);
err:
    OSSL_SELF_TEST_onend(st, crng_test_pass);
    OSSL_SELF_TEST_free(st);
    OPENSSL_cleanse(buf, sizeof(buf));
    rand_pool_free(pool);
    return r;
}

void prov_crngt_cleanup_entropy(PROV_DRBG *drbg,
                                unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}
