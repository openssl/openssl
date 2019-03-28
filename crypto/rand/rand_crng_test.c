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
#include "internal/rand_int.h"
#include "internal/thread_once.h"
#include "rand_lcl.h"

static RAND_POOL *crngt_pool;
static unsigned char *crngt_prev;

int (*crngt_get_entropy)(unsigned char *) = &rand_crngt_get_entropy_cb;

int rand_crngt_get_entropy_cb(unsigned char *buf)
{
    size_t n;
    unsigned char *p;

    while ((n = rand_pool_acquire_entropy(crngt_pool)) != 0)
        if (n >= CRNGT_BUFSIZ) {
            p = rand_pool_detach(crngt_pool);
            memcpy(crngt_prev, p, CRNGT_BUFSIZ);
            rand_pool_reattach(crngt_pool, p);
            return 1;
        }
    return 0;

}
void rand_crngt_cleanup(void)
{
    rand_pool_free(crngt_pool);
    OPENSSL_secure_free(crngt_prev);
    crngt_pool = NULL;
    crngt_prev = NULL;
}

int rand_crngt_init(void)
{
    if ((crngt_pool = rand_pool_new(0, CRNGT_BUFSIZ, CRNGT_BUFSIZ)) == NULL)
        return 0;
    if ((crngt_prev = OPENSSL_secure_malloc(CRNGT_BUFSIZ)) != NULL
        && crngt_get_entropy(crngt_prev))
        return 1;
    rand_crngt_cleanup();
    return 0;
}

static CRYPTO_ONCE rand_crngt_init_flag = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_rand_crngt_init)
{
    return OPENSSL_init_crypto(0, NULL)
        && rand_crngt_init()
        && OPENSSL_atexit(&rand_crngt_cleanup);
}

int rand_crngt_single_init(void)
{
    return RUN_ONCE(&rand_crngt_init_flag, do_rand_crngt_init);
}

size_t rand_crngt_get_entropy(RAND_DRBG *drbg,
                              unsigned char **pout,
                              int entropy, size_t min_len, size_t max_len,
                              int prediction_resistance)
{
    unsigned char buf[CRNGT_BUFSIZ];
    RAND_POOL *pool;
    size_t q, r = 0, s, t = 0;
    int attempts = 3;

    if (!RUN_ONCE(&rand_crngt_init_flag, do_rand_crngt_init))
        return 0;

    if ((pool = rand_pool_new(entropy, min_len, max_len)) == NULL)
        return 0;

    while ((q = rand_pool_bytes_needed(pool, 1)) > 0 && attempts-- > 0) {
        s = q > sizeof(buf) ? sizeof(buf) : q;
        if (!crngt_get_entropy(buf)
            || memcmp(crngt_prev, buf, CRNGT_BUFSIZ) == 0
            || !rand_pool_add(pool, buf, s, s * 8))
            goto err;
        memcpy(crngt_prev, buf, CRNGT_BUFSIZ);
        t += s;
        attempts++;
    }
    r = t;
    *pout = rand_pool_detach(pool);
err:
    rand_pool_free(pool);
    return r;
}

void rand_crngt_cleanup_entropy(RAND_DRBG *drbg,
                                unsigned char *out, size_t outlen)
{
    OPENSSL_secure_clear_free(out, outlen);
}
