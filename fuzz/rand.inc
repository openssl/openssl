/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */
#include <openssl/rand.h>

int FuzzerSetRand(void)
{
    return 0;
}
#if 0
static int rand_test_init(EVP_TEST *t, const char *name)
{
    RAND_DATA *rdata;
    EVP_RAND *rand;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int strength = 256;

    if (!TEST_ptr(rdata = OPENSSL_zalloc(sizeof(*rdata))))
        return 0;

    /* TEST-RAND is available in the FIPS provider but not with "fips=yes" */
    rand = EVP_RAND_fetch(libctx, "TEST-RAND", "-fips");
    if (rand == NULL)
        goto err;
    rdata->parent = EVP_RAND_CTX_new(rand, NULL);
    EVP_RAND_free(rand);
    if (rdata->parent == NULL)
        goto err;

    *params = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    if (!EVP_RAND_set_ctx_params(rdata->parent, params))
        goto err;

    rand = EVP_RAND_fetch(libctx, name, NULL);
    if (rand == NULL)
        goto err;
    rdata->ctx = EVP_RAND_CTX_new(rand, rdata->parent);
    EVP_RAND_free(rand);
    if (rdata->ctx == NULL)
        goto err;

    rdata->n = -1;
    t->data = rdata;
    return 1;
 err:
    EVP_RAND_CTX_free(rdata->parent);
    OPENSSL_free(rdata);
    return 0;
}
#endif
