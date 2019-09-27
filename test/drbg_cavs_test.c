/*
 * Copyright 2017-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../crypto/rand/rand_local.h"

#include "testutil.h"
#include "drbg_cavs_data.h"

static int app_data_index;

typedef struct test_ctx_st {
    const unsigned char *entropy;
    size_t entropylen;
    int entropycnt;
    const unsigned char *nonce;
    size_t noncelen;
    int noncecnt;
} TEST_CTX;

static size_t kat_entropy(RAND_DRBG *drbg, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len,
                          int prediction_resistance)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t kat_nonce(RAND_DRBG *drbg, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(drbg, app_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

/*
 * Do a single NO_RESEED KAT:
 *
 * Instantiate
 * Generate Random Bits (pr=false)
 * Generate Random Bits (pr=false)
 * Uninstantiate
 *
 * Return 0 on failure.
 */
static int single_kat_no_reseed(const struct drbg_kat *td)
{
    struct drbg_kat_no_reseed *data = (struct drbg_kat_no_reseed *)td->t;
    RAND_DRBG *drbg = NULL;
    unsigned char *buff = NULL;
    unsigned int flags = 0;
    int failures = 0;
    TEST_CTX t;

    if ((td->flags & USE_DF) == 0)
        flags |= RAND_DRBG_FLAG_CTR_NO_DF;
    if ((td->flags & USE_HMAC) != 0)
        flags |= RAND_DRBG_FLAG_HMAC;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, flags, NULL)))
        return 0;

    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = data->entropyin;
    t.entropylen = td->entropyinlen;
    t.nonce = data->nonce;
    t.noncelen = td->noncelen;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);

    buff = OPENSSL_malloc(td->retbyteslen);
    if (buff == NULL)
        goto err;

    if (!TEST_true(RAND_DRBG_instantiate(drbg, data->persstr, td->persstrlen))
        || !TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 0,
                                         data->addin1, td->addinlen))
        || !TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 0,
                                         data->addin2, td->addinlen))
        || !TEST_true(RAND_DRBG_uninstantiate(drbg))
        || !TEST_mem_eq(data->retbytes, td->retbyteslen, buff,
                        td->retbyteslen))
        failures++;

err:
    OPENSSL_free(buff);
    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}

/*-
 * Do a single PR_FALSE KAT:
 *
 * Instantiate
 * Reseed
 * Generate Random Bits (pr=false)
 * Generate Random Bits (pr=false)
 * Uninstantiate
 *
 * Return 0 on failure.
 */
static int single_kat_pr_false(const struct drbg_kat *td)
{
    struct drbg_kat_pr_false *data = (struct drbg_kat_pr_false *)td->t;
    RAND_DRBG *drbg = NULL;
    unsigned char *buff = NULL;
    unsigned int flags = 0;
    int failures = 0;
    TEST_CTX t;

    if ((td->flags & USE_DF) == 0)
        flags |= RAND_DRBG_FLAG_CTR_NO_DF;
    if ((td->flags & USE_HMAC) != 0)
        flags |= RAND_DRBG_FLAG_HMAC;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, flags, NULL)))
        return 0;

    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = data->entropyin;
    t.entropylen = td->entropyinlen;
    t.nonce = data->nonce;
    t.noncelen = td->noncelen;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);

    buff = OPENSSL_malloc(td->retbyteslen);
    if (buff == NULL)
        goto err;

    if (!TEST_true(RAND_DRBG_instantiate(drbg, data->persstr, td->persstrlen)))
        failures++;

    t.entropy = data->entropyinreseed;
    t.entropylen = td->entropyinlen;

    if (!TEST_true(RAND_DRBG_reseed(drbg, data->addinreseed, td->addinlen, 0))
        || !TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 0,
                                         data->addin1, td->addinlen))
        || !TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 0,
                                         data->addin2, td->addinlen))
        || !TEST_true(RAND_DRBG_uninstantiate(drbg))
        || !TEST_mem_eq(data->retbytes, td->retbyteslen, buff,
                        td->retbyteslen))
        failures++;

err:
    OPENSSL_free(buff);
    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}

/*-
 * Do a single PR_TRUE KAT:
 *
 * Instantiate
 * Generate Random Bits (pr=true)
 * Generate Random Bits (pr=true)
 * Uninstantiate
 *
 * Return 0 on failure.
 */
static int single_kat_pr_true(const struct drbg_kat *td)
{
    struct drbg_kat_pr_true *data = (struct drbg_kat_pr_true *)td->t;
    RAND_DRBG *drbg = NULL;
    unsigned char *buff = NULL;
    unsigned int flags = 0;
    int failures = 0;
    TEST_CTX t;

    if ((td->flags & USE_DF) == 0)
        flags |= RAND_DRBG_FLAG_CTR_NO_DF;
    if ((td->flags & USE_HMAC) != 0)
        flags |= RAND_DRBG_FLAG_HMAC;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, flags, NULL)))
        return 0;

    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.nonce = data->nonce;
    t.noncelen = td->noncelen;
    t.entropy = data->entropyin;
    t.entropylen = td->entropyinlen;
    RAND_DRBG_set_ex_data(drbg, app_data_index, &t);

    buff = OPENSSL_malloc(td->retbyteslen);
    if (buff == NULL)
        goto err;

    if (!TEST_true(RAND_DRBG_instantiate(drbg, data->persstr, td->persstrlen)))
        failures++;

    t.entropy = data->entropyinpr1;
    t.entropylen = td->entropyinlen;

    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 1,
                                      data->addin1, td->addinlen)))
        failures++;

    t.entropy = data->entropyinpr2;
    t.entropylen = td->entropyinlen;

    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->retbyteslen, 1,
                                      data->addin2, td->addinlen))
        || !TEST_true(RAND_DRBG_uninstantiate(drbg))
        || !TEST_mem_eq(data->retbytes, td->retbyteslen, buff,
                        td->retbyteslen))
        failures++;

err:
    OPENSSL_free(buff);
    RAND_DRBG_uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}

static int test_cavs_kats(const struct drbg_kat *test[], int i)
{
    const struct drbg_kat *td = test[i];
    int rv = 0;

#ifdef FIPS_MODE
    /* FIPS mode doesn't support instantiating without a derivation function */
    if ((td->flags & USE_DF) == 0)
        return TEST_skip("instantiating without derivation function "
                         "is not supported in FIPS mode");
#endif
    switch (td->type) {
    case NO_RESEED:
        if (!single_kat_no_reseed(td))
            goto err;
        break;
    case PR_FALSE:
        if (!single_kat_pr_false(td))
            goto err;
        break;
    case PR_TRUE:
        if (!single_kat_pr_true(td))
            goto err;
        break;
    default:    /* cant happen */
        goto err;
    }
    rv = 1;
err:
    return rv;
}

static int test_cavs_ctr(int i)
{
    return test_cavs_kats(drbg_ctr_test, i);
}

static int test_cavs_hmac(int i)
{
    return test_cavs_kats(drbg_hmac_test, i);
}

static int test_cavs_hash(int i)
{
    return test_cavs_kats(drbg_hash_test, i);
}

int setup_tests(void)
{
    app_data_index = RAND_DRBG_get_ex_new_index(0L, NULL, NULL, NULL, NULL);

    ADD_ALL_TESTS(test_cavs_ctr,  drbg_ctr_nelem);
    ADD_ALL_TESTS(test_cavs_hmac, drbg_hmac_nelem);
    ADD_ALL_TESTS(test_cavs_hash, drbg_hash_nelem);

    return 1;
}
