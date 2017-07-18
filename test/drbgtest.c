/*
 * Copyright 2011-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include "e_os.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../crypto/rand/rand_lcl.h"

#include "testutil.h"
#include "drbgtest.h"

typedef struct drbg_selftest_data_st {
    int post;
    int nid;
    unsigned int flags;

    /* KAT data for no PR */
    const unsigned char *ent;
    size_t entlen;
    const unsigned char *nonce;
    size_t noncelen;
    const unsigned char *pers;
    size_t perslen;
    const unsigned char *adin;
    size_t adinlen;
    const unsigned char *entreseed;
    size_t entreseedlen;
    const unsigned char *adinreseed;
    size_t adinreseedlen;
    const unsigned char *adin2;
    size_t adin2len;
    const unsigned char *expected;
    size_t exlen;
    const unsigned char *kat2;
    size_t kat2len;

    /* KAT data for PR */
    const unsigned char *ent_pr;
    size_t entlen_pr;
    const unsigned char *nonce_pr;
    size_t noncelen_pr;
    const unsigned char *pers_pr;
    size_t perslen_pr;
    const unsigned char *adin_pr;
    size_t adinlen_pr;
    const unsigned char *entpr_pr;
    size_t entprlen_pr;
    const unsigned char *ading_pr;
    size_t adinglen_pr;
    const unsigned char *entg_pr;
    size_t entglen_pr;
    const unsigned char *kat_pr;
    size_t katlen_pr;
    const unsigned char *kat2_pr;
    size_t kat2len_pr;
} DRBG_SELFTEST_DATA;

#define make_drbg_test_data(nid, flag, pr, post) {\
    post, nid, flag, \
    pr##_entropyinput, sizeof(pr##_entropyinput), \
    pr##_nonce, sizeof(pr##_nonce), \
    pr##_personalizationstring, sizeof(pr##_personalizationstring), \
    pr##_additionalinput, sizeof(pr##_additionalinput), \
    pr##_entropyinputreseed, sizeof(pr##_entropyinputreseed), \
    pr##_additionalinputreseed, sizeof(pr##_additionalinputreseed), \
    pr##_additionalinput2, sizeof(pr##_additionalinput2), \
    pr##_int_returnedbits, sizeof(pr##_int_returnedbits), \
    pr##_returnedbits, sizeof(pr##_returnedbits), \
    pr##_pr_entropyinput, sizeof(pr##_pr_entropyinput), \
    pr##_pr_nonce, sizeof(pr##_pr_nonce), \
    pr##_pr_personalizationstring, sizeof(pr##_pr_personalizationstring), \
    pr##_pr_additionalinput, sizeof(pr##_pr_additionalinput), \
    pr##_pr_entropyinputpr, sizeof(pr##_pr_entropyinputpr), \
    pr##_pr_additionalinput2, sizeof(pr##_pr_additionalinput2), \
    pr##_pr_entropyinputpr2, sizeof(pr##_pr_entropyinputpr2), \
    pr##_pr_int_returnedbits, sizeof(pr##_pr_int_returnedbits), \
    pr##_pr_returnedbits, sizeof(pr##_pr_returnedbits) \
    }

#define make_drbg_test_data_df(nid, pr, p) \
    make_drbg_test_data(nid, RAND_DRBG_FLAG_CTR_USE_DF, pr, p)

static DRBG_SELFTEST_DATA drbg_test[] = {
    make_drbg_test_data_df(NID_aes_128_ctr,    aes_128_use_df, 0),
    make_drbg_test_data_df(NID_aes_192_ctr,    aes_192_use_df, 0),
    make_drbg_test_data_df(NID_aes_256_ctr,    aes_256_use_df, 1),
    make_drbg_test_data   (NID_aes_128_ctr, 0, aes_128_no_df, 0),
    make_drbg_test_data   (NID_aes_192_ctr, 0, aes_192_no_df, 0),
    make_drbg_test_data   (NID_aes_256_ctr, 0, aes_256_no_df, 1),
};

static int app_data_index;

/*
 * Test context data, attached as appdata to the DRBG_CTX
 */
typedef struct test_ctx_st {
    const unsigned char *ent;
    size_t entlen;
    int entcnt;
    const unsigned char *nonce;
    size_t noncelen;
    int noncecnt;
} TEST_CTX;

static size_t kat_entropy(DRBG_CTX *dctx, unsigned char **pout,
                          int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(dctx, app_data_index);

    t->entcnt++;
    *pout = (unsigned char *)t->ent;
    return t->entlen;
}

static size_t kat_nonce(DRBG_CTX *dctx, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_ex_data(dctx, app_data_index);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

static int uninstantiate(DRBG_CTX *dctx)
{
    int ret = dctx == NULL ? 1 : RAND_DRBG_uninstantiate(dctx);

    ERR_clear_error();
    return ret;
}

/*
 * Do a single KAT test.  Return 0 on failure.
 */
static int single_kat(DRBG_SELFTEST_DATA *td)
{
    DRBG_CTX *dctx = NULL;
    TEST_CTX t;
    int failures = 0;
    unsigned char buff[1024];

    /*
     * Test without PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_ptr(dctx = RAND_DRBG_new(td->nid, td->flags, NULL)))
        return 0;
    if (!TEST_true(RAND_DRBG_set_callbacks(dctx, kat_entropy, NULL,
                                           kat_nonce, NULL))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.ent = td->ent;
    t.entlen = td->entlen;
    t.nonce = td->nonce;
    t.noncelen = td->noncelen;
    RAND_DRBG_set_ex_data(dctx, app_data_index, &t);

    if (!TEST_true(RAND_DRBG_instantiate(dctx, td->pers, td->perslen))
            || !TEST_true(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                             td->adin, td->adinlen))
            || !TEST_mem_eq(td->expected, td->exlen, buff, td->exlen))
        failures++;

    /* Reseed DRBG with test entropy and additional input */
    t.ent = td->entreseed;
    t.entlen = td->entreseedlen;
    if (!TEST_true(RAND_DRBG_reseed(dctx, td->adinreseed, td->adinreseedlen)
            || !TEST_true(RAND_DRBG_generate(dctx, buff, td->kat2len, 0,
                                             td->adin2, td->adin2len))
            || !TEST_mem_eq(td->kat2, td->kat2len, buff, td->kat2len)))
        failures++;
    uninstantiate(dctx);

    /*
     * Now test with PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_true(RAND_DRBG_set(dctx, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(dctx, kat_entropy, NULL,
                                                  kat_nonce, NULL)))
        failures++;
    RAND_DRBG_set_ex_data(dctx, app_data_index, &t);
    t.ent = td->ent_pr;
    t.entlen = td->entlen_pr;
    t.nonce = td->nonce_pr;
    t.noncelen = td->noncelen_pr;
    t.entcnt = 0;
    t.noncecnt = 0;
    if (!TEST_true(RAND_DRBG_instantiate(dctx, td->pers_pr, td->perslen_pr)))
        failures++;

    /*
     * Now generate with PR: we need to supply entropy as this will
     * perform a reseed operation.
     */
    t.ent = td->entpr_pr;
    t.entlen = td->entprlen_pr;
    if (!TEST_true(RAND_DRBG_generate(dctx, buff, td->katlen_pr, 1,
                                      td->adin_pr, td->adinlen_pr))
            || !TEST_mem_eq(td->kat_pr, td->katlen_pr, buff, td->katlen_pr))
        failures++;

    /*
     * Now generate again with PR: supply new entropy again.
     */
    t.ent = td->entg_pr;
    t.entlen = td->entglen_pr;

    if (!TEST_true(RAND_DRBG_generate(dctx, buff, td->kat2len_pr, 1,
                                      td->ading_pr, td->adinglen_pr))
                || !TEST_mem_eq(td->kat2_pr, td->kat2len_pr,
                                buff, td->kat2len_pr))
        failures++;

err:
    uninstantiate(dctx);
    RAND_DRBG_free(dctx);
    return failures == 0;
}

/*
 * Initialise a DRBG based on selftest data
 */
static int init(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td, TEST_CTX *t)
{
    if (!TEST_true(RAND_DRBG_set(dctx, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(dctx, kat_entropy, NULL,
                                                  kat_nonce, NULL)))
        return 0;
    RAND_DRBG_set_ex_data(dctx, app_data_index, t);
    t->ent = td->ent;
    t->entlen = td->entlen;
    t->nonce = td->nonce;
    t->noncelen = td->noncelen;
    t->entcnt = 0;
    t->noncecnt = 0;
    return 1;
}

/*
 * Initialise and instantiate DRBG based on selftest data
 */
static int instantiate(DRBG_CTX *dctx, DRBG_SELFTEST_DATA *td,
                       TEST_CTX *t)
{
    if (!TEST_true(init(dctx, td, t))
            || !TEST_true(RAND_DRBG_instantiate(dctx, td->pers, td->perslen)))
        return 0;
    return 1;
}

/*
 * Perform extensive error checking as required by SP800-90.
 * Induce several failure modes and check an error condition is set.
 */
static int error_check(DRBG_SELFTEST_DATA *td)
{
    static char zero[sizeof(DRBG_CTX)];
    DRBG_CTX *dctx = NULL;
    TEST_CTX t;
    unsigned char buff[1024];
    unsigned int reseed_counter_tmp;
    int ret = 0;

    if (!TEST_ptr(dctx = RAND_DRBG_new(0, 0, NULL)))
        goto err;

    /*
     * Personalisation string tests
     */

    /* Test detection of too large personlisation string */
    if (!init(dctx, td, &t)
            || RAND_DRBG_instantiate(dctx, td->pers, dctx->max_pers + 1) > 0)
        goto err;

    /*
     * Entropy source tests
     */

    /* Test entropy source failure detecion: i.e. returns no data */
    t.entlen = 0;
    if (TEST_int_le(RAND_DRBG_instantiate(dctx, td->pers, td->perslen), 0))
        goto err;

    /* Try to generate output from uninstantiated DRBG */
    if (!TEST_false(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                       td->adin, td->adinlen))
            || !uninstantiate(dctx))
        goto err;

    /* Test insufficient entropy */
    t.entlen = dctx->min_entropy - 1;
    if (!init(dctx, td, &t)
            || RAND_DRBG_instantiate(dctx, td->pers, td->perslen) > 0
            || !uninstantiate(dctx))
        goto err;

    /* Test too much entropy */
    t.entlen = dctx->max_entropy + 1;
    if (!init(dctx, td, &t)
            || RAND_DRBG_instantiate(dctx, td->pers, td->perslen) > 0
            || !uninstantiate(dctx))
        goto err;

    /*
     * Nonce tests
     */

    /* Test too small nonce */
    if (dctx->min_nonce) {
        t.noncelen = dctx->min_nonce - 1;
        if (!init(dctx, td, &t)
                || RAND_DRBG_instantiate(dctx, td->pers, td->perslen) > 0
                || !uninstantiate(dctx))
            goto err;
    }

    /* Test too large nonce */
    if (dctx->max_nonce) {
        t.noncelen = dctx->max_nonce + 1;
        if (!init(dctx, td, &t)
                || RAND_DRBG_instantiate(dctx, td->pers, td->perslen) > 0
                || !uninstantiate(dctx))
            goto err;
    }

    /* Instantiate with valid data, Check generation is now OK */
    if (!instantiate(dctx, td, &t)
            || !TEST_true(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                             td->adin, td->adinlen)))
        goto err;

    /* Request too much data for one request */
    if (!TEST_false(RAND_DRBG_generate(dctx, buff, dctx->max_request + 1, 0,
                                       td->adin, td->adinlen)))
        goto err;

    /* Try too large additional input */
    if (!TEST_false(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                       td->adin, dctx->max_adin + 1)))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entlen = 0;
    if (TEST_false(RAND_DRBG_generate(dctx, buff, td->exlen, 1,
                                      td->adin, td->adinlen))
            || !uninstantiate(dctx))
        goto err;

    /* Instantiate again with valid data */
    if (!instantiate(dctx, td, &t))
        goto err;
    reseed_counter_tmp = dctx->reseed_counter;
    dctx->reseed_counter = dctx->reseed_interval;

    /* Generate output and check entropy has been requested for reseed */
    t.entcnt = 0;
    if (!TEST_true(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entcnt, 1)
            || !TEST_int_eq(dctx->reseed_counter, reseed_counter_tmp + 1)
            || !uninstantiate(dctx))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entlen = 0;
    if (!TEST_false(RAND_DRBG_generate(dctx, buff, td->exlen, 1,
                                       td->adin, td->adinlen))
            || !uninstantiate(dctx))
        goto err;

    /* Test reseed counter works */
    if (!instantiate(dctx, td, &t))
        goto err;
    reseed_counter_tmp = dctx->reseed_counter;
    dctx->reseed_counter = dctx->reseed_interval;

    /* Generate output and check entropy has been requested for reseed */
    t.entcnt = 0;
    if (!TEST_true(RAND_DRBG_generate(dctx, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entcnt, 1)
            || !TEST_int_eq(dctx->reseed_counter, reseed_counter_tmp + 1)
            || !uninstantiate(dctx))
        goto err;

    /*
     * Explicit reseed tests
     */

    /* Test explicit reseed with too large additional input */
    if (!init(dctx, td, &t)
            || RAND_DRBG_reseed(dctx, td->adin, dctx->max_adin + 1) > 0)
        goto err;

    /* Test explicit reseed with entropy source failure */
    t.entlen = 0;
    if (!TEST_int_le(RAND_DRBG_reseed(dctx, td->adin, td->adinlen), 0)
            || !uninstantiate(dctx))
        goto err;

    /* Test explicit reseed with too much entropy */
    if (!init(dctx, td, &t))
        goto err;
    t.entlen = dctx->max_entropy + 1;
    if (!TEST_int_le(RAND_DRBG_reseed(dctx, td->adin, td->adinlen), 0)
            || !uninstantiate(dctx))
        goto err;

    /* Test explicit reseed with too little entropy */
    if (!init(dctx, td, &t))
        goto err;
    t.entlen = dctx->min_entropy - 1;
    if (!TEST_int_le(RAND_DRBG_reseed(dctx, td->adin, td->adinlen), 0)
            || !uninstantiate(dctx))
        goto err;

    /* Standard says we have to check uninstantiate really zeroes */
    if (!TEST_mem_eq(zero, sizeof(dctx->ctr), &dctx->ctr, sizeof(dctx->ctr)))
        goto err;

    ret = 1;

err:
    uninstantiate(dctx);
    RAND_DRBG_free(dctx);
    return ret;
}

static int test_kats(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (!single_kat(td))
        goto err;
    rv = 1;

err:
    return rv;
}

static int test_error_checks(int i)
{
    DRBG_SELFTEST_DATA *td = &drbg_test[i];
    int rv = 0;

    if (error_check(td))
        goto err;
    rv = 1;

err:
    return rv;
}


int setup_tests(void)
{
    app_data_index = RAND_DRBG_get_ex_new_index(0L, NULL, NULL, NULL, NULL);

    ADD_ALL_TESTS(test_kats, OSSL_NELEM(drbg_test));
    ADD_ALL_TESTS(test_error_checks, OSSL_NELEM(drbg_test));
    return 1;
}
