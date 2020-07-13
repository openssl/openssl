/*
 * Copyright 2011-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RAND_DRBG_set is deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>
#include "internal/nelem.h"
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include "../crypto/rand/rand_local.h"
#include "../include/crypto/rand.h"
#include "../providers/implementations/rands/drbg_local.h"
#include "../crypto/evp/evp_local.h"

#if defined(_WIN32)
# include <windows.h>
#endif


#if defined(OPENSSL_SYS_UNIX)
# include <sys/types.h>
# include <sys/wait.h>
# include <unistd.h>
#endif

#include "testutil.h"
#include "drbgtest.h"

typedef struct drbg_selftest_data_st {
    int post;
    int nid;
    unsigned int flags;

    /* KAT data for no PR */
    const unsigned char *entropy;
    size_t entropylen;
    const unsigned char *nonce;
    size_t noncelen;
    const unsigned char *pers;
    size_t perslen;
    const unsigned char *adin;
    size_t adinlen;
    const unsigned char *entropyreseed;
    size_t entropyreseedlen;
    const unsigned char *adinreseed;
    size_t adinreseedlen;
    const unsigned char *adin2;
    size_t adin2len;
    const unsigned char *expected;
    size_t exlen;
    const unsigned char *kat2;
    size_t kat2len;

    /* KAT data for PR */
    const unsigned char *entropy_pr;
    size_t entropylen_pr;
    const unsigned char *nonce_pr;
    size_t noncelen_pr;
    const unsigned char *pers_pr;
    size_t perslen_pr;
    const unsigned char *adin_pr;
    size_t adinlen_pr;
    const unsigned char *entropypr_pr;
    size_t entropyprlen_pr;
    const unsigned char *ading_pr;
    size_t adinglen_pr;
    const unsigned char *entropyg_pr;
    size_t entropyglen_pr;
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

#define make_drbg_test_data_use_df(nid, pr, p) \
    make_drbg_test_data(nid, 0, pr, p)

#define make_drbg_test_data_no_df(nid, pr, p)                      \
    make_drbg_test_data(nid, RAND_DRBG_FLAG_CTR_NO_DF, pr, p)

#define make_drbg_test_data_hash(nid, pr, p) \
    make_drbg_test_data(nid, RAND_DRBG_FLAG_HMAC, hmac_##pr, p), \
    make_drbg_test_data(nid, 0, pr, p)

static DRBG_SELFTEST_DATA drbg_test[] = {
#ifndef FIPS_MODULE
    /* FIPS mode doesn't support CTR DRBG without a derivation function */
    make_drbg_test_data_no_df (NID_aes_128_ctr, aes_128_no_df,  0),
    make_drbg_test_data_no_df (NID_aes_192_ctr, aes_192_no_df,  0),
    make_drbg_test_data_no_df (NID_aes_256_ctr, aes_256_no_df,  1),
#endif
    make_drbg_test_data_use_df(NID_aes_128_ctr, aes_128_use_df, 0),
    make_drbg_test_data_use_df(NID_aes_192_ctr, aes_192_use_df, 0),
    make_drbg_test_data_use_df(NID_aes_256_ctr, aes_256_use_df, 1),
    make_drbg_test_data_hash(NID_sha1, sha1, 0),
    make_drbg_test_data_hash(NID_sha224, sha224, 0),
    make_drbg_test_data_hash(NID_sha256, sha256, 1),
    make_drbg_test_data_hash(NID_sha384, sha384, 0),
    make_drbg_test_data_hash(NID_sha512, sha512, 0),
};

/*
 * DRBG query functions
 */
static int state(RAND_DRBG *drbg)
{
    return EVP_RAND_state(drbg->rand);
}

static size_t query_rand_size_t(RAND_DRBG *drbg, const char *name)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    size_t n;

    *params = OSSL_PARAM_construct_size_t(name, &n);
    if (EVP_RAND_get_ctx_params(drbg->rand, params))
        return n;
    return 0;
}

static unsigned int query_rand_uint(RAND_DRBG *drbg, const char *name)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    unsigned int n;

    *params = OSSL_PARAM_construct_uint(name, &n);
    if (EVP_RAND_get_ctx_params(drbg->rand, params))
        return n;
    return 0;
}

#define DRBG_SIZE_T(name)                               \
    static size_t name(RAND_DRBG *drbg)                 \
    {                                                   \
        return query_rand_size_t(drbg, #name);          \
    }
DRBG_SIZE_T(min_entropylen)
DRBG_SIZE_T(max_entropylen)
DRBG_SIZE_T(min_noncelen)
DRBG_SIZE_T(max_noncelen)
DRBG_SIZE_T(max_perslen)
DRBG_SIZE_T(max_adinlen)

#define DRBG_UINT(name)                                 \
    static unsigned int name(RAND_DRBG *drbg)           \
    {                                                   \
        return query_rand_uint(drbg, #name);            \
    }
DRBG_UINT(reseed_requests)
DRBG_UINT(reseed_counter)

static PROV_DRBG *prov_rand(RAND_DRBG *drbg)
{
    return (PROV_DRBG *)drbg->rand->data;
}

static void set_generate_counter(RAND_DRBG *drbg, unsigned int n)
{
    PROV_DRBG *p = prov_rand(drbg);

    p->reseed_gen_counter = n;
}

static void set_reseed_counter(RAND_DRBG *drbg, unsigned int n)
{
    PROV_DRBG *p = prov_rand(drbg);

    p->reseed_counter = n;
}

static void inc_reseed_counter(RAND_DRBG *drbg)
{
    set_reseed_counter(drbg, reseed_counter(drbg) + 1);
}

static time_t reseed_time(RAND_DRBG *drbg)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    time_t t;

    *params = OSSL_PARAM_construct_time_t(OSSL_DRBG_PARAM_RESEED_TIME, &t);
    if (EVP_RAND_get_ctx_params(drbg->rand, params))
        return t;
    return 0;
}

/*
 * Test context data, attached as EXDATA to the RAND_DRBG
 */
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
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_callback_data(drbg);

    t->entropycnt++;
    *pout = (unsigned char *)t->entropy;
    return t->entropylen;
}

static size_t kat_nonce(RAND_DRBG *drbg, unsigned char **pout,
                        int entropy, size_t min_len, size_t max_len)
{
    TEST_CTX *t = (TEST_CTX *)RAND_DRBG_get_callback_data(drbg);

    t->noncecnt++;
    *pout = (unsigned char *)t->nonce;
    return t->noncelen;
}

/*
 * When building the FIPS module, it isn't possible to disable the continuous
 * RNG tests.  Tests that require this are skipped.
 */
static int crngt_skip(void)
{
#ifdef FIPS_MODULE
    return 1;
#else
    return 0;
#endif
}

 /*
 * Disable CRNG testing if it is enabled.
 * This stub remains to indicate the calling locations where it is necessary.
 * Once the RNG infrastructure is able to disable these tests, it should be
 * reconstituted.
 */
static int disable_crngt(RAND_DRBG *drbg)
{
    return 1;
}

static int uninstantiate(RAND_DRBG *drbg)
{
    int ret = drbg == NULL ? 1 : RAND_DRBG_uninstantiate(drbg);

    ERR_clear_error();
    return ret;
}

/*
 * Do a single KAT test.  Return 0 on failure.
 */
static int single_kat(DRBG_SELFTEST_DATA *td)
{
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    int failures = 0;
    unsigned char buff[1024];

    if (crngt_skip())
        return TEST_skip("CRNGT cannot be disabled");

    /*
     * Test without PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL)))
        return 0;
    if (!TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                           kat_nonce, NULL))
        || !TEST_true(RAND_DRBG_set_callback_data(drbg, &t))
        || !TEST_true(disable_crngt(drbg))) {
        failures++;
        goto err;
    }
    memset(&t, 0, sizeof(t));
    t.entropy = td->entropy;
    t.entropylen = td->entropylen;
    t.nonce = td->nonce;
    t.noncelen = td->noncelen;

    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                             td->adin, td->adinlen))
            || !TEST_mem_eq(td->expected, td->exlen, buff, td->exlen))
        failures++;

    /* Reseed DRBG with test entropy and additional input */
    t.entropy = td->entropyreseed;
    t.entropylen = td->entropyreseedlen;
    if (!TEST_true(RAND_DRBG_reseed(drbg, td->adinreseed, td->adinreseedlen, 0)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len, 0,
                                             td->adin2, td->adin2len))
            || !TEST_mem_eq(td->kat2, td->kat2len, buff, td->kat2len)))
        failures++;
    uninstantiate(drbg);

    /*
     * Now test with PR: Instantiate DRBG with test entropy, nonce and
     * personalisation string.
     */
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                                  kat_nonce, NULL))
            || !TEST_true(RAND_DRBG_set_callback_data(drbg, &t)))
        failures++;
    t.entropy = td->entropy_pr;
    t.entropylen = td->entropylen_pr;
    t.nonce = td->nonce_pr;
    t.noncelen = td->noncelen_pr;
    t.entropycnt = 0;
    t.noncecnt = 0;
    if (!TEST_true(RAND_DRBG_instantiate(drbg, td->pers_pr, td->perslen_pr)))
        failures++;

    /*
     * Now generate with PR: we need to supply entropy as this will
     * perform a reseed operation.
     */
    t.entropy = td->entropypr_pr;
    t.entropylen = td->entropyprlen_pr;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->katlen_pr, 1,
                                      td->adin_pr, td->adinlen_pr))
            || !TEST_mem_eq(td->kat_pr, td->katlen_pr, buff, td->katlen_pr))
        failures++;

    /*
     * Now generate again with PR: supply new entropy again.
     */
    t.entropy = td->entropyg_pr;
    t.entropylen = td->entropyglen_pr;

    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->kat2len_pr, 1,
                                      td->ading_pr, td->adinglen_pr))
                || !TEST_mem_eq(td->kat2_pr, td->kat2len_pr,
                                buff, td->kat2len_pr))
        failures++;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return failures == 0;
}

/*
 * Initialise a DRBG based on selftest data
 */
static int init(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td, TEST_CTX *t)
{
    if (!TEST_true(RAND_DRBG_set(drbg, td->nid, td->flags))
            || !TEST_true(RAND_DRBG_set_callbacks(drbg, kat_entropy, NULL,
                                                  kat_nonce, NULL)))
        return 0;
    RAND_DRBG_set_callback_data(drbg, t);
    t->entropy = td->entropy;
    t->entropylen = td->entropylen;
    t->nonce = td->nonce;
    t->noncelen = td->noncelen;
    t->entropycnt = 0;
    t->noncecnt = 0;
    return 1;
}

/*
 * Initialise and instantiate DRBG based on selftest data
 */
static int instantiate(RAND_DRBG *drbg, DRBG_SELFTEST_DATA *td,
                       TEST_CTX *t)
{
    if (!TEST_true(init(drbg, td, t))
            || !TEST_true(RAND_DRBG_instantiate(drbg, td->pers, td->perslen)))
        return 0;
    return 1;
}

/*
 * Perform extensive error checking as required by SP800-90.
 * Induce several failure modes and check an error condition is set.
 */
static int error_check(DRBG_SELFTEST_DATA *td)
{
    RAND_DRBG *drbg = NULL;
    TEST_CTX t;
    unsigned char buff[1024];
    unsigned int reseed_counter_tmp;
    int ret = 0;

    if (!TEST_ptr(drbg = RAND_DRBG_new(td->nid, td->flags, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;

    /*
     * Personalisation string tests
     */

    /* Test detection of too large personalisation string */
    if (!init(drbg, td, &t)
            || !TEST_false(RAND_DRBG_instantiate(drbg, td->pers, max_perslen(drbg) + 1)))
        goto err;

    /*
     * Entropy source tests
     */

    /* Test entropy source failure detection: i.e. returns no data */
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_instantiate(drbg, td->pers, td->perslen)))
        goto err;

    /* Try to generate output from uninstantiated DRBG */
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                       td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Test insufficient entropy */
    if (!init(drbg, td, &t))
        goto err;
    t.entropylen = min_entropylen(drbg) - 1;
    if (!TEST_false(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
            || !uninstantiate(drbg))
        goto err;

    /* Test too much entropy */
    if (!init(drbg, td, &t))
        goto err;
    t.entropylen = max_entropylen(drbg) + 1;
    if (!TEST_false(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
            || !uninstantiate(drbg))
        goto err;

    /*
     * Nonce tests
     */

    /* Test too small nonce */
    if (min_noncelen(drbg) != 0) {
        if (!init(drbg, td, &t))
            goto err;
        t.noncelen = min_noncelen(drbg) - 1;
        if (!TEST_false(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
                || !uninstantiate(drbg))
            goto err;
    }

    /* Test too large nonce */
    if (max_noncelen(drbg) != 0) {
        if (!init(drbg, td, &t))
            goto err;
        t.noncelen = max_noncelen(drbg) + 1;
        if (!TEST_false(RAND_DRBG_instantiate(drbg, td->pers, td->perslen))
                || !uninstantiate(drbg))
            goto err;
    }

    /* Instantiate with valid data, Check generation is now OK */
    if (!instantiate(drbg, td, &t)
            || !TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                             td->adin, td->adinlen)))
        goto err;

    /* Try too large additional input */
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                       td->adin, max_adinlen(drbg) + 1)))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1,
                                      td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Instantiate again with valid data */
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = reseed_counter(drbg);
    set_generate_counter(drbg, reseed_requests(drbg));

    /* Generate output and check entropy has been requested for reseed */
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(reseed_counter(drbg), reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    /*
     * Check prediction resistance request fails if entropy source
     * failure.
     */
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_generate(drbg, buff, td->exlen, 1,
                                       td->adin, td->adinlen))
            || !uninstantiate(drbg))
        goto err;

    /* Test reseed counter works */
    if (!instantiate(drbg, td, &t))
        goto err;
    reseed_counter_tmp = reseed_counter(drbg);
    set_generate_counter(drbg, reseed_requests(drbg));

    /* Generate output and check entropy has been requested for reseed */
    t.entropycnt = 0;
    if (!TEST_true(RAND_DRBG_generate(drbg, buff, td->exlen, 0,
                                      td->adin, td->adinlen))
            || !TEST_int_eq(t.entropycnt, 1)
            || !TEST_int_eq(reseed_counter(drbg), reseed_counter_tmp + 1)
            || !uninstantiate(drbg))
        goto err;

    /*
     * Explicit reseed tests
     */

    /* Test explicit reseed with too large additional input */
    if (!instantiate(drbg, td, &t)
            || !TEST_false(RAND_DRBG_reseed(drbg, td->adin, max_adinlen(drbg) + 1, 0)))
        goto err;

    /* Test explicit reseed with entropy source failure */
    t.entropylen = 0;
    if (!TEST_false(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0))
            || !uninstantiate(drbg))
        goto err;

    /* Test explicit reseed with too much entropy */
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = max_entropylen(drbg) + 1;
    if (!TEST_false(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0))
            || !uninstantiate(drbg))
        goto err;

    /* Test explicit reseed with too little entropy */
    if (!instantiate(drbg, td, &t))
        goto err;
    t.entropylen = min_entropylen(drbg) - 1;
    if (!TEST_false(RAND_DRBG_reseed(drbg, td->adin, td->adinlen, 0))
            || !uninstantiate(drbg))
        goto err;

    /* Standard says we have to check uninstantiate really zeroes */
    if (!TEST_true(EVP_RAND_verify_zeroization(drbg->rand)))
        goto err;

    ret = 1;

err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
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

    if (crngt_skip())
        return TEST_skip("CRNGT cannot be disabled");

    if (!error_check(td))
        goto err;
    rv = 1;

err:
    return rv;
}

/*
 * Generates random output using RAND_bytes() and RAND_priv_bytes()
 * and checks whether the three shared DRBGs were reseeded as
 * expected.
 *
 * |expect_success|: expected outcome (as reported by RAND_status())
 * |primary|, |public|, |private|: pointers to the three shared DRBGs
 * |expect_xxx_reseed| =
 *       1:  it is expected that the specified DRBG is reseeded
 *       0:  it is expected that the specified DRBG is not reseeded
 *      -1:  don't check whether the specified DRBG was reseeded or not
 * |reseed_time|: if nonzero, used instead of time(NULL) to set the
 *                |before_reseed| time.
 */
static int test_drbg_reseed(int expect_success,
                            RAND_DRBG *primary,
                            RAND_DRBG *public,
                            RAND_DRBG *private,
                            int expect_primary_reseed,
                            int expect_public_reseed,
                            int expect_private_reseed,
                            time_t reseed_when
                           )
{
    unsigned char buf[32];
    time_t before_reseed, after_reseed;
    int expected_state = (expect_success ? DRBG_READY : DRBG_ERROR);
    unsigned int primary_reseed, public_reseed, private_reseed;

    /*
     * step 1: check preconditions
     */

    /* Test whether seed propagation is enabled */
    if (!TEST_int_ne(primary_reseed = reseed_counter(primary), 0)
        || !TEST_int_ne(public_reseed = reseed_counter(public), 0)
        || !TEST_int_ne(private_reseed = reseed_counter(private), 0))
        return 0;

    /*
     * step 2: generate random output
     */

    if (reseed_when == 0)
        reseed_when = time(NULL);

    /* Generate random output from the public and private DRBG */
    before_reseed = expect_primary_reseed == 1 ? reseed_when : 0;
    if (!TEST_int_eq(RAND_bytes(buf, sizeof(buf)), expect_success)
        || !TEST_int_eq(RAND_priv_bytes(buf, sizeof(buf)), expect_success))
        return 0;
    after_reseed = time(NULL);


    /*
     * step 3: check postconditions
     */

    /* Test whether reseeding succeeded as expected */
    if (/*!TEST_int_eq(state(primary), expected_state)
        || */!TEST_int_eq(state(public), expected_state)
        || !TEST_int_eq(state(private), expected_state))
        return 0;

    if (expect_primary_reseed >= 0) {
        /* Test whether primary DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(primary), primary_reseed))
            return 0;
    }

    if (expect_public_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(public), public_reseed)
                || !TEST_uint_ge(reseed_counter(public),
                                 reseed_counter(primary)))
            return 0;
    }

    if (expect_private_reseed >= 0) {
        /* Test whether public DRBG was reseeded as expected */
        if (!TEST_int_ge(reseed_counter(private), private_reseed)
                || !TEST_uint_ge(reseed_counter(private),
                                 reseed_counter(primary)))
            return 0;
    }

    if (expect_success == 1) {
        /* Test whether reseed time of primary DRBG is set correctly */
        if (!TEST_time_t_le(before_reseed, reseed_time(primary))
            || !TEST_time_t_le(reseed_time(primary), after_reseed))
            return 0;

        /* Test whether reseed times of child DRBGs are synchronized with primary */
        if (!TEST_time_t_ge(reseed_time(public), reseed_time(primary))
            || !TEST_time_t_ge(reseed_time(private), reseed_time(primary)))
            return 0;
    } else {
        ERR_clear_error();
    }

    return 1;
}


#if defined(OPENSSL_SYS_UNIX)
/*
 * Test whether primary, public and private DRBG are reseeded after
 * forking the process.
 */
static int test_drbg_reseed_after_fork(RAND_DRBG *primary,
                                       RAND_DRBG *public,
                                       RAND_DRBG *private)
{
    pid_t pid;
    int status=0;

    pid = fork();
    if (!TEST_int_ge(pid, 0))
        return 0;

    if (pid > 0) {
        /* I'm the parent; wait for the child and check its exit code */
        return TEST_int_eq(waitpid(pid, &status, 0), pid) && TEST_int_eq(status, 0);
    }

    /* I'm the child; check whether all three DRBGs reseed. */
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 1, 1, 1, 0)))
        status = 1;
    exit(status);
}
#endif

/*
 * Test whether the default rand_method (RAND_OpenSSL()) is
 * setup correctly, in particular whether reseeding  works
 * as designed.
 */
static int test_rand_drbg_reseed(void)
{
    RAND_DRBG *primary, *public, *private;
    unsigned char rand_add_buf[256];
    int rv = 0;
    time_t before_reseed;

    if (crngt_skip())
        return TEST_skip("CRNGT cannot be disabled");

    /* Check whether RAND_OpenSSL() is the default method */
    if (!TEST_ptr_eq(RAND_get_rand_method(), RAND_OpenSSL()))
        return 0;

    /* All three DRBGs should be non-null */
    if (!TEST_ptr(primary = RAND_DRBG_get0_master())
        || !TEST_ptr(public = RAND_DRBG_get0_public())
        || !TEST_ptr(private = RAND_DRBG_get0_private()))
        return 0;

    /* There should be three distinct DRBGs, two of them chained to primary */
    if (!TEST_ptr_ne(public, private)
        || !TEST_ptr_ne(public, primary)
        || !TEST_ptr_ne(private, primary)
        || !TEST_ptr_eq(public->parent, primary)
        || !TEST_ptr_eq(private->parent, primary))
        return 0;

    /* Disable CRNG testing for the primary DRBG */
    if (!TEST_true(disable_crngt(primary)))
        return 0;

    /* uninstantiate the three global DRBGs */
    RAND_DRBG_uninstantiate(primary);
    RAND_DRBG_uninstantiate(private);
    RAND_DRBG_uninstantiate(public);


    /*
     * Test initial seeding of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 1, 1, 1, 0)))
        goto error;


    /*
     * Test initial state of shared DRBGs
     */
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 0, 0, 0, 0)))
        goto error;

    /*
     * Test whether the public and private DRBG are both reseeded when their
     * reseed counters differ from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 0, 1, 1, 0)))
        goto error;

    /*
     * Test whether the public DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    inc_reseed_counter(private);
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 0, 1, 0, 0)))
        goto error;

    /*
     * Test whether the private DRBG is reseeded when its reseed counter differs
     * from the primary's reseed counter.
     */
    inc_reseed_counter(primary);
    inc_reseed_counter(public);
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 0, 0, 1, 0)))
        goto error;

#if defined(OPENSSL_SYS_UNIX)
    if (!TEST_true(test_drbg_reseed_after_fork(primary, public, private)))
        goto error;
#endif

    /* fill 'randomness' buffer with some arbitrary data */
    memset(rand_add_buf, 'r', sizeof(rand_add_buf));

#ifndef FIPS_MODULE
    /*
     * Test whether all three DRBGs are reseeded by RAND_add().
     * The before_reseed time has to be measured here and passed into the
     * test_drbg_reseed() test, because the primary DRBG gets already reseeded
     * in RAND_add(), whence the check for the condition
     * before_reseed <= reseed_time(primary) will fail if the time value happens
     * to increase between the RAND_add() and the test_drbg_reseed() call.
     */
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 1, 1, 1,
                                    before_reseed)))
        goto error;
#else /* FIPS_MODULE */
    /*
     * In FIPS mode, random data provided by the application via RAND_add()
     * is not considered a trusted entropy source. It is only treated as
     * additional_data and no reseeding is forced. This test assures that
     * no reseeding occurs.
     */
    before_reseed = time(NULL);
    RAND_add(rand_add_buf, sizeof(rand_add_buf), sizeof(rand_add_buf));
    if (!TEST_true(test_drbg_reseed(1, primary, public, private, 0, 0, 0,
                                    before_reseed)))
        goto error;
#endif

    rv = 1;

error:
   return rv;
}

#if defined(OPENSSL_THREADS)
static int multi_thread_rand_bytes_succeeded = 1;
static int multi_thread_rand_priv_bytes_succeeded = 1;

static void run_multi_thread_test(void)
{
    unsigned char buf[256];
    time_t start = time(NULL);
    RAND_DRBG *public = NULL, *private = NULL;

    if (!TEST_ptr(public = RAND_DRBG_get0_public())
            || !TEST_ptr(private = RAND_DRBG_get0_private())) {
        multi_thread_rand_bytes_succeeded = 0;
        return;
    }
    RAND_DRBG_set_reseed_time_interval(private, 1);
    RAND_DRBG_set_reseed_time_interval(public, 1);

    do {
        if (RAND_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_bytes_succeeded = 0;
        if (RAND_priv_bytes(buf, sizeof(buf)) <= 0)
            multi_thread_rand_priv_bytes_succeeded = 0;
    }
    while(time(NULL) - start < 5);
}

# if defined(OPENSSL_SYS_WINDOWS)

typedef HANDLE thread_t;

static DWORD WINAPI thread_run(LPVOID arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return 0;
}

static int run_thread(thread_t *t)
{
    *t = CreateThread(NULL, 0, thread_run, NULL, 0, NULL);
    return *t != NULL;
}

static int wait_for_thread(thread_t thread)
{
    return WaitForSingleObject(thread, INFINITE) == 0;
}

# else

typedef pthread_t thread_t;

static void *thread_run(void *arg)
{
    run_multi_thread_test();
    /*
     * Because we're linking with a static library, we must stop each
     * thread explicitly, or so says OPENSSL_thread_stop(3)
     */
    OPENSSL_thread_stop();
    return NULL;
}

static int run_thread(thread_t *t)
{
    return pthread_create(t, NULL, thread_run, NULL) == 0;
}

static int wait_for_thread(thread_t thread)
{
    return pthread_join(thread, NULL) == 0;
}

# endif

/*
 * The main thread will also run the test, so we'll have THREADS+1 parallel
 * tests running
 */
# define THREADS 3

static int test_multi_thread(void)
{
    thread_t t[THREADS];
    int i;

    for (i = 0; i < THREADS; i++)
        run_thread(&t[i]);
    run_multi_thread_test();
    for (i = 0; i < THREADS; i++)
        wait_for_thread(t[i]);

    if (!TEST_true(multi_thread_rand_bytes_succeeded))
        return 0;
    if (!TEST_true(multi_thread_rand_priv_bytes_succeeded))
        return 0;

    return 1;
}
#endif

static int test_rand_drbg_prediction_resistance(void)
{
    RAND_DRBG *x = NULL, *y = NULL, *z = NULL;
    unsigned char buf1[51], buf2[sizeof(buf1)];
    int ret = 0, xreseed, yreseed, zreseed;

    if (crngt_skip())
        return TEST_skip("CRNGT cannot be disabled");

    /* Initialise a three long DRBG chain */
    if (!TEST_ptr(x = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(x))
        || !TEST_true(RAND_DRBG_instantiate(x, NULL, 0))
        || !TEST_ptr(y = RAND_DRBG_new(0, 0, x))
        || !TEST_true(RAND_DRBG_instantiate(y, NULL, 0))
        || !TEST_ptr(z = RAND_DRBG_new(0, 0, y))
        || !TEST_true(RAND_DRBG_instantiate(z, NULL, 0)))
        goto err;

    /*
     * During a normal reseed, only the last DRBG in the chain should
     * be reseeded.
     */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(RAND_DRBG_reseed(z, NULL, 0, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * When prediction resistance is requested, the request should be
     * propagated to the primary, so that the entire DRBG chain reseeds.
     */
    zreseed = reseed_counter(z);
    if (!TEST_true(RAND_DRBG_reseed(z, NULL, 0, 1))
        || !TEST_int_gt(reseed_counter(x), xreseed)
        || !TEST_int_gt(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * During a normal generate, only the last DRBG should be reseed */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(RAND_DRBG_generate(z, buf1, sizeof(buf1), 0, NULL, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    /*
     * When a prediction resistant generate is requested, the request
     * should be propagated to the primary, reseeding the entire DRBG chain.
     */
    zreseed = reseed_counter(z);
    if (!TEST_true(RAND_DRBG_generate(z, buf2, sizeof(buf2), 1, NULL, 0))
        || !TEST_int_gt(reseed_counter(x), xreseed)
        || !TEST_int_gt(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed)
        || !TEST_mem_ne(buf1, sizeof(buf1), buf2, sizeof(buf2)))
        goto err;

    /* Verify that a normal reseed still only reseeds the last DRBG */
    inc_reseed_counter(y);
    xreseed = reseed_counter(x);
    yreseed = reseed_counter(y);
    zreseed = reseed_counter(z);
    if (!TEST_true(RAND_DRBG_reseed(z, NULL, 0, 0))
        || !TEST_int_eq(reseed_counter(x), xreseed)
        || !TEST_int_eq(reseed_counter(y), yreseed)
        || !TEST_int_gt(reseed_counter(z), zreseed))
        goto err;

    ret = 1;
err:
    RAND_DRBG_free(z);
    RAND_DRBG_free(y);
    RAND_DRBG_free(x);
    return ret;
}

static int test_multi_set(void)
{
    int rv = 0;
    RAND_DRBG *drbg = NULL;

    if (crngt_skip())
        return TEST_skip("CRNGT cannot be disabled");

    /* init drbg with default CTR initializer */
    if (!TEST_ptr(drbg = RAND_DRBG_new(0, 0, NULL))
        || !TEST_true(disable_crngt(drbg)))
        goto err;
    /* change it to use hmac */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha1, RAND_DRBG_FLAG_HMAC)))
        goto err;
    /* change it to use hash */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_sha256, 0)))
        goto err;
    /* change it to use ctr */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    /* use same type */
    if (!TEST_true(RAND_DRBG_set(drbg, NID_aes_192_ctr, 0)))
        goto err;
    if (!TEST_int_gt(RAND_DRBG_instantiate(drbg, NULL, 0), 0))
        goto err;

    rv = 1;
err:
    uninstantiate(drbg);
    RAND_DRBG_free(drbg);
    return rv;
}

static int test_set_defaults(void)
{
    RAND_DRBG *primary = NULL, *public = NULL, *private = NULL;

   /* Check the default type and flags for primary, public and private */
    return TEST_ptr(primary = RAND_DRBG_get0_master())
           && TEST_ptr(public = RAND_DRBG_get0_public())
           && TEST_ptr(private = RAND_DRBG_get0_private())
           && TEST_int_eq(primary->type, RAND_DRBG_TYPE)
           && TEST_int_eq(primary->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIMARY)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)

           /* change primary DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256,
                                               RAND_DRBG_FLAG_PRIMARY))
           && TEST_true(RAND_DRBG_uninstantiate(primary))
           && TEST_int_eq(primary->type, NID_sha256)
           && TEST_int_eq(primary->flags, RAND_DRBG_FLAG_PRIMARY)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, RAND_DRBG_TYPE)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PRIVATE)
           /* change private DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256,
                        RAND_DRBG_FLAG_PRIVATE|RAND_DRBG_FLAG_HMAC))
           && TEST_true(RAND_DRBG_uninstantiate(private))
           && TEST_int_eq(primary->type, NID_sha256)
           && TEST_int_eq(primary->flags, RAND_DRBG_FLAG_PRIMARY)
           && TEST_int_eq(public->type, RAND_DRBG_TYPE)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAGS | RAND_DRBG_FLAG_PUBLIC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           /* change public DRBG and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha1,
                                               RAND_DRBG_FLAG_PUBLIC
                                               | RAND_DRBG_FLAG_HMAC))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(primary->type, NID_sha256)
           && TEST_int_eq(primary->flags, RAND_DRBG_FLAG_PRIMARY)
           && TEST_int_eq(public->type, NID_sha1)
           && TEST_int_eq(public->flags,
                          RAND_DRBG_FLAG_PUBLIC | RAND_DRBG_FLAG_HMAC)
           && TEST_int_eq(private->type, NID_sha256)
           && TEST_int_eq(private->flags,
                          RAND_DRBG_FLAG_PRIVATE | RAND_DRBG_FLAG_HMAC)
           /* Change DRBG defaults and change public and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_sha256, 0))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_int_eq(public->type, NID_sha256)
           && TEST_int_eq(public->flags, RAND_DRBG_FLAG_PUBLIC)

          /* FIPS mode doesn't support CTR DRBG without a derivation function */
#ifndef FIPS_MODULE
          /* Change DRBG defaults and change primary and check again */
           && TEST_true(RAND_DRBG_set_defaults(NID_aes_256_ctr,
                                               RAND_DRBG_FLAG_CTR_NO_DF))
           && TEST_true(RAND_DRBG_uninstantiate(primary))
           && TEST_int_eq(primary->type, NID_aes_256_ctr)
           && TEST_int_eq(primary->flags,
                          RAND_DRBG_FLAG_PRIMARY|RAND_DRBG_FLAG_CTR_NO_DF)
#endif
           /* Reset back to the standard defaults */
           && TEST_true(RAND_DRBG_set_defaults(RAND_DRBG_TYPE,
                                               RAND_DRBG_FLAGS
                                               | RAND_DRBG_FLAG_PRIMARY
                                               | RAND_DRBG_FLAG_PUBLIC
                                               | RAND_DRBG_FLAG_PRIVATE))
           && TEST_true(RAND_DRBG_uninstantiate(primary))
           && TEST_true(RAND_DRBG_uninstantiate(public))
           && TEST_true(RAND_DRBG_uninstantiate(private));
}

#if 0
/*
 * A list of the FIPS DRGB types.
 * Because of the way HMAC DRGBs are implemented, both the NID and flags
 * are required.
 */
static const struct s_drgb_types {
    int nid;
    int flags;
} drgb_types[] = {
    { NID_aes_128_ctr,  0                   },
    { NID_aes_192_ctr,  0                   },
    { NID_aes_256_ctr,  0                   },
    { NID_sha1,         0                   },
    { NID_sha224,       0                   },
    { NID_sha256,       0                   },
    { NID_sha384,       0                   },
    { NID_sha512,       0                   },
    { NID_sha512_224,   0                   },
    { NID_sha512_256,   0                   },
    { NID_sha3_224,     0                   },
    { NID_sha3_256,     0                   },
    { NID_sha3_384,     0                   },
    { NID_sha3_512,     0                   },
    { NID_sha1,         RAND_DRBG_FLAG_HMAC },
    { NID_sha224,       RAND_DRBG_FLAG_HMAC },
    { NID_sha256,       RAND_DRBG_FLAG_HMAC },
    { NID_sha384,       RAND_DRBG_FLAG_HMAC },
    { NID_sha512,       RAND_DRBG_FLAG_HMAC },
    { NID_sha512_224,   RAND_DRBG_FLAG_HMAC },
    { NID_sha512_256,   RAND_DRBG_FLAG_HMAC },
    { NID_sha3_224,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_256,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_384,     RAND_DRBG_FLAG_HMAC },
    { NID_sha3_512,     RAND_DRBG_FLAG_HMAC },
};

/* Six cases for each covers seed sizes up to 32 bytes */
static const size_t crngt_num_cases = 6;

static size_t crngt_case, crngt_idx;

static int crngt_entropy_cb(OPENSSL_CTX *ctx, RAND_POOL *pool,
                            unsigned char *buf, unsigned char *md,
                            unsigned int *md_size)
{
    size_t i, z;

    if (!TEST_int_lt(crngt_idx, crngt_num_cases))
        return 0;
    /* Generate a block of unique data unless this is the duplication point */
    z = crngt_idx++;
    if (z > 0 && crngt_case == z)
        z--;
    for (i = 0; i < CRNGT_BUFSIZ; i++)
        buf[i] = (unsigned char)(i + 'A' + z);
    return EVP_Digest(buf, CRNGT_BUFSIZ, md, md_size, EVP_sha256(), NULL);
}
#endif

int setup_tests(void)
{
    ADD_ALL_TESTS(test_kats, 1);
    ADD_ALL_TESTS(test_error_checks, OSSL_NELEM(drbg_test));
    ADD_TEST(test_rand_drbg_reseed);
    ADD_TEST(test_rand_drbg_prediction_resistance);
    ADD_TEST(test_multi_set);
    ADD_TEST(test_set_defaults);
#if defined(OPENSSL_THREADS)
    ADD_TEST(test_multi_thread);
#endif
    return 1;
}
