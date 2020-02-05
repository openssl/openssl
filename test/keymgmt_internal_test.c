/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include "internal/core.h"
#include "internal/nelem.h"
#include "crypto/evp.h"          /* For the internal API */
#include "testutil.h"

typedef struct {
    OPENSSL_CTX *ctx1;
    OSSL_PROVIDER *prov1;
    OPENSSL_CTX *ctx2;
    OSSL_PROVIDER *prov2;
} FIXTURE;

static void tear_down(FIXTURE *fixture)
{
    if (fixture != NULL) {
        OSSL_PROVIDER_unload(fixture->prov1);
        OSSL_PROVIDER_unload(fixture->prov2);
        OPENSSL_CTX_free(fixture->ctx1);
        OPENSSL_CTX_free(fixture->ctx2);
        OPENSSL_free(fixture);
    }
}

static FIXTURE *set_up(const char *testcase_name)
{
    FIXTURE *fixture;

    if (!TEST_ptr(fixture = OPENSSL_zalloc(sizeof(*fixture)))
        || !TEST_ptr(fixture->ctx1 = OPENSSL_CTX_new())
        || !TEST_ptr(fixture->prov1 = OSSL_PROVIDER_load(fixture->ctx1,
                                                         "default"))
        || !TEST_ptr(fixture->ctx2 = OPENSSL_CTX_new())
        || !TEST_ptr(fixture->prov2 = OSSL_PROVIDER_load(fixture->ctx2,
                                                         "default"))) {
        tear_down(fixture);
        return NULL;
    }
    return fixture;
}

/* Array indexes */
#define N       0
#define E       1
#define D       2
#define P       3
#define Q       4
#define F3      5                /* Extra factor */
#define DP      6
#define DQ      7
#define E3      8                /* Extra exponent */
#define QINV    9
#define C3      10               /* Extra coefficient */

/*
 * We have to do this because OSSL_PARAM_get_ulong() can't handle params
 * holding data that isn't exactly sizeof(uint32_t) or sizeof(uint64_t),
 * and because the other end deals with BIGNUM, the resulting param might
 * be any size.  In this particular test, we know that the expected data
 * fits within an unsigned long, and we want to get the data in that form
 * to make testing of values easier.
 */
static int get_ulong_via_BN(const OSSL_PARAM *p, unsigned long *goal)
{
    BIGNUM *n = NULL;
    int ret = 1;                 /* Ever so hopeful */

    if (!TEST_true(OSSL_PARAM_get_BN(p, &n))
        || !TEST_true(BN_bn2nativepad(n, (unsigned char *)goal, sizeof(*goal))))
        ret = 0;
    BN_free(n);
    return ret;
}

static int export_cb(const OSSL_PARAM *params, void *arg)
{
    unsigned long *keydata = arg;
    const OSSL_PARAM *p = NULL;
    int factors_idx;
    int exponents_idx;
    int coefficients_idx;
    int ret = 1;                 /* Ever so hopeful */

    if (keydata == NULL)
        return 0;

    if (!TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_N))
        || !TEST_true(get_ulong_via_BN(p, &keydata[N]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_E))
        || !TEST_true(get_ulong_via_BN(p, &keydata[E]))
        || !TEST_ptr(p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_D))
        || !TEST_true(get_ulong_via_BN(p, &keydata[D])))
        ret = 0;

    for (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_FACTOR),
             factors_idx = P;
         p != NULL && factors_idx <= F3;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_PKEY_PARAM_RSA_FACTOR),
         factors_idx++)
        if (!TEST_true(get_ulong_via_BN(p, &keydata[factors_idx])))
            ret = 0;
    for (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_EXPONENT),
             exponents_idx = DP;
         p != NULL && exponents_idx <= E3;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_PKEY_PARAM_RSA_EXPONENT),
         exponents_idx++)
        if (!TEST_true(get_ulong_via_BN(p, &keydata[exponents_idx])))
            ret = 0;
    for (p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_RSA_COEFFICIENT),
             coefficients_idx = QINV;
         p != NULL && coefficients_idx <= C3;
         p = OSSL_PARAM_locate_const(p + 1, OSSL_PKEY_PARAM_RSA_COEFFICIENT),
         coefficients_idx++)
        if (!TEST_true(get_ulong_via_BN(p, &keydata[coefficients_idx])))
            ret = 0;

    if (!TEST_int_le(factors_idx, F3)
        || !TEST_int_le(exponents_idx, E3)
        || !TEST_int_le(coefficients_idx, C3))
        ret = 0;
    return ret;
}

static int test_pass_rsa(FIXTURE *fixture)
{
    size_t i;
    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *bn1 = NULL, *bn2 = NULL, *bn3 = NULL;
    EVP_PKEY *pk = NULL;
    EVP_KEYMGMT *km1 = NULL, *km2 = NULL;
    void *provkey = NULL;
    /*
     * 32-bit RSA key, extracted from this command,
     * executed with OpenSSL 1.0.2:
     *
     * openssl genrsa 32 | openssl rsa -text
     */
    static BN_ULONG expected[] = {
        0xbc747fc5,              /* N */
        0x10001,                 /* E */
        0x7b133399,              /* D */
        0xe963,                  /* P */
        0xceb7,                  /* Q */
        0,                       /* F3 */
        0x8599,                  /* DP */
        0xbd87,                  /* DQ */
        0,                       /* E3 */
        0xcc3b,                  /* QINV */
        0,                       /* C3 */
        0                        /* Extra, should remain zero */
    };
    static unsigned long keydata[OSSL_NELEM(expected)] = { 0, };

    if (!TEST_ptr(rsa = RSA_new()))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[N]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[E]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[D]))
        || !TEST_true(RSA_set0_key(rsa, bn1, bn2, bn3)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[P]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[Q]))
        || !TEST_true(RSA_set0_factors(rsa, bn1, bn2)))
        goto err;

    if (!TEST_ptr(bn1 = BN_new())
        || !TEST_true(BN_set_word(bn1, expected[DP]))
        || !TEST_ptr(bn2 = BN_new())
        || !TEST_true(BN_set_word(bn2, expected[DQ]))
        || !TEST_ptr(bn3 = BN_new())
        || !TEST_true(BN_set_word(bn3, expected[QINV]))
        || !TEST_true(RSA_set0_crt_params(rsa, bn1, bn2, bn3)))
        goto err;
    bn1 = bn2 = bn3 = NULL;

    if (!TEST_ptr(pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_assign_RSA(pk, rsa)))
        goto err;
    rsa = NULL;

    if (!TEST_ptr(km1 = EVP_KEYMGMT_fetch(fixture->ctx1, "RSA", NULL))
        || !TEST_ptr(km2 = EVP_KEYMGMT_fetch(fixture->ctx2, "RSA", NULL))
        || !TEST_ptr_ne(km1, km2))
        goto err;

    if (!TEST_ptr(evp_keymgmt_util_export_to_provider(pk, km1))
        || !TEST_ptr(provkey = evp_keymgmt_util_export_to_provider(pk, km2)))
        goto err;

    if (!TEST_true(evp_keymgmt_export(km2, provkey,
                                      OSSL_KEYMGMT_SELECT_KEYPAIR,
                                      &export_cb, keydata)))
        goto err;

    /*
     * At this point, the hope is that keydata will have all the numbers
     * from the key.
     */

    for (i = 0; i < OSSL_NELEM(expected); i++) {
        int rv = TEST_int_eq(expected[i], keydata[i]);

        if (!rv)
            TEST_info("i = %zu", i);
        else
            ret++;
    }

    ret = (ret == OSSL_NELEM(expected));

 err:
    RSA_free(rsa);
    BN_free(bn1);
    BN_free(bn2);
    BN_free(bn3);
    EVP_PKEY_free(pk);
    EVP_KEYMGMT_free(km1);
    EVP_KEYMGMT_free(km2);

    return ret;
}

static int (*tests[])(FIXTURE *) = {
    test_pass_rsa
};

static int test_pass_key(int n)
{
    SETUP_TEST_FIXTURE(FIXTURE, set_up);
    EXECUTE_TEST(tests[n], tear_down);
    return result;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_pass_key, 1);
    return 1;
}
