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

static int test_pass_rsa(FIXTURE *fixture)
{
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

    size_t i;
    int ret = 0;
    RSA *rsa = NULL;
    BIGNUM *bn1 = NULL, *bn2 = NULL, *bn3 = NULL;
    EVP_PKEY *pk = NULL;
    EVP_KEYMGMT *km1 = NULL, *km2 = NULL;
    void *provdata = NULL;
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
    OSSL_PARAM params[] = {
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_N, &keydata[N]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_E, &keydata[E]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_D, &keydata[D]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR, &keydata[P]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR, &keydata[Q]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR, &keydata[F3]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT, &keydata[DP]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT, &keydata[DQ]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT, &keydata[E3]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_COEFFICIENT, &keydata[QINV]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_COEFFICIENT, &keydata[C3]),
        OSSL_PARAM_END
    };

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

    if (!TEST_ptr(evp_keymgmt_export_to_provider(pk, km1, 0))
        || !TEST_ptr(provdata = evp_keymgmt_export_to_provider(pk, km2, 0)))
        goto err;

    if (!TEST_true(evp_keymgmt_exportkey(km2, provdata, params)))
        goto err;

    /*
     * At this point, the hope is that keydata will have all the numbers
     * from the key.
     */

    for (i = 0; i < OSSL_NELEM(expected); i++)
        ret += !! TEST_int_eq(expected[i], keydata[i]);

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
