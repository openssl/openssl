/*
 * Copyright 2021-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the >License>).  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include "crypto/rand.h"
#include "testutil.h"

static int test_rand(void)
{
    EVP_RAND_CTX *privctx;
    const OSSL_PROVIDER *prov;
    int indicator = 1;
    OSSL_PARAM params[2], *p = params;
    unsigned char entropy1[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05 };
    unsigned char entropy2[] = { 0xff, 0xfe, 0xfd };
    unsigned char outbuf[3];

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             entropy1, sizeof(entropy1));
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(privctx = RAND_get0_private(NULL))
            || !TEST_true(EVP_RAND_CTX_set_params(privctx, params))
            || !TEST_int_gt(RAND_priv_bytes(outbuf, sizeof(outbuf)), 0)
            || !TEST_mem_eq(outbuf, sizeof(outbuf), entropy1, sizeof(outbuf))
            || !TEST_int_le(RAND_priv_bytes(outbuf, sizeof(outbuf) + 1), 0)
            || !TEST_int_gt(RAND_priv_bytes(outbuf, sizeof(outbuf)), 0)
            || !TEST_mem_eq(outbuf, sizeof(outbuf),
                            entropy1 + sizeof(outbuf), sizeof(outbuf)))
        return 0;

    *params = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                                entropy2, sizeof(entropy2));
    if (!TEST_true(EVP_RAND_CTX_set_params(privctx, params))
            || !TEST_int_gt(RAND_priv_bytes(outbuf, sizeof(outbuf)), 0)
            || !TEST_mem_eq(outbuf, sizeof(outbuf), entropy2, sizeof(outbuf)))
        return 0;

    if (fips_provider_version_lt(NULL, 3, 4, 0)) {
        /* Skip the rest and pass the test */
        return 1;
    }
    /* Verify that the FIPS indicator can be read and is false */
    prov = EVP_RAND_get0_provider(EVP_RAND_CTX_get0_rand(privctx));
    if (prov != NULL
            && strcmp(OSSL_PROVIDER_get0_name(prov), "fips") == 0) {
        params[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_FIPS_APPROVED_INDICATOR,
                                             &indicator);
        if (!TEST_true(EVP_RAND_CTX_get_params(privctx, params))
                || !TEST_int_eq(indicator, 0))
            return 0;
    }
    return 1;
}

static int test_rand_uniform(void)
{
    uint32_t x, i, j;
    int err = 0, res = 0;
    OSSL_LIB_CTX *ctx;

    if (!test_get_libctx(&ctx, NULL, NULL, NULL, NULL))
        goto err;

    for (i = 1; i < 100; i += 13) {
        x = ossl_rand_uniform_uint32(ctx, i, &err);
        if (!TEST_int_eq(err, 0)
                || !TEST_uint_ge(x, 0)
                || !TEST_uint_lt(x, i))
            return 0;
    }
    for (i = 1; i < 100; i += 17)
        for (j = i + 1; j < 150; j += 11) {
            x = ossl_rand_range_uint32(ctx, i, j, &err);
            if (!TEST_int_eq(err, 0)
                    || !TEST_uint_ge(x, i)
                    || !TEST_uint_lt(x, j))
                return 0;
        }

    res = 1;
 err:
    OSSL_LIB_CTX_free(ctx);
    return res;
}

/* Test the FIPS health tests */
static int fips_health_test_one(const uint8_t *buf, size_t n, size_t gen)
{
    int res = 0;
    EVP_RAND *crngt_alg = NULL, *parent_alg = NULL;
    EVP_RAND_CTX *crngt = NULL, *parent = NULL;
    OSSL_PARAM p[2];
    uint8_t out[1000];
    int indicator = -1;

    p[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
                                             (void *)buf, n);
    p[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(parent_alg = EVP_RAND_fetch(NULL, "TEST-RAND", "-fips"))
            || !TEST_ptr(crngt_alg = EVP_RAND_fetch(NULL, "CRNG-TEST", "-fips"))
            || !TEST_ptr(parent = EVP_RAND_CTX_new(parent_alg, NULL))
            || !TEST_ptr(crngt = EVP_RAND_CTX_new(crngt_alg, parent))
            || !TEST_true(EVP_RAND_instantiate(parent, 0, 0,
                                               (unsigned char *)"abc", 3, p))
            || !TEST_true(EVP_RAND_instantiate(crngt, 0, 0,
                                               (unsigned char *)"def", 3, NULL))
            || !TEST_size_t_le(gen, sizeof(out)))
        goto err;

    /* Verify that the FIPS indicator is negative */
    p[0] = OSSL_PARAM_construct_int(OSSL_RAND_PARAM_FIPS_APPROVED_INDICATOR,
                                    &indicator);
    if (!TEST_true(EVP_RAND_CTX_get_params(crngt, p))
            || !TEST_int_le(indicator, 0))
        goto err;

    ERR_set_mark();
    res = EVP_RAND_generate(crngt, out, gen, 0, 0, NULL, 0);
    ERR_pop_to_mark();
 err:
    EVP_RAND_CTX_free(crngt);
    EVP_RAND_CTX_free(parent);
    EVP_RAND_free(crngt_alg);
    EVP_RAND_free(parent_alg);
    return res;
}

static int fips_health_tests(void)
{
    uint8_t buf[1000];
    size_t i;

    /* Verify tests can pass */
    for (i = 0; i < sizeof(buf); i++)
        buf[i] = 0xff & i;
    if (!TEST_true(fips_health_test_one(buf, i, i)))
        return 0;

    /* Verify RCT can fail */
    for (i = 0; i < 20; i++)
        buf[i] = 0xff & (i > 10 ? 200 : i);
    if (!TEST_false(fips_health_test_one(buf, i, i)))
        return 0;

    /* Verify APT can fail */
    for (i = 0; i < sizeof(buf); i++)
        buf[i] = 0xff & (i >= 512 && i % 8 == 0 ? 0x80 : i);
    if (!TEST_false(fips_health_test_one(buf, i, i)))
        return 0;
    return 1;
}

int setup_tests(void)
{
    char *configfile;

    if (!TEST_ptr(configfile = test_get_argument(0))
            || !TEST_true(RAND_set_DRBG_type(NULL, "TEST-RAND", "fips=no",
                                             NULL, NULL))
            || (fips_provider_version_ge(NULL, 3, 0, 8)
                && !TEST_true(OSSL_LIB_CTX_load_config(NULL, configfile))))
        return 0;

    ADD_TEST(test_rand);
    ADD_TEST(test_rand_uniform);

    if (OSSL_PROVIDER_available(NULL, "fips")
            && fips_provider_version_ge(NULL, 3, 4, 0))
        ADD_TEST(fips_health_tests);

    return 1;
}
