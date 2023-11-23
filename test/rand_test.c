/*
 * Copyright 2021-2023 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/rand.h"
#include "testutil.h"

static int test_rand(void)
{
    EVP_RAND_CTX *privctx;
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

int setup_tests(void)
{
    if (!TEST_true(RAND_set_DRBG_type(NULL, "TEST-RAND", NULL, NULL, NULL)))
        return 0;
    ADD_TEST(test_rand);
    ADD_TEST(test_rand_uniform);
    return 1;
}
