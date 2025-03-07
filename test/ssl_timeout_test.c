/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <ssl/ssl_local.h>

#include "testutil.h"
#include "testutil/output.h"

#ifndef B_TRUE
# define B_TRUE (1 == 1)
#endif

#ifndef B_FALSE
# define B_FALSE (1 != 1)
#endif

struct sample {
    time_t time;
    time_t timeout;
    time_t expected;
    int expected_ovf;
};

struct sample_64 {
    uint64_t time;
    uint64_t timeout;
    uint64_t expected;
    int expected_ovf;
};

static struct sample_64 test_sample_64[] = {
    {
        0xfffffffffffff3ff,
        0x100,
        0xfffffffffffff4ff,
        B_FALSE
    },
    {
        0x100,
        0xfffffffffffff3ff,
        0x100,
        B_FALSE
    },
    {
        0x8000000000000000,
        0x7fffffffffffffff,
        0xffffffffffffffff,
        B_FALSE
    },
    {
        0x7fffffffffffffff,
        0x8000000000000000,
        0x7fffffffffffffff,
        B_FALSE
    },
    {
        0xffffffffffff3fff,
	0x100,
        0xffffffffffff40ff,
	B_FALSE
    },
    {
	0x100,
        0xffffffffffff3fff,
        0x100,
	B_FALSE
    },
    {
        0xffffffffffffffff,
        0x0,
        0xffffffffffffffff,
        B_FALSE
    },
    {
        0x0,
        0xffffffffffffffff,
        0x0,
        B_FALSE
    },
    {
        0xffffffffffffffff,
        0x100,
        0xff,
        B_FALSE
    },
    {
        0x100,
        0xffffffffffffffff,
        0x100,
        B_FALSE
    },
    {
        0x7fffffffffffffff,
        0x7fffffffffffffff,
        0xfffffffffffffffe,
        B_TRUE
    },
    {
        0x20,
        0x7fffffffffffffff,
        0x800000000000001f,
        B_TRUE
    },
    {
        0x7fffffffffffffff,
        0x20,
        0x800000000000001f,
        B_TRUE
    },
    {
        0x130,
        0x66f3cafa,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3cafa,
        0x130,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3caf8,
        0x130,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x130,
        0x66f3caf8,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x2020202020202020,
        0xffffffffffffffff,
        0x2020202020202020,
        B_FALSE
    },
    {
        0xffffffffffffffff,
        0x2020202020202020,
        0x202020202020201f,
        B_FALSE
    },
    { 0 }
};

static struct sample test_sample_32[] = {
    {
        0xfffff3ff,
        0x100,
        0xfffff4ff,
        B_FALSE
    },
    {
        0x100,
        0xfffff3ff,
        0x100,
        B_FALSE
    },
    {
        0x80000000,
        0x7fffffff,
        0xffffffff,
        B_FALSE
    },
    {
        0x7fffffff,
        0x80000000,
        0x7fffffff,
        B_FALSE
    },
    {
        0xffff3fff,
	0x100,
        0xffff40ff,
	B_FALSE
    },
    {
	0x100,
        0xffff3fff,
        0x100,
	B_FALSE
    },
    {
        0xffffffff,
        0x0,
        0xffffffff,
        B_FALSE
    },
    {
        0x0,
        0xffffffff,
        0x0,
        B_FALSE
    },
    {
        0xffffffff,
        0x100,
        0xff,
        B_FALSE
    },
    {
        0x100,
        0xffffffff,
        0x100,
        B_FALSE
    },
    {
        0x7fffffff,
        0x7fffffff,
        0xfffffffe,
        B_TRUE
    },
    {
        0x20,
        0x7fffffff,
        0x8000001f,
        B_TRUE
    },
    {
        0x7fffffff,
        0x20,
        0x8000001f,
        B_TRUE
    },
    {
        0x130,
        0x66f3cafa,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3cafa,
        0x130,
        0x66f3cc2a,
        B_FALSE
    },
    {
        0x66f3caf8,
        0x130,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x130,
        0x66f3caf8,
        0x66f3cc28,
        B_FALSE
    },
    {
        0x20202020,
        0xffffffff,
        0x20202020,
        B_FALSE
    },
    {
        0xffffffff,
        0x20202020,
        0x2020201f,
        B_FALSE
    },
    { 0 }
};

static int test_ssl_timeout(void)
{
    int i = 0;
    SSL_SESSION *s;
    SSL_CTX *ctx;
    OSSL_LIB_CTX *libctx;
    time_t result;
    int overflow;
    int testresult = 1;
    struct sample *test_sample;

    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
    if (!TEST_ptr(ctx)) {
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    s = SSL_SESSION_new();
    if (!TEST_ptr(ctx)) {
        SSL_CTX_free(ctx);
        OSSL_LIB_CTX_free(libctx);
        return 0;
    }

    if (sizeof(time_t) == 8)
        test_sample = (struct sample *)test_sample_64;
    else
        test_sample = test_sample_32;

    while (!((test_sample[i].time == 0) && (test_sample[i].timeout == 0))) {
        ssl_session_set_times(s, test_sample[i].time, test_sample[i].timeout);
        ssl_session_calculate_timeout(s);
        ssl_session_get_calc_timeout(s, &result, &overflow);
        if (!TEST_time_t_eq(result, test_sample[i].expected)) {
            testresult = 0;
            TEST_info("test_ssl_timeout (%d) fails for %p + %p = %p, got %p\n",
                i, (void *)test_sample[i].time, (void *)test_sample[i].timeout,
                (void *)test_sample[i].expected, (void *)result);
        }
        if (!TEST_int_eq(overflow, test_sample[i].expected_ovf)) {
            TEST_info("test_ssl_timeout (%d) failed to detect overflow for "
                      "%p + %p = %p (%s), got %p (%s)\n",
                i, (void *)test_sample[i].time, (void *)test_sample[i].timeout,
                (void *)test_sample[i].expected,
                (test_sample[i].expected_ovf ? "with overflow" : "no overflow"),
                (void *)result,
                (overflow ? "with overflow" : "no overflow"));
            testresult = 0;
        }
        i++;
    }

    SSL_SESSION_free(s);
    SSL_CTX_free(ctx);
    OSSL_LIB_CTX_free(libctx);

    return testresult;
}


int setup_tests(void)
{
    ADD_TEST(test_ssl_timeout);

    return 1;
}
