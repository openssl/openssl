/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <limits.h>
#include <string.h>
#include <openssl/bio.h>
#include "testutil.h"

/*
 * Regression tests for buffer BIO ctrl paths that take a signed length
 * (see https://github.com/openssl/openssl/issues/30725).
 */
static int test_buffer_invalid_lengths(void)
{
    BIO *mem = NULL, *bufbio = NULL;
    char buf[16] = { 0 };
    int testresult = 0;

    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(bufbio = BIO_new(BIO_f_buffer()))) {
        BIO_free(mem);
        goto err;
    }
    BIO_push(bufbio, mem);

    if (!TEST_long_eq(BIO_ctrl(bufbio, BIO_C_SET_BUFF_READ_DATA, -1, buf), 0))
        goto err;
#if LONG_MAX > INT_MAX
    if (!TEST_long_eq(BIO_ctrl(bufbio, BIO_C_SET_BUFF_READ_DATA,
                          (long)INT_MAX + 1, buf),
            0))
        goto err;
#endif
    if (!TEST_long_eq(BIO_ctrl(bufbio, BIO_C_SET_BUFF_READ_DATA, 1, NULL), 0)
        || !TEST_long_eq(BIO_buffer_peek(bufbio, buf, -1), 0)
        || !TEST_long_eq(BIO_buffer_peek(bufbio, NULL, 1), 0)
        || !TEST_long_eq(BIO_set_buffer_size(bufbio, -1), 0)
        || !TEST_long_eq(BIO_int_ctrl(bufbio, BIO_C_SET_BUFF_SIZE, -1, 0), 0)
        || !TEST_long_eq(BIO_int_ctrl(bufbio, BIO_C_SET_BUFF_SIZE, -1, 1), 0))
        goto err;

    testresult = 1;
err:
    BIO_free_all(bufbio);
    return testresult;
}

static int test_buffer_failed_read_data_preserves_state(void)
{
    BIO *mem = NULL, *bufbio = NULL;
    static const char seed[] = "abcde";
    char out[16];
    int testresult = 0;

    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(bufbio = BIO_new(BIO_f_buffer()))) {
        BIO_free(mem);
        goto err;
    }
    BIO_push(bufbio, mem);

    if (!TEST_long_eq(BIO_set_buffer_read_data(bufbio, (void *)seed,
                          (long)sizeof(seed) - 1),
            1))
        goto err;

    if (!TEST_long_eq(BIO_ctrl(bufbio, BIO_C_SET_BUFF_READ_DATA, 1, NULL), 0))
        goto err;

    memset(out, 0, sizeof(out));
    if (!TEST_long_eq(BIO_buffer_peek(bufbio, out, (int)sizeof(seed) - 1),
            (long)sizeof(seed) - 1))
        goto err;
    if (!TEST_str_eq(out, seed))
        goto err;

    testresult = 1;
err:
    BIO_free_all(bufbio);
    return testresult;
}

static int test_buffer_failed_peek_preserves_state(void)
{
    BIO *mem = NULL, *bufbio = NULL;
    static const char seed[] = "xy";
    char out[16];
    int testresult = 0;

    if (!TEST_ptr(mem = BIO_new(BIO_s_mem())))
        goto err;
    if (!TEST_ptr(bufbio = BIO_new(BIO_f_buffer()))) {
        BIO_free(mem);
        goto err;
    }
    BIO_push(bufbio, mem);

    if (!TEST_long_eq(BIO_set_buffer_read_data(bufbio, (void *)seed, 2), 1))
        goto err;

    if (!TEST_long_eq(BIO_buffer_peek(bufbio, NULL, 1), 0))
        goto err;
    if (!TEST_long_eq(BIO_buffer_peek(bufbio, out, -1), 0))
        goto err;
    if (!TEST_long_eq(BIO_buffer_peek(bufbio, NULL, 0), 0))
        goto err;

    memset(out, 0, sizeof(out));
    if (!TEST_long_eq(BIO_buffer_peek(bufbio, out, 2), 2))
        goto err;
    out[2] = '\0';
    if (!TEST_str_eq(out, seed))
        goto err;

    testresult = 1;
err:
    BIO_free_all(bufbio);
    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_TEST(test_buffer_invalid_lengths);
    ADD_TEST(test_buffer_failed_read_data_preserves_state);
    ADD_TEST(test_buffer_failed_peek_preserves_state);
    return 1;
}
