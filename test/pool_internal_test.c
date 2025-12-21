/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal test for CRYPTO_BUFFER and buffer pools */

#include <stdio.h>
#include <string.h>

#include <internal/pool.h>
#include "testutil.h"
#include "internal/nelem.h"

static int test_crypto_buffer(void)
{
    CRYPTO_BUFFER *b1, *b2, *b3, *b4;
    CRYPTO_BUFFER_POOL *pool;
    uint8_t *data_ptr;
    int ret = 1;

    if (!TEST_ptr(b1 = CRYPTO_BUFFER_new((const uint8_t *)"DERP", 5, NULL)))
        return 0;
    if (!TEST_ptr(b2 = CRYPTO_BUFFER_new((const uint8_t *)"DERP", 5, NULL)))
        return 0;
    if (!TEST_ptr(b3 = CRYPTO_BUFFER_new_from_static_data_unsafe(
                      (const uint8_t *)"DERP", 5, NULL)))
        return 0;

    if (!TEST_ptr(b4 = CRYPTO_BUFFER_alloc(&data_ptr, 5)))
        return 0;
    memcpy(data_ptr, "DERP", 5);

    if (!TEST_ptr_ne(CRYPTO_BUFFER_data(b1), CRYPTO_BUFFER_data(b2)))
        ret = 0;
    if (!TEST_ptr_eq(CRYPTO_BUFFER_data(b3), "DERP"))
        ret = 0;
    if (!TEST_ptr_ne(CRYPTO_BUFFER_data(b3), CRYPTO_BUFFER_data(b1)))
        ret = 0;
    if (!TEST_ptr_ne(CRYPTO_BUFFER_data(b4), CRYPTO_BUFFER_data(b1)))
        ret = 0;

    if (!TEST_int_eq(CRYPTO_BUFFER_up_ref(b2), 1))
        ret = 0;

    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b2)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b3)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b3)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b4)))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b1), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b2), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b3), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b4), 5))
        ret = 0;

    CRYPTO_BUFFER_free(NULL);
    CRYPTO_BUFFER_free(b2);
    CRYPTO_BUFFER_free(b2);
    CRYPTO_BUFFER_free(b1);
    CRYPTO_BUFFER_free(b3);

    if (!TEST_ptr(pool = CRYPTO_BUFFER_POOL_new()))
        return 0;
    if (!TEST_ptr(b1 = CRYPTO_BUFFER_new((const uint8_t *)"DERP", 5, pool)))
        return 0;
    if (!TEST_ptr(b2 = CRYPTO_BUFFER_new((const uint8_t *)"DERP", 5, pool)))
        return 0;
    if (!TEST_ptr(b3 = CRYPTO_BUFFER_new_from_static_data_unsafe(
                      (const uint8_t *)"DERP", 5, pool)))
        return 0;
    if (!TEST_ptr(b4 = CRYPTO_BUFFER_new((const uint8_t *)"DERP", 5, pool)))
        return 0;

    if (!TEST_int_eq(CRYPTO_BUFFER_up_ref(b2), 1))
        ret = 0;
    /* Pool should dedup the data for b1 and b2 */
    if (!TEST_ptr_eq(CRYPTO_BUFFER_data(b1), CRYPTO_BUFFER_data(b2)))
        ret = 0;
    /* Adding the static b3 will replace the previous non-static copy in the pool */
    if (!TEST_ptr_ne(CRYPTO_BUFFER_data(b3), CRYPTO_BUFFER_data(b2)))
        ret = 0;
    /* Subsequent buffers will get the static version */
    if (!TEST_ptr_eq(CRYPTO_BUFFER_data(b3), CRYPTO_BUFFER_data(b4)))
        ret = 0;
    if (!TEST_ptr_eq(CRYPTO_BUFFER_data(b4), "DERP"))
        ret = 0;

    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b2)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b3)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b3)))
        ret = 0;
    if (!TEST_str_eq((const char *)CRYPTO_BUFFER_data(b1),
            (const char *)CRYPTO_BUFFER_data(b4)))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b1), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b2), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b3), 5))
        ret = 0;
    if (!TEST_int_eq(CRYPTO_BUFFER_len(b4), 5))
        ret = 0;

    CRYPTO_BUFFER_free(b2);
    CRYPTO_BUFFER_free(b2);
    CRYPTO_BUFFER_free(b1);
    CRYPTO_BUFFER_free(b3);
    CRYPTO_BUFFER_free(b4);
    CRYPTO_BUFFER_POOL_free(pool);

    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_crypto_buffer);
    return 1;
}
