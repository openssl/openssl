/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.opentls.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <opentls/tls.h>
#include <opentls/bio.h>
#include <opentls/err.h>

#include "internal/packet.h"

#include "tlstestlib.h"
#include "testutil.h"

struct async_ctrs {
    unsigned int rctr;
    unsigned int wctr;
};

static tls_CTX *serverctx = NULL;
static tls_CTX *clientctx = NULL;

#define MAX_ATTEMPTS    100


/*
 * There are 9 passes in the tests
 * 0 = control test
 * tests during writes
 * 1 = free buffers
 * 2 = + allocate buffers after free
 * 3 = + allocate buffers again
 * 4 = + free buffers after allocation
 * tests during reads
 * 5 = + free buffers
 * 6 = + free buffers again
 * 7 = + allocate buffers after free
 * 8 = + free buffers after allocation
 */
static int test_func(int test)
{
    int result = 0;
    tls *servertls = NULL, *clienttls = NULL;
    int ret;
    size_t i, j;
    const char testdata[] = "Test data";
    char buf[sizeof(testdata)];

    if (!TEST_true(create_tls_objects(serverctx, clientctx, &servertls, &clienttls,
                                      NULL, NULL))) {
        TEST_error("Test %d failed: Create tls objects failed\n", test);
        goto end;
    }

    if (!TEST_true(create_tls_connection(servertls, clienttls, tls_ERROR_NONE))) {
        TEST_error("Test %d failed: Create tls connection failed\n", test);
        goto end;
    }

    /*
     * Send and receive some test data. Do the whole thing twice to ensure
     * we hit at least one async event in both reading and writing
     */
    for (j = 0; j < 2; j++) {
        int len;

        /*

         * Write some test data. It should never take more than 2 attempts
         * (the first one might be a retryable fail).
         */
        for (ret = -1, i = 0, len = 0; len != sizeof(testdata) && i < 2;
             i++) {
            /* test == 0 mean to free/allocate = control */
            if (test >= 1 && !TEST_true(tls_free_buffers(clienttls)))
                goto end;
            if (test >= 2 && !TEST_true(tls_alloc_buffers(clienttls)))
                goto end;
            /* allocate a second time */
            if (test >= 3 && !TEST_true(tls_alloc_buffers(clienttls)))
                goto end;
            if (test >= 4 && !TEST_true(tls_free_buffers(clienttls)))
                goto end;

            ret = tls_write(clienttls, testdata + len,
                            sizeof(testdata) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int tls_error = tls_get_error(clienttls, ret);

                if (tls_error == tls_ERROR_SYSCALL ||
                    tls_error == tls_ERROR_tls) {
                    TEST_error("Test %d failed: Failed to write app data\n", test);
                    goto end;
                }
            }
        }
        if (!TEST_size_t_eq(len, sizeof(testdata)))
            goto end;
        /*
         * Now read the test data. It may take more attempts here because
         * it could fail once for each byte read, including all overhead
         * bytes from the record header/padding etc.
         */
        for (ret = -1, i = 0, len = 0; len != sizeof(testdata) &&
                 i < MAX_ATTEMPTS; i++)
        {
            if (test >= 5 && !TEST_true(tls_free_buffers(servertls)))
                goto end;
            /* free a second time */
            if (test >= 6 && !TEST_true(tls_free_buffers(servertls)))
                goto end;
            if (test >= 7 && !TEST_true(tls_alloc_buffers(servertls)))
                goto end;
            if (test >= 8 && !TEST_true(tls_free_buffers(servertls)))
                goto end;

            ret = tls_read(servertls, buf + len, sizeof(buf) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int tls_error = tls_get_error(servertls, ret);

                if (tls_error == tls_ERROR_SYSCALL ||
                    tls_error == tls_ERROR_tls) {
                    TEST_error("Test %d failed: Failed to read app data\n", test);
                    goto end;
                }
            }
        }
        if (!TEST_mem_eq(buf, len, testdata, sizeof(testdata)))
            goto end;
    }

    result = 1;
 end:
    if (!result)
        ERR_print_errors_fp(stderr);

    tls_free(clienttls);
    tls_free(servertls);

    return result;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    char *cert, *pkey;

    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(pkey = test_get_argument(1)))
        return 0;

    if (!create_tls_ctx_pair(TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, 0,
                             &serverctx, &clientctx, cert, pkey)) {
        TEST_error("Failed to create tls_CTX pair\n");
        return 0;
    }

    ADD_ALL_TESTS(test_func, 9);
    return 1;
}

void cleanup_tests(void)
{
    tls_CTX_free(clientctx);
    tls_CTX_free(serverctx);
}
