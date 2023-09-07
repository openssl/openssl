/*
 * Copyright 2016-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

/* We include internal headers so we can check if the buffers are allocated */
#include "../ssl/ssl_local.h"
#include "../ssl/record/record_local.h"
#include "internal/recordmethod.h"
#include "../ssl/record/methods/recmethod_local.h"

#include "internal/packet.h"

#include "helpers/ssltestlib.h"
#include "testutil.h"

struct async_ctrs {
    unsigned int rctr;
    unsigned int wctr;
};

static SSL_CTX *serverctx = NULL;
static SSL_CTX *clientctx = NULL;

#define MAX_ATTEMPTS    100

static int checkbuffers(SSL *s, int isalloced)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(s);
    OSSL_RECORD_LAYER *rrl = sc->rlayer.rrl;
    OSSL_RECORD_LAYER *wrl = sc->rlayer.wrl;

    if (isalloced)
        return rrl->rbuf.buf != NULL && wrl->wbuf[0].buf != NULL;

    return rrl->rbuf.buf == NULL && wrl->wbuf[0].buf == NULL;
}

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
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret;
    size_t i, j;
    const char testdata[] = "Test data";
    char buf[sizeof(testdata)];

    if (!TEST_true(create_ssl_objects(serverctx, clientctx, &serverssl, &clientssl,
                                      NULL, NULL))) {
        TEST_error("Test %d failed: Create SSL objects failed\n", test);
        goto end;
    }

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))) {
        TEST_error("Test %d failed: Create SSL connection failed\n", test);
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
            if (test >= 1 && (!TEST_true(SSL_free_buffers(clientssl))
                              || !TEST_true(checkbuffers(clientssl, 0))))
                goto end;
            if (test >= 2 && (!TEST_true(SSL_alloc_buffers(clientssl))
                              || !TEST_true(checkbuffers(clientssl, 1))))
                goto end;
            /* allocate a second time */
            if (test >= 3 && (!TEST_true(SSL_alloc_buffers(clientssl))
                              || !TEST_true(checkbuffers(clientssl, 1))))
                goto end;
            if (test >= 4 && (!TEST_true(SSL_free_buffers(clientssl))
                              || !TEST_true(checkbuffers(clientssl, 0))))
                goto end;

            ret = SSL_write(clientssl, testdata + len,
                            sizeof(testdata) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int ssl_error = SSL_get_error(clientssl, ret);

                if (ssl_error == SSL_ERROR_SYSCALL ||
                    ssl_error == SSL_ERROR_SSL) {
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
            if (test >= 5 && (!TEST_true(SSL_free_buffers(serverssl))
                              || !TEST_true(checkbuffers(serverssl, 0))))
                goto end;
            /* free a second time */
            if (test >= 6 && (!TEST_true(SSL_free_buffers(serverssl))
                              || !TEST_true(checkbuffers(serverssl, 0))))
                goto end;
            if (test >= 7 && (!TEST_true(SSL_alloc_buffers(serverssl))
                              || !TEST_true(checkbuffers(serverssl, 1))))
                goto end;
            if (test >= 8 && (!TEST_true(SSL_free_buffers(serverssl))
                              || !TEST_true(checkbuffers(serverssl, 0))))
                goto end;

            ret = SSL_read(serverssl, buf + len, sizeof(buf) - len);
            if (ret > 0) {
                len += ret;
            } else {
                int ssl_error = SSL_get_error(serverssl, ret);

                if (ssl_error == SSL_ERROR_SYSCALL ||
                    ssl_error == SSL_ERROR_SSL) {
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

    SSL_free(clientssl);
    SSL_free(serverssl);

    return result;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    char *cert, *pkey;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
            || !TEST_ptr(pkey = test_get_argument(1)))
        return 0;

    if (!create_ssl_ctx_pair(NULL, TLS_server_method(), TLS_client_method(),
                             TLS1_VERSION, 0,
                             &serverctx, &clientctx, cert, pkey)) {
        TEST_error("Failed to create SSL_CTX pair\n");
        return 0;
    }

    ADD_ALL_TESTS(test_func, 9);
    return 1;
}

void cleanup_tests(void)
{
    SSL_CTX_free(clientctx);
    SSL_CTX_free(serverctx);
}
