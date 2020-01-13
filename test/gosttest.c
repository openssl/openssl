/*
 * Copyright 2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "tlstestlib.h"
#include "testutil.h"
#include "internal/nelem.h"

static char *cert1 = NULL;
static char *privkey1 = NULL;
static char *cert2 = NULL;
static char *privkey2 = NULL;

static struct {
    char *cipher;
    int expected_prot;
    int certnum;
} ciphers[] = {
    /* Server doesn't have a cert with appropriate sig algs - should fail */
    {"AES128-SHA", 0, 0},
    /* Server doesn't have a TLSv1.3 capable cert - should use TLSv1.2 */
    {"GOST2012-GOST8912-GOST8912", TLS1_2_VERSION, 0},
    /* Server doesn't have a TLSv1.3 capable cert - should use TLSv1.2 */
    {"GOST2012-GOST8912-GOST8912", TLS1_2_VERSION, 1},
    /* Server doesn't have a TLSv1.3 capable cert - should use TLSv1.2 */
    {"GOST2001-GOST89-GOST89", TLS1_2_VERSION, 0},
};

/* Test that we never negotiate TLSv1.3 if using GOST */
static int test_tls13(int idx)
{
    tls_CTX *cctx = NULL, *sctx = NULL;
    tls *clienttls = NULL, *servertls = NULL;
    int testresult = 0;

    if (!TEST_true(create_tls_ctx_pair(TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_VERSION,
                                       0,
                                       &sctx, &cctx,
                                       ciphers[idx].certnum == 0 ? cert1
                                                                 : cert2,
                                       ciphers[idx].certnum == 0 ? privkey1
                                                                 : privkey2)))
        goto end;

    if (!TEST_true(tls_CTX_set_cipher_list(cctx, ciphers[idx].cipher))
            || !TEST_true(tls_CTX_set_cipher_list(sctx, ciphers[idx].cipher))
            || !TEST_true(create_tls_objects(sctx, cctx, &servertls, &clienttls,
                                             NULL, NULL)))
        goto end;

    if (ciphers[idx].expected_prot == 0) {
        if (!TEST_false(create_tls_connection(servertls, clienttls,
                                              tls_ERROR_NONE)))
            goto end;
    } else {
        if (!TEST_true(create_tls_connection(servertls, clienttls,
                                             tls_ERROR_NONE))
                || !TEST_int_eq(tls_version(clienttls),
                                ciphers[idx].expected_prot))
        goto end;
    }

    testresult = 1;

 end:
    tls_free(servertls);
    tls_free(clienttls);
    tls_CTX_free(sctx);
    tls_CTX_free(cctx);

    return testresult;
}

OPT_TEST_DECLARE_USAGE("certfile1 privkeyfile1 certfile2 privkeyfile2\n")

int setup_tests(void)
{
    if (!TEST_ptr(cert1 = test_get_argument(0))
            || !TEST_ptr(privkey1 = test_get_argument(1))
            || !TEST_ptr(cert2 = test_get_argument(2))
            || !TEST_ptr(privkey2 = test_get_argument(3)))
        return 0;

    ADD_ALL_TESTS(test_tls13, Otls_NELEM(ciphers));
    return 1;
}
