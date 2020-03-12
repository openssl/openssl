/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/provider.h>

#include "ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

/* TODO(3.0): Re-enable this code. See comment in setup_tests() */
OSSL_PROVIDER *defctxlegacy = NULL;

static int test_different_libctx(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0;
    OPENSSL_CTX *libctx = OPENSSL_CTX_new();

    /* Verify that the default provider in the default libctx is not available */
    if (!TEST_false(OSSL_PROVIDER_available(NULL, "default")))
        goto end;

    cctx = SSL_CTX_new_with_libctx(libctx, NULL, TLS_client_method());
    if (!TEST_ptr(cctx))
        goto end;
    sctx = SSL_CTX_new_with_libctx(libctx, NULL, TLS_server_method());
    if (!TEST_ptr(sctx))
        goto end;

    /*
     * TODO(3.0): Make this work in TLSv1.3. Currently we can only do RSA key
     * exchange, because we don't have key gen/param gen for EC yet - which
     * implies TLSv1.2 only
     */
    if (!TEST_true(create_ssl_ctx_pair(NULL,
                                       NULL,
                                       TLS1_VERSION,
                                       TLS1_2_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto end;

    /* Ensure we use a FIPS compatible ciphersuite and sigalg */
    if (!TEST_true(SSL_CTX_set_cipher_list(cctx, "AES128-SHA256"))
            || !TEST_true(SSL_CTX_set1_sigalgs_list(cctx, "RSA+SHA256")))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    /* This time we expect success */
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    /*
     * Verify that the default provider in the default libctx is still not
     * available
     */
    if (!TEST_false(OSSL_PROVIDER_available(NULL, "default")))
        goto end;

    testresult = 1;

 end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    OPENSSL_CTX_free(libctx);

    return testresult;
}

int setup_tests(void)
{
    char *certsdir = NULL;
    /*
     * For tests in this file we want to ensure the default ctx does not have
     * the default provider loaded into the default ctx. So we load "legacy" to
     * prevent default from being auto-loaded. This tests that there is no
     * "leakage", i.e. when using SSL_CTX_new_with_libctx() we expect only the
     * specific libctx to be used - nothing should fall back to the default
     * libctx
     */
    defctxlegacy = OSSL_PROVIDER_load(NULL, "legacy");

    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        return 0;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL) {
        OPENSSL_free(cert);
        return 0;
    }

    ADD_TEST(test_different_libctx);

    return 1;
}

void cleanup_tests(void)
{
    /* TODO(3.0): Re-enable this code. See comment in setup_tests() */
    OSSL_PROVIDER_unload(defctxlegacy);
}
