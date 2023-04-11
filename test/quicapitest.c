/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/quic.h>

#include "helpers/ssltestlib.h"
#include "helpers/quictestlib.h"
#include "testutil.h"
#include "testutil/output.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defctxnull = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;

static int is_fips = 0;

/*
 * Test that we read what we've written.
 * Test 0: Non-blocking
 * Test 1: Blocking
 */
static int test_quic_write_read(int idx)
{
    SSL_CTX *cctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    SSL *clientquic = NULL;
    QUIC_TSERVER *qtserv = NULL;
    int j, ret = 0;
    unsigned char buf[20];
    static char *msg = "A test message";
    size_t msglen = strlen(msg);
    size_t numbytes = 0;
    int ssock = 0, csock = 0;

    if (idx == 1 && !qtest_supports_blocking())
        return TEST_skip("Blocking tests not supported in this build");

    if (!TEST_ptr(cctx)
            || !TEST_true(qtest_create_quic_objects(libctx, cctx, cert, privkey,
                                                    idx, &qtserv, &clientquic,
                                                    NULL))
            || !TEST_true(SSL_set_tlsext_host_name(clientquic, "localhost"))
            || !TEST_true(qtest_create_quic_connection(qtserv, clientquic)))
        goto end;

    if (idx == 1) {
        if (!TEST_true(BIO_get_fd(ossl_quic_tserver_get0_rbio(qtserv), &ssock)))
            goto end;
        if (!TEST_int_gt(csock = SSL_get_rfd(clientquic), 0))
            goto end;
    }

    for (j = 0; j < 2; j++) {
        /* Check that sending and receiving app data is ok */
        if (!TEST_true(SSL_write_ex(clientquic, msg, msglen, &numbytes)))
            goto end;
        if (idx == 1) {
            do {
                if (!TEST_true(wait_until_sock_readable(ssock)))
                    goto end;

                ossl_quic_tserver_tick(qtserv);

                if (!TEST_true(ossl_quic_tserver_read(qtserv, buf, sizeof(buf),
                                                      &numbytes)))
                    goto end;
            } while (numbytes == 0);

            if (!TEST_mem_eq(buf, numbytes, msg, msglen))
                goto end;
        }

        if (!TEST_true(ossl_quic_tserver_write(qtserv, (unsigned char *)msg,
                                               msglen, &numbytes)))
            goto end;
        ossl_quic_tserver_tick(qtserv);
        SSL_tick(clientquic);
        /*
         * In blocking mode the SSL_read_ex call will block until the socket is
         * readable and has our data. In non-blocking mode we're doing everything
         * in memory, so it should be immediately available
         */
        if (!TEST_true(SSL_read_ex(clientquic, buf, 1, &numbytes))
                || !TEST_size_t_eq(numbytes, 1)
                || !TEST_true(SSL_has_pending(clientquic))
                || !TEST_int_eq(SSL_pending(clientquic), msglen - 1)
                || !TEST_true(SSL_read_ex(clientquic, buf + 1, sizeof(buf) - 1, &numbytes))
                || !TEST_mem_eq(buf, numbytes + 1, msg, msglen))
            goto end;
    }

    if (!TEST_true(qtest_shutdown(qtserv, clientquic)))
        goto end;

    ret = 1;

 end:
    ossl_quic_tserver_free(qtserv);
    SSL_free(clientquic);
    SSL_CTX_free(cctx);

    return ret;
}

/* Test that a vanilla QUIC SSL object has the expected ciphersuites available */
static int test_ciphersuites(void)
{
    SSL_CTX *ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    SSL *ssl;
    int testresult = 0;
    const STACK_OF(SSL_CIPHER) *ciphers = NULL;
    const SSL_CIPHER *cipher;
    /* We expect this exact list of ciphersuites by default */
    int cipherids[] = {
        TLS1_3_CK_AES_256_GCM_SHA384,
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
        TLS1_3_CK_CHACHA20_POLY1305_SHA256,
#endif
        TLS1_3_CK_AES_128_GCM_SHA256
    };
    size_t i, j;

    if (!TEST_ptr(ctx))
        return 0;

    ssl = SSL_new(ctx);
    if (!TEST_ptr(ssl))
        goto err;

    ciphers = SSL_get_ciphers(ssl);

    for (i = 0, j = 0; i < OSSL_NELEM(cipherids); i++) {
        if (cipherids[i] == TLS1_3_CK_CHACHA20_POLY1305_SHA256 && is_fips)
            continue;
        cipher = sk_SSL_CIPHER_value(ciphers, j++);
        if (!TEST_ptr(cipher))
            goto err;
        if (!TEST_uint_eq(SSL_CIPHER_get_id(cipher), cipherids[i]))
            goto err;
    }

    /* We should have checked all the ciphers in the stack */
    if (!TEST_int_eq(sk_SSL_CIPHER_num(ciphers), j))
        goto err;

    testresult = 1;
 err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);

    return testresult;
}

/*
 * Test that SSL_version, SSL_get_version, SSL_is_quic, SSL_is_tls and
 * SSL_is_dtls return the expected results for a QUIC connection. Compare with
 * test_version() in sslapitest.c which does the same thing for TLS/DTLS
 * connections.
 */
static int test_version(void)
{
    SSL_CTX *cctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    SSL *clientquic = NULL;
    QUIC_TSERVER *qtserv = NULL;
    int testresult = 0;

    if (!TEST_ptr(cctx)
            || !TEST_true(qtest_create_quic_objects(libctx, cctx, cert, privkey,
                                                    0, &qtserv, &clientquic,
                                                    NULL))
            || !TEST_true(qtest_create_quic_connection(qtserv, clientquic)))
        goto err;

    if (!TEST_int_eq(SSL_version(clientquic), OSSL_QUIC1_VERSION)
            || !TEST_str_eq(SSL_get_version(clientquic), "QUICv1"))
        goto err;

    if (!TEST_true(SSL_is_quic(clientquic))
            || !TEST_false(SSL_is_tls(clientquic))
            || !TEST_false(SSL_is_dtls(clientquic)))
        goto err;


    testresult = 1;
 err:
    ossl_quic_tserver_free(qtserv);
    SSL_free(clientquic);
    SSL_CTX_free(cctx);

    return testresult;
}

OPT_TEST_DECLARE_USAGE("provider config\n")

int setup_tests(void)
{
    char *modulename;
    char *configfile;

    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    defctxnull = OSSL_PROVIDER_load(NULL, "null");

    /*
     * Verify that the default and fips providers in the default libctx are not
     * available
     */
    if (!TEST_false(OSSL_PROVIDER_available(NULL, "default"))
            || !TEST_false(OSSL_PROVIDER_available(NULL, "fips")))
        goto err;

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        goto err;
    }

    if (!TEST_ptr(modulename = test_get_argument(0))
            || !TEST_ptr(configfile = test_get_argument(1))
            || !TEST_ptr(certsdir = test_get_argument(2)))
        goto err;

    if (!TEST_true(OSSL_LIB_CTX_load_config(libctx, configfile)))
        goto err;

    /* Check we have the expected provider available */
    if (!TEST_true(OSSL_PROVIDER_available(libctx, modulename)))
        goto err;

    /* Check the default provider is not available */
    if (strcmp(modulename, "default") != 0
            && !TEST_false(OSSL_PROVIDER_available(libctx, "default")))
        goto err;

    if (strcmp(modulename, "fips") == 0)
        is_fips = 1;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    ADD_ALL_TESTS(test_quic_write_read, 2);
    ADD_TEST(test_ciphersuites);
    ADD_TEST(test_version);

    return 1;
 err:
    cleanup_tests();
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OSSL_PROVIDER_unload(defctxnull);
    OSSL_LIB_CTX_free(libctx);
}
