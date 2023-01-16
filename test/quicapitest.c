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
#include "../ssl/ssl_local.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defctxnull = NULL;
static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *datadir = NULL;

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
    uint64_t sid = UINT64_MAX;

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

    sid = 0; /* client-initiated bidirectional stream */

    for (j = 0; j < 2; j++) {
        /* Check that sending and receiving app data is ok */
        if (!TEST_true(SSL_write_ex(clientquic, msg, msglen, &numbytes))
            || !TEST_size_t_eq(numbytes, msglen))
            goto end;
        if (idx == 1) {
            do {
                if (!TEST_true(wait_until_sock_readable(ssock)))
                    goto end;

                ossl_quic_tserver_tick(qtserv);

                if (!TEST_true(ossl_quic_tserver_read(qtserv, sid, buf, sizeof(buf),
                                                      &numbytes)))
                    goto end;
            } while (numbytes == 0);

            if (!TEST_mem_eq(buf, numbytes, msg, msglen))
                goto end;
        }

        ossl_quic_tserver_tick(qtserv);
        if (!TEST_true(ossl_quic_tserver_write(qtserv, sid, (unsigned char *)msg,
                                               msglen, &numbytes)))
            goto end;
        ossl_quic_tserver_tick(qtserv);
        SSL_handle_events(clientquic);
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

#if !defined(OPENSSL_NO_SSL_TRACE) && !defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_ZLIB)
static void strip_line_ends(char *str)
{
    size_t i;

    for (i = strlen(str);
         i > 0 && (str[i - 1] == '\n' || str[i - 1] == '\r');
         i--);

    str[i] = '\0';
}

static int compare_with_file(BIO *membio)
{
    BIO *file = NULL;
    char buf1[512], buf2[512];
    char *reffile;
    int ret = 0;
    size_t i;

    reffile = test_mk_file_path(datadir, "ssltraceref.txt");
    if (!TEST_ptr(reffile))
        goto err;

    file = BIO_new_file(reffile, "rb");
    if (!TEST_ptr(file))
        goto err;

    while (BIO_gets(file, buf1, sizeof(buf1)) > 0) {
        if (BIO_gets(membio, buf2, sizeof(buf2)) <= 0) {
            TEST_error("Failed reading mem data");
            goto err;
        }
        strip_line_ends(buf1);
        strip_line_ends(buf2);
        if (strlen(buf1) != strlen(buf2)) {
            TEST_error("Actual and ref line data length mismatch");
            TEST_info("%s", buf1);
            TEST_info("%s", buf2);
           goto err;
        }
        for (i = 0; i < strlen(buf1); i++) {
            /* '?' is a wild card character in the reference text */
            if (buf1[i] == '?')
                buf2[i] = '?';
        }
        if (!TEST_str_eq(buf1, buf2))
            goto err;
    }
    if (!TEST_true(BIO_eof(file))
            || !TEST_true(BIO_eof(membio)))
        goto err;

    ret = 1;
 err:
    OPENSSL_free(reffile);
    BIO_free(file);
    return ret;
}

/*
 * Tests that the SSL_trace() msg_callback works as expected with a QUIC
 * connection. This also provides testing of the msg_callback at the same time.
 */
static int test_ssl_trace(void)
{
    SSL_CTX *cctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method());
    SSL *clientquic = NULL;
    QUIC_TSERVER *qtserv = NULL;
    int testresult = 0;
    BIO *bio = BIO_new(BIO_s_mem());

    /*
     * Ensure we only configure ciphersuites that are available with both the
     * default and fips providers to get the same output in both cases
     */
    if (!TEST_true(SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256")))
        goto err;

    if (!TEST_ptr(cctx)
            || !TEST_ptr(bio)
            || !TEST_true(qtest_create_quic_objects(libctx, cctx, cert, privkey,
                                                    0, &qtserv, &clientquic,
                                                    NULL)))
        goto err;

    SSL_set_msg_callback(clientquic, SSL_trace);
    SSL_set_msg_callback_arg(clientquic, bio);

    if (!TEST_true(qtest_create_quic_connection(qtserv, clientquic)))
        goto err;

    if (!TEST_true(compare_with_file(bio)))
        goto err;

    testresult = 1;
 err:
    ossl_quic_tserver_free(qtserv);
    SSL_free(clientquic);
    SSL_CTX_free(cctx);
    BIO_free(bio);

    return testresult;
}
#endif

static int ensure_valid_ciphers(const STACK_OF(SSL_CIPHER) *ciphers)
{
    size_t i;

    /* Ensure ciphersuite list is suitably subsetted. */
    for (i = 0; i < (size_t)sk_SSL_CIPHER_num(ciphers); ++i) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        switch (SSL_CIPHER_get_id(cipher)) {
            case TLS1_3_CK_AES_128_GCM_SHA256:
            case TLS1_3_CK_AES_256_GCM_SHA384:
            case TLS1_3_CK_CHACHA20_POLY1305_SHA256:
                break;
            default:
                TEST_error("forbidden cipher: %s", SSL_CIPHER_get_name(cipher));
                return 0;
        }
    }

    return 1;
}

/*
 * Test that handshake-layer APIs which shouldn't work don't work with QUIC.
 */
static int test_quic_forbidden_apis_ctx(void)
{
    int testresult = 0;
    SSL_CTX *ctx = NULL;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method())))
        goto err;

    /* This function returns 0 on success and 1 on error, and should fail. */
    if (!TEST_true(SSL_CTX_set_tlsext_use_srtp(ctx, "SRTP_AEAD_AES_128_GCM")))
        goto err;

    /*
     * List of ciphersuites we do and don't allow in QUIC.
     */
#define QUIC_CIPHERSUITES \
    "TLS_AES_128_GCM_SHA256:"           \
    "TLS_AES_256_GCM_SHA384:"           \
    "TLS_CHACHA20_POLY1305_SHA256"

#define NON_QUIC_CIPHERSUITES           \
    "TLS_AES_128_CCM_SHA256:"           \
    "TLS_AES_256_CCM_SHA384:"           \
    "TLS_AES_128_CCM_8_SHA256"

    /* Set TLSv1.3 ciphersuite list for the SSL_CTX. */
    if (!TEST_true(SSL_CTX_set_ciphersuites(ctx,
                                            QUIC_CIPHERSUITES ":"
                                            NON_QUIC_CIPHERSUITES)))
        goto err;

    /*
     * Forbidden ciphersuites should show up in SSL_CTX accessors, they are only
     * filtered in SSL_get1_supported_ciphers, so we don't check for
     * non-inclusion here.
     */

    testresult = 1;
err:
    SSL_CTX_free(ctx);
    return testresult;
}

static int test_quic_forbidden_apis(void)
{
    int testresult = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *ciphers = NULL;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    /* This function returns 0 on success and 1 on error, and should fail. */
    if (!TEST_true(SSL_set_tlsext_use_srtp(ssl, "SRTP_AEAD_AES_128_GCM")))
        goto err;

    /* Set TLSv1.3 ciphersuite list for the SSL_CTX. */
    if (!TEST_true(SSL_set_ciphersuites(ssl,
                                        QUIC_CIPHERSUITES ":"
                                        NON_QUIC_CIPHERSUITES)))
        goto err;

    /* Non-QUIC ciphersuites must not appear in supported ciphers list. */
    if (!TEST_ptr(ciphers = SSL_get1_supported_ciphers(ssl))
        || !TEST_true(ensure_valid_ciphers(ciphers)))
        goto err;

    testresult = 1;
err:
    sk_SSL_CIPHER_free(ciphers);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return testresult;
}

static int test_quic_forbidden_options(void)
{
    int testresult = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    char buf[16];
    size_t len;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method())))
        goto err;

    /* QUIC options restrictions do not affect SSL_CTX */
    SSL_CTX_set_options(ctx, UINT64_MAX);

    if (!TEST_uint64_t_eq(SSL_CTX_get_options(ctx), UINT64_MAX))
        goto err;

    /* Set options on CTX which should not be inherited (tested below). */
    SSL_CTX_set_read_ahead(ctx, 1);
    SSL_CTX_set_max_early_data(ctx, 1);
    SSL_CTX_set_recv_max_early_data(ctx, 1);

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    /* Only permitted options get transferred to SSL object */
    if (!TEST_uint64_t_eq(SSL_get_options(ssl), OSSL_QUIC_PERMITTED_OPTIONS))
        goto err;

    /* Try again using SSL_set_options */
    SSL_set_options(ssl, UINT64_MAX);

    if (!TEST_uint64_t_eq(SSL_get_options(ssl), OSSL_QUIC_PERMITTED_OPTIONS))
        goto err;

    /* Clear everything */
    SSL_clear_options(ssl, UINT64_MAX);

    if (!TEST_uint64_t_eq(SSL_get_options(ssl), 0))
        goto err;

    /* Readahead */
    if (!TEST_false(SSL_get_read_ahead(ssl)))
        goto err;

    SSL_set_read_ahead(ssl, 1);
    if (!TEST_false(SSL_get_read_ahead(ssl)))
        goto err;

    /* Block padding */
    if (!TEST_true(SSL_set_block_padding(ssl, 0))
        || !TEST_true(SSL_set_block_padding(ssl, 1))
        || !TEST_false(SSL_set_block_padding(ssl, 2)))
        goto err;

    /* Max fragment length */
    if (!TEST_true(SSL_set_tlsext_max_fragment_length(ssl, TLSEXT_max_fragment_length_DISABLED))
        || !TEST_false(SSL_set_tlsext_max_fragment_length(ssl, TLSEXT_max_fragment_length_512)))
        goto err;

    /* Max early data */
    if (!TEST_false(SSL_get_recv_max_early_data(ssl))
        || !TEST_false(SSL_get_max_early_data(ssl))
        || !TEST_false(SSL_set_recv_max_early_data(ssl, 1))
        || !TEST_false(SSL_set_max_early_data(ssl, 1)))
        goto err;

    /* Read/Write */
    if (!TEST_false(SSL_read_early_data(ssl, buf, sizeof(buf), &len))
        || !TEST_false(SSL_write_early_data(ssl, buf, sizeof(buf), &len)))
        goto err;

    /* Buffer Management */
    if (!TEST_true(SSL_alloc_buffers(ssl))
        || !TEST_false(SSL_free_buffers(ssl)))
        goto err;

    /* Pipelining */
    if (!TEST_false(SSL_set_max_send_fragment(ssl, 2))
        || !TEST_false(SSL_set_split_send_fragment(ssl, 2))
        || !TEST_false(SSL_set_max_pipelines(ssl, 2)))
        goto err;

    /* Protocol Version */
    if (!TEST_false(SSL_set_max_proto_version(ssl, TLS1_2_VERSION))
        || !TEST_true(SSL_set_max_proto_version(ssl, TLS1_3_VERSION)))
        goto err;

    /* HRR */
    if  (!TEST_false(SSL_stateless(ssl)))
        goto err;

    testresult = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return testresult;
}

static int test_quic_set_fd(int idx)
{
    int testresult = 0;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int fd = -1, resfd = -1;
    BIO *bio = NULL;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, OSSL_QUIC_client_method())))
        goto err;

    if (!TEST_ptr(ssl = SSL_new(ctx)))
        goto err;

    if (!TEST_int_ge(fd = BIO_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, 0), 0))
        goto err;

    if (idx == 0) {
        if (!TEST_true(SSL_set_fd(ssl, fd)))
            goto err;
        if (!TEST_ptr(bio = SSL_get_rbio(ssl)))
            goto err;
        if (!TEST_ptr_eq(bio, SSL_get_wbio(ssl)))
            goto err;
    } else if (idx == 1) {
        if (!TEST_true(SSL_set_rfd(ssl, fd)))
            goto err;
        if (!TEST_ptr(bio = SSL_get_rbio(ssl)))
            goto err;
        if (!TEST_ptr_null(SSL_get_wbio(ssl)))
            goto err;
    } else {
        if (!TEST_true(SSL_set_wfd(ssl, fd)))
            goto err;
        if (!TEST_ptr(bio = SSL_get_wbio(ssl)))
            goto err;
        if (!TEST_ptr_null(SSL_get_rbio(ssl)))
            goto err;
    }

    if (!TEST_int_eq(BIO_method_type(bio), BIO_TYPE_DGRAM))
        goto err;

    if (!TEST_true(BIO_get_fd(bio, &resfd))
        || !TEST_int_eq(resfd, fd))
        goto err;

    testresult = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    if (fd >= 0)
        BIO_closesocket(fd);
    return testresult;
}

OPT_TEST_DECLARE_USAGE("provider config certsdir datadir\n")

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
            || !TEST_ptr(certsdir = test_get_argument(2))
            || !TEST_ptr(datadir = test_get_argument(3)))
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
#if !defined(OPENSSL_NO_SSL_TRACE) && !defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_ZLIB)
    ADD_TEST(test_ssl_trace);
#endif
    ADD_TEST(test_quic_forbidden_apis_ctx);
    ADD_TEST(test_quic_forbidden_apis);
    ADD_TEST(test_quic_forbidden_options);
    ADD_ALL_TESTS(test_quic_set_fd, 3);
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
