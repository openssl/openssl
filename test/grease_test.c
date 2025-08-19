/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/ssl.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

#undef OSSL_NO_USABLE_TLS1_3
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
/*
 * If we don't have ec or dh then there are no built-in groups that are usable
 * with TLSv1.3
 */
# define OSSL_NO_USABLE_TLS1_3
#endif

#define GREASE_SETUP_ALL 0
#define GREASE_SETUP_KS  1

static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;

static unsigned char SID_CTX[] = { 'g', 'r', 'e', 'a', 's', 'e'};

static int my_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}

static int setup_cert(SSL *ssl)
{
    if (!TEST_int_eq(SSL_use_PrivateKey_file(ssl, privkey, SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_use_certificate_file(ssl, cert, SSL_FILETYPE_PEM), 1)
            || !TEST_int_eq(SSL_check_private_key(ssl), 1))
        return 0;
    return 1;
}

static unsigned char extension_data[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
static int setup_grease(SSL_CTX *ctx, int gr_set)
{
    if (gr_set == GREASE_SETUP_ALL) {
        if (!TEST_true(SSL_CTX_add_grease_to_ciphers(ctx, 0x5A5A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_ciphers(ctx, 0x6A6A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_ciphers(ctx, 0x7A7A)))
            return 0;

        /* Duplicate */
        if (!TEST_false(SSL_CTX_add_grease_to_ciphers(ctx, 0x5A5A)))
            return 0;

        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_supported_versions,
                                                       0x5A5A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_signature_algorithms,
                                                       0x6A6A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_signature_algorithms,
                                                       0x7A7A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_supported_groups,
                                                       0x11118A8A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_compress_certificate,
                                                       0x9A9A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_psk_kex_modes, 0x9A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_client_cert_type, 0x8A)))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_server_cert_type, 0x7A)))
            return 0;
    }

    if (gr_set == GREASE_SETUP_ALL || gr_set == GREASE_SETUP_KS) {
        /* Fails due to strict key-share checking unless it matches a value in supported_groups */
        if (!TEST_true(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_key_share, 0x11118A8A)))
            return 0;
    }

    if (gr_set == GREASE_SETUP_ALL) {
        /* Duplicate */
        if (!TEST_false(SSL_CTX_add_grease_to_extension(ctx, TLSEXT_TYPE_supported_versions,
                                                        0x5A5A)))
            return 0;

        if (!TEST_true(SSL_CTX_add_grease_extension(ctx, 0x1111, extension_data,
                                                    sizeof(extension_data))))
            return 0;
        if (!TEST_true(SSL_CTX_add_grease_extension(ctx, 0x2222, extension_data,
                                                    sizeof(extension_data))))
            return 0;

        /* Duplicate */
        if (!TEST_false(SSL_CTX_add_grease_extension(ctx, 0x2222, extension_data,
                                                     sizeof(extension_data))))
            return 0;
    }

    return 1;
}

/*
 * Test dimensions:
 *   (2) TLSv1.2 vs TLSv1.3
 *
 * Tests:
 * idx = 0 - is the normal success case, certificate
 * idx = 1 - add client authentication
 * idx = 2 - add client authentication (PHA)
 * idx = 3 - simple resumption
 * idx = 4 - simple resumption, no ticket
 * idx = 5 - resumption with client authentication
 * idx = 6 - resumption with client authentication, no ticket
 *
 * 7 * 2 - 1 = 13 tests (-1 because idx=2 is skipped for TLSv1.2)
 */
static int test_grease_internal(int idx, int gr_set)
{
#define GREASE_TESTS 7
#define GREASE_DIMS 2
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    int testresult = 0, ret, expected = 1;
    int tls_version;
    SSL_SESSION *client_sess = NULL;
    int idx_prot;
    int client_auth = 0;
    int resumption = 0;

    if (!TEST_int_le(idx, GREASE_TESTS * GREASE_DIMS))
        return 0;

    idx_prot = idx / GREASE_TESTS;
    idx %= GREASE_TESTS;

    switch (idx_prot) {
    case 0:
#ifdef OSSL_NO_USABLE_TLS1_3
        testresult = TEST_skip("TLSv1.3 disabled");
        goto end;
#else
        tls_version = TLS1_3_VERSION;
        break;
#endif
    case 1:
#ifdef OPENSSL_NO_TLS1_2
        testresult = TEST_skip("TLSv1.2 disabled");
        goto end;
#else
        tls_version = TLS1_2_VERSION;
        break;
#endif
    default:
        goto end;
    }

    if (idx == 2 && tls_version != TLS1_3_VERSION) {
        testresult = TEST_skip("PHA requires TLSv1.3");
        goto end;
    }

    if (!TEST_true(create_ssl_ctx_pair(NULL,
                                       TLS_server_method(), TLS_client_method(),
                                       tls_version, tls_version,
                                       &sctx, &cctx, NULL, NULL)))
        goto end;

    /* No Ticket */
    if (idx == 4 || idx == 6) {
        SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
        SSL_CTX_set_options(cctx, SSL_OP_NO_TICKET);
    }
    if (!TEST_true(SSL_CTX_set_session_id_context(sctx, SID_CTX, sizeof(SID_CTX))))
        goto end;
    if (!TEST_true(SSL_CTX_set_session_id_context(cctx, SID_CTX, sizeof(SID_CTX))))
        goto end;

    /* Configure Grease */
    if (!TEST_true(setup_grease(sctx, gr_set)) || !TEST_true(setup_grease(cctx, gr_set)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    if (!TEST_true(setup_cert(serverssl)))
        goto end;

    /* Client Authentication */
    if (idx == 1 || idx == 2 || idx == 5 || idx == 6) {
        if (!TEST_true(setup_cert(clientssl)))
            goto end;

        /* PHA */
        if (idx == 2) {
            SSL_set_verify(serverssl,
                           SSL_VERIFY_PEER
                           | SSL_VERIFY_FAIL_IF_NO_PEER_CERT
                           | SSL_VERIFY_POST_HANDSHAKE,
                           my_verify_cb);
            SSL_set_post_handshake_auth(clientssl, 1);
        } else {
            SSL_set_verify(serverssl,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           my_verify_cb);
        }
        client_auth = 1;
    }

    /* Resumption */
    if (idx == 3 || idx == 4 || idx == 5 || idx == 6)
        resumption = 1;

    /* With strict key-share checking, the connection is expected to fail */
    if (gr_set == GREASE_SETUP_KS)
        expected = 0;

    ret = create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE);
    if (!TEST_int_eq(expected, ret))
        goto end;

    if (idx == 2) {
        /* Make PHA happen... */
        if (!TEST_true(SSL_verify_client_post_handshake(serverssl)))
            goto end;
        if (!TEST_true(SSL_do_handshake(serverssl)))
            goto end;
        if (!TEST_int_le(SSL_read(clientssl, NULL, 0), 0))
            goto end;
        if (!TEST_int_le(SSL_read(serverssl, NULL, 0), 0))
            goto end;
    }

    if (client_auth) {
        /* only if connection is expected to succeed */
        if (expected == 1 && !TEST_ptr(SSL_get0_peer_certificate(serverssl)))
            goto end;
    }

    if (resumption) {
        if (!TEST_ptr((client_sess = SSL_get1_session(clientssl))))
            goto end;

        SSL_shutdown(clientssl);
        SSL_shutdown(serverssl);
        SSL_free(clientssl);
        SSL_free(serverssl);
        serverssl = clientssl = NULL;

        if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                          NULL, NULL))
                || !TEST_true(SSL_set_session(clientssl, client_sess)))
            goto end;

        if (!TEST_true(setup_cert(serverssl)))
            goto end;

        /* Client Auth */
        if (idx == 5 || idx == 6) {
            if (!TEST_true(setup_cert(clientssl)))
                goto end;
            SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                           my_verify_cb);
        }

        ret = create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE);
        if (!TEST_int_eq(expected, ret))
            goto end;
        if (!TEST_true(SSL_session_reused(clientssl)))
            goto end;
    }

    testresult = 1;

 end:
    SSL_SESSION_free(client_sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    if (testresult == 0)
        TEST_info("idx_prot=%d, idx=%d", idx_prot, idx);
    return testresult;
}

/* Wrapper for generic tests */
static int test_grease(int idx)
{
    return test_grease_internal(idx, GREASE_SETUP_ALL);
}

/*
 * Wrapper for testing key-share grease; when supported_groups is also not set,
 * the connection should fail
 */
static int test_grease_key_share(void)
{
    return test_grease_internal(0, GREASE_SETUP_KS);
}

OPT_TEST_DECLARE_USAGE("certdir\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certsdir = test_get_argument(0)))
        return 0;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    ADD_ALL_TESTS(test_grease, GREASE_TESTS * GREASE_DIMS);
    ADD_TEST(test_grease_key_share);
    return 1;

 err:
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
}
