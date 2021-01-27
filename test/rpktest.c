/*
 * Copyright 2016-2021 The OpenSSL Project Authors. All Rights Reserved.
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

static char *certsdir = NULL;
static char *rootcert = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static char *cert2 = NULL;
static char *privkey2 = NULL;
static char *cert448 = NULL;
static char *privkey448 = NULL;
static char *cert25519 = NULL;
static char *privkey25519 = NULL;

static unsigned char SID_CTX[] = { 'r', 'p', 'k' };

static int rpk_verify_cb(int ok, X509_STORE_CTX *ctx)
{
    return 1;
}
/*
 * Test dimensions:
 *   (2) SSL_OP_RPK_SERVER off/on for server
 *   (2) SSL_OP_RPK_CLIENT off/on for server
 *   (2) SSL_OP_RPK_SERVER off/on for client
 *   (2) SSL_OP_RPK_CLIENT off/on for client
 *   (4) RSA vs ECDSA vs Ed25519 vs Ed448 certificates
 *   (2) TLSv1.2 vs TLSv1.3
 *
 * Tests:
 * idx = 0 - is the normal success case, certificate, single peer key
 * idx = 1 - only a private key
 * idx = 2 - add client authentication
 * idx = 3 - add second peer key (rootcert.pem)
 * idx = 4 - add second peer key (different, RSA or ECDSA)
 * idx = 5 - reverse peer keys (rootcert.pem, different order)
 * idx = 6 - reverse peer keys (RSA or ECDSA, different order)
 * idx = 7 - expects failure due to mismatched key (RSA or ECDSA)
 * idx = 8 - expects failure due to no configured key on client
 * idx = 9 - add client authentication (PHA)
 * idx = 10 - add client authentication (privake key only)
 * idx = 11 - simple resumption
 * idx = 12 - simple resumption, no ticket
 * idx = 13 - resumption with client authentication
 * idx = 14 - resumption with client authentication, no ticket
 *
 * 14 * 2 * 4 * 2 * 2 * 2 * 2 = 1920 tests
 */
static int test_rpk(int idx)
{
# define RPK_TESTS 15
# define RPK_DIMS (2 * 4 * 2 * 2 * 2 * 2)
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    EVP_PKEY *pkey = NULL, *other_pkey = NULL, *root_pkey = NULL;
    X509 *x509 = NULL, *other_x509 = NULL, *root_x509 = NULL;
    int testresult = 0, ret, expected = 1;
    int tls_version;
    char *cert_file = NULL;
    char *privkey_file = NULL;
    char *other_cert_file = NULL;
    SSL_SESSION *client_sess = NULL;
    SSL_SESSION *server_sess = NULL;
    int idx_server_server_rpk, idx_server_client_rpk;
    int idx_client_server_rpk, idx_client_client_rpk;
    int idx_cert, idx_prot;
    int client_auth = 0;
    int resumption = 0;
    uint64_t server_op = 0, client_op = 0;

    if (!TEST_int_le(idx, RPK_TESTS * RPK_DIMS))
        return 0;

    idx_server_server_rpk = idx / (RPK_TESTS * 2 * 4 * 2 * 2 * 2);
    idx %= RPK_TESTS * 2 * 4 * 2 * 2 * 2;
    idx_server_client_rpk = idx / (RPK_TESTS * 2 * 4 * 2 * 2);
    idx %= RPK_TESTS * 2 * 4 * 2 * 2;
    idx_client_server_rpk = idx / (RPK_TESTS * 2 * 4 * 2);
    idx %= RPK_TESTS * 2 * 4 * 2;
    idx_client_client_rpk = idx / (RPK_TESTS * 2 * 4);
    idx %= RPK_TESTS * 2 * 4;
    idx_cert = idx / (RPK_TESTS * 2);
    idx %= RPK_TESTS * 2;
    idx_prot = idx / RPK_TESTS;
    idx %= RPK_TESTS;

    /* Load "root" cert/pubkey */
    root_x509 = load_cert_pem(rootcert, NULL);
    if (!TEST_ptr(root_x509))
        goto end;
    root_pkey = X509_get0_pubkey(root_x509);
    if (!TEST_ptr(root_pkey))
        goto end;

    if (idx_server_server_rpk)
        server_op |= SSL_OP_RPK_SERVER;
    if (idx_server_client_rpk)
        server_op |= SSL_OP_RPK_CLIENT;
    if (idx_client_server_rpk)
        client_op |= SSL_OP_RPK_SERVER;
    if (idx_client_client_rpk)
        client_op |= SSL_OP_RPK_CLIENT;

    switch (idx_cert) {
        case 0:
            /* use RSA */
            cert_file = cert;
            privkey_file = privkey;
            other_cert_file = cert2;
            break;
#ifndef OPENSSL_NO_ECDSA
        case 1:
            /* use ECDSA */
            cert_file = cert2;
            privkey_file = privkey2;
            other_cert_file = cert;
            break;
        case 2:
            /* use Ed448 */
            cert_file = cert448;
            privkey_file = privkey448;
            other_cert_file = cert;
            break;
        case 3:
            /* use Ed25519 */
            cert_file = cert25519;
            privkey_file = privkey25519;
            other_cert_file = cert;
            break;
#endif
        default:
            testresult = TEST_skip("EDCSA disabled");
            goto end;
    }
    /* Load primary cert */
    x509 = load_cert_pem(cert_file, NULL);
    if (!TEST_ptr(x509))
        goto end;
    pkey = X509_get0_pubkey(x509);
    /* load other cert */
    other_x509 = load_cert_pem(other_cert_file, NULL);
    if (!TEST_ptr(other_x509))
        goto end;
    other_pkey = X509_get0_pubkey(other_x509);
#ifdef OPENSSL_NO_ECDSA
    /* Can't get other_key if it's ECDSA */
    if (other_pkey == NULL && idx_cert == 0
            && (idx == 4 || idx == 6 || idx == 7)) {
        testresult = TEST_skip("EDCSA disabled");
        goto end;
    }
#endif

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

    if (!TEST_true(create_ssl_ctx_pair(NULL,
                                       TLS_server_method(), TLS_client_method(),
                                       tls_version, tls_version,
                                       &sctx, &cctx, NULL, NULL)))
        goto end;

    if (!TEST_true(SSL_CTX_set_options(sctx, server_op)))
        goto end;
    if (!TEST_true(SSL_CTX_set_options(cctx, client_op)))
        goto end;
    if (!TEST_true(SSL_CTX_set_session_id_context(sctx, SID_CTX, sizeof(SID_CTX))))
        goto end;
    if (!TEST_true(SSL_CTX_set_session_id_context(cctx, SID_CTX, sizeof(SID_CTX))))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto end;

    /* Set private key and certificate */
    if (!TEST_int_eq(SSL_use_PrivateKey_file(serverssl, privkey_file, SSL_FILETYPE_PEM), 1))
        goto end;
    /* Only a private key */
    if (idx == 1) {
        if (idx_server_server_rpk == 0 || idx_client_server_rpk == 0)
            expected = 0;
    } else {
        /* Add certificate */
        if (!TEST_int_eq(SSL_use_certificate_file(serverssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(serverssl), 1))
            goto end;
    }

    switch (idx) {
    default:
        if (!TEST_true(idx < RPK_TESTS))
            goto end;
        break;
    case 0:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        break;
    case 1:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        break;
    case 2:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, pkey)))
            goto end;
        /* Use the same key for client auth */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
            goto end;
        SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
        client_auth = 1;
        break;
    case 3:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, root_pkey)))
            goto end;
        break;
    case 4:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, other_pkey)))
            goto end;
        break;
    case 5:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, root_pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        break;
    case 6:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, other_pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        break;
    case 7:
        if (idx_server_server_rpk == 1 && idx_client_server_rpk == 1)
            expected = 0;
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, other_pkey)))
            goto end;
        break;
    case 8:
        if (idx_server_server_rpk == 1 && idx_client_server_rpk == 1)
            expected = 0;
        /* no peer keyes */
        break;
    case 9:
        if (tls_version != TLS1_3_VERSION) {
            testresult = TEST_skip("PHA requires TLSv1.3");
            goto end;
        }
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, pkey)))
            goto end;
        /* Use the same key for client auth */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
            goto end;
        SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_POST_HANDSHAKE, rpk_verify_cb);
        SSL_set_post_handshake_auth(clientssl, 1);
        client_auth = 1;
        break;
    case 10:
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, pkey)))
            goto end;
        /* Use the same key for client auth */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        /* Since there's no cert, this is expected to fail without RPK support */
        if ((server_op & client_op & SSL_OP_RPK_CLIENT) == 0)
            expected = 0;
        SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
        client_auth = 1;
        break;
    case 11:
        if ((server_op & client_op & SSL_OP_RPK_SERVER) == 0) {
            testresult = TEST_skip("Only testing resumption with server RPK");
            goto end;
        }
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        resumption = 1;
        break;
    case 12:
        if ((server_op & client_op & SSL_OP_RPK_SERVER) == 0) {
            testresult = TEST_skip("Only testing resumption with server RPK");
            goto end;
        }
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        SSL_set_options(serverssl, SSL_OP_NO_TICKET);
        SSL_set_options(clientssl, SSL_OP_NO_TICKET);
        resumption = 1;
        break;
    case 13:
        if ((server_op & client_op & SSL_OP_RPK_SERVER) == 0) {
            testresult = TEST_skip("Only testing resumption with server RPK");
            goto end;
        }
        if ((server_op & client_op & SSL_OP_RPK_CLIENT) == 0) {
            testresult = TEST_skip("Only testing client authentication resumption with client RPK");
            goto end;
        }
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, pkey)))
            goto end;
        /* Use the same key for client auth */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
            goto end;
        SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
        client_auth = 1;
        resumption = 1;
        break;
    case 14:
        if ((server_op & client_op & SSL_OP_RPK_SERVER) == 0) {
            testresult = TEST_skip("Only testing resumption with server RPK");
            goto end;
        }
        if ((server_op & client_op & SSL_OP_RPK_CLIENT) == 0) {
            testresult = TEST_skip("Only testing client authentication resumption with client RPK");
            goto end;
        }
        if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, pkey)))
            goto end;
        if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, pkey)))
            goto end;
        /* Use the same key for client auth */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
            goto end;
        SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
        SSL_set_options(serverssl, SSL_OP_NO_TICKET);
        SSL_set_options(clientssl, SSL_OP_NO_TICKET);
        client_auth = 1;
        resumption = 1;
        break;
    }

    ret = create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE);
    if (!TEST_int_eq(expected, ret))
        goto end;

    /* Make sure client gets RPK or certificate as configured */
    if (expected == 1) {
        if (server_op & client_op & SSL_OP_RPK_SERVER) {
            if (!TEST_ptr(SSL_get0_peer_rpk(clientssl)))
                goto end;
            if (!TEST_true(SSL_rpk_send_negotiated(serverssl)))
                goto end;
            if (!TEST_true(SSL_rpk_receive_negotiated(clientssl)))
                goto end;
        } else {
            if (!TEST_ptr(SSL_get0_peer_certificate(clientssl)))
                goto end;
            if (!TEST_false(SSL_rpk_send_negotiated(serverssl)))
                goto end;
            if (!TEST_false(SSL_rpk_receive_negotiated(clientssl)))
                goto end;
        }
    }

    if (idx == 9) {
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

    /* Make sure server gets an RPK or certificate as configured */
    if (client_auth) {
        if (server_op & client_op & SSL_OP_RPK_CLIENT) {
            if (!TEST_ptr(SSL_get0_peer_rpk(serverssl)))
                goto end;
            if (!TEST_true(SSL_rpk_send_negotiated(clientssl)))
                goto end;
            if (!TEST_true(SSL_rpk_receive_negotiated(serverssl)))
                goto end;
        } else {
            /* only if connection is expected to succeed */
            if (expected == 1 && !TEST_ptr(SSL_get0_peer_certificate(serverssl)))
                goto end;
            if (!TEST_false(SSL_rpk_send_negotiated(clientssl)))
                goto end;
            if (!TEST_false(SSL_rpk_receive_negotiated(serverssl)))
                goto end;
        }
    }

    if (resumption) {
        EVP_PKEY *client_pkey = NULL;
        EVP_PKEY *server_pkey = NULL;

        if (!TEST_ptr((client_sess = SSL_get1_session(clientssl)))
                || !TEST_ptr((client_pkey = SSL_SESSION_get0_peer_rpk(client_sess))))
            goto end;
        if (client_auth) {
            if (!TEST_ptr((server_sess = SSL_get1_session(serverssl)))
                || !TEST_ptr((server_pkey = SSL_SESSION_get0_peer_rpk(server_sess))))
            goto end;
        }
        SSL_shutdown(clientssl);
        SSL_shutdown(serverssl);
        SSL_free(clientssl);
        SSL_free(serverssl);
        serverssl = clientssl = NULL;

        if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                          NULL, NULL))
                || !TEST_true(SSL_set_session(clientssl, client_sess)))
            goto end;

        /* Set private key (and maybe certificate */
        if (!TEST_int_eq(SSL_use_PrivateKey_file(serverssl, privkey_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_use_certificate_file(serverssl, cert_file, SSL_FILETYPE_PEM), 1))
            goto end;
        if (!TEST_int_eq(SSL_check_private_key(serverssl), 1))
            goto end;

        switch (idx) {
        default:
            break;
        case 11:
            if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, client_pkey)))
                goto end;
            break;
        case 12:
            if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, client_pkey)))
                goto end;
            SSL_set_options(clientssl, SSL_OP_NO_TICKET);
            SSL_set_options(serverssl, SSL_OP_NO_TICKET);
            break;
        case 13:
            if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, client_pkey)))
                goto end;
            if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, server_pkey)))
                goto end;
            /* Use the same key for client auth */
            if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
                goto end;
            if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
                goto end;
            if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
                goto end;
            SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
            break;
        case 14:
            if (!TEST_true(SSL_add1_expected_peer_rpk(clientssl, client_pkey)))
                goto end;
            if (!TEST_true(SSL_add1_expected_peer_rpk(serverssl, server_pkey)))
                goto end;
            /* Use the same key for client auth */
            if (!TEST_int_eq(SSL_use_PrivateKey_file(clientssl, privkey_file, SSL_FILETYPE_PEM), 1))
                goto end;
            if (!TEST_int_eq(SSL_use_certificate_file(clientssl, cert_file, SSL_FILETYPE_PEM), 1))
                goto end;
            if (!TEST_int_eq(SSL_check_private_key(clientssl), 1))
                goto end;
            SSL_set_verify(serverssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, rpk_verify_cb);
            SSL_set_options(serverssl, SSL_OP_NO_TICKET);
            SSL_set_options(clientssl, SSL_OP_NO_TICKET);
            break;
        }

        ret = create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE);
        if (!TEST_int_eq(expected, ret))
            goto end;
        if (!TEST_true(SSL_session_reused(clientssl)))
            goto end;

        if (!TEST_ptr(SSL_get0_peer_rpk(clientssl)))
            goto end;
        if (!TEST_true(SSL_rpk_send_negotiated(serverssl)))
            goto end;
        if (!TEST_true(SSL_rpk_receive_negotiated(clientssl)))
            goto end;

        if (client_auth) {
            if (!TEST_ptr(SSL_get0_peer_rpk(serverssl)))
                goto end;
            if (!TEST_true(SSL_rpk_receive_negotiated(serverssl)))
                goto end;
            if (!TEST_true(SSL_rpk_send_negotiated(clientssl)))
                goto end;
        }
    }

    testresult = 1;

 end:
    SSL_SESSION_free(client_sess);
    SSL_SESSION_free(server_sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    X509_free(x509);
    X509_free(other_x509);
    X509_free(root_x509);

    if (testresult == 0) {
        TEST_info("idx_ss_rpk=%d, idx_sc_rpk=%d, idx_cs_rpk=%d, idx_cc_rpk=%d, idx_cert=%d, idx_prot=%d, idx=%d",
                  idx_server_server_rpk, idx_server_client_rpk,
                  idx_client_server_rpk, idx_client_client_rpk,
                  idx_cert, idx_prot, idx);
    }
    return testresult;
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

    rootcert = test_mk_file_path(certsdir, "rootcert.pem");
    if (rootcert == NULL)
        goto err;

    cert = test_mk_file_path(certsdir, "servercert.pem");
    if (cert == NULL)
        goto err;

    privkey = test_mk_file_path(certsdir, "serverkey.pem");
    if (privkey == NULL)
        goto err;

    cert2 = test_mk_file_path(certsdir, "server-ecdsa-cert.pem");
    if (cert2 == NULL)
        goto err;

    privkey2 = test_mk_file_path(certsdir, "server-ecdsa-key.pem");
    if (privkey2 == NULL)
        goto err;

    cert448 = test_mk_file_path(certsdir, "server-ed448-cert.pem");
    if (cert2 == NULL)
        goto err;

    privkey448 = test_mk_file_path(certsdir, "server-ed448-key.pem");
    if (privkey2 == NULL)
        goto err;

    cert25519 = test_mk_file_path(certsdir, "server-ed25519-cert.pem");
    if (cert2 == NULL)
        goto err;

    privkey25519 = test_mk_file_path(certsdir, "server-ed25519-key.pem");
    if (privkey2 == NULL)
        goto err;

    ADD_ALL_TESTS(test_rpk, RPK_TESTS * RPK_DIMS);
    return 1;

 err:
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(rootcert);
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OPENSSL_free(cert2);
    OPENSSL_free(privkey2);
    OPENSSL_free(cert448);
    OPENSSL_free(privkey448);
    OPENSSL_free(cert25519);
    OPENSSL_free(privkey25519);
 }
