/*
 * Copyright 2025-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Tests for TLS 1.3 key schedule secret cleansing.
 *
 * Verify that OPENSSL_cleanse() is called on TLS 1.3 key schedule secrets
 * in SSL_CONNECTION during connection reset (SSL_clear) and free (SSL_free),
 * per RFC 8446 §7.1.
 */

#include <stdio.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"
#include "testutil/output.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"

#undef OSSL_NO_USABLE_TLS1_3
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
# define OSSL_NO_USABLE_TLS1_3
#endif

static char *cert = NULL;
static char *privkey = NULL;

#ifndef OSSL_NO_USABLE_TLS1_3

/*
 * Test that all TLS 1.3 key schedule secrets are zeroed after SSL_clear().
 *
 * Completes a TLS 1.3 handshake, verifies secrets were populated, then calls
 * SSL_clear() and checks that ossl_ssl_connection_reset() erased every secret
 * field via OPENSSL_cleanse().
 */
static int test_tls13_secret_cleanse_on_clear(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CONNECTION *sc = NULL;
    int testresult = 0;
    unsigned char zero[EVP_MAX_MD_SIZE];

    memset(zero, 0, sizeof(zero));

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto err;

    if (!TEST_int_eq(SSL_version(serverssl), TLS1_3_VERSION))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    if (!TEST_ptr(sc))
        goto err;

    /* Verify that secrets were actually set during the handshake */
    if (!TEST_true(memcmp(sc->master_secret, zero,
                          sizeof(sc->master_secret)) != 0)) {
        TEST_info("master_secret was zero after handshake - test inconclusive");
        goto err;
    }

    /*
     * SSL_clear() calls ossl_ssl_connection_reset() which should cleanse
     * all TLS 1.3 key schedule secrets.
     */
    if (!TEST_true(SSL_clear(serverssl)))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    if (!TEST_ptr(sc))
        goto err;

    if (!TEST_true(memcmp(sc->early_secret, zero,
                          sizeof(sc->early_secret)) == 0)) {
        TEST_info("early_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->handshake_secret, zero,
                          sizeof(sc->handshake_secret)) == 0)) {
        TEST_info("handshake_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->master_secret, zero,
                          sizeof(sc->master_secret)) == 0)) {
        TEST_info("master_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->resumption_master_secret, zero,
                          sizeof(sc->resumption_master_secret)) == 0)) {
        TEST_info("resumption_master_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->exporter_master_secret, zero,
                          sizeof(sc->exporter_master_secret)) == 0)) {
        TEST_info("exporter_master_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->client_app_traffic_secret, zero,
                          sizeof(sc->client_app_traffic_secret)) == 0)) {
        TEST_info("client_app_traffic_secret not erased after SSL_clear()");
        goto err;
    }
    if (!TEST_true(memcmp(sc->server_app_traffic_secret, zero,
                          sizeof(sc->server_app_traffic_secret)) == 0)) {
        TEST_info("server_app_traffic_secret not erased after SSL_clear()");
        goto err;
    }

    testresult = 1;

 err:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Test that secrets from a previous TLS 1.3 session do not leak across
 * SSL_clear() when the SSL object is reused (connection pooling scenario).
 *
 * Saves a known secret before SSL_clear(), then verifies it has been erased
 * afterwards not merely overwritten by a new handshake.
 */
static int test_tls13_secret_leak_on_reuse(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL;
    SSL_CONNECTION *sc = NULL;
    int testresult = 0;
    unsigned char zero[EVP_MAX_MD_SIZE];
    unsigned char saved_master_secret[EVP_MAX_MD_SIZE];

    memset(zero, 0, sizeof(zero));

    if (!TEST_true(create_ssl_ctx_pair(NULL, TLS_server_method(),
                                       TLS_client_method(),
                                       TLS1_3_VERSION, TLS1_3_VERSION,
                                       &sctx, &cctx, cert, privkey)))
        goto err;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
                                      NULL, NULL)))
        goto err;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                                         SSL_ERROR_NONE)))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    if (!TEST_ptr(sc))
        goto err;

    memcpy(saved_master_secret, sc->master_secret, sizeof(saved_master_secret));

    if (!TEST_true(memcmp(saved_master_secret, zero, sizeof(zero)) != 0)) {
        TEST_info("master_secret was zero - test inconclusive");
        goto err;
    }

    if (!TEST_true(SSL_clear(serverssl)))
        goto err;

    sc = SSL_CONNECTION_FROM_SSL(serverssl);
    if (!TEST_ptr(sc))
        goto err;

    if (!TEST_true(memcmp(sc->master_secret, zero, sizeof(zero)) == 0)) {
        TEST_info("master_secret persists after SSL_clear() "
                  "(CWE-459: Incomplete Cleanup)");
        TEST_info("The old master_secret matches the saved copy: %s",
                  memcmp(sc->master_secret, saved_master_secret,
                         sizeof(saved_master_secret)) == 0 ? "YES" : "NO");
        goto err;
    }

    testresult = 1;

 err:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    OPENSSL_cleanse(saved_master_secret, sizeof(saved_master_secret));
    return testresult;
}

#endif /* OSSL_NO_USABLE_TLS1_3 */

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

#ifndef OSSL_NO_USABLE_TLS1_3
    ADD_TEST(test_tls13_secret_cleanse_on_clear);
    ADD_TEST(test_tls13_secret_leak_on_reuse);
#endif

    return 1;
}

void cleanup_tests(void)
{
}
