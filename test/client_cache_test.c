/*
 * Copyright 2023-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/ssl.h>

#include "helpers/ssltestlib.h"
#include "internal/dane.h"
#include "testutil.h"

static char *certsdir = NULL;
static char *cert = NULL;
static char *privkey = NULL;
static OSSL_LIB_CTX *libctx = NULL;

static const unsigned char sid_ctx[] = "sid";
static const unsigned char cache_id[] = "this is a test";
static const unsigned char cache_id2[] = "different";

static SSL_SESSION *external_cache = NULL;
static SSL_SESSION *session_get_cb(SSL *ssl, const unsigned char *data, int len, int *copy)
{
    unsigned char *cid;
    size_t cid_len;

    if (!SSL_SESSION_get1_cache_id(external_cache, &cid, &cid_len))
        return NULL;

    if (len != (int)cid_len || memcmp(cid, data, len) != 0) {
        OPENSSL_free(cid);
        return NULL;
    }

    OPENSSL_free(cid);
    *copy = 1;
    return external_cache;
}

static int test_client_cache_external(void)
{
    int ret = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *cssl = NULL, *sssl = NULL;
    uint32_t mode;
    SSL_SESSION *sess1 = NULL;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    mode = SSL_SESS_CACHE_CLIENT | SSL_SESS_CACHE_NO_INTERNAL_LOOKUP;
    if (!TEST_true(SSL_CTX_set_session_cache_mode(cctx, mode))
        || !TEST_true(SSL_CTX_set_session_id_context(sctx, sid_ctx, sizeof(sid_ctx)))
        || !TEST_true(SSL_CTX_set_session_id_context(cctx, sid_ctx, sizeof(sid_ctx))))
        goto end;

    SSL_CTX_sess_set_get_cb(cctx, session_get_cb);

    /* Initial connection - establishes external_cache */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id, sizeof(cache_id)))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_ptr(external_cache = SSL_get1_session(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Test automatic assignment of session when client has cache_id set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id, sizeof(cache_id)))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(cssl))
        || !TEST_ptr(sess1 = SSL_get1_session(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is resumed when no cache_id is set, but session is assigned */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set_session(cssl, sess1))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is not resumed when no cache_id is set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_false(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is not resumed when a different cache_id is set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id2, sizeof(cache_id2)))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_false(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    ret = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_SESSION_free(external_cache);
    external_cache = NULL;
    SSL_SESSION_free(sess1);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
}

static int test_client_cache(void)
{
    int ret = 0;
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *cssl = NULL, *sssl = NULL;
    SSL_SESSION *sess1 = NULL, *sess2 = NULL, *sess3 = NULL;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT))
        || !TEST_true(SSL_CTX_set_session_id_context(sctx, sid_ctx, sizeof(sid_ctx)))
        || !TEST_true(SSL_CTX_set_session_id_context(cctx, sid_ctx, sizeof(sid_ctx))))
        goto end;

    /* Initial connection */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id, sizeof(cache_id)))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_ptr(sess1 = SSL_get1_session(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Test automatic assignment of session when client has cache_id set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id, sizeof(cache_id)))
        || !TEST_ptr(sess2 = SSL_get1_previous_client_session(cssl))
        || !TEST_ptr_eq(sess1, sess2)
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(cssl))
        || !TEST_ptr(sess3 = SSL_get1_session(cssl))
        || !TEST_ptr_eq(sess2, sess3))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is resumed when no cache_id is set, but session is assigned */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set_session(cssl, sess3))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is not resumed when no cache_id is set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_false(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    /* Ensure client is not resumed when a different cache_id is set */
    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL))
        || !TEST_true(SSL_set1_cache_id(cssl, cache_id2, sizeof(cache_id2)))
        || !TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE))
        || !TEST_false(SSL_session_reused(cssl)))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    ret = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_SESSION_free(sess1);
    SSL_SESSION_free(sess2);
    SSL_SESSION_free(sess3);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return ret;
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

    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        goto err;

    ADD_TEST(test_client_cache);
    ADD_TEST(test_client_cache_external);
    return 1;

err:
    return 0;
}

void cleanup_tests(void)
{
    OPENSSL_free(cert);
    OPENSSL_free(privkey);
    OSSL_LIB_CTX_free(libctx);
}
