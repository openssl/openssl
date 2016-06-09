/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include "ssltestlib.h"

static char *cert = NULL;
static char *privkey = NULL;

static int test_tlsext_status_type(void)
{
    SSL_CTX *ctx = NULL;
    SSL *con = NULL;
    int testresult = 0;

    /* Test tlsext_status_type */
    ctx = SSL_CTX_new(TLS_method());

    if (SSL_CTX_get_tlsext_status_type(ctx) != -1) {
        printf("Unexpected initial value for "
               "SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    con = SSL_new(ctx);

    if (SSL_get_tlsext_status_type(con) != -1) {
        printf("Unexpected initial value for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    if (!SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_get_tlsext_status_type(con) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    SSL_free(con);
    con = NULL;

    if (!SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_CTX_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_CTX_get_tlsext_status_type(ctx) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    con = SSL_new(ctx);

    if (SSL_get_tlsext_status_type(con) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type() (test 2)\n");
        goto end;
    }

    testresult = 1;

 end:
    SSL_free(con);
    SSL_CTX_free(ctx);

    return testresult;
}

static int test_session(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl1 = NULL, *clientssl1 = NULL;
    SSL *serverssl2 = NULL, *clientssl2 = NULL;
    SSL_SESSION *sess1 = NULL, *sess2 = NULL;
    int testresult = 0;

    if (!create_ssl_ctx_pair(TLS_server_method(), TLS_client_method(), &sctx,
                             &cctx, cert, privkey)) {
        printf("Unable to create SSL_CTX pair\n");
        return 0;
    }

    /* Turn on client session cache */
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);

    if (!create_ssl_connection(sctx, cctx, &serverssl1, &clientssl1, NULL,
                               NULL)) {
        printf("Unable to create SSL connection\n");
        goto end;
    }

    sess1 = SSL_get1_session(clientssl1);
    if (sess1 == NULL) {
        printf("Unexpected NULL session\n");
        goto end;
    }

    if (SSL_CTX_add_session(cctx, sess1)) {
        /* Should have failed because it should already be in the cache */
        printf("Unexpected success adding session to cache\n");
        goto end;
    }

    if (!create_ssl_connection(sctx, cctx, &serverssl2, &clientssl2, NULL,
                               NULL)) {
        printf("Unable to create second SSL connection\n");
        goto end;
    }

    sess2 = SSL_get1_session(clientssl2);
    if (sess2 == NULL) {
        printf("Unexpected NULL session from clientssl2\n");
        goto end;
    }

    /*
     * This should clear sess2 from the cache because it is a "bad" session. See
     * SSL_set_session() documentation.
     */
    if (!SSL_set_session(clientssl2, sess1)) {
        printf("Unexpected failure setting session\n");
        goto end;
    }

    if (SSL_get_session(clientssl2) != sess1) {
        printf("Unexpected session found\n");
        goto end;
    }

    if (!SSL_CTX_add_session(cctx, sess2)) {
        /*
         * Should have succeeded because it should not already be in the cache
         */
        printf("Unexpected failure adding session to cache\n");
        goto end;
    }

    if (!SSL_CTX_remove_session(cctx, sess2)) {
        printf("Unexpected failure removing session from cache\n");
        goto end;
    }

    if (SSL_CTX_remove_session(cctx, sess2)) {
        printf("Unexpected success removing session from cache\n");
        goto end;
    }

    testresult = 1;
 end:
    SSL_free(serverssl1);
    SSL_free(clientssl1);
    SSL_free(serverssl2);
    SSL_free(clientssl2);
    SSL_SESSION_free(sess1);
    SSL_SESSION_free(sess2);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

#define RUNTEST(testname)   \
    do { \
        printf("Testing " #testname "..."); \
        if (test_##testname()) {\
            printf("ok\n"); \
        } else { \
            printf("not ok\n"); \
            goto end; \
        } \
    } while(0)

int main(int argc, char *argv[])
{
    BIO *err;
    int testresult = 0;

    if (argc != 3) {
        printf("Invalid argument count\n");
        goto end;
    }

    cert = argv[1];
    privkey = argv[2];

    err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    RUNTEST(tlsext_status_type);
    RUNTEST(session);

    testresult = 1;

 end:

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(err) <= 0)
        testresult = 0;
#endif
    BIO_free(err);

    if (testresult)
        printf("PASS\n");

    return testresult ? 0 : 1;
}
