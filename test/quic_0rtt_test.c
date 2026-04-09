/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>
#include <openssl/quic.h>
#include <openssl/bio.h>
#include <openssl/lhash.h>
#include <openssl/rand.h>

#include "helpers/quictestlib.h"
#include "helpers/ssltestlib.h"

#if defined(OPENSSL_THREADS)
#include "internal/thread_arch.h"
#endif

#include "internal/numbers.h" /* UINT64_C */

#include "testutil.h"

static char *certfile, *keyfile;

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defctxnull = NULL;

#define MESSAGE "Hello There!"
#define MESSAGE_LEN (sizeof(MESSAGE) - 1)

static SSL *client_ssl;
static SSL *server_ssl;

static void handle_events(void)
{
    SSL_handle_events(client_ssl);
    SSL_handle_events(server_ssl);
}

static void set_server(SSL *s)
{
    server_ssl = s;
}
static void set_client(SSL *s)
{
    client_ssl = s;
}

static int send_msg(SSL *s, const char *msg, int to_write, const char *print_msg)
{
    int rv, done;

    if (to_write <= 0)
        return 0;

    done = 0;
    rv = 0;
    while (!done) {
        rv = SSL_write(s, msg, to_write);
        if (rv <= 0) {
            switch (SSL_get_error(s, rv)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
                rv = 0;
                break;
            default:
                TEST_info("%s write failed\n", print_msg);
                return 0;
            }
        } else {
            done = 1;
        }
        /*
         * Need to poke to handle_events() two times. Not doing so makes
         * shutdown operation in caller later to fail. It then makes session
         * resumption to fail, because instead of finishing shutdown we do
         * SSL_free(). The exact failure mechanism is yet to be understood,
         * making sure we call handle_events() two times here fixes/workarounds
         * the problem. It's a magic!
         */
        handle_events();
        handle_events();
    }

    return rv == to_write;
}

static int recv_msg(SSL *s, char *buf, int to_read, const char *print_msg)
{
    int read, rv, done;

    if (to_read <= 0)
        return 0;

    done = 0;
    read = 0;
    while (!done) {
        if (read < to_read) {
            to_read = to_read - read;
            rv = SSL_read(s, &buf[read], to_read);
            if (rv <= 0) {
                switch (SSL_get_error(s, rv)) {
                case SSL_ERROR_WANT_READ:
                case SSL_ERROR_WANT_WRITE:
                case SSL_ERROR_WANT_CONNECT:
                case SSL_ERROR_WANT_ACCEPT:
                    rv = 0;
                    break;
                default:
                    TEST_info("%s read failed at %d\n", print_msg, read);
                    return 0;
                }
                break;
            }
            read += rv;
        } else {
            done = 1;
        }
        handle_events();
    }

    return done;
}

static int create_connection(SSL *clientssl, SSL *serverssl_listener, SSL **serverssl)
{
    int done = 0;
    SSL *serverconn = NULL;

    while (!done) {
        done = SSL_connect(clientssl);
        if (done != 1) {
            switch (SSL_get_error(clientssl, done)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
                done = 0;
                break;
            default:
                TEST_info("SSL_connect() failure");
                return 0;
            }
        }
        done = SSL_handle_events(clientssl);
        if (done == 0) {
            break;
        }
        done = SSL_handle_events(serverssl_listener);
        if (done == 0) {
            break;
        }
        serverconn = SSL_accept_connection(serverssl_listener, 0);
        done = (serverconn != NULL);
    }

    if (done != 0)
        *serverssl = serverconn;

    return done;
}

static int destroy_connection(SSL *clientssl, SSL *serverssl)
{
    int done = 0;

    while (!done) {
        done = SSL_shutdown(clientssl);
        if (done != 1) {
            switch (SSL_get_error(clientssl, done)) {
            case SSL_ERROR_WANT_READ:
            case SSL_ERROR_WANT_WRITE:
            case SSL_ERROR_WANT_CONNECT:
            case SSL_ERROR_WANT_ACCEPT:
                done = 0;
                break;
            default:
                TEST_info("SSL_shutdown() failure");
                return 0;
            }
        }
        done = SSL_handle_events(clientssl);
        if (done == 0) {
            break;
        }
        done = SSL_handle_events(serverssl);
        if (done == 0) {
            break;
        }
    }

    return done;
}

/*
 * Test QUIC connection using regular QUIC client and server methods.
 * No quic t-server is needed. Runs non blocking variant using busy-loops.
 */
static int test_quic_conn(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL, *serverssl_listener = NULL;
    char recv_buf[80];
    int testresult = 0;

    if (!TEST_true(create_quic_ctx_pair(libctx, &cctx, &sctx, certfile, keyfile)))
        return 0;

    if (!TEST_true(create_quic_conn_objects(cctx, sctx, &clientssl, &serverssl_listener)))
        goto end;

    testresult = SSL_listen(serverssl_listener);
    if (testresult == 0) {
        TEST_info("%s SSL_listen() failed", __func__);
        goto end;
    }

    testresult = create_connection(clientssl, serverssl_listener, &serverssl);
    if (testresult == 0) {
        TEST_info("%s connect failed", __func__);
        goto end;
    }

    set_server(serverssl);
    set_client(clientssl);

    testresult = send_msg(clientssl, MESSAGE, MESSAGE_LEN,
        "test_quic_conn send_msg(clnt -> srv)");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(serverssl, recv_buf, MESSAGE_LEN,
        "test_quic_conn recv_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    testresult = send_msg(serverssl, MESSAGE, MESSAGE_LEN,
        "test_quic_conn send_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(clientssl, recv_buf, MESSAGE_LEN,
        "test_quic_conn recv_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    testresult = 1;
end:
    set_server(NULL);
    set_client(NULL);

    SSL_free(clientssl);
    SSL_free(serverssl);
    SSL_free(serverssl_listener);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

static int test_quic_resume(void)
{
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *clientssl = NULL, *serverssl = NULL, *serverssl_listener = NULL, *new_clientssl;
    SSL_SESSION *sess = NULL;
    BIO *bio = NULL;
    char recv_buf[80];
    int testresult = 0;

    if (!TEST_true(create_quic_ctx_pair(libctx, &cctx, &sctx, certfile, keyfile)))
        return 0;
    /*
     * note: no t-server for testing is used here.
     */
    if (!TEST_true(create_quic_conn_objects(cctx, sctx, &clientssl, &serverssl_listener)))
        goto end;

    testresult = SSL_listen(serverssl_listener);
    if (testresult == 0) {
        TEST_info("%s SSL_listen() failed", __func__);
        goto end;
    }

    testresult = create_connection(clientssl, serverssl_listener, &serverssl);
    if (testresult == 0) {
        TEST_info("%s connect failed", __func__);
        goto end;
    }

    set_server(serverssl);
    set_client(clientssl);

    testresult = send_msg(clientssl, MESSAGE, MESSAGE_LEN,
        "test_quic_resume send_msg(clnt -> srv)");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(serverssl, recv_buf, MESSAGE_LEN,
        "test_quic_resume recv_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    testresult = send_msg(serverssl, MESSAGE, MESSAGE_LEN,
        "test_quic_resume send_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(clientssl, recv_buf, MESSAGE_LEN,
        "test_quic_resume recv_msg(srv -> clnt)");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    sess = SSL_get1_session(clientssl);
    if (!TEST_ptr(sess)) {
        TEST_info("%s SSL_get1_session() fails", __func__);
        testresult = 0;
        goto end;
    }

    /*
     * Drop existing connection and create new client.
     * The new client is using the same client BIO.
     */
    set_server(NULL);
    set_client(NULL);
    /*
     * Need to call SSL_shutdown() in order to be able
     * to resume session. Paragraph here comes from
     * SSL_shutdown(3ossl)
     *
     *    This approach of a single SSL_shutdown() call without
     *    waiting is preferable to simply calling SSL_free(3)
     *    or SSL_clear(3) as calling SSL_shutdown() beforehand
     *    makes an SSL session eligible for subsequent reuse and
     *    notifies the peer of connection shutdown.
     *
     * NOTE: session from test_quic_conn() can not be resumed,
     * because the test uses SSL_free().
     */
    destroy_connection(clientssl, serverssl);
    SSL_free(serverssl);
    serverssl = NULL;
    bio = SSL_get_rbio(clientssl);
    if (bio != SSL_get_wbio(clientssl)) {
        TEST_info("%s bio != SSL_get_wbio(clientssl)", __func__);
        testresult = 0;
        goto end;
    }
    /*
     * NOTE: We can not free existing client yet, because
     * c_bio is not copied/duplicated. Old client can
     * be freed after create_quic_client() returns.
     * The create_quic_client() duplicates the bio
     * for new_clientssl.
     */
    new_clientssl = create_quic_client(cctx, bio);
    if (new_clientssl == NULL) {
        TEST_info("%s create_quic_client() failed", __func__);
        testresult = 0;
        goto end;
    }
    SSL_free(clientssl);
    clientssl = new_clientssl;

    testresult = SSL_set_session(clientssl, sess);
    if (testresult == 0) {
        TEST_info("%s SSL_set_session(clientssl) failed", __func__);
        goto end;
    }

    testresult = create_connection(clientssl, serverssl_listener, &serverssl);
    if (testresult == 0) {
        TEST_info("%s re-connect failed", __func__);
        goto end;
    }

    set_server(serverssl);
    set_client(clientssl);

    testresult = send_msg(clientssl, MESSAGE, MESSAGE_LEN,
        "test_quic_resume send_msg(clnt -> srv) [resumed]");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(serverssl, recv_buf, MESSAGE_LEN,
        "test_quic_resume recv_msg(srv -> clnt) [resumed]");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    testresult = send_msg(serverssl, MESSAGE, MESSAGE_LEN,
        "test_quic_resume send_msg(srv -> clnt) [resumed]");
    if (testresult == 0)
        goto end;

    memset(recv_buf, 0, sizeof(recv_buf));
    testresult = recv_msg(clientssl, recv_buf, MESSAGE_LEN,
        "test_quic_resume recv_msg(srv -> clnt) [resumed]");
    if (testresult == 0)
        goto end;
    if (!TEST_str_eq(recv_buf, MESSAGE))
        goto end;

    testresult = SSL_session_reused(clientssl);
    if (testresult == 0) {
        TEST_info("%s SSL_session_reused(): did not reuse", __func__);
        goto end;
    }

    testresult = 1;
end:
    set_server(NULL);
    set_client(NULL);
    SSL_SESSION_free(sess);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_free(serverssl_listener);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);

    return testresult;
}

int setup_tests(void)
{
#if defined(OPENSSL_NO_QUIC)
    return TEST_skip("QUIC is not supported by this build");
#else
    libctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(libctx))
        return 0;

    defctxnull = OSSL_PROVIDER_load(NULL, "null");

    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(certfile = test_get_argument(0))
        || !TEST_ptr(keyfile = test_get_argument(1)))
        return 0;

    ADD_TEST(test_quic_conn);
    ADD_TEST(test_quic_resume);

    return 1;
#endif
}

void cleanup_tests(void)
{
    OSSL_PROVIDER_unload(defctxnull);
    OSSL_LIB_CTX_free(libctx);
}
