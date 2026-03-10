/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#if !defined(OPENSSL_SYS_WINDOWS) && !defined(OPENSSL_NO_SOCK) && !defined(__DJGPP__)

#include "internal/sockets.h"
#include <openssl/bio.h>
#include <internal/bio.h>
#include <openssl/err.h>

#include "testutil.h"

#include <signal.h>
#include <errno.h>

static volatile sig_atomic_t sigpipe_seen = 0;

static void sigpipe_handler(int sig)
{
    (void)sig;
    sigpipe_seen++;
}

/*
 * 0 - normal flow
 * 1 - kTLS
 * 2 - TFO
 */
static int test_bio_write_triggers_sigpipe(int test)
{
#if defined(MSG_NOSIGNAL)
    int fds[2] = { -1, -1 };
    BIO *b = NULL;
    const char c = 'x';
    int ret;
    int ok = 0;
    struct sigaction sa, oldsa;

    /* Install SIGPIPE handler */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigpipe_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    if (!TEST_int_eq(sigaction(SIGPIPE, &sa, &oldsa), 0))
        goto end;

    /* Create a pair of connected sockets. */
    if (!TEST_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0))
        goto end;

    /* Close peer end to make writes hit a broken pipe. */
    if (!TEST_int_eq(closesocket(fds[1]), 0))
        goto end;
    fds[1] = -1;

    b = BIO_new_socket(fds[0], BIO_NOCLOSE);
    if (!TEST_ptr(b))
        goto end;
    /*
     * Attempt write. We don't care about return value beyond
     * "it attempted", the point is SIGPIPE delivery.
     */
    ERR_clear_error();
    errno = 0;
    sigpipe_seen = 0;

    if (test == 1) {
#ifndef OPENSSL_NO_KTLS
        BIO_set_ktls_ctrl_msg_flag(b);
#else
        TEST_skip("OPENSSL_NO_KTLS is defined\n");
        ok = 1;
        goto end;
#endif
    }

    if (test == 2) {
#ifdef OSSL_TFO_SENDTO
        struct in_addr a4;
        BIO_ADDR *peer = BIO_ADDR_new();
        if (!TEST_ptr(peer))
            goto end;
        inet_pton(AF_INET, "127.0.0.1", &a4);
        BIO_ADDR_rawmake(peer, AF_INET, &a4, sizeof(a4), 443);
        ret = BIO_ctrl(b, BIO_C_SET_CONNECT, 2, peer);
        BIO_ADDR_free(peer);
        if (!TEST_int_eq(ret, 1))
            goto end;
#else
        TEST_skip("OSSL_TFO_SENDTO is not defined\n");
        ok = 1;
        goto end;
#endif
    }

    if (!TEST_int_eq(BIO_set_send_flags(b, MSG_NOSIGNAL), 1))
        goto end;
    ret = BIO_write(b, &c, 1);
    (void)ret;

    /* PASS only if SIGPIPE wasn't delivered. */
    if (!TEST_int_eq((int)sigpipe_seen, 0))
        goto end;

    ok = 1;

end:
    BIO_free(b);

    if (fds[0] >= 0) {
        closesocket(fds[0]);
        fds[0] = -1;
    }
    if (fds[1] >= 0) {
        closesocket(fds[1]);
        fds[1] = -1;
    }

    /* Restore previous handler. */
    (void)sigaction(SIGPIPE, &oldsa, NULL);

    return ok;
#else
    /* No MSG_NOSIGNAL on this platform -> skip. */
    TEST_skip("MSG_NOSIGNAL is not defined on this platform");
    return 1;
#endif
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_bio_write_triggers_sigpipe, 3);
    return 1;
}
#endif
