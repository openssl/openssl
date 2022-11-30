/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "quictestlib.h"
#include "../testutil.h"

struct ossl_quic_fault {
    QUIC_TSERVER *qtserv;
};

int qtest_create_quic_objects(SSL_CTX *clientctx, char *certfile, char *keyfile,
                              QUIC_TSERVER **qtserv, SSL **cssl,
                              OSSL_QUIC_FAULT **fault)
{
    /* ALPN value as recognised by QUIC_TSERVER */
    unsigned char alpn[] = { 8, 'o', 's', 's', 'l', 't', 'e', 's', 't' };
    QUIC_TSERVER_ARGS tserver_args = {0};
    BIO *bio1 = NULL, *bio2 = NULL;
    BIO_ADDR *peeraddr = NULL;
    struct in_addr ina = {0};

    *qtserv = NULL;
    if (fault != NULL)
        *fault = NULL;
    *cssl = SSL_new(clientctx);
    if (!TEST_ptr(*cssl))
        return 0;

    if (!TEST_true(SSL_set_blocking_mode(*cssl, 0)))
        goto err;

    /* SSL_set_alpn_protos returns 0 for success! */
    if (!TEST_false(SSL_set_alpn_protos(*cssl, alpn, sizeof(alpn))))
        goto err;

    if (!TEST_true(BIO_new_bio_dgram_pair(&bio1, 0, &bio2, 0)))
        goto err;

    if (!TEST_true(BIO_dgram_set_caps(bio1, BIO_DGRAM_CAP_HANDLES_DST_ADDR))
            || !TEST_true(BIO_dgram_set_caps(bio2, BIO_DGRAM_CAP_HANDLES_DST_ADDR)))
        goto err;

    SSL_set_bio(*cssl, bio1, bio1);

    if (!TEST_ptr(peeraddr = BIO_ADDR_new()))
        goto err;

    /* Dummy server address */
    if (!TEST_true(BIO_ADDR_rawmake(peeraddr, AF_INET, &ina, sizeof(ina),
                                    htons(0))))
        goto err;

    if (!TEST_true(SSL_set_initial_peer_addr(*cssl, peeraddr)))
        goto err;

    /* 2 refs are passed for bio2 */
    if (!BIO_up_ref(bio2))
        goto err;
    tserver_args.net_rbio = bio2;
    tserver_args.net_wbio = bio2;

    if (!TEST_ptr(*qtserv = ossl_quic_tserver_new(&tserver_args, certfile,
                                                  keyfile))) {
        /* We hold 2 refs to bio2 at the moment */
        BIO_free(bio2);
        goto err;
    }
    /* Ownership of bio2 is now held by *qtserv */
    bio2 = NULL;

    if (fault != NULL) {
        *fault = OPENSSL_zalloc(sizeof(**fault));
        if (*fault == NULL)
            goto err;

        (*fault)->qtserv = *qtserv;
    }

    BIO_ADDR_free(peeraddr);

    return 1;
 err:
    BIO_ADDR_free(peeraddr);
    BIO_free(bio1);
    BIO_free(bio2);
    SSL_free(*cssl);
    ossl_quic_tserver_free(*qtserv);
    if (fault != NULL)
        OPENSSL_free(*fault);

    return 0;
}

#define MAXLOOPS    1000

int qtest_create_quic_connection(QUIC_TSERVER *qtserv, SSL *clientssl)
{
    int retc = -1, rets = 0, err, abortctr = 0, ret = 0;
    int clienterr = 0, servererr = 0;

    do {
        err = SSL_ERROR_WANT_WRITE;
        while (!clienterr && retc <= 0 && err == SSL_ERROR_WANT_WRITE) {
            retc = SSL_connect(clientssl);
            if (retc <= 0)
                err = SSL_get_error(clientssl, retc);
        }

        if (!clienterr && retc <= 0 && err != SSL_ERROR_WANT_READ) {
            TEST_info("SSL_connect() failed %d, %d", retc, err);
            TEST_openssl_errors();
            clienterr = 1;
        }

        /*
         * We're cheating. We don't take any notice of SSL_get_tick_timeout()
         * and tick everytime around the loop anyway. This is inefficient. We
         * can get away with it in test code because we control both ends of
         * the communications and don't expect network delays. This shouldn't
         * be done in a real application.
         */
        if (!clienterr)
            SSL_tick(clientssl);
        if (!servererr) {
            ossl_quic_tserver_tick(qtserv);
            servererr = ossl_quic_tserver_is_term_any(qtserv);
            if (!servererr && !rets)
                rets = ossl_quic_tserver_is_connected(qtserv);
        }

        if (clienterr && servererr)
            goto err;

        if (++abortctr == MAXLOOPS) {
            TEST_info("No progress made");
            goto err;
        }
    } while (retc <=0 || rets <= 0);

    ret = 1;
 err:
    return ret;
}
