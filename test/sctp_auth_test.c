/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "testutil.h"

#include "opt.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/bio.h>
#include <openssl/rand.h>

#if !defined(OPENSSL_NO_SCTP) && !defined(OPENSSL_NO_SOCK)
# include <netinet/sctp.h>
#endif

static int test_sctp_auth_basic(void)
{
#ifdef OPENSSL_NO_SCTP
    TEST_skip("SCTP disabled in this build");
    return 1;
#else
    int ret = 0;            /* overall test result */
    int skipped = 0;        /* mark skip cases that are not failures */
    int sfd = -1, cfd = -1; /* server and client sockets */
    BIO *sb = NULL, *cb = NULL;
    struct sockaddr_in srv;
    socklen_t slen;
    unsigned char key[64];

    /* Create server one-to-many SCTP socket */
    sfd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (sfd < 0) {
        TEST_skip("no SCTP socket support on this system");
        skipped = 1;
        goto out;
    }

    /* Bind server to 127.0.0.1:ephemeral and listen for associations */
    memset(&srv, 0, sizeof(srv));
    srv.sin_family = AF_INET;
    srv.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    srv.sin_port = 0;
    {
        int on = 1;

        (void)setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
    }
    if (!TEST_int_ge(bind(sfd, (struct sockaddr *)&srv, sizeof(srv)), 0))
        goto out;
    if (!TEST_int_ge(listen(sfd, 1), 0))
        goto out;
    slen = sizeof(srv);
    if (!TEST_int_ge(getsockname(sfd, (struct sockaddr *)&srv, &slen), 0))
        goto out;

    /* Create client one-to-many SCTP socket */
    cfd = socket(AF_INET, SOCK_SEQPACKET, IPPROTO_SCTP);
    if (cfd < 0) {
        TEST_skip("no SCTP socket support for client");
        skipped = 1;
        goto out;
    }

    /*
     * Subscribe to association change notifications so we can learn
     * the association id on a one-to-many socket after connect.
     * Prefer RFC6458 SCTP_EVENT when available, otherwise use SCTP_EVENTS.
     */
# ifdef SCTP_EVENT
    {
        struct sctp_event ev;

        memset(&ev, 0, sizeof(ev));
        ev.se_type = SCTP_ASSOC_CHANGE;
        ev.se_on = 1;
        ev.se_assoc_id = 0;
        (void)setsockopt(cfd, IPPROTO_SCTP, SCTP_EVENT, &ev, sizeof(ev));
    }
# else
    {
        struct sctp_event_subscribe es;

        memset(&es, 0, sizeof(es));
        es.sctp_association_event = 1;
        (void)setsockopt(cfd, IPPROTO_SCTP, SCTP_EVENTS, &es, sizeof(es));
    }
# endif

    /*
     * Wrap both ends with BIO_s_datagram_sctp before connect, so that
     * BIO_new_dgram_sctp can enable SCTP AUTH chunks on the sockets.
     * If SCTP AUTH is not available, this returns NULL and we skip.
     */
    sb = BIO_new_dgram_sctp(sfd, BIO_NOCLOSE);
    cb = BIO_new_dgram_sctp(cfd, BIO_NOCLOSE);
    if (sb == NULL || cb == NULL) {
        TEST_skip("SCTP AUTH not available or not enabled in kernel");
        skipped = 1;
        goto out;
    }

    /* Establish an association to the server */
    if (!TEST_int_ge(connect(cfd, (struct sockaddr *)&srv, sizeof(srv)), 0))
        goto out;

    /*
     * Find the association id. Use SCTP_STATUS to query the only live assoc.
     */
    {
        struct sctp_status st;
        socklen_t stlen = (socklen_t)sizeof(st);

        memset(&st, 0, sizeof(st));

        /*
         * Read one SCTP notification and extract the assoc id from the
         * SCTP_ASSOC_CHANGE event that is delivered after connect.
         * Use a short receive timeout to avoid hanging if notifications
         * are not supported.
         */
        {
            union sctp_notification sn;
            struct timeval tv;
            ssize_t nread;

            memset(&sn, 0, sizeof(sn));
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            nread = recv(cfd, &sn, sizeof(sn), 0);
            if (nread < (ssize_t)sizeof(struct sctp_assoc_change)
                || sn.sn_header.sn_type != SCTP_ASSOC_CHANGE) {
                TEST_skip("no SCTP_ASSOC_CHANGE notification received");
                skipped = 1;
                goto out;
            }
            st.sstat_assoc_id = sn.sn_assoc_change.sac_assoc_id;
        }

        if (!TEST_true(st.sstat_assoc_id != 0))
            goto out;
        if (!TEST_int_ge(getsockopt(cfd, IPPROTO_SCTP, SCTP_STATUS, &st, &stlen), 0))
            goto out;

#ifdef SCTP_SNDINFO
        {
            struct sctp_sndinfo si;

            memset(&si, 0, sizeof(si));
            si.snd_assoc_id = st.sstat_assoc_id;
            if (BIO_ctrl(cb, BIO_CTRL_DGRAM_SCTP_SET_SNDINFO, (long)sizeof(si), &si) <= 0)
                goto out;
        }
#endif

        /* Query current active key number for this assoc */
        struct sctp_authkeyid ak;
        socklen_t aklen = (socklen_t)sizeof(ak);
        uint16_t before_keyno;

        memset(&ak, 0, sizeof(ak));
        ak.scact_assoc_id = st.sstat_assoc_id;
        if (!TEST_int_ge(getsockopt(cfd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY, &ak, &aklen), 0)) {
            TEST_skip("SCTP AUTH not supported by kernel for this socket");
            skipped = 1;
            goto out;
        }
        before_keyno = ak.scact_keynumber;

        /* Generate a 64 byte key to add as next auth key */
        if (!TEST_true(RAND_bytes(key, sizeof(key))))
            goto out;

        /* Exercise the fixed control paths */
        long lret;

        lret = BIO_ctrl(cb, BIO_CTRL_DGRAM_SCTP_ADD_AUTH_KEY,
                        (long)sizeof(key), key);
        if (!TEST_true(lret >= 0))
            goto out;

        errno = 0;
        lret = BIO_ctrl(cb, BIO_CTRL_DGRAM_SCTP_NEXT_AUTH_KEY, 0L, NULL);
        if (lret < 0) {
            if (errno == EINVAL) {
                TEST_skip("SCTP NEXT_AUTH_KEY not supported on this kernel");
                skipped = 1;
                goto out;
            }
            goto out;
        }

        /*
         * Tell the BIO that ChangeCipherSpec was received, which
         * triggers deactivation of the old key or deletion of the
         * second last key, depending on platform support.
         * Return value can be 0 (from setsockopt success) or 1
         * if no action was required. Only -1 indicates failure.
         */
        lret = BIO_ctrl(cb, BIO_CTRL_DGRAM_SCTP_AUTH_CCS_RCVD, 0, NULL);
        if (lret < 0) {
            if (errno == EINVAL) {
                TEST_skip("SCTP AUTH_CCS_RCVD not supported on this kernel");
                skipped = 1;
            }
            goto out;
        }

        memset(&ak, 0, sizeof(ak));
        ak.scact_assoc_id = st.sstat_assoc_id;
        aklen = (socklen_t)sizeof(ak);
        if (!TEST_int_ge(getsockopt(cfd, IPPROTO_SCTP, SCTP_AUTH_ACTIVE_KEY,
                                    &ak, &aklen), 0)) {
            if (errno == EINVAL || errno == ENOTSUP || errno == EOPNOTSUPP) {
                TEST_skip("SCTP AUTH_ACTIVE_KEY query not supported");
                skipped = 1;
            }
            goto out;
        }
        if (!TEST_true((int)ak.scact_keynumber != (int)before_keyno))
            goto out;
    }

    ret = 1;

 out: {
        /* Capture errno right at the failure point before cleanup can change it */
        int out_errno = errno;

        if (cb != NULL)
            BIO_free(cb);
        if (sb != NULL)
            BIO_free(sb);
        if (cfd >= 0)
            close(cfd);
        if (sfd >= 0)
            close(sfd);

        /* If we are failing and not skipping, print the saved errno */
        if (!ret && !skipped && out_errno != 0)
            TEST_note("failure errno=%d (%s)", out_errno, strerror(out_errno));

        if (skipped)
            return 1; /* skipped tests still count as pass for harness */
        return ret;
    }
#endif /* OPENSSL_NO_SCTP */
}

int setup_tests(void)
{
    ADD_TEST(test_sctp_auth_basic);
    return 1;
}
