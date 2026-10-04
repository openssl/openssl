/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl/record/methods/recmethod_local.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

static char *cert = NULL;
static char *privkey = NULL;

static const char *cipher_names[] = {
    "aes-128-ecb",
    "aes-256-ecb",
#if !defined(OPENSSL_NO_CHACHA)
    "chacha20",
#endif
};

static int test_dtls_crypt_sequence_number(int idx)
{
    /*
     * Test all possiblie Encryption Algorithms for dtls_crypt_sequence_number function
     * aes-128-ecb, "aes-256-ecb" and "chacha20"
     */
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char initial_seq[2] = { 0, 0 };
    unsigned char zero_seq[2] = { 0, 0 };
    unsigned char rec_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    cipher = EVP_CIPHER_fetch(NULL, cipher_names[idx], NULL);
    if (!TEST_ptr(cipher))
        goto err;

    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is no longer zero */
    if (!TEST_mem_ne(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is back to zero */
    if (!TEST_mem_eq(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return 1;
err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (cipher != NULL)
        EVP_CIPHER_free(cipher);
    return 0;
}

/* rfc9147 section 4.2.2 sequence number reconstruction vectors. */
typedef struct seq_num_test_st {
    /* Zero also represents the initial empty replay window. */
    uint64_t max_seq_num;
    uint64_t truncated;
    size_t seqlen;
    uint64_t seq_num;
} SEQ_NUM_TEST;

static const SEQ_NUM_TEST seq_num_tests[] = {
    /* Empty window and first-period lower-bound cases. */
    { 0, 0, 1, 0 },
    { 0, 1, 1, 1 },
    { 0, 0x7f, 1, 0x7f },
    { 0, 0x80, 1, 0x80 },
    { 0, 0x81, 1, 0x81 },
    { 0, 0xff, 1, 0xff },
    { 0, 0, 2, 0 },
    { 0, 1, 2, 1 },
    { 0, 0x7fff, 2, 0x7fff },
    { 0, 0x8000, 2, 0x8000 },
    { 0, 0x8001, 2, 0x8001 },
    { 0, 0x8002, 2, 0x8002 },
    { 0, 40000, 2, 40000 },
    { 0, 0xffff, 2, 0xffff },

    /* Ordinary forward progression */
    { 5, 6, 2, 6 },
    { 5, 6, 1, 6 },
    { 200, 201, 2, 201 },
    { 0x1234, 0x1235, 2, 0x1235 },

    /* 8- and 16-bit wraps */
    { 0xfe, 0xff, 1, 0xff },
    { 0xff, 0x00, 1, 0x100 },
    { 0x100, 0x01, 1, 0x101 },
    { 0x1fe, 0xff, 1, 0x1ff },
    { 0x1ff, 0x00, 1, 0x200 },
    { 0xfffe, 0xffff, 2, 0xffff },
    { 0xffff, 0x0000, 2, 0x10000 },
    { 0x10000, 0x0001, 2, 0x10001 },
    { 0x1fffe, 0xffff, 2, 0x1ffff },
    { 0x1ffff, 0x0000, 2, 0x20000 },
    { 0x20000, 0x0001, 2, 0x20001 },

    /* Reordered records */
    { 0x100, 0xff, 2, 0xff },
    { 0x100, 0xfe, 2, 0xfe },
    { 0x10010, 0x000f, 2, 0x1000f },
    { 300, 40, 1, 296 },

    /* Half-period ties select the forward candidate in either phase. */
    { 199, 72, 1, 328 }, /* candidate 72, 128 behind: pick 328 */
    { 299, 172, 1, 428 }, /* candidate 428, 128 ahead: keep it */
    { 0x180ff, 0x0100, 2, 0x20100 }, /* candidate 0x10100: pick 0x20100 */
    { 0x100ff, 0x8100, 2, 0x18100 }, /* candidate 0x18100: keep it */

    /* Top-of-uint64_t fallback and overflow boundaries */
    { UINT64_MAX, 0, 2, UINT64_MAX & ~UINT64_C(0xffff) },
    { UINT64_MAX, 0xffff, 2, UINT64_MAX },
    { UINT64_MAX, 0xffc0, 2, (UINT64_MAX & ~UINT64_C(0xffff)) | 0xffc0 },
    { UINT64_MAX, 5, 1, (UINT64_MAX & ~UINT64_C(0xff)) | 5 },
    { UINT64_MAX - 1, 0, 2, UINT64_MAX & ~UINT64_C(0xffff) },
    { UINT64_MAX - 0x10000, 0, 2, UINT64_MAX - 0xffff },
    { UINT64_MAX - 0x10000, 1, 2, UINT64_MAX - 0xffff + 1 },
    { UINT64_MAX - 0x10000, 0x8000, 2,
        (UINT64_MAX - 0xffff) | 0x8000 },
};

static int test_seq_num_reconstruction(int idx)
{
    const SEQ_NUM_TEST *t = &seq_num_tests[idx];
    uint64_t seq_num = 0;

    seq_num = dtls13_reconstruct_seq_num(t->max_seq_num, t->truncated,
        t->seqlen);

    if (!TEST_uint64_t_eq(seq_num, t->seq_num))
        return 0;

    /* The reconstructed value must retain the wire bits used in the AAD. */
    return TEST_uint64_t_eq(seq_num & DTLS13_UNI_HDR_SEQ_MASK(t->seqlen),
        t->truncated);
}

#ifndef OPENSSL_NO_DTLS1_3
/* Empty and single-entry ACK vectors, with and without trailing data. */
static int test_dtls13_ack_length(int idx)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    BIO *wbio;
    unsigned char ack[2 + 16 + 1] = { 0 };
    size_t len = idx < 2 ? 2 : 18;
    int trailing = idx % 2;
    PACKET pkt;
    int testresult = 0;

    ack[1] = (unsigned char)(len - 2);
    ack[len] = 0xff;

    if (!TEST_ptr(ctx = SSL_CTX_new(DTLS_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(PACKET_buf_init(&pkt, ack, len + trailing))
        || !TEST_ptr(wbio = BIO_new(BIO_s_mem())))
        goto end;

    SSL_set0_wbio(ssl, wbio);

    if (!TEST_int_eq(dtls_process_ack(sc, &pkt),
            trailing ? MSG_PROCESS_ERROR : MSG_PROCESS_FINISHED_READING))
        goto end;

    if (trailing
        && !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_R_LENGTH_TOO_LONG))
        goto end;

    testresult = 1;
end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return testresult;
}

/*
 * Test that dtls1_increment_epoch() enforces the RFC 9147 Section 8 limit
 * on the write (sending) epoch for DTLS 1.3: "sending implementations MUST
 * NOT allow the epoch to exceed 2^48-1". This is stricter than the 2^64-1
 * wrap-around ceiling in Section 6.1, and applies only to the write side
 * and only for DTLS 1.3 -- DTLS 1.2 keeps its existing UINT16_MAX limit.
 *
 * There's no way to actually drive 2^48 real KeyUpdates in a test, so this
 * drives one real DTLS 1.3 handshake to get a genuinely-typed connection
 * (SSL_CONNECTION_IS_DTLS13() depends on the negotiated method, not
 * anything that can be poked directly), then writes w_conn_epoch directly
 * to one below the limit before calling the real increment function at and
 * past the boundary.
 */
static int test_dtls13_increment_epoch_max(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *sc = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION))
        goto end;

    if (!TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(serverssl)))
        goto end;

    if (!TEST_true(SSL_CONNECTION_IS_DTLS13(sc)))
        goto end;

    /* One below the Section 8 limit: incrementing must still succeed. */
    sc->rlayer.d->w_conn_epoch = DTLS1_3_MAX_EPOCH - 1;
    if (!TEST_true(dtls1_increment_epoch(sc, SSL3_CC_WRITE)))
        goto end;
    if (!TEST_uint64_t_eq(sc->rlayer.d->w_conn_epoch, DTLS1_3_MAX_EPOCH))
        goto end;

    /* Already at the limit: incrementing further must be rejected. */
    if (!TEST_false(dtls1_increment_epoch(sc, SSL3_CC_WRITE)))
        goto end;
    if (!TEST_uint64_t_eq(sc->rlayer.d->w_conn_epoch, DTLS1_3_MAX_EPOCH))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/* Exercise ACK coverage for the client's final flight and the server's tickets. */
static int test_dtls13_ack_coverage(int server)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL, *sender, *peer;
    SSL_CONNECTION *sc, *psc;
    dtls_sent_msg *msg = NULL;
    DTLS1_RECORD_NUMBER *recnum;
    pitem *item;
    piterator iter;
    unsigned char ack[18], buf, discard[2048];
    WPACKET pkt;
    uint64_t epoch, seqnum;
    size_t acklen, written;
    OSSL_TIME timeout;
    int i, ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    /* An empty client Certificate and Finished give us two messages to ACK. */
    if (!server)
        SSL_CTX_set_verify(sctx, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_CTX_set_num_tickets(sctx, server ? 2 : 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    ret = SSL_connect(clientssl);
    if (!TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_accept(serverssl);
    if (!TEST_int_eq(SSL_get_error(serverssl, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_connect(clientssl);
    if (!TEST_int_eq(SSL_get_error(clientssl, ret), SSL_ERROR_WANT_READ))
        goto end;
    if (!TEST_int_eq(SSL_accept(serverssl), 1))
        goto end;
    /* SSL_write() must not finish the peer's handshake and ACK our test flight. */
    if (!server
        && (!TEST_int_gt(BIO_read(SSL_get_rbio(clientssl), discard, sizeof(discard)), 0)
            || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(clientssl)), 0)))
        goto end;

    sender = server ? serverssl : clientssl;
    peer = server ? clientssl : serverssl;
    sc = SSL_CONNECTION_FROM_SSL(sender);
    psc = SSL_CONNECTION_FROM_SSL(peer);
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /*
     * When the sender is the client, mTLS is turned on above, so the
     * peer (the server) sent its own CertificateRequest as part of the
     * initial handshake, not PHA. Once the client's response -- the
     * next flight -- arrives, that CertificateRequest and the rest of
     * the server's flight must be fully retired, not preserved by the
     * PHA-specific handling.
     */
    if (!server
        && (!TEST_size_t_eq(pqueue_size(&psc->d1->sent_messages), 0)
            || !TEST_true(ossl_time_is_zero(psc->d1->next_timeout))))
        goto end;

    /* ACK the last message first, keeping the earlier message outstanding. */
    iter = pqueue_iterator(&sc->d1->sent_messages);
    while ((item = pqueue_next(&iter)) != NULL)
        msg = item->data;
    if (!TEST_ptr(msg)
        || !TEST_ptr(recnum = ossl_list_record_number_head(&msg->rec_nums)))
        goto end;
    epoch = recnum->epoch;
    seqnum = recnum->seqnum;

    /* Avoid timer expiry while inspecting ACK processing. */
    timeout = sc->d1->next_timeout = ossl_time_add(ossl_time_now(), ossl_seconds2time(3600));

    for (i = 0; i < 5; i++) {
        int complete = i == 4;
        int appdata = server || complete;

        /* Empty, nonmatching, partial, duplicate, then the remaining record. */
        if (complete) {
            dtls_sent_msg *unacked = pqueue_peek(&sc->d1->sent_messages)->data;
            uint64_t oldseq;

            if (!TEST_ptr(recnum = ossl_list_record_number_head(&unacked->rec_nums)))
                goto end;
            oldseq = recnum->seqnum;
            sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
            if (!TEST_int_gt(DTLSv1_handle_timeout(sender), 0)
                || !TEST_true(ossl_list_record_number_is_empty(&msg->rec_nums))
                /*
                 * The retransmit no longer wipes rec_nums -- it accumulates
                 * -- so the new, higher-numbered record is now at the tail,
                 * not the head (the original entry is still there too).
                 */
                || !TEST_ptr(recnum = ossl_list_record_number_tail(&unacked->rec_nums))
                || !TEST_uint64_t_gt(recnum->seqnum, oldseq)
                /* Both the original and the retransmitted record number are present. */
                || !TEST_size_t_eq(ossl_list_record_number_num(&unacked->rec_nums), 2))
                goto end;
            sc->d1->next_timeout = timeout;
            /* Only the unacknowledged message should have been retransmitted. */
            msg = pqueue_peek(&sc->d1->sent_messages)->data;
            if (!TEST_ptr(recnum = ossl_list_record_number_head(&msg->rec_nums)))
                goto end;
            epoch = recnum->epoch;
            seqnum = recnum->seqnum;
        }
        if (!TEST_true(WPACKET_init_static_len(&pkt, ack, sizeof(ack), 2)))
            goto end;
        if ((i != 0
                && (!TEST_true(WPACKET_put_bytes_u64(&pkt, epoch))
                    || !TEST_true(WPACKET_put_bytes_u64(&pkt,
                        i == 1 ? seqnum + 1000 : seqnum))))
            || !TEST_true(WPACKET_finish(&pkt))
            || !TEST_true(WPACKET_get_total_written(&pkt, &acklen))) {
            WPACKET_cleanup(&pkt);
            goto end;
        }
        WPACKET_cleanup(&pkt);
        if (!TEST_int_eq(dtls1_write_bytes(psc, SSL3_RT_ACK,
                             ack, acklen, &written),
                1)
            || !TEST_size_t_eq(written, acklen)
            || !TEST_int_eq(SSL_write(peer, "x", 1), 1)
            || !TEST_int_gt(BIO_flush(psc->wbio), 0))
            goto end;

        /* Application data is buffered until the client's final ACK arrives. */
        ret = SSL_read(sender, &buf, sizeof(buf));
        if (!TEST_int_eq(SSL_get_error(sender, ret),
                appdata ? SSL_ERROR_NONE : SSL_ERROR_WANT_READ)
            || (appdata && !TEST_uchar_eq(buf, 'x'))
            || !TEST_int_eq(SSL_get_state(sender), appdata ? TLS_ST_OK : TLS_ST_CW_FINISHED)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), complete ? 0 : 2)
            || !TEST_int_eq(ossl_time_compare(sc->d1->next_timeout,
                                complete ? ossl_time_zero() : timeout),
                0)
            || (!appdata && !TEST_size_t_eq(pqueue_size(sc->rlayer.d->buffered_app_data), i + 1))
            || (!complete && !TEST_int_eq(ossl_list_record_number_is_empty(&msg->rec_nums), i >= 2)))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int ticket_count;

static int count_ticket(SSL *ssl, SSL_SESSION *session)
{
    ticket_count++;
    return 0;
}

/*
 * Replace lost ticket ACKs after another loss or WANT_WRITE, with whole or
 * fragmented retransmissions, and with or without an outstanding local flight.
 */
static int test_dtls13_ticket_ack_retransmit(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    BIO *retry = NULL;
    piterator iter;
    pitem *item;
    unsigned char buf[2048];
    unsigned int readseq, writeseq;
    OSSL_TIME client_timeout = ossl_time_zero();
    int i, ret, dropped, testresult = 0;
    int pending_key_update = idx / 4;
    int fragmented = (idx / 2) % 2;
    int retry_write = idx % 2;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    readseq = cc->d1->handshake_read_seq;
    writeseq = cc->d1->next_handshake_write_seq;
    if (!TEST_int_eq(ticket_count, 2)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2))
        goto end;

    if (pending_key_update) {
        if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
            goto end;
        ret = SSL_do_handshake(client);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
            goto end;
        client_timeout = cc->d1->next_timeout = ossl_time_add(ossl_time_now(), ossl_seconds2time(3600));
        writeseq = cc->d1->next_handshake_write_seq;
    }

    if (fragmented) {
        /* Refragment the tickets on retransmission, after processing them whole. */
        SSL_set_options(server, SSL_OP_NO_QUERY_MTU);
        if (!TEST_long_gt(SSL_set_mtu(server, 256), 0))
            goto end;
    }
    if (retry_write) {
        if (!TEST_ptr(retry = BIO_new(bio_s_maybe_retry()))
            || !TEST_true(BIO_up_ref(SSL_get_wbio(client))))
            goto end;
        SSL_set0_wbio(client, BIO_push(retry, SSL_get_wbio(client)));
        retry = NULL;
    }

    for (i = 0; i < 2; i++) {
        /*
         * Lose the initial ACKs, then also lose the first replacement ACKs.
         * In the pending-flight cases, discard the KeyUpdate too: the server
         * must not process it or send an ACK for the client's local flight.
         */
        dropped = 0;
        while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
            dropped++;
        if (!TEST_int_gt(dropped, 0))
            goto end;
        sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
        if (!TEST_int_gt(DTLSv1_handle_timeout(server), 0))
            goto end;
        iter = pqueue_iterator(&sc->d1->sent_messages);
        while ((item = pqueue_next(&iter)) != NULL) {
            dtls_sent_msg *msg = item->data;
            size_t records = ossl_list_record_number_num(&msg->rec_nums);

            /*
             * No ACK ever actually lands in this test (every one gets
             * dropped), so record numbers accumulate across every round
             * instead of being reset by each retransmit: 1 from the
             * original send plus one more per retransmit so far.
             */
            if (fragmented ? !TEST_size_t_gt(records, 1)
                           : !TEST_size_t_eq(records, (size_t)(i + 2)))
                goto end;
        }

        if (retry_write) {
            if (!TEST_long_eq(BIO_ctrl(SSL_get_wbio(client),
                                  MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 0, NULL),
                    1))
                goto end;
            ret = SSL_read(client, buf, 1);
            if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_WRITE))
                goto end;
            ret = SSL_read(client, buf, 1);
            if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_WRITE)
                || !TEST_long_eq(BIO_ctrl(SSL_get_wbio(client),
                                     MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 100, NULL),
                    1))
                goto end;
        }
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_int_eq(SSL_get_state(client), pending_key_update ? TLS_ST_CW_KEY_UPDATE : TLS_ST_OK)
            || !TEST_int_eq(ticket_count, 2)
            || !TEST_uint_eq(cc->d1->handshake_read_seq, readseq)
            || !TEST_uint_eq(cc->d1->next_handshake_write_seq, writeseq)
            || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
            || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout))
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), pending_key_update ? 1 : 0)
            || !TEST_int_eq(ossl_time_compare(cc->d1->next_timeout, client_timeout), 0))
            goto end;
    }

    /* The deliberately lost KeyUpdate must still be waiting for its own ACK. */
    if (pending_key_update) {
        testresult = 1;
        goto end;
    }

    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout))
        || !TEST_int_eq(DTLSv1_handle_timeout(server), 0)
        || !TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    BIO_free(retry);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_dtls13_pha_ack_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf, discard[2048];
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;
    ret = SSL_read(client, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 2))
        goto end;

    /* Drop the ACK for the PHA response and let the client retransmit. */
    if (!TEST_int_gt(BIO_read(SSL_get_rbio(client), discard, sizeof(discard)), 0)
        || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
        goto end;
    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(SSL_is_init_finished(server))
        || !TEST_true(SSL_is_init_finished(client))
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(cc->d1->next_timeout))
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;
    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static int test_dtls13_ack_list_bound(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    /*
     * Declare two body bytes but supply only one, keeping reassembly incomplete.
     */
    unsigned char frag[] = {
        SSL3_MT_KEY_UPDATE, /* msg_type */
        0, 0, 2, /* msg_body_len */
        0, 0, /* msg_seq */
        0, 0, 0, /* fragment_offset */
        0, 0, 1, /* fragment_length */
        0 /* fragment data */
    };
    unsigned char buf;
    const size_t max_records = (SSL3_RT_MAX_PLAIN_LENGTH - DTLS13_ACK_HEADER_LEN)
        / DTLS13_RECORD_NUMBER_LEN;
    size_t i, written;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    if (!TEST_size_t_eq(ossl_list_record_number_num(&sc->d1->ack_rec_num), 0))
        goto end;

    /*
     * Repeat the first byte of a two-byte message in fresh records, leaving
     * reassembly incomplete. Consume each record before sending the next.
     */
    frag[4] = (unsigned char)(cc->d1->next_handshake_write_seq >> 8);
    frag[5] = (unsigned char)cc->d1->next_handshake_write_seq;
    for (i = 0; i < 2 * max_records; i++) {
        if (!TEST_int_eq(dtls1_write_bytes(cc, SSL3_RT_HANDSHAKE, frag,
                             sizeof(frag), &written),
                1)
            || !TEST_size_t_eq(written, sizeof(frag))
            || !TEST_int_gt(BIO_flush(SSL_get_wbio(client)), 0))
            goto end;
        ret = SSL_read(server, &buf, sizeof(buf));
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(server)), 0)
            || !TEST_size_t_eq(ossl_list_record_number_num(&sc->d1->ack_rec_num),
                i < max_records ? i + 1 : max_records))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
static int large_ticket_cb(SSL *ssl, void *arg)
{
    static const unsigned char appdata[8192] = { 0 };

    return SSL_SESSION_set1_ticket_appdata(SSL_get_session(ssl), appdata,
        sizeof(appdata));
}

/* Split ACKs at the MTU or fragment limit, including a retry between records. */
static int test_dtls13_ack_records(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    BIO *retry = NULL;
    pitem *item;
    dtls_sent_msg *msg;
    unsigned char buf;
    size_t limit;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_session_ticket_cb(sctx, large_ticket_cb, NULL, NULL))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    SSL_set_options(server, SSL_OP_NO_QUERY_MTU);
    SSL_set_options(client, SSL_OP_NO_QUERY_MTU);
    if (!TEST_long_gt(SSL_set_mtu(server, 256), 0)
        || !TEST_long_gt(SSL_set_mtu(client, idx == 1 ? 1500 : 256), 0)
        || !TEST_true(SSL_set_max_send_fragment(client, 512))
        || !TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_ptr(item = pqueue_peek(&sc->d1->sent_messages)))
        goto end;

    /* The ticket must require more ACK entries than fit in one record. */
    msg = item->data;
    limit = idx == 1 ? 512 : DTLS_get_data_mtu(client);
    if (!TEST_size_t_gt(DTLS13_ACK_HEADER_LEN
                + DTLS13_RECORD_NUMBER_LEN * ossl_list_record_number_num(&msg->rec_nums),
            limit))
        goto end;
    sc->d1->next_timeout = ossl_time_add(ossl_time_now(), ossl_seconds2time(3600));

    if (idx == 2) {
        if (!TEST_ptr(retry = BIO_new(bio_s_maybe_retry()))
            || !TEST_true(BIO_up_ref(SSL_get_wbio(client))))
            goto end;
        SSL_set0_wbio(client, BIO_push(retry, SSL_get_wbio(client)));
        retry = NULL;
        if (!TEST_long_eq(BIO_ctrl(SSL_get_wbio(client),
                              MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 1, NULL),
                1))
            goto end;
        ret = SSL_read(client, &buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_WRITE)
            || !TEST_size_t_gt(cc->init_off, 0)
            || !TEST_long_eq(BIO_ctrl(SSL_get_wbio(client),
                                 MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 100, NULL),
                1))
            goto end;
    }

    if (!TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's'))
        goto end;
    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout))
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    BIO_free(retry);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A late ACK for the *original* copy of a retransmitted message must still
 * retire it. RFC 9147 section 7.2: "Implementations MUST treat a record as
 * having been acknowledged if it appears in any ACK." dtls1_retransmit_message()
 * clears a message's rec_nums right before resending it, so today an ACK
 * that matches the original record (R0) has nothing left to match once a
 * retransmission (R1) has happened -- the message never retires and its
 * retransmit timer never stops, even though the peer genuinely has it.
 *
 * Uses KeyUpdate: the smallest, single-record message, matching the issue's
 * most severe reported case (a hang, not just wasted retransmissions).
 *
 * idx 0: a single retransmission before the held ACK is delivered -- the
 *        core bug (issue's primary scenario).
 * idx 1: three retransmissions before the held ACK is delivered -- the
 *        pathological case (e.g. a custom DTLS_set_timer_cb() whose
 *        interval is shorter than the real round trip, so *every* ACK is
 *        always "late" relative to the next retransmit). Proves the fix
 *        accumulates history across the *entire* retransmission run, not
 *        just one generation back -- a fix that only kept the previous
 *        round's numbers would pass idx 0 but fail here.
 */
static int test_dtls13_keyupdate_ack_history(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    dtls_sent_msg *msg;
    unsigned char buf[2048];
    int ret, testresult = 0;
    int retransmits = idx == 0 ? 1 : 3;
    int i;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /*
     * Let the handshake ticket ACKs through first, so the server has no
     * outstanding flight of its own -- isolates this test from #32854/#32878.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(ticket_count, 2)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
        goto end;

    /* Client sends a KeyUpdate: this is R0. */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
        goto end;

    msg = pqueue_peek(&cc->d1->sent_messages)->data;
    if (!TEST_size_t_eq(ossl_list_record_number_num(&msg->rec_nums), 1))
        goto end;

    /*
     * Server receives R0 and queues its ACK for it -- but deliberately don't
     * deliver that ACK to the client yet. It just sits in the client's rbio
     * (a mempacket queue) until something reads it; nothing reads it out
     * from under us just by calling other functions below.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /*
     * Force the client to retransmit R0 as R1..R(retransmits): today, each
     * retransmit wipes whatever record numbers were there before it.
     */
    for (i = 0; i < retransmits; i++) {
        cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
        if (!TEST_true(SSL_handle_events(client)))
            goto end;
    }

    /*
     * Record numbers accumulate across every round instead of being wiped
     * by each retransmit: the original R0 plus one more per retransmit.
     */
    if (!TEST_size_t_eq(ossl_list_record_number_num(&msg->rec_nums),
            (size_t)(retransmits + 1)))
        goto end;

    /* *Now* deliver the ACK that was actually for R0, held since before the retransmit(s). */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Assertions that fail today: R0's ack matched nothing (its record
     * number was wiped by the retransmit), so the message never retires.
     */
    if (!TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(cc->d1->next_timeout))
        || !TEST_false(dtls_any_sent_messages_are_missing_acknowledge(cc)))
        goto end;

    /* Prove it's not just harmlessly stuck: the KeyUpdate completed and app data flows. */
    if (!TEST_int_eq(SSL_get_state(client), TLS_ST_OK)
        || !TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same late-ACK-after-retransmit history bug, but for the client's
 * Finished -- the issue's other reported "severe" case (a hang), alongside
 * KeyUpdate. Finished is sent during the handshake rather than
 * post-handshake, but dtls1_retransmit_message()/dtls_process_ack() don't
 * distinguish between the two: both just operate on a generic dtls_sent_msg,
 * so this proves the fix isn't specific to post-handshake messages.
 *
 * idx 0: a single retransmission before the held ACK is delivered.
 * idx 1: three retransmissions before the held ACK is delivered.
 */
static int test_dtls13_finished_ack_history(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *cc;
    dtls_sent_msg *msg;
    unsigned char buf[2048];
    int ret, testresult = 0;
    int retransmits = idx == 0 ? 1 : 3;
    int i;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
            NULL, NULL)))
        goto end;
    cc = SSL_CONNECTION_FROM_SSL(client);

    ret = SSL_connect(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_accept(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;
    /* Sends the client's Finished: this is R0. */
    ret = SSL_connect(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Server processes Finished, completes, and queues its ACK -- but
     * deliberately don't deliver that ACK to the client yet.
     */
    if (!TEST_int_eq(SSL_accept(server), 1)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    msg = pqueue_peek(&cc->d1->sent_messages)->data;
    if (!TEST_size_t_eq(ossl_list_record_number_num(&msg->rec_nums), 1))
        goto end;

    /* Force the client to retransmit R0 as R1..R(retransmits). */
    for (i = 0; i < retransmits; i++) {
        cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
        if (!TEST_true(SSL_handle_events(client)))
            goto end;
    }

    /* Record numbers accumulate across every round instead of being wiped. */
    if (!TEST_size_t_eq(ossl_list_record_number_num(&msg->rec_nums),
            (size_t)(retransmits + 1)))
        goto end;

    /* *Now* deliver the ACK that was actually for R0, held since before the retransmit(s). */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Assertions that fail today: R0's ack matched nothing (its record
     * number was wiped by the retransmit), so the message never retires.
     */
    if (!TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(cc->d1->next_timeout))
        || !TEST_false(dtls_any_sent_messages_are_missing_acknowledge(cc))
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_OK))
        goto end;

    /* Prove it's not just harmlessly stuck: app data flows both ways. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A message that fragments into K>1 records in a single transmission round
 * must not retire on a single matching ACK. RFC 9147 section 7.2 is a
 * per-record rule, but completeness is per-message: the peer needs *every*
 * fragment, from any combination of rounds, not just any one of them.
 *
 * Also proves coverage aggregates *across* rounds: deliver a different
 * fragment from two separate, individually-incomplete retransmission
 * rounds, and confirm the message retires once their union covers the
 * whole message. "Per-round accumulate" (also rejected) would never notice
 * this and would retransmit forever.
 *
 * idx == 0: the client already has the whole (originally unfragmented)
 * ticket before either round below runs -- this exercises only the
 * *sender's* ACK/coverage bookkeeping.
 *
 * idx == 1: companion case. The MTU is lowered *before* the ticket is ever
 * sent, so round 1 *is* the original transmission, already fragmented; the
 * client is deliberately left holding only one of its fragments, so it
 * cannot reassemble the message until round 2 supplies the rest. This
 * exercises the *receive*-side reassembly across rounds instead, asserting
 * ticket_count moves from 0 to 1 exactly once, on round 2, not before.
 */
static int test_dtls13_ticket_ack_history_fragmented(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    BIO *bio;
    dtls_sent_msg *msg;
    unsigned char buf[2048];
    unsigned char frag[8][1024];
    int fraglen[8];
    int nfrags, ret, dropped, i, j, testresult = 0;
    size_t round1_frag0_len, round2_frag0_len;
    DTLS1_RECORD_NUMBER *r;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 1)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL)))
        goto end;

    if (idx == 1) {
        /*
         * Lower the MTU before the connection is even established, so the
         * ticket's very first transmission is already fragmented, and use
         * the bare handshake primitive instead of create_ssl_connection():
         * the latter forces two SSL_read_ex() calls on the client purely to
         * deliver NewSessionTicket messages, which would reassemble and
         * deliver this ticket before we get a chance to intercept it.
         */
        SSL_set_options(server, SSL_OP_NO_QUERY_MTU);
        if (!TEST_long_gt(SSL_set_mtu(server, 257), 0)
            || !TEST_true(create_bare_ssl_connection_ex(server, client,
                SSL_ERROR_NONE, 1, 0, NULL, NULL)))
            goto end;
    } else if (!TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE))) {
        goto end;
    }
    sc = SSL_CONNECTION_FROM_SSL(server);
    bio = SSL_get_rbio(client);

    if (!TEST_int_eq(ticket_count, idx == 0 ? 1 : 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    if (idx == 0) {
        /*
         * Drop the ticket's original ACK. The ticket flows server -> client
         * (that direction is `bio`, used below for the fragments); the
         * client's ACK for it flows the other way, client -> server, i.e.
         * the server's rbio.
         */
        dropped = 0;
        while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
            dropped++;
        if (!TEST_int_gt(dropped, 0))
            goto end;

        /* Lower the MTU so a retransmission fragments the ticket. */
        SSL_set_options(server, SSL_OP_NO_QUERY_MTU);
        if (!TEST_long_gt(SSL_set_mtu(server, 257), 0))
            goto end;

        /* Round 1: force a retransmit. The ticket now fragments into K records. */
        sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
        if (!TEST_true(SSL_handle_events(server)))
            goto end;
    }

    /*
     * Capture every fragment of round 1, delivering none of them yet.
     * idx == 0: round 1 is the retransmit just forced above.
     * idx == 1: round 1 is the original transmission itself, already
     * fragmented because the MTU was lowered before it was ever sent.
     */
    nfrags = 0;
    while ((ret = BIO_read(bio, frag[nfrags], sizeof(frag[0]))) > 0) {
        fraglen[nfrags] = ret;
        nfrags++;
        if (!TEST_int_lt(nfrags, (int)OSSL_NELEM(frag)))
            goto end;
    }
    if (!TEST_int_gt(nfrags, 1))
        goto end;

    /*
     * idx == 0: record numbers accumulate across rounds instead of being
     * wiped -- the original (non-fragmented) send plus every fragment of
     * round 1.
     * idx == 1: there is no separate, earlier non-fragmented send -- round 1
     * *is* the original send, so it's just round 1's own fragments.
     */
    msg = pqueue_peek(&sc->d1->sent_messages)->data;
    if (!TEST_size_t_eq(ossl_list_record_number_num(&msg->rec_nums),
            (size_t)(idx == 0 ? nfrags + 1 : nfrags)))
        goto end;

    /*
     * Record round 1's fragment 0 length now, before round 2 changes the MTU
     * and appends its own entries: round 1's fragment 0 is the first entry
     * inserted for round 1, i.e. the head (idx == 1) or the entry right
     * after the original whole-message entry (idx == 0).
     */
    r = ossl_list_record_number_head(&msg->rec_nums);
    if (idx == 0)
        r = ossl_list_record_number_next(r);
    if (!TEST_ptr(r))
        goto end;
    round1_frag0_len = r->frag_len;

    /* Deliver only fragment 0 of round 1 back to the client. */
    if (!TEST_int_eq(mempacket_test_inject(bio, (const char *)frag[0], fraglen[0],
                         -1, INJECT_PACKET_IGNORE_REC_SEQ),
            fraglen[0]))
        goto end;

    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The client generated an ACK for fragment 0, but it's just sitting in
     * the server's rbio until the server actually reads it -- dtls_process_ack()
     * runs on the server side, since the server is the one waiting on this
     * ticket's acknowledgment.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * A single fragment's ACK must not retire the ticket, and (idx == 1)
     * one fragment out of K is not enough for the client to reassemble and
     * deliver it either.
     */
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_int_eq(ticket_count, idx == 0 ? 1 : 0))
        goto end;

    /*
     * Round 2: lower the MTU further and force another retransmit, so this
     * round splits the ticket at *different* offsets than round 1 did.
     * Round 1's larger MTU (257) makes its fragment 0 longer than round 2's
     * (256), so the two rounds' covered ranges overlap by a byte instead of
     * landing on identical boundaries -- proving coverage is tracked by
     * actual byte range, not by an index into an assumed-stable fragment
     * layout (the "per-round accumulate" design rejected in section 3 of
     * the design notes would have no way to notice this either).
     */
    if (!TEST_long_gt(SSL_set_mtu(server, 256), 0))
        goto end;
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server)))
        goto end;

    /* Capture round 2's fragments, delivering everything *except* fragment 0. */
    nfrags = 0;
    while ((ret = BIO_read(bio, frag[nfrags], sizeof(frag[0]))) > 0) {
        fraglen[nfrags] = ret;
        nfrags++;
        if (!TEST_int_lt(nfrags, (int)OSSL_NELEM(frag)))
            goto end;
    }
    if (!TEST_int_gt(nfrags, 1))
        goto end;

    /*
     * Confirm the MTU change actually moved the fragment boundary: round 2's
     * fragment 0 (the entry nfrags - 1 positions back from the tail, since
     * round 2 just appended nfrags fresh entries there) must be shorter than
     * round 1's, so the two rounds' covered ranges overlap rather than
     * landing on the same split point or leaving a gap between them.
     */
    r = ossl_list_record_number_tail(&msg->rec_nums);
    for (j = 0; j < nfrags - 1; j++)
        r = ossl_list_record_number_prev(r);
    if (!TEST_ptr(r))
        goto end;
    round2_frag0_len = r->frag_len;
    if (!TEST_size_t_gt(round1_frag0_len, round2_frag0_len))
        goto end;

    for (i = 1; i < nfrags; i++) {
        if (!TEST_int_eq(mempacket_test_inject(bio, (const char *)frag[i],
                             fraglen[i], -1, INJECT_PACKET_IGNORE_REC_SEQ),
                fraglen[i]))
            goto end;
    }

    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Let the server actually process the ACK(s) for round 2's fragments. */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Round 1's fragment 0 plus round 2's remaining fragments between them
     * cover the whole ticket, even though neither round was ever
     * individually complete, on both sides of the connection: the sender's
     * bookkeeping retires the message (idx == 0 and idx == 1 alike), and
     * (idx == 1) the client reassembles and delivers it for the first time
     * here -- not on round 1's partial delivery above, and only once.
     */
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout))
        || !TEST_int_eq(ticket_count, 1))
        goto end;

    /* Prove it's not just harmlessly stuck. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Drive the server's unacknowledged NewSessionTicket through an interrupted
 * fragmented retransmission followed by a full restart:
 *
 *   round 1: retransmit at a lowered MTU; the write of the second fragment
 *            fails with a retryable error leaving s->init_off nonzero;
 *   round 2: retransmit again with writes enabled. Before the init_off reset
 *            in dtls1_retransmit_message(), this restarted fragmentation
 *            from round 1's stale offset against the freshly-reloaded full
 *            message, recording byte ranges past msg_body_len -- ranges
 *            dtls_process_ack() then used directly as bitmask indices.
 */
static int interrupted_ticket_retransmit_setup(SSL_CTX **sctx_out, SSL_CTX **cctx_out,
    SSL **server_out, SSL **client_out,
    SSL_CONNECTION **sc_out,
    dtls_sent_msg **msg_out)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    BIO *retry = NULL;
    unsigned char buf[2048];
    int dropped;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 1)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    if (!TEST_int_eq(ticket_count, 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;
    *msg_out = pqueue_peek(&sc->d1->sent_messages)->data;
    if (!TEST_ptr(*msg_out)
        /*
         * Needs at least two ~223-byte fragments at the MTU set below, so a
         * mid-round write can be failed after one fragment has gone out.
         */
        || !TEST_size_t_gt((*msg_out)->msg_info.msg_body_len, 223))
        goto end;

    /* Drop the ticket's original ACK so it stays retransmittable. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* Lower the MTU so a retransmission fragments the ticket. */
    SSL_set_options(server, SSL_OP_NO_QUERY_MTU);
    if (!TEST_long_gt(SSL_set_mtu(server, 257), 0))
        goto end;

    /* Fail the write following the next successful one. */
    if (!TEST_ptr(retry = BIO_new(bio_s_maybe_retry()))
        || !TEST_true(BIO_up_ref(SSL_get_wbio(server))))
        goto end;
    SSL_set0_wbio(server, BIO_push(retry, SSL_get_wbio(server)));
    retry = NULL;
    if (!TEST_long_eq(BIO_ctrl(SSL_get_wbio(server),
                          MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 1, NULL),
            1))
        goto end;

    /*
     * Round 1: the first fragment's record write succeeds; the second
     * fragment's write fails, aborting the retransmission mid-message.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_false(SSL_handle_events(server))
        || !TEST_size_t_gt(sc->init_off, 0))
        goto end;

    /* Round 2: retransmit again, this time letting every write through. */
    if (!TEST_long_eq(BIO_ctrl(SSL_get_wbio(server),
                          MAYBE_RETRY_CTRL_SET_RETRY_AFTER_CNT, 10000, NULL),
            1))
        goto end;
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server)))
        goto end;

    /* The client already has the ticket; discard round 2's retransmission. */
    while (BIO_read(SSL_get_rbio(client), buf, sizeof(buf)) > 0)
        ;

    *sctx_out = sctx;
    *cctx_out = cctx;
    *server_out = server;
    *client_out = client;
    *sc_out = sc;
    return 1;

end:
    BIO_free(retry);
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return 0;
}

/*
 * Every byte range recorded across the ticket's retransmissions must fit
 * within msg_body_len: dtls_process_ack() uses these ranges directly as
 * indices into a bitmask of only ceil(msg_body_len / 8) bytes.
 */
static int test_dtls13_interrupted_retransmit_range(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc = NULL;
    dtls_sent_msg *msg = NULL;
    DTLS1_RECORD_NUMBER *recnum;
    size_t body_len;
    int testresult = 0;

    if (!interrupted_ticket_retransmit_setup(&sctx, &cctx, &server, &client,
            &sc, &msg))
        goto end;

    /* The retransmissions must actually have fragmented the ticket. */
    if (!TEST_size_t_ge(ossl_list_record_number_num(&msg->rec_nums), 3))
        goto end;

    body_len = msg->msg_info.msg_body_len;
    for (recnum = ossl_list_record_number_head(&msg->rec_nums);
        recnum != NULL; recnum = ossl_list_record_number_next(recnum)) {
        if (!TEST_size_t_le(recnum->frag_off, body_len)
            || !TEST_size_t_le(recnum->frag_len, body_len - recnum->frag_off))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * ACK the record number with the largest recorded byte range, through the
 * client's real write path, and process the ACK on the server. Before the
 * range check backstop in dtls_process_ack(), a corrupt recorded range here
 * would index past msg->covered's trailing bitmask allocation.
 */
static int test_dtls13_ack_bitmap_oob(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc = NULL, *cc;
    dtls_sent_msg *msg = NULL;
    DTLS1_RECORD_NUMBER *recnum, *pick = NULL;
    unsigned char ack[18], buf[2048];
    WPACKET pkt;
    size_t acklen, written, worst = 0;
    int ret, testresult = 0;

    if (!interrupted_ticket_retransmit_setup(&sctx, &cctx, &server, &client,
            &sc, &msg))
        goto end;
    cc = SSL_CONNECTION_FROM_SSL(client);

    if (!TEST_size_t_ge(ossl_list_record_number_num(&msg->rec_nums), 3))
        goto end;

    for (recnum = ossl_list_record_number_head(&msg->rec_nums);
        recnum != NULL; recnum = ossl_list_record_number_next(recnum))
        if (recnum->frag_off + recnum->frag_len > worst) {
            worst = recnum->frag_off + recnum->frag_len;
            pick = recnum;
        }
    if (!TEST_ptr(pick))
        goto end;

    /* Keep the retransmit timer out of the way while the ACK is processed. */
    sc->d1->next_timeout = ossl_time_add(ossl_time_now(), ossl_seconds2time(3600));

    /* One RecordNumber entry: epoch and sequence_number, u16 length-prefixed. */
    if (!TEST_true(WPACKET_init_static_len(&pkt, ack, sizeof(ack), 2))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, pick->epoch))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, pick->seqnum))
        || !TEST_true(WPACKET_finish(&pkt))
        || !TEST_true(WPACKET_get_total_written(&pkt, &acklen))) {
        WPACKET_cleanup(&pkt);
        goto end;
    }
    WPACKET_cleanup(&pkt);

    if (!TEST_int_eq(dtls1_write_bytes(cc, SSL3_RT_ACK, ack, acklen, &written), 1)
        || !TEST_size_t_eq(written, acklen)
        || !TEST_int_gt(BIO_flush(SSL_get_wbio(client)), 0))
        goto end;

    /* dtls_process_ack() marks the coverage bitmap for the picked record. */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* The connection must survive processing the ACK. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Recover from a lost ACK for the client's Finished: the server must still
 * accept a retransmission of Finished at its original (now superseded) read
 * epoch and replace the lost ACK, rather than silently discarding it.
 */
static int test_dtls13_finished_ack_loss_recovers(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *cc;
    unsigned char buf, discard[2048];
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
            NULL, NULL)))
        goto end;
    cc = SSL_CONNECTION_FROM_SSL(client);

    ret = SSL_connect(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_accept(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;
    /* Sends the client's Finished. */
    ret = SSL_connect(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    /* Server processes Finished, completes, and queues its ACK. */
    if (!TEST_int_eq(SSL_accept(server), 1)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
        goto end;

    /* Drop the server's ACK for the client's Finished. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(client), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /* Force the client to retransmit Finished at its original epoch. */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(),
        ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client)))
        goto end;

    /*
     * The server has already moved to the next read epoch, so this
     * retransmission only authenticates via the server's retained previous
     * read epoch: a fresh ACK must appear here.
     */
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /* The client picks up the replacement ACK and completes. */
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_OK)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(cc->d1->next_timeout)))
        goto end;

    /* Application data flows both ways. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Recover from a lost ACK for a KeyUpdate: the receiver must still accept a
 * retransmission of the KeyUpdate at its original (now superseded) read
 * epoch and replace the lost ACK, rather than silently discarding it and
 * leaving the initiator retransmitting forever. idx == 0 is the server
 * initiating (the issue's reported case); idx == 1 is the client initiating
 * (noted in the issue as sharing the same problem but untested there).
 */
static int test_dtls13_keyupdate_ack_loss_recovers(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL, *sender, *receiver;
    SSL_CONNECTION *sc, *cc, *sender_c;
    unsigned char buf, discard[2048];
    int ret, dropped, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /*
     * Let the handshake ticket ACKs through, so neither side has a pending
     * flight of its own and anything observed below is unambiguously this
     * bug, not #32878's separate flight-cancellation problem.
     */
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(ticket_count, 2)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    sender = idx ? client : server;
    receiver = idx ? server : client;
    sender_c = idx ? cc : sc;

    if (!TEST_true(SSL_key_update(sender, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(sender);
    if (!TEST_int_eq(SSL_get_error(sender, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sender_c->d1->sent_messages), 1))
        goto end;

    /* Receiver processes the KeyUpdate, bumps its read epoch, and ACKs it. */
    ret = SSL_read(receiver, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(receiver, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Drop that ACK. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(sender), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sender_c->d1->sent_messages), 1))
        goto end;

    /* Force the sender to retransmit the KeyUpdate at its original epoch. */
    sender_c->d1->next_timeout = ossl_time_subtract(ossl_time_now(),
        ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(sender)))
        goto end;

    /*
     * The receiver has already moved to the next read epoch, so this
     * retransmission only authenticates via the receiver's retained
     * previous read epoch: a fresh ACK must appear here.
     */
    ret = SSL_read(receiver, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(receiver, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(sender)), 0))
        goto end;

    /* The sender picks up the replacement ACK and completes. */
    ret = SSL_read(sender, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(sender, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(sender), TLS_ST_OK)
        || !TEST_size_t_eq(pqueue_size(&sender_c->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sender_c->d1->next_timeout)))
        goto end;

    /* Application data flows both ways. */
    if (!TEST_int_eq(SSL_write(sender, "x", 1), 1)
        || !TEST_int_eq(SSL_read(receiver, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'x')
        || !TEST_int_eq(SSL_write(receiver, "y", 1), 1)
        || !TEST_int_eq(SSL_read(sender, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'y'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * SSL_free_buffers() must also release the retained previous-epoch read
 * layer's buffer, not just the active layer's. dtls_get_more_records()
 * never uses the retained layer's own read buffer after retention -- it
 * reuses the active layer's packet buffer to authenticate a
 * previous-epoch record -- so leaving it allocated after SSL_free_buffers()
 * reports success is a pure leak until the whole layer chain is torn down.
 */
static int test_dtls13_prev_epoch_rl_buffer_freed(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    OSSL_RECORD_LAYER *rrl;
    unsigned char buf;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    rrl = sc->rlayer.rrl;

    /* The server's epoch-2 read layer must have been retained. */
    if (!TEST_ptr(rrl->prev_epoch_rl))
        goto end;

    /* Exchange and consume application data both ways. */
    if (!TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c')
        || !TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's'))
        goto end;

    if (!TEST_true(SSL_free_buffers(server)))
        goto end;

    if (!TEST_ptr_null(rrl->rbuf.buf))
        goto end;

    /*
     * Without releasing the retained previous-epoch layer's buffer in
     * dtls_set_prev_epoch_rl(), this would stay allocated even though
     * SSL_free_buffers() reported success above.
     */
    if (!TEST_ptr_null(rrl->prev_epoch_rl->rbuf.buf))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Epoch 2 is always the fixed DTLS 1.3 handshake epoch: no compliant peer
 * ever sends application data there. A record that only authenticates
 * because of that epoch's retained keys must never be delivered as
 * application data -- but a retained *application* epoch (3+, from
 * KeyUpdate recovery) must be left alone, since it can legitimately carry
 * reordered application traffic.
 */
static int test_dtls_prev_epoch_allows_type(void)
{
    OSSL_RECORD_LAYER rl;
    int testresult = 0;

    memset(&rl, 0, sizeof(rl));

    rl.epoch = 2;
    if (!TEST_false(dtls_prev_epoch_allows_type(&rl, SSL3_RT_APPLICATION_DATA))
        || !TEST_true(dtls_prev_epoch_allows_type(&rl, SSL3_RT_HANDSHAKE)))
        goto end;

    rl.epoch = 3;
    if (!TEST_true(dtls_prev_epoch_allows_type(&rl, SSL3_RT_APPLICATION_DATA)))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/*
 * dtls_record_from_retained_epoch() is what statem_dtls.c's dispatch and
 * discard/buffer decisions OR into their existing conditions to recognize a
 * record that only authenticated via the retained previous read epoch, so
 * it never gets treated as content that genuinely arrived at the currently
 * active epoch.
 */
static int test_dtls_record_from_retained_epoch(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, dtlsv1_3_server_method(),
            dtlsv1_3_client_method(), 0, 0, &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
            NULL, NULL)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    sc->rlayer.d->r_conn_epoch = 3;

    /* Record actually arrived at the currently active epoch. */
    sc->s3.tmp.record_epoch = 3;
    if (!TEST_false(dtls_record_from_retained_epoch(sc)))
        goto end;

    /* Record only authenticated via the retained previous epoch. */
    sc->s3.tmp.record_epoch = 2;
    if (!TEST_true(dtls_record_from_retained_epoch(sc)))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * dtls1_process_out_of_seq_message() must never let a record that only
 * authenticated via a retained previous epoch get buffered for future
 * reassembly -- which would eventually process it as new content -- and
 * must only ACK it when it genuinely corresponds to something already
 * fully processed (seq strictly before the next expected one).
 *
 * idx 0: already fully processed (seq < expected). The legitimate
 *        retransmission-recovery case from the earlier review round: ACK,
 *        don't buffer.
 * idx 1: "expected next" seq (seq == expected). Proves this function is
 *        safe on the exact input dtls_get_reassembled_message() must now
 *        route here instead of treating as fresh (see
 *        test_dtls_record_from_retained_epoch() above for that routing
 *        condition) -- must not be buffered or ACKed.
 * idx 2: looks like a future message (seq > expected). Must not be
 *        buffered for later processing as new content, and must not be
 *        ACKed either.
 */
static int test_dtls13_out_of_seq_retained_epoch(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    struct hm_header_st msg_hdr;
    int testresult = 0;
    int expect_ack;

    if (!TEST_true(create_ssl_ctx_pair(NULL, dtlsv1_3_server_method(),
            dtlsv1_3_client_method(), 0, 0, &sctx, &cctx, cert, privkey))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client,
            NULL, NULL)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    sc->rlayer.d->r_conn_epoch = 3;
    sc->s3.tmp.record_epoch = 2;
    sc->d1->handshake_read_seq = 5;

    memset(&msg_hdr, 0, sizeof(msg_hdr));
    msg_hdr.type = SSL3_MT_KEY_UPDATE;

    switch (idx) {
    case 0:
        msg_hdr.seq = 4;
        expect_ack = 1;
        break;
    case 1:
        msg_hdr.seq = 5;
        expect_ack = 0;
        break;
    case 2:
        msg_hdr.seq = 6;
        expect_ack = 0;
        break;
    default:
        goto end;
    }

    if (!TEST_int_eq(dtls1_process_out_of_seq_message(sc, &msg_hdr),
            DTLS1_HM_FRAGMENT_RETRY))
        goto end;

    /* Never buffered for future reassembly/processing as new content. */
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->rcvd_messages), 0))
        goto end;

    if (expect_ack) {
        if (!TEST_ptr(ossl_list_record_number_head(&sc->d1->ack_rec_num)))
            goto end;
    } else if (!TEST_ptr_null(ossl_list_record_number_head(&sc->d1->ack_rec_num))) {
        goto end;
    }

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Encrypt a handshake message under a retained (stale) epoch's own real
 * cipher context and inject it straight into the receiver's rbio, exactly
 * as tls13_cipher() builds a unified-header DTLS 1.3 record. No separate key
 * material or network write is needed: the retained read layer already
 * holds the real traffic keys for that epoch, so running its own cipher
 * context in the encrypt direction for one record produces ciphertext the
 * same layer's decrypt path will accept.
 *
 * Ported from Mounir Idrassi's inject_previous() in his
 * repro_prev_epoch_delivery.c reproducer for this issue.
 */
static int inject_at_retained_epoch(SSL *receiver, unsigned char inner_type,
    const unsigned char *body, size_t body_len)
{
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL(receiver);
    OSSL_RECORD_LAYER *prev = sc->rlayer.rrl->prev_epoch_rl;
    unsigned char plain[64], cipher[64], header[5], nonce[EVP_MAX_IV_LENGTH];
    unsigned char seq[SEQ_NUM_SIZE], *pseq = seq;
    uint64_t sequence, truncated;
    size_t ivlen, offset, i, pktlen;
    int outl = 0, finl = 0;

    if (prev == NULL || prev->enc_ctx == NULL || prev->iv == NULL
        || prev->taglen == 0 || body_len + 1 > sizeof(plain)
        || body_len + 1 + prev->taglen + 5 > sizeof(cipher))
        return 0;

    sequence = prev->bitmap.max_seq_num + 1;
    truncated = sequence & 0xffff;
    memcpy(plain, body, body_len);
    plain[body_len] = inner_type;

    l2n8(sequence, pseq);
    ivlen = (size_t)EVP_CIPHER_CTX_get_iv_length(prev->enc_ctx);
    if (ivlen < SEQ_NUM_SIZE || ivlen > sizeof(nonce))
        return 0;
    offset = ivlen - SEQ_NUM_SIZE;
    memcpy(nonce, prev->iv, offset);
    for (i = 0; i < SEQ_NUM_SIZE; i++)
        nonce[offset + i] = prev->iv[offset + i] ^ seq[i];

    header[0] = (unsigned char)(DTLS13_UNI_HDR_FIX_BITS | DTLS13_UNI_HDR_SEQ_BIT
        | DTLS13_UNI_HDR_LEN_BIT | (prev->epoch & DTLS13_UNI_HDR_EPOCH_BITS_MASK));
    header[1] = (unsigned char)(truncated >> 8);
    header[2] = (unsigned char)truncated;
    header[3] = (unsigned char)((body_len + 1 + prev->taglen) >> 8);
    header[4] = (unsigned char)(body_len + 1 + prev->taglen);

    if (EVP_CipherInit_ex(prev->enc_ctx, NULL, NULL, NULL, nonce, 1) <= 0
        || EVP_CipherUpdate(prev->enc_ctx, NULL, &outl, header, sizeof(header)) <= 0
        || EVP_CipherUpdate(prev->enc_ctx, cipher + 5, &outl, plain,
               (int)(body_len + 1))
            <= 0
        || EVP_CipherFinal_ex(prev->enc_ctx, cipher + 5 + outl, &finl) <= 0
        || (size_t)outl + (size_t)finl != body_len + 1
        || EVP_CIPHER_CTX_ctrl(prev->enc_ctx, EVP_CTRL_AEAD_GET_TAG,
               (int)prev->taglen, cipher + 5 + body_len + 1)
            <= 0)
        return 0;

    memcpy(cipher, header, sizeof(header));
    pktlen = 5 + body_len + 1 + prev->taglen;

    /*
     * Mask the 16-bit sequence number exactly as a transmitted record does.
     * dtls_crypt_sequence_number() is reversible, so the receiver recovers
     * the value selected above.
     */
    if (prev->sn_enc_ctx != NULL
        && !dtls_crypt_sequence_number(prev->sn_enc_ctx, cipher + 1, 2,
            cipher + 5))
        return 0;

    return mempacket_test_inject(SSL_get_rbio(receiver), (const char *)cipher,
               (int)pktlen, -1, INJECT_PACKET_IGNORE_REC_SEQ)
        == (int)pktlen;
}

/*
 * A record that authenticates only via the retained epoch-2
 * read layer, but whose handshake sequence number matches exactly
 * what the server is still waiting for, must not be treated as fresh
 * content: dtls_get_reassembled_message() must still route it to
 * dtls1_process_out_of_seq_message() via dtls_record_from_retained_epoch(),
 * even though the plain "seq != expected" check alone would not catch it.
 *
 * Unlike test_dtls13_out_of_seq_retained_epoch() above, which calls
 * dtls1_process_out_of_seq_message() directly, this goes through the real
 * receive path, so it actually exercises the routing decision
 * in dtls_get_reassembled_message() instead of assuming it already
 * happened.
 */
static int test_dtls13_retained_epoch_seq_match(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    OSSL_RECORD_LAYER *active, *prev;
    unsigned char message[DTLS1_HM_HEADER_LENGTH + 1];
    unsigned char buf;
    unsigned short expected;
    uint64_t epoch_before;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    active = sc->rlayer.rrl;
    prev = active->prev_epoch_rl;

    /* The server's epoch-2 (Finished-recovery) read layer must be retained. */
    if (!TEST_ptr(prev) || !TEST_uint64_t_eq(prev->epoch, 2))
        goto end;

    epoch_before = active->epoch;
    expected = sc->d1->handshake_read_seq;

    /* A KeyUpdate claiming exactly the sequence number the server still
     * expects next. */
    memset(message, 0, sizeof(message));
    message[0] = SSL3_MT_KEY_UPDATE;
    message[3] = 1;
    message[4] = (unsigned char)(expected >> 8);
    message[5] = (unsigned char)expected;
    message[11] = 1;
    message[DTLS1_HM_HEADER_LENGTH] = SSL_KEY_UPDATE_NOT_REQUESTED;

    if (!TEST_true(inject_at_retained_epoch(server, SSL3_RT_HANDSHAKE,
            message, sizeof(message))))
        goto end;

    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Must not have been processed as fresh content: a genuine KeyUpdate
     * would install a new read epoch, and the server must not have
     * re-entered handshake processing. Check the connection's *current*
     * read layer (sc->rlayer.rrl), not "active" -- that pointer was saved
     * before the read, and a real epoch bump replaces sc->rlayer.rrl with
     * a new OSSL_RECORD_LAYER while retaining the old one as its
     * prev_epoch_rl, so active->epoch would still read as unchanged
     * either way.
     */
    if (!TEST_uint64_t_eq(sc->rlayer.rrl->epoch, epoch_before)
        || !TEST_false(SSL_in_init(server))
        || !TEST_int_eq(sc->d1->handshake_read_seq, expected))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * Epoch 2 is always the fixed DTLS 1.3 handshake epoch: no compliant peer
 * ever sends application data there. A record that only authenticates via
 * those retained keys must never be delivered as application data, unlike a
 * retained *application* epoch (3+), which can legitimately carry reordered
 * application traffic -- see test_dtls_prev_epoch_allows_type() above for
 * that distinction in isolation.
 */
static int test_dtls13_retained_epoch_app_data_rejected(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    OSSL_RECORD_LAYER *prev;
    unsigned char body[1] = { 'P' };
    unsigned char buf = 0;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    prev = sc->rlayer.rrl->prev_epoch_rl;

    /* The server's epoch-2 (Finished-recovery) read layer must be retained. */
    if (!TEST_ptr(prev) || !TEST_uint64_t_eq(prev->epoch, 2))
        goto end;

    if (!TEST_true(inject_at_retained_epoch(server, SSL3_RT_APPLICATION_DATA,
            body, sizeof(body))))
        goto end;

    /*
     * The record authenticates, but dtls_prev_epoch_allows_type() must
     * discard it once decoded rather than deliver it -- it must never reach
     * here as readable application data.
     */
    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_uchar_eq(buf, 0))
        goto end;

    /* Prove it's not just harmlessly stuck. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * An ACK record that only authenticated via the retained epoch-2 read layer
 * must not be processed beyond the Finished-recovery window: once the
 * handshake is over, records protected with the retained handshake keys
 * must not modify the post-handshake retransmission state (d1->sent_messages)
 * or cancel its retransmission timer.
 *
 * The same connection rejects application data authenticated with those
 * same retained keys (see test_dtls13_retained_epoch_app_data_rejected()
 * above), but the ACK branch of dtls_get_reassembled_message() returns
 * before the retained-epoch restriction is applied, dtls1_read_bytes()
 * records the authenticating epoch for handshake records only, and
 * dtls_process_ack() removes matching entries from the retransmission queue,
 * so the ACK path must itself enforce the handshake/application protection
 * boundary rather than relying on which epoch authenticated the record.
 */
static int test_dtls13_retained_epoch_ack_authority(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    OSSL_RECORD_LAYER *prev;
    piterator iter;
    pitem *item;
    dtls_sent_msg *msg;
    DTLS1_RECORD_NUMBER *recnum;
    unsigned char body[2 + 16], discard[2048], buf = 0;
    uint64_t epoch = 0, seqnum = 0, active_epoch, bitmap_before;
    size_t off;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        /*
         * Pin an AEAD whose per-record plaintext length needs no extra
         * declaration, so inject_at_retained_epoch()'s assumptions hold
         * regardless of suite priority changes (AES-CCM would need more).
         */
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    prev = sc->rlayer.rrl->prev_epoch_rl;

    /* The server's epoch-2 (Finished-recovery) read layer must be retained. */
    if (!TEST_ptr(prev) || !TEST_uint64_t_eq(prev->epoch, 2))
        goto end;

    /* Let any pending flight ACKs through so the baseline is settled. */
    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* Arm a post-handshake flight: a server KeyUpdate awaiting its ACK. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* The client processes it and ACKs; drop that ACK. */
    ret = SSL_read(client, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /*
     * Forge an ACK record at the retained epoch claiming the outstanding
     * record. The claimed (epoch, sequence) pair is copied from the
     * server's own retransmission queue; it belongs to the currently active
     * read epoch, while the record itself only authenticates via epoch 2.
     */
    iter = pqueue_iterator(&sc->d1->sent_messages);
    item = pqueue_next(&iter);
    if (!TEST_ptr(item))
        goto end;
    msg = (dtls_sent_msg *)item->data;
    recnum = ossl_list_record_number_head(&msg->rec_nums);
    if (!TEST_ptr(recnum))
        goto end;
    epoch = recnum->epoch;
    seqnum = recnum->seqnum;
    active_epoch = sc->rlayer.rrl->epoch;
    if (!TEST_uint64_t_eq(epoch, active_epoch))
        goto end;

    body[0] = 0;
    body[1] = 16;
    for (off = 0; off < 8; off++) {
        body[2 + off] = (unsigned char)(epoch >> (8 * (7 - off)));
        body[10 + off] = (unsigned char)(seqnum >> (8 * (7 - off)));
    }
    bitmap_before = prev->bitmap.max_seq_num;
    if (!TEST_true(inject_at_retained_epoch(server, SSL3_RT_ACK, body,
            sizeof(body))))
        goto end;

    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The record only authenticated via the retained handshake epoch, so it
     * must not complete the outstanding application-epoch flight nor stop
     * its retransmission timer. It did pass the retained layer's own replay
     * window (only updated after successful decryption) and must not have
     * moved the active read epoch.
     */
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout))
        || !TEST_uint64_t_eq(prev->bitmap.max_seq_num, bitmap_before + 1)
        || !TEST_uint64_t_eq(sc->rlayer.rrl->epoch, active_epoch))
        goto end;

    /*
     * The legitimate recovery must still work afterwards: force the
     * retransmission timer, let the client re-ACK the retransmitted
     * KeyUpdate, and let the server complete on the replacement ACK.
     * (The genuine ACK was deliberately dropped above, so the server is
     * still waiting for it and a bare SSL_write() would first drive the
     * unfinished handshake and fail with SSL_ERROR_WANT_READ.)
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(),
        ossl_seconds2time(1));
    if (!TEST_int_gt(DTLSv1_handle_timeout(server), 0)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    ret = SSL_read(client, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    ret = SSL_read(server, &buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* With the flight settled, bidirectional application data flows. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * RFC9147 Section 5.8.4: the different categories of post-handshake message have
 * independent reliability state machines. A message of one category therefore
 * acknowledges nothing of another, and processing it must neither discard our
 * own outstanding flight nor cancel that flight's retransmit timer.
 *
 * idx 0: the server's NewSessionTickets must survive an inbound KeyUpdate.
 * idx 1: the client's KeyUpdate must survive an inbound NewSessionTicket.
 */
static int test_dtls13_keyupdate_preserves_flight(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    dtls_sent_msg *msg;
    piterator iter;
    pitem *item;
    unsigned char buf[2048];
    OSSL_TIME timeout;
    int ret, dropped, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);

    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;

    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /* The client processed both tickets, but their ACKs are still unread. */
    if (!TEST_int_eq(ticket_count, 2)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    if (idx == 0) {
        /* Lose the ticket ACKs, leaving both tickets outstanding. */
        dropped = 0;
        while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
            dropped++;
        if (!TEST_int_gt(dropped, 0)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2))
            goto end;

        /* Pin the timer so the comparisons cannot race against real time. */
        timeout = sc->d1->next_timeout = ossl_time_add(ossl_time_now(),
            ossl_seconds2time(3600));

        /* An unrelated KeyUpdate, which acknowledges none of the tickets. */
        if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
            goto end;
        ret = SSL_do_handshake(client);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
            goto end;

        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
            || !TEST_int_eq(SSL_get_state(server), TLS_ST_OK)
            /* Both tickets and their retransmit timer must have survived. */
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
            || !TEST_int_eq(ossl_time_compare(sc->d1->next_timeout, timeout), 0)
            || !TEST_true(dtls_any_sent_messages_are_missing_acknowledge(sc)))
            goto end;
        iter = pqueue_iterator(&sc->d1->sent_messages);
        while ((item = pqueue_next(&iter)) != NULL) {
            msg = item->data;

            if (!TEST_uchar_eq(msg->msg_info.msg_type, SSL3_MT_NEWSESSION_TICKET)
                || !TEST_false(ossl_list_record_number_is_empty(&msg->rec_nums)))
                goto end;
        }

        /* The KeyUpdate itself must still have been acknowledged. */
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_int_eq(SSL_get_state(client), TLS_ST_OK)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0))
            goto end;

        /* The preserved tickets must still be retransmittable, and be ACKed. */
        sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(),
            ossl_seconds2time(1));
        if (!TEST_true(SSL_handle_events(server)))
            goto end;
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            /* A retransmitted ticket must not reach the application twice. */
            || !TEST_int_eq(ticket_count, 2)
            || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
            goto end;

        /* With the replacement ACKs delivered the flight is finally retired. */
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
            || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout))
            || !TEST_true(SSL_handle_events(server)))
            goto end;

        /* Application data must still flow in both directions. */
        if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
            || !TEST_int_eq(SSL_read(client, buf, 1), 1)
            || !TEST_uchar_eq(buf[0], 's')
            || !TEST_int_eq(SSL_write(client, "c", 1), 1)
            || !TEST_int_eq(SSL_read(server, buf, 1), 1)
            || !TEST_uchar_eq(buf[0], 'c'))
            goto end;
    } else {
        /*
         * Let the ticket ACKs through so that the server's flight retires.
         * Only the client is then left holding an outstanding flight.
         */
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
            || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
            goto end;

        /* The client sends a KeyUpdate and waits for its ACK. */
        if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
            goto end;
        ret = SSL_do_handshake(client);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
            goto end;
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
            goto end;

        /* Lose the ACK, leaving the KeyUpdate outstanding on the client. */
        dropped = 0;
        while (BIO_read(SSL_get_rbio(client), buf, sizeof(buf)) > 0)
            dropped++;
        if (!TEST_int_gt(dropped, 0)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
            goto end;
        timeout = cc->d1->next_timeout = ossl_time_add(ossl_time_now(),
            ossl_seconds2time(3600));

        /*
         * The ticket has to be a fresh one. A retransmission is dropped on
         * handshake_read_seq before tls_process_new_session_ticket() runs, so
         * it would never reach the code under test.
         */
        if (!TEST_true(SSL_new_session_ticket(server))
            || !TEST_int_eq(SSL_do_handshake(server), 1))
            goto end;

        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            /* Proves a genuinely new ticket was processed, not a duplicate. */
            || !TEST_int_eq(ticket_count, 3)
            /* The KeyUpdate and its retransmit timer must have survived. */
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1)
            || !TEST_int_eq(ossl_time_compare(cc->d1->next_timeout, timeout), 0)
            || !TEST_true(dtls_any_sent_messages_are_missing_acknowledge(cc))
            || !TEST_ptr(item = pqueue_peek(&cc->d1->sent_messages)))
            goto end;
        msg = item->data;
        if (!TEST_uchar_eq(msg->msg_info.msg_type, SSL3_MT_KEY_UPDATE))
            goto end;

        /*
         * Preserving the queued KeyUpdate and its timer is not enough on its
         * own. RFC 9147 section 8 requires the KeyUpdate to be acknowledged
         * before its new keys are used for anything else, and section 5.8.4
         * requires it to be acknowledged before another KeyUpdate is sent --
         * both restrictions must survive the unrelated ticket too.
         */
        if (!TEST_int_eq(SSL_get_state(client), TLS_ST_CW_KEY_UPDATE))
            goto end;

        /*
         * The ticket's ACK isn't held back like new content would be, so
         * it already reached the server. That's harmless: the server's
         * own flight was already retired above, so the ACK matches
         * nothing there.
         */
        if (!TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
            goto end;

        /*
         * The server's own read epoch already advanced when it processed
         * the client's KeyUpdate above, so this ACK -- sent at the client's
         * still-unbumped write epoch -- now only authenticates via the
         * server's retained previous read epoch.
         */
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
            goto end;

        /* A second KeyUpdate must be refused while the first is unacked. */
        if (!TEST_false(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
            goto end;

        /*
         * Application data must not leak out under the new epoch's keys
         * either: an attempt to write should not succeed while the
         * KeyUpdate is unacknowledged, and nothing new should reach the
         * wire.
         */
        ret = SSL_write(client, "x", 1);
        if (!TEST_int_le(ret, 0)
            || !TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * read_state_machine() reaches dtls1_stop_timer() from its post-process path
 * too, not just from MSG_PROCESS_FINISHED_READING: a post-handshake
 * CertificateRequest completes via tls_prepare_client_certificate(), which
 * returns WORK_FINISHED_STOP while hand_state is TLS_ST_CR_CERT_REQ. A client
 * holding an unacknowledged KeyUpdate must not lose it when that request
 * arrives.
 */
static int test_dtls13_cert_req_preserves_flight(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    dtls_sent_msg *msg;
    piterator iter;
    pitem *item;
    unsigned char buf[2048];
    int ret, dropped, found, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        /* No tickets, so the only outstanding flight is the one we create. */
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    if (!TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0))
        goto end;

    /*
     * The client sends a KeyUpdate and waits for its ACK. Lose the
     * KeyUpdate itself, not just its ACK, so the server's own read epoch
     * never advances
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
        goto end;
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
        goto end;

    /* Now request post-handshake authentication. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * The client does not answer with its empty Certificate and Finished
     * yet: RFC 9147 section 8 means the still-unacknowledged KeyUpdate's new
     * keys must not be used for anything else, so that response is held
     * back rather than built and sent unacknowledged. Only the KeyUpdate is
     * still outstanding.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(cc->d1->next_timeout)))
        goto end;
    found = 0;
    iter = pqueue_iterator(&cc->d1->sent_messages);
    while ((item = pqueue_next(&iter)) != NULL) {
        msg = item->data;

        if (msg->msg_info.msg_type == SSL3_MT_KEY_UPDATE
            && !ossl_list_record_number_is_empty(&msg->rec_nums))
            found++;
    }
    if (!TEST_int_eq(found, 1))
        goto end;

    /*
     * Not discarding the KeyUpdate is not enough on its own: RFC 9147
     * section 8 requires it to be acknowledged before its new keys are
     * used for anything else -- the PHA response is no exception, which is
     * exactly why it was held back rather than sent -- and section 5.8.4
     * requires it to be acknowledged before another KeyUpdate is sent.
     */
    if (!TEST_int_eq(SSL_get_state(client), TLS_ST_CW_KEY_UPDATE))
        goto end;

    /* Nothing has been transmitted for the deferred PHA response either. */
    if (!TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    if (!TEST_false(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    /*
     * Application data must not leak out under the new epoch's keys
     * either: an attempt to write should not succeed while the KeyUpdate
     * is unacknowledged, and nothing new should reach the wire.
     */
    ret = SSL_write(client, "x", 1);
    if (!TEST_int_le(ret, 0)
        || !TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /*
     * Recover the lost KeyUpdate by retransmission. The server never saw
     * the original, so its read epoch is still where it started and this
     * authenticates normally, producing a genuine, fresh ACK.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client)))
        goto end;
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Once that ACK is processed, the KeyUpdate is fully acknowledged, and
     * the held-back PHA response resumes: it is finally built and sent.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 2)
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_CW_FINISHED)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /* Confirm it is a genuine, processable PHA response, not just bytes. */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A post-handshake authentication response (Certificate + Finished) and a
 * KeyUpdate sent at the same epoch, before either is acknowledged, are
 * written under the identical set of keys. An unrelated NewSessionTicket
 * exchange must not discard a still-unacknowledged flight, so both of these
 * can end up queued together, unacknowledged, at the same time.
 *
 * idx 0: both are eventually acknowledged in a single exchange -- cleaning
 * them up together must not release whatever they share more than once.
 * idx 1: only the PHA response is acknowledged while the KeyUpdate remains
 * outstanding, and a second, unrelated ticket triggers cleanup of the now-
 * acknowledged response while the KeyUpdate stays queued -- the KeyUpdate
 * must still retransmit correctly afterward.
 */
static int test_dtls13_pha_keyupdate_shared_wrl(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *cc;
    dtls_sent_msg *msg;
    piterator iter;
    pitem *item;
    const void *wrl_finished = NULL, *wrl_keyupdate = NULL;
    unsigned char buf[2048];
    int ret, dropped, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    cc = SSL_CONNECTION_FROM_SSL(client);

    /* Trigger PHA: server requests, client responds with Certificate+Finished. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 2))
        goto end;

    /* Server processes the response and ACKs it; drop that ACK. */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;
    dropped = 0;
    while (BIO_read(SSL_get_rbio(client), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /*
     * A fresh ticket, processed while the PHA response is still unacked,
     * must not discard it.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_OK)
        || !TEST_int_eq(ticket_count, 1)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 2))
        goto end;

    /*
     * Retransmit the still-unacked PHA response now, while the server has
     * not yet seen any KeyUpdate and so can still authenticate it at its
     * current epoch. This replacement ACK is not itself the point under
     * test -- it just needs to still be unread when the epoch moves on.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client)))
        goto end;
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /*
     * Now the application requests a KeyUpdate. It is sent under the
     * current epoch's keys; those write keys are not superseded until this
     * KeyUpdate is itself acknowledged, so the epoch does not change yet.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 3))
        goto end;

    /*
     * Confirm the premise: Finished and KeyUpdate share the same saved
     * write record layer. The KeyUpdate's own new write keys are not
     * installed until it is acknowledged, so at this point both messages
     * are still sitting under that one, current write layer.
     */
    iter = pqueue_iterator(&cc->d1->sent_messages);
    while ((item = pqueue_next(&iter)) != NULL) {
        msg = item->data;
        if (msg->msg_info.msg_type == SSL3_MT_FINISHED)
            wrl_finished = msg->saved_retransmit_state.wrl;
        else if (msg->msg_info.msg_type == SSL3_MT_KEY_UPDATE)
            wrl_keyupdate = msg->saved_retransmit_state.wrl;
    }
    if (!TEST_ptr(wrl_finished) || !TEST_ptr_eq(wrl_finished, wrl_keyupdate))
        goto end;

    /*
     * Read the replacement ACK for Certificate+Finished, pending since
     * before the KeyUpdate was sent. KeyUpdate is still outstanding, so
     * this alone must not clear anything out yet.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 3))
        goto end;

    if (idx == 0) {
        /*
         * Let the server also process and ACK the KeyUpdate. Once the
         * client reads that ACK, every sent message is fully acknowledged
         * at the same time, so Certificate, Finished and KeyUpdate are all
         * cleaned up together in one pass.
         */
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
            goto end;
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0))
            goto end;

        /* If that didn't already crash, keep using the connection. */
        if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
            || !TEST_int_eq(SSL_read(client, buf, 1), 1)
            || !TEST_uchar_eq(buf[0], 's')
            || !TEST_int_eq(SSL_write(client, "c", 1), 1)
            || !TEST_int_eq(SSL_read(server, buf, 1), 1)
            || !TEST_uchar_eq(buf[0], 'c'))
            goto end;
    } else {
        /*
         * Do not let the server see the KeyUpdate yet. A second, distinct
         * ticket, processed while the KeyUpdate is still outstanding,
         * causes Certificate and Finished -- now fully acked -- to be
         * cleaned up while the KeyUpdate stays queued. The client must
         * still correctly report that it is waiting on the KeyUpdate's own
         * ACK, rather than treating the connection as idle just because the
         * ticket's ACK was sent.
         */
        if (!TEST_true(SSL_new_session_ticket(server))
            || !TEST_int_eq(SSL_do_handshake(server), 1))
            goto end;
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
            || !TEST_int_eq(SSL_get_state(client), TLS_ST_CW_KEY_UPDATE)
            || !TEST_int_eq(ticket_count, 2)
            || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1))
            goto end;

        /*
         * Force a retransmit of the KeyUpdate, resending it under the
         * original epoch's keys, then confirm the connection still works
         * correctly by continuing to use it afterward.
         */
        cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
        if (!TEST_true(SSL_handle_events(client)))
            goto end;
        ret = SSL_read(server, buf, 1);
        if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
            goto end;
    }

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * If the server sends a CertificateRequest followed by a ticket that gets
 * lost, the client's next flight -- Certificate and Finished -- implicitly
 * acks only the request. Processing that flight must retire the request,
 * but must not also discard the unrelated, still unacknowledged ticket or
 * stop its retransmission.
 */
static int test_dtls13_cert_req_finished_preserves_ticket(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    dtls_sent_msg *msg;
    piterator iter;
    pitem *item;
    unsigned char buf[2048];
    int ret, dropped, found, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    /* Request PHA first; the client answers it before the ticket exists. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The client answers the CertificateRequest with Certificate+Finished. */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Now send a ticket -- sequenced after the CertificateRequest -- and
     * lose it before the client ever sees it.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2))
        goto end;
    dropped = 0;
    while (BIO_read(SSL_get_rbio(client), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /*
     * The server processes the client's response. This must retire the
     * CertificateRequest, but must not touch the still-unacknowledged,
     * unrelated ticket.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;
    found = 0;
    iter = pqueue_iterator(&sc->d1->sent_messages);
    while ((item = pqueue_next(&iter)) != NULL) {
        msg = item->data;

        if (msg->msg_info.msg_type == SSL3_MT_NEWSESSION_TICKET)
            found++;
    }
    if (!TEST_int_eq(found, 1))
        goto end;

    /*
     * Confirm the surviving entry is a genuinely live retransmit, not just
     * an uncollected leftover: force it and let the client process it.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server)))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(ticket_count, 1))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * rfc9147 section 7.1 lets the client ACK a CertificateRequest explicitly
 * if it cannot produce its response right away, rather than only ever
 * completing it implicitly by eventually answering with Certificate and
 * Finished. If that explicit ACK happens before Finished arrives,
 * dtls1_retire_sent_certificate_request_messages() finds nothing left to
 * retire when Finished is later processed -- that must not stop a
 * different, still-unacknowledged ticket from being preserved.
 */
static int test_dtls13_cert_req_explicit_ack_preserves_ticket(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    dtls_sent_msg *msg;
    DTLS1_RECORD_NUMBER *recnum;
    piterator iter;
    pitem *item;
    unsigned char buf[2048], ack[18];
    WPACKET pkt;
    uint64_t epoch, seqnum;
    size_t acklen, written;
    int ret, dropped, found, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /* Request PHA; this sends just the CertificateRequest. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * The client ACKs the CertificateRequest explicitly instead of
     * answering it yet, modelling the rfc9147 7.1 case. Construct that
     * ACK directly against the CertificateRequest's own record number,
     * the same way test_dtls13_ack_coverage() constructs synthetic ACKs.
     */
    iter = pqueue_iterator(&sc->d1->sent_messages);
    if (!TEST_ptr(item = pqueue_next(&iter)))
        goto end;
    msg = item->data;
    if (!TEST_ptr(recnum = ossl_list_record_number_head(&msg->rec_nums)))
        goto end;
    epoch = recnum->epoch;
    seqnum = recnum->seqnum;
    if (!TEST_true(WPACKET_init_static_len(&pkt, ack, sizeof(ack), 2))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, epoch))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, seqnum))
        || !TEST_true(WPACKET_finish(&pkt))
        || !TEST_true(WPACKET_get_total_written(&pkt, &acklen))) {
        WPACKET_cleanup(&pkt);
        goto end;
    }
    WPACKET_cleanup(&pkt);
    if (!TEST_int_eq(dtls1_write_bytes(cc, SSL3_RT_ACK, ack, acklen, &written), 1)
        || !TEST_size_t_eq(written, acklen)
        || !TEST_int_gt(BIO_flush(cc->wbio), 0))
        goto end;

    /*
     * The server processes that explicit ACK. The CertificateRequest is
     * now gone via ordinary ACK processing, not via the Finished-triggered
     * retire exercised below.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
        goto end;

    /*
     * The client, which never saw the explicit ACK above (it was
     * constructed directly against the server's view of what it sent),
     * still answers the CertificateRequest itself with Certificate and
     * Finished. This must happen before the ticket below is sent and
     * dropped: the CertificateRequest datagram is otherwise still
     * sitting unread in the client's rbio, and draining the rbio for the
     * ticket would discard it too, along with this response.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Now send a ticket -- sequenced after the CertificateRequest -- and
     * lose it before the client ever sees it. The client's response above
     * is already sitting unprocessed in the server's rbio at this point.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;
    dropped = 0;
    while (BIO_read(SSL_get_rbio(client), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /*
     * The server processes the client's response, reaching
     * TLS_ST_SR_FINISHED.
     * dtls1_retire_sent_certificate_request_messages() finds nothing to
     * retire here -- the CertificateRequest is already gone, from the
     * explicit ACK above -- which must not stop the still-unacknowledged,
     * unrelated ticket from being preserved.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;
    found = 0;
    iter = pqueue_iterator(&sc->d1->sent_messages);
    while ((item = pqueue_next(&iter)) != NULL) {
        msg = item->data;

        if (msg->msg_info.msg_type == SSL3_MT_NEWSESSION_TICKET)
            found++;
    }
    if (!TEST_int_eq(found, 1))
        goto end;

    /*
     * Confirm the surviving entry is a genuinely live retransmit, not just
     * an uncollected leftover: force it and let the client process it.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server)))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(ticket_count, 1))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same protections apply symmetrically when the server is the one with
 * an outstanding KeyUpdate: its new write keys are not installed until its
 * own KeyUpdate is acknowledged (see the deferred-install logic in
 * dtls_process_ack() and the TLS_ST_SW_KEY_UPDATE/TLS_ST_CW_KEY_UPDATE
 * post-work cases), so it must still refuse to start a second KeyUpdate of
 * its own in that window.
 *
 * It must NOT, however, hold back acknowledging whatever the peer sends it
 * meanwhile: since its own new keys are not installed yet, that
 * acknowledgment goes out under its current, still-valid keys, which RFC
 * 9147 section 8 never restricted.
 *
 * Here the server's own KeyUpdate is unacknowledged when the client
 * independently sends its own, unrelated KeyUpdate.
 */
static int test_dtls13_server_keyupdate_preserves_ack(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048];
    uint64_t s_wepoch, c_wepoch;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    s_wepoch = dtls1_get_epoch(sc, SSL3_CC_WRITE);
    c_wepoch = dtls1_get_epoch(cc, SSL3_CC_WRITE);

    /*
     * The server sends a KeyUpdate and waits for its ACK. Its write epoch
     * must not advance yet -- the new keys are held back until the ACK
     * arrives.
     */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), s_wepoch))
        goto end;

    /*
     * The client independently sends its own, unrelated KeyUpdate to the
     * server, without ever reading the server's KeyUpdate. This is not a
     * response to anything the server sent -- it just needs to arrive
     * while the server's own KeyUpdate is outstanding. Same deal: the
     * client's write epoch must not advance until its own KeyUpdate is
     * acknowledged.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), c_wepoch))
        goto end;

    /*
     * The server processes the client's KeyUpdate and immediately
     * acknowledges it under its current, still-valid keys rather than
     * holding it back. In the same call, it also receives the client's
     * acknowledgment of the server's own KeyUpdate -- sent by the client
     * back in the previous step, at the client's own still-current epoch,
     * and only decryptable here because the server retains its previous
     * read epoch's keys (see the retained-previous-read-epoch fix this PR
     * is stacked on: it lets an old-epoch ACK that arrives after the read
     * epoch has already moved on still authenticate, rather than being
     * silently dropped). That completes the server's own KeyUpdate too:
     * both sides are now fully resolved, with no deadlock, in just this
     * one call.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), s_wepoch + 1))
        goto end;

    /*
     * The client processes the server's KeyUpdate, acknowledging it
     * immediately for the same reason, and in the same call also
     * processes the server's acknowledgment of the client's own
     * KeyUpdate (sent by the server just above). That completes the
     * client's KeyUpdate too: its new write keys are installed and its
     * retransmit entry is retired.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), c_wepoch + 1))
        goto end;

    /* Confirm both newly installed write keys actually work. */
    if (!TEST_int_eq(SSL_write(client, "c", 1), 1))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(ret, 1) || !TEST_mem_eq(buf, 1, "c", 1))
        goto end;
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(ret, 1) || !TEST_mem_eq(buf, 1, "s", 1))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The server's own KeyUpdate can also become outstanding while a
 * post-handshake authentication exchange it started is still in progress.
 * Completing that exchange must not acknowledge the client's response, or
 * issue a new ticket, under the KeyUpdate's new, unconfirmed keys -- both
 * must wait until the KeyUpdate is itself acknowledged.
 *
 * This does not need to separately cover the server proactively issuing a
 * new CertificateRequest or ticket of its own while its KeyUpdate is
 * outstanding: SSL_verify_client_post_handshake() and
 * SSL_new_session_ticket() both already refuse to start a new one while
 * the connection is still mid-handshake-activity for any reason, which an
 * unacknowledged KeyUpdate always is. That path never becomes reachable,
 * so there is nothing to hold back there.
 */
static int test_dtls13_server_keyupdate_preserves_pha(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    unsigned char buf[2048];
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    /* Request PHA first, and let the client answer it. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Now send the server's own KeyUpdate. Processing it also reads the
     * client's already-waiting response in the same call, so completing
     * PHA and sending the KeyUpdate happen together here. The KeyUpdate
     * itself is expected on the wire to the client -- what must NOT also
     * go out is the completed PHA exchange's own acknowledgment, since
     * the server's KeyUpdate is still unacknowledged at this point. The
     * server's retransmit queue holding exactly the KeyUpdate (not also
     * an ACK) confirms that.
     */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The client reads the server's KeyUpdate and acknowledges it. */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose that acknowledgment, leaving the KeyUpdate outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * Recover the KeyUpdate by retransmission. The client already
     * processed the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server)))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Once that acknowledgment is processed, the KeyUpdate is fully
     * acknowledged, and the held-back acknowledgment of the PHA response
     * resumes: it is finally sent.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /* Confirm it is genuine, processable data, not just bytes. */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The server's own KeyUpdate being deferred-resumed after a post-handshake
 * authentication exchange must resume by actually sending the held-back
 * ACK, not by reprocessing TLS_ST_SR_FINISHED from scratch. The latter sees
 * post_handshake_auth already advanced past SSL_PHA_REQUESTED on this
 * second pass, takes the ordinary "no ticket" branch, and overwrites
 * deferred_ack_state -- silently dropping a NewSessionTicket that the first,
 * PHA pass had already decided to issue.
 */
static int test_dtls13_server_keyupdate_preserves_pha_ticket(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    unsigned char buf[2048];
    size_t sent_tickets, new_quota;
    int i, ret, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);

    /*
     * create_ssl_connection() only has the client read (and thus ACK) the
     * initial handshake's NewSessionTicket messages; the server never reads
     * those ACKs. Drain them here so sent_messages starts out empty, rather
     * than carrying two leftover, unacked ticket entries into the scenario
     * below.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
        goto end;

    /* The initial handshake already issued its configured ticket quota. */
    sent_tickets = sc->sent_tickets;
    if (!TEST_size_t_gt(sent_tickets, 0)
        || !TEST_int_eq(ticket_count, (int)sent_tickets))
        goto end;

    /*
     * Raise the ticket quota. tls_post_process_client_certificate() is
     * going to reset sc->sent_tickets to 0 once it processes the PHA
     * response's Certificate below ("resend session tickets" on
     * re-authentication), so this is not "one extra ticket" -- it is the
     * quota the server will fully reissue from scratch, since num_tickets
     * > sent_tickets(==0) again once that reset happens.
     */
    new_quota = sent_tickets + 1;
    if (!TEST_true(SSL_set_num_tickets(server, new_quota)))
        goto end;

    /*
     * Request PHA first, and let the client answer it. The ticket-issuing
     * branch under test (ossl_statem_server13_write_transition()'s
     * TLS_ST_SR_FINISHED case) skips issuing a ticket outright whenever
     * SSL_VERIFY_PEER is set with no sid_ctx configured -- unrelated to the
     * KeyUpdate defer/resume logic under test, but SSL_VERIFY_PEER is
     * required to make the server actually request a client certificate
     * for PHA, so a sid_ctx must be set too.
     */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_set_session_id_context(server,
            (const unsigned char *)"pha_ticket_test", 15)))
        goto end;
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Send the server's own KeyUpdate. Processing it also reads the
     * client's already-waiting PHA response in the same call, deciding to
     * reissue the ticket quota -- but holding both that and the PHA
     * response's own ACK back behind the still-unacknowledged KeyUpdate.
     */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The client reads the server's KeyUpdate and acknowledges it. */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes that ACK. Its own KeyUpdate is now fully
     * acknowledged, so both the held-back PHA-response ACK and the full
     * reissued ticket quota decided above must now actually be sent.
     * TLS_ST_SW_SESSION_TICKET's write_transition case keeps constructing
     * tickets, once resumed, until sent_tickets reaches num_tickets again
     * (SSL_IS_FIRST_HANDSHAKE() stays true throughout this connection) --
     * i.e. sc->sent_tickets ends at new_quota, not at 1.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(server), TLS_ST_OK)
        || !TEST_size_t_eq(sc->sent_tickets, new_quota)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /*
     * The pending bytes above are not just the tickets: the held-back ACK
     * for the client's PHA Finished must itself have actually been
     * constructed and sent, not silently skipped in favour of jumping
     * straight to the tickets. dtls_construct_ack() drains
     * sc->d1->ack_rec_num as it writes each entry, so a still-pending
     * entry here means the resume reached TLS_ST_SW_ACK without ever
     * dispatching to it for construction.
     */
    if (!TEST_true(ossl_list_record_number_is_empty(&sc->d1->ack_rec_num)))
        goto end;

    /*
     * Confirm these are genuine, processable tickets, not just bytes.
     * Mirror create_ssl_connection_ex()'s pattern for the initial
     * handshake's own tickets: one SSL_read() per ticket, not a single call
     * draining all of them.
     */
    for (i = 0; i < (int)new_quota; i++) {
        ret = SSL_read(client, buf, 1);
        if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
            goto end;
    }
    if (!TEST_int_eq(ticket_count, (int)(sent_tickets + new_quota)))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * ossl_statem_server13_write_transition()'s top-of-function ack_for_retransmit
 * handling and its deferred-KeyUpdate resume handling (see
 * test_dtls13_server_keyupdate_preserves_pha_ticket() above) both use
 * st->deferred_ack_state, for two different purposes: the former saves
 * st->hand_state there to come back to after re-ACKing a stale
 * retransmission without reprocessing it; the latter saves there what
 * should happen once the held-back PHA-response ACK is finally sent (here,
 * issuing the reissued ticket quota).
 *
 * While the server is parked at TLS_ST_SW_KEY_UPDATE waiting for its own
 * KeyUpdate to be acknowledged, with deferred_ack_state holding that
 * ticket continuation, an entirely ordinary DTLS retransmission -- the
 * client's retransmit timer for its own still-unacknowledged PHA response
 * firing, because the server is deliberately holding that ACK back --
 * takes the ack_for_retransmit path and overwrites deferred_ack_state with
 * TLS_ST_SW_KEY_UPDATE (st->hand_state at that moment). The ticket
 * continuation is lost. Once the KeyUpdate is finally acknowledged, the
 * resume sends the held-back ACK correctly, but then reads the clobbered
 * deferred_ack_state back into hand_state, hits the
 * "already sent, don't construct another" guard for TLS_ST_SW_KEY_UPDATE,
 * and parks there permanently: deferred_key_update_state is already
 * TLS_ST_BEFORE by this point, so nothing will ever resume it again. The
 * ticket is never sent and the server's write side never reaches
 * TLS_ST_OK.
 */
static int test_dtls13_server_keyupdate_pha_ticket_survives_retransmit(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048];
    size_t sent_tickets, new_quota;
    int ret, testresult = 0;

    ticket_count = 0;
    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    SSL_CTX_set_session_cache_mode(cctx, SSL_SESS_CACHE_CLIENT);
    SSL_CTX_sess_set_new_cb(cctx, count_ticket);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /*
     * create_ssl_connection() only has the client read (and thus ACK) the
     * initial handshake's NewSessionTicket messages; the server never
     * reads those ACKs. Drain them here so sent_messages starts empty.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
        goto end;

    /* The initial handshake already issued its configured ticket quota. */
    sent_tickets = sc->sent_tickets;
    if (!TEST_size_t_gt(sent_tickets, 0)
        || !TEST_int_eq(ticket_count, (int)sent_tickets))
        goto end;

    /*
     * Raise the ticket quota. tls_post_process_client_certificate() resets
     * sc->sent_tickets to 0 once it processes the PHA response's
     * Certificate below, so the server reissues this whole quota once
     * Finished is processed and num_tickets > sent_tickets(==0) again.
     */
    new_quota = sent_tickets + 1;
    if (!TEST_true(SSL_set_num_tickets(server, new_quota)))
        goto end;

    /* Request PHA first, and let the client answer it. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_set_session_id_context(server,
            (const unsigned char *)"pha_ticket_test", 15)))
        goto end;
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * The client answers the CertificateRequest with Certificate and
     * Finished, sitting unprocessed in the server's rbio for now.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Send the server's own KeyUpdate. Processing it also reads the
     * client's already-waiting PHA response in the same call, deciding to
     * reissue the ticket quota -- but holding both that and the PHA
     * response's own ACK back behind the still-unacknowledged KeyUpdate.
     */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * Before the server's own KeyUpdate is acknowledged, the client's
     * retransmit timer for its still-unacknowledged PHA response fires --
     * an entirely ordinary DTLS retransmission, not an adversarial one --
     * and it resends Certificate and Finished.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(),
        ossl_seconds2time(1));
    if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
        goto end;

    /*
     * The server recognizes this as a retransmission of an
     * already-processed message and takes the ack_for_retransmit path to
     * re-ACK it without reprocessing, while still parked at
     * TLS_ST_SW_KEY_UPDATE waiting for its own KeyUpdate's ACK.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* The client reads the server's KeyUpdate and acknowledges it. */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes that ACK. Its own KeyUpdate is now fully
     * acknowledged, so both the held-back PHA-response ACK and the full
     * reissued ticket quota decided above must now actually be sent --
     * this is exactly what the ack_for_retransmit interleaving above must
     * not be able to prevent.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(server), TLS_ST_OK)
        || !TEST_size_t_eq(sc->sent_tickets, new_quota)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * dtls_process_ack() must not install a pending KeyUpdate's new write keys
 * merely because the KeyUpdate's own record was acknowledged. RFC 9147
 * section 7 lets a peer ACK a buffered message before it has processed the
 * messages that precede it, so an ACK of the KeyUpdate alone does not
 * establish that the peer has processed everything sent before it and
 * installed the corresponding read keys. Erratum 8047 requires waiting for
 * every preceding message to be acknowledged too.
 *
 * The server sends a ticket, then -- without waiting for it to be
 * acknowledged -- a KeyUpdate, both still at the current write epoch. Only
 * the KeyUpdate datagram is delivered, so the client buffers it ahead of
 * the still-missing ticket and does not install new read keys; the record
 * is merely queued on its ACK list. Forcing the client to flush that
 * queued ACK immediately, before the ticket ever arrives, models a peer
 * acknowledging a buffered record it has not actually processed (OpenSSL's
 * own client would not otherwise flush it until the next in-order
 * message). The server must still withhold its new write keys, because the
 * ticket sent before the KeyUpdate remains unacknowledged.
 *
 * The ticket's retransmit timer is then forced, so the still-unacknowledged
 * ticket (and only the ticket -- the already-acknowledged KeyUpdate is not
 * retransmitted, per rfc9147) goes out again. The client processes it and
 * acknowledges it. The KeyUpdate it had buffered ahead of the ticket is now
 * unblocked -- dtls1_has_buffered_ready_message() is what lets the same
 * read that just handled the ticket loop back and dispatch it too, instead
 * of stranding it until some unrelated new record happens to arrive later.
 * Once the ticket's ACK arrives, everything is finally acknowledged, and
 * the server must install its new write keys; application data must then
 * flow normally both ways, since the client's own read epoch was updated
 * when it processed the KeyUpdate above.
 */
static int test_dtls13_keyupdate_ack_defers_write_keys(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char discard[2048], buf;
    uint64_t epoch_before;
    unsigned short seq_before;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* Send a ticket, then a KeyUpdate the client never gets to see yet. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /* Drop the ticket datagram; the KeyUpdate datagram is still queued behind it. */
    if (!TEST_int_gt(BIO_read(SSL_get_rbio(client), discard, sizeof(discard)), 0))
        goto end;

    /* The client buffers the out-of-order KeyUpdate rather than processing it. */
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->rcvd_messages), 1)
        || !TEST_ptr(ossl_list_record_number_head(&cc->d1->ack_rec_num)))
        goto end;

    /*
     * Force the client to flush that queued ACK now, as though it were
     * acknowledging the buffered KeyUpdate on receipt rather than once it
     * is actually processed.
     */
    cc->statem.ack_for_retransmit = 1;
    ossl_statem_set_in_init(cc, 1);
    ret = SSL_do_handshake(client);
    if (ret != 1 && !TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The KeyUpdate's own record is now acknowledged, but the ticket sent
     * before it is not. The new write keys must still be withheld.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * The ticket is still outstanding, so its retransmit timer is still
     * armed. Force it: the ticket goes out again, but the already-acked
     * KeyUpdate entry does not -- dtls1_retransmit_sent_messages() skips
     * anything with an empty record-number list.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /*
     * The client processes the retransmitted ticket -- now, finally, in
     * order -- and acknowledges it. The KeyUpdate it had buffered ahead of
     * the ticket is dispatched in this same call too: handshake_read_seq
     * advances by 2 (ticket, then KeyUpdate), and the reassembly buffer
     * drains completely rather than leaving the KeyUpdate stranded.
     */
    seq_before = cc->d1->handshake_read_seq;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq((int)cc->d1->handshake_read_seq, (int)seq_before + 2)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->rcvd_messages), 0))
        goto end;

    /*
     * The server processes the ticket's ACK: everything is now
     * acknowledged, so the deferred write keys must finally be installed.
     */
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /*
     * Application data now flows both ways: the client's own read epoch
     * was updated when it processed the KeyUpdate above.
     */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same deferred-write-key guarantee as
 * test_dtls13_keyupdate_ack_defers_write_keys() above, exercised end to end
 * without ever buffering anything out of order: the ticket is delivered and
 * processed normally, but its ACK specifically is what gets lost in
 * transit. The KeyUpdate sent after it is delivered and acknowledged
 * normally too, so the server ends up seeing exactly the preconditions
 * comment 1 is about -- the KeyUpdate's record acknowledged, the earlier
 * ticket's not -- through perfectly ordinary message delivery, nothing
 * buffered out of order at all.
 *
 * Recovering the lost ACK via the ticket's own retransmit timer -- the same
 * mechanism test_dtls13_cert_req_explicit_ack_preserves_ticket() already
 * proves elsewhere in this file, where a retransmission is recognized and
 * freshly acknowledged rather than reprocessed -- then lets both the
 * deferred write-key install and bidirectional application data be
 * verified completely: the client's own read epoch was already updated
 * when it processed the KeyUpdate in order, so unlike the sibling test
 * above there is nothing left needing a further trigger to catch up.
 */
static int test_dtls13_keyupdate_ack_defers_write_keys_ticket_ack_lost(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    unsigned char discard[2048], buf;
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The KeyUpdate is sent, delivered, and acknowledged normally too. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The KeyUpdate is acknowledged, but the ticket sent before it is
     * not -- its ACK never arrived. The new write keys must still be
     * withheld.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Force the ticket's retransmit timer. The client already processed
     * the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes the fresh ACK: everything is now acknowledged,
     * so the deferred write keys must finally be installed.
     */
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1)
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /*
     * Application data flows both ways: the client's own read epoch was
     * already updated when it processed the KeyUpdate above, in order, so
     * this needs no further trigger to catch up.
     */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A ticket's ACK is lost, and the server's own KeyUpdate is then sent and
 * acknowledged normally, so it is correctly withheld behind that
 * still-unacknowledged ticket. The client then sends its own, independent
 * KeyUpdate; the server processing that finishes a read flight, which
 * clears the server's own, now fully-acknowledged KeyUpdate entry out of
 * sent_messages, leaving only the still-unacknowledged ticket behind.
 * Recovering the ticket's ACK after that must still install the deferred
 * write key, even though the KeyUpdate's own entry no longer exists in
 * sent_messages to be found.
 */
static int test_dtls13_keyupdate_ack_survives_entry_eviction(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    unsigned char discard[2048], buf;
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The server's KeyUpdate is sent, delivered, and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The KeyUpdate is acknowledged, but the ticket sent before it is not.
     * The new write keys must still be withheld -- same as the sibling
     * test up to this point.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Now the client sends its own KeyUpdate. The server processing it
     * finishes a read flight, which clears the server's own,
     * already-acknowledged KeyUpdate entry out of sent_messages -- the
     * queue drops from two entries to one, leaving only the still-
     * unacknowledged ticket.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /* The server's own KeyUpdate is still logically pending. */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /* Let the client see the server's ACK of its KeyUpdate. */
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Force the ticket's retransmit timer. The client already processed
     * the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes the fresh ACK: everything is now acknowledged,
     * so the deferred write keys must finally be installed -- even though
     * the KeyUpdate's own sent_messages entry was evicted before this
     * point.
     */
    ret = SSL_read(server, &buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1))
        goto end;

    /* Application data now flows both ways under the new keys. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, &buf, 1), 1)
        || !TEST_uchar_eq(buf, 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same entry-eviction scenario as
 * test_dtls13_keyupdate_ack_survives_entry_eviction() above, but with a
 * completed post-handshake authentication exchange as the trigger instead
 * of an inbound KeyUpdate from the peer: completing the client's PHA
 * response (Certificate + Finished) also finishes a read flight, the same
 * as processing that inbound KeyUpdate does in the sibling test.
 *
 * PHA must be requested before the server's own KeyUpdate even exists:
 * SSL_verify_client_post_handshake() refuses to start while any KeyUpdate
 * is still outstanding (see test_dtls13_server_keyupdate_preserves_pha()'s
 * doc comment above), so the reverse order used by the sibling test isn't
 * available here. The ticket being unacknowledged does not block it,
 * though, so that ordering constraint is the only one in play.
 *
 * To still isolate the KeyUpdate's send-and-ack cycle from the PHA
 * response -- rather than reading the response bundled into the same call
 * that sends the KeyUpdate, as the existing PHA tests do -- the client's
 * first PHA response is dropped before the server ever reads it. The
 * KeyUpdate is then sent and acknowledged on its own. Only afterward is
 * the client's still-unacknowledged response recovered, by forcing its own
 * retransmit timer: that recovery is what finishes the read flight and
 * evicts the server's already-acknowledged KeyUpdate entry, exactly as in
 * the sibling test, just reached by a different route.
 */
static int test_dtls13_keyupdate_ack_survives_pha_completion_eviction(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048];
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * Request PHA -- allowed, since an outstanding ticket alone is not
     * "mid-handshake-activity" the way an outstanding KeyUpdate is.
     */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2))
        goto end;

    /*
     * The client reads the CertificateRequest and immediately builds and
     * sends its Certificate + Finished response.
     */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Drop that response before the server ever sees it. This isolates the
     * server's own KeyUpdate, sent next, from being bundled together with
     * reading the PHA response in the same call, the way the existing PHA
     * tests do it -- the response is only delivered later, by the client's
     * own retransmit timer, once the KeyUpdate has already been fully
     * acknowledged.
     */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The server's own KeyUpdate is sent and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 3)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The KeyUpdate is acknowledged, but the ticket sent before it is not.
     * The new write keys must still be withheld. The PHA response's entry
     * is still sitting in sent_messages too, unacknowledged -- the server
     * never saw the client's first attempt.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Force the client to retransmit its still-unacknowledged PHA
     * response -- the server never saw the original.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /*
     * The server processes the recovered Certificate + Finished. This
     * finishes a read flight, which clears the server's own, already-
     * acknowledged KeyUpdate entry out of sent_messages -- leaving only the
     * still-unacknowledged ticket behind. PHA itself completes normally:
     * nothing here was waiting on the KeyUpdate's own ACK, only on the
     * ticket's, so the PHA response's ACK is not held back either.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * The server's own KeyUpdate is still logically pending -- even though
     * PHA just completed successfully and its ACK is already on the wire.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Application data flows both ways right now, under the client's
     * retained, still-current epoch -- demonstrating that this alone is
     * not proof the deferred key change completed.
     */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    /*
     * Force the ticket's retransmit timer. The client already processed
     * the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes the fresh ACK: everything is now acknowledged,
     * so the deferred write keys must finally be installed -- even though
     * the KeyUpdate's own sent_messages entry was evicted, by PHA
     * completion, before this point.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1))
        goto end;

    /* Application data still flows both ways, now under the new epoch. */
    if (!TEST_int_eq(SSL_write(server, "S", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'S')
        || !TEST_int_eq(SSL_write(client, "C", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'C'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same guarantee as
 * test_dtls13_keyupdate_ack_survives_pha_completion_eviction() above --
 * install succeeds once every message the KeyUpdate was withheld behind is
 * resolved -- but reached a different way. Here the CertificateRequest
 * itself is the only preceding message, and RFC 9147 section 7.2 lets it
 * be retired purely implicitly, by the client's Certificate + Finished
 * response, with no ACK record involved at all. No ticket is involved
 * either, so by the time that response is processed, sent_messages goes
 * completely empty in that same call -- nothing else is ever going to
 * arrive afterward to prompt a recheck, so the install has to happen as a
 * direct consequence of processing that response.
 */
static int test_dtls13_keyupdate_install_on_pha_cert_req_retirement(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048];
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* Request PHA -- nothing else is outstanding yet. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1))
        goto end;

    /*
     * The client reads the CertificateRequest and immediately builds and
     * sends its Certificate + Finished response.
     */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Drop that response before the server ever sees it -- it is never
     * explicitly ACKed in this test at all. Its eventual retirement is
     * only ever implicit, via RFC 9147 7.2.
     */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The server's own KeyUpdate is sent and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 2)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The KeyUpdate is acknowledged by an ordinary ACK record. The
     * CertificateRequest sent before it is the only thing still
     * outstanding -- and it was never, and will never be, explicitly
     * ACKed.
     */
    if (!TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Force the client to retransmit its still-unacknowledged PHA
     * response -- the server never saw the original.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /*
     * The server processes the recovered Certificate + Finished. This
     * implicitly retires the CertificateRequest (RFC 9147 7.2) -- no ACK
     * record is involved at all. With nothing else outstanding, the
     * sent_messages queue goes completely empty right here. The deferred
     * write key must be installed as a direct consequence of this, since
     * no ACK record will ever arrive to trigger it afterward.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0))
        goto end;

    if (!TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1))
        goto end;

    /* Application data flows both ways under the new epoch. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

#define PHA_ACK_STOPS_TIMER_MAX_RECS 4

/*
 * Split a buffer of concatenated DTLS 1.3 unified-header records -- as
 * produced by this stack's own writer, which always sets both the
 * sequence-number and length bits -- into its individual records' lengths,
 * so each can be delivered to the peer as its own separate datagram.
 */
static int split_unified_header_records(const unsigned char *in, size_t inlen,
    size_t reclen[PHA_ACK_STOPS_TIMER_MAX_RECS])
{
    size_t off = 0;
    int n = 0;

    while (off < inlen) {
        size_t len;

        if (n >= PHA_ACK_STOPS_TIMER_MAX_RECS
            || inlen - off < DTLS13_UNI_HDR_FIXED_LENGTH
            || !DTLS13_UNI_HDR_FIX_BITS_IS_SET(in[off])
            || DTLS13_UNI_HDR_CID_BIT_IS_SET(in[off])
            || !DTLS13_UNI_HDR_LEN_BIT_IS_SET(in[off])
            || !DTLS13_UNI_HDR_SEQ_BIT_IS_SET(in[off]))
            return -1;
        len = DTLS13_UNI_HDR_FIXED_LENGTH
            + (((size_t)in[off + 3] << 8) | in[off + 4]);
        if (inlen - off < len)
            return -1;
        reclen[n++] = len;
        off += len;
    }
    return n;
}

/*
 * dtls_process_ack() must stop the retransmission timer when an ACK
 * completes the outstanding flight even while the read sub-state-machine
 * is still mid-flight on an incomplete post-handshake authentication
 * response: returning MSG_PROCESS_CONTINUE_READING there bypasses the
 * dtls1_stop_timer_for_read_flight() call that ordinary flight completion
 * makes, so a fully-acknowledged flight's timer was otherwise left
 * running, eventually failing the connection with SSL_R_READ_TIMEOUT_EXPIRED
 * even though nothing was left to retransmit.
 *
 * The client's PHA response (an empty Certificate, then Finished) is split
 * into its individual records here and delivered one at a time -- OpenSSL
 * would otherwise coalesce them into one datagram -- so an explicit ACK of
 * the CertificateRequest (rfc9147 section 7.1) can be injected between
 * them, leaving the server mid-read (TLS_ST_SR_CERT) at the moment its own
 * flight becomes fully acknowledged.
 */
static int test_dtls13_pha_ack_stops_timer(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    dtls_sent_msg *msg;
    DTLS1_RECORD_NUMBER *recnum;
    piterator iter;
    pitem *item;
    unsigned char dgram[4096], ack[18], buf[256];
    size_t dgramlen, reclen[PHA_ACK_STOPS_TIMER_MAX_RECS], off;
    WPACKET pkt;
    uint64_t epoch, seqnum;
    size_t acklen, written;
    int ret, nrec, i, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /* Request PHA; this sends just the CertificateRequest. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* The CertificateRequest's own record number, to forge its ACK below. */
    iter = pqueue_iterator(&sc->d1->sent_messages);
    if (!TEST_ptr(item = pqueue_next(&iter)))
        goto end;
    msg = item->data;
    if (!TEST_ptr(recnum = ossl_list_record_number_head(&msg->rec_nums)))
        goto end;
    epoch = recnum->epoch;
    seqnum = recnum->seqnum;

    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Capture the client's PHA response without letting the server see any
     * of it yet, and split it into its individual records.
     */
    dgramlen = 0;
    while (BIO_ctrl_pending(SSL_get_rbio(server)) > 0) {
        ret = BIO_read(SSL_get_rbio(server), dgram + dgramlen,
            (int)(sizeof(dgram) - dgramlen));
        if (!TEST_int_gt(ret, 0))
            goto end;
        dgramlen += (size_t)ret;
    }
    nrec = split_unified_header_records(dgram, dgramlen, reclen);
    if (!TEST_int_ge(nrec, 2))
        goto end;

    /* Deliver only the Certificate. Hold the rest back. */
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(server), dgram, (int)reclen[0]),
            (int)reclen[0]))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->statem.hand_state, TLS_ST_SR_CERT)
        || !TEST_false(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /*
     * The explicit ACK, as permitted by rfc9147 section 7.1, arrives after
     * Certificate and before Finished -- while the server is still mid-read
     * of the PHA response.
     */
    if (!TEST_true(WPACKET_init_static_len(&pkt, ack, sizeof(ack), 2))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, epoch))
        || !TEST_true(WPACKET_put_bytes_u64(&pkt, seqnum))
        || !TEST_true(WPACKET_finish(&pkt))
        || !TEST_true(WPACKET_get_total_written(&pkt, &acklen))) {
        WPACKET_cleanup(&pkt);
        goto end;
    }
    WPACKET_cleanup(&pkt);
    if (!TEST_int_eq(dtls1_write_bytes(cc, SSL3_RT_ACK, ack, acklen, &written), 1)
        || !TEST_size_t_eq(written, acklen)
        || !TEST_int_gt(BIO_flush(cc->wbio), 0))
        goto end;

    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        /*
         * A fully-ACKed entry isn't swept out of sent_messages until
         * something calls dtls1_clear_sent_buffer() -- which, absent the
         * fix below, doesn't happen here. Check acknowledgment directly
         * rather than via pqueue_size(), so this isn't itself entangled
         * with the fix under test.
         */
        || !TEST_false(dtls_any_sent_messages_are_missing_acknowledge(sc))
        || !TEST_int_eq(sc->statem.hand_state, TLS_ST_SR_CERT))
        goto end;

    /*
     * The flight is now fully acknowledged, but the server is still
     * mid-read: the timer must be stopped here regardless, not left
     * running until the rest of the PHA response completes it.
     */
    if (!TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    /* The withheld records still complete the authentication exchange. */
    off = reclen[0];
    for (i = 1; i < nrec; i++) {
        if (!TEST_int_eq(BIO_write(SSL_get_rbio(server), dgram + off,
                             (int)reclen[i]),
                (int)reclen[i]))
            goto end;
        off += reclen[i];
    }
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_int_eq(sc->statem.hand_state, TLS_ST_OK)
        || !TEST_true(SSL_is_init_finished(server))
        || !TEST_true(ossl_time_is_zero(sc->d1->next_timeout)))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * ossl_statem_client_post_work()'s TLS_ST_OK case can complete a finished
 * post-handshake authentication exchange by looping straight back into
 * reading an already-buffered message, instead of calling
 * tls_finish_handshake(). post_handshake_auth must still be restored to
 * SSL_PHA_EXT_SENT either way, so that a second CertificateRequest is
 * recognized rather than rejected as unexpected.
 *
 * Completing round 1 from the client's own side normally happens by
 * processing the server's ACK of its response -- but an ACK never advances
 * handshake_read_seq, so it can never be the trigger for this early-return
 * path (dtls1_has_buffered_ready_message() keys strictly off
 * handshake_read_seq). The trigger instead has to be a genuine handshake
 * message whose processing both advances handshake_read_seq to match an
 * already-buffered one and independently drives hand_state back to
 * TLS_ST_OK -- and round 1's own ACK is deliberately never delivered here
 * at all, so post_handshake_auth is still sitting at SSL_PHA_REQUESTED,
 * unreset, when that happens.
 *
 * Round 2's CertificateRequest is delivered first, on its own: its sequence
 * number is one past a ticket that hasn't been sent to the client yet, so
 * it buffers rather than dispatching. The withheld ticket is delivered
 * next: processing it advances handshake_read_seq to match the buffered
 * CertificateRequest, and acking it drives hand_state through
 * TLS_ST_CW_ACK back to TLS_ST_OK -- the exact moment under test, with
 * post_handshake_auth still unreset from round 1. post_handshake_auth must
 * come out of that same call correctly transitioned for round 2, not
 * stranded at whatever the skipped reset left it at.
 */
static int test_dtls13_pha_second_request_survives_buffered_dispatch(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048], discard[2048], ticket[2048], certreq2[2048];
    size_t ticketlen, certreq2len;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);

    /* Round 1: request PHA, let the client answer, and the server finish it. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    /*
     * Discard the server's ACK of that response -- it is never delivered
     * to the client at all in this test. post_handshake_auth is left
     * sitting at SSL_PHA_REQUESTED, exactly as it was when round 1's
     * CertificateRequest first arrived.
     */
    while (BIO_read(SSL_get_rbio(client), discard, sizeof(discard)) > 0)
        continue;
    if (!TEST_int_eq(cc->post_handshake_auth, SSL_PHA_REQUESTED))
        goto end;

    /*
     * The server sends a ticket, captured and withheld -- it is the thing
     * round 2's CertificateRequest will be buffered behind.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ticketlen = 0;
    while (BIO_ctrl_pending(SSL_get_rbio(client)) > 0) {
        ret = BIO_read(SSL_get_rbio(client), ticket + ticketlen,
            (int)(sizeof(ticket) - ticketlen));
        if (!TEST_int_gt(ret, 0))
            goto end;
        ticketlen += (size_t)ret;
    }
    if (!TEST_size_t_gt(ticketlen, 0))
        goto end;

    /*
     * The server, already idle again, immediately requests round 2. Its
     * CertificateRequest is captured too.
     */
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    certreq2len = 0;
    while (BIO_ctrl_pending(SSL_get_rbio(client)) > 0) {
        ret = BIO_read(SSL_get_rbio(client), certreq2 + certreq2len,
            (int)(sizeof(certreq2) - certreq2len));
        if (!TEST_int_gt(ret, 0))
            goto end;
        certreq2len += (size_t)ret;
    }
    if (!TEST_size_t_gt(certreq2len, 0))
        goto end;

    /*
     * Deliver round 2's CertificateRequest on its own, first. Its sequence
     * number is one past the still-withheld ticket's, so it buffers rather
     * than dispatching -- hand_state never moves, and post_handshake_auth
     * is untouched.
     */
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(client), certreq2,
                         (int)certreq2len),
            (int)certreq2len))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->rcvd_messages), 1)
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_REQUESTED))
        goto end;

    /*
     * Deliver the withheld ticket. Processing it advances
     * handshake_read_seq to match the buffered CertificateRequest, and
     * acking it drives hand_state back to TLS_ST_OK with that
     * CertificateRequest already sitting there ready -- the exact
     * TLS_ST_OK early-return path under test, reached without
     * tls_finish_handshake() ever running, and with post_handshake_auth
     * still unreset from round 1. It must come out of this call correctly
     * transitioned to SSL_PHA_REQUESTED for round 2, not stranded at
     * whatever the skipped reset left it at.
     */
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(client), ticket, (int)ticketlen),
            (int)ticketlen))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->rcvd_messages), 0)
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_REQUESTED))
        goto end;

    /* Round 2 completes normally: the server reads the client's response. */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    /*
     * Let the client process the server's ACK of that second response too.
     * This doesn't yet bring the client fully idle: round 1's own flight
     * (Certificate + CertificateVerify + Finished) was never acknowledged
     * -- its ACK was deliberately discarded above, to set up the scenario
     * -- so dtls_any_sent_messages_are_missing_acknowledge() still sees it
     * outstanding, and dtls_process_ack() keeps reverting hand_state to
     * pre_ack_hand_state (TLS_ST_CW_FINISHED) instead of reaching
     * TLS_ST_OK.
     */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * Force that still-outstanding round 1 flight to retransmit, and let
     * the server acknowledge it for real this time, so the connection can
     * finish settling to idle on both sides.
     */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(SSL_is_init_finished(client)))
        goto end;

    /* The connection is now genuinely usable. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A client's own deferred write-key install must be respected not just by
 * the install logic itself, but by anything else deciding whether it's
 * safe to send new post-handshake content.
 *
 * A first PHA response is sent and left deliberately unacknowledged. A
 * ticket returns the client to idle anyway -- post-handshake message
 * categories don't acknowledge each other, so this doesn't retire that
 * response. The client then sends its own KeyUpdate, withheld behind the
 * still-unacknowledged first response; only the KeyUpdate's own ACK is
 * delivered, so the KeyUpdate itself ends up acknowledged while the
 * install it's waiting on stays pending.
 *
 * A second CertificateRequest arriving in that window must still be
 * deferred, not answered immediately: answering it would send genuinely
 * new content under the client's current write epoch, which hasn't
 * actually switched over yet. Delivering the withheld first response's
 * own ACK afterward must complete the install and release the deferred
 * second response at the new epoch, which the server must then accept.
 */
static int test_dtls13_pha_defer_waits_for_write_key_install(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048], ack1[2048];
    size_t ack1len;
    uint64_t epoch_before;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(cc, SSL3_CC_WRITE);

    /* Round 1: request PHA, let the client answer. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_CW_FINISHED)
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_REQUESTED))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    /*
     * Capture the server's ACK of that response instead of delivering it
     * -- held back until the very end of this test.
     */
    ack1len = 0;
    while (BIO_ctrl_pending(SSL_get_rbio(client)) > 0) {
        ret = BIO_read(SSL_get_rbio(client), ack1 + ack1len,
            (int)(sizeof(ack1) - ack1len));
        if (!TEST_int_gt(ret, 0))
            goto end;
        ack1len += (size_t)ret;
    }
    if (!TEST_size_t_gt(ack1len, 0))
        goto end;

    /*
     * A ticket takes the client back to idle anyway, without acknowledging
     * the still-outstanding first response.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(SSL_is_init_finished(client))
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_EXT_SENT))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The client's own KeyUpdate is sent and withheld behind the still-
     * outstanding first response.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(cc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_READ), epoch_before + 1))
        goto end;

    /*
     * Only the KeyUpdate's own ACK is delivered. The KeyUpdate is now
     * acked, but its write-key install is still withheld behind the
     * first response.
     */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(cc->d1->key_update_write_pending)
        || !TEST_false(dtls_has_unacked_key_update(cc))
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * A second CertificateRequest arrives in exactly this window. It must
     * be deferred, not answered now.
     */
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq((int)cc->statem.deferred_key_update_state,
            (int)TLS_ST_CR_CERT_REQ)
        || !TEST_int_eq(SSL_get_state(client), TLS_ST_CW_KEY_UPDATE)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Delivering the withheld first response's ACK completes the install
     * and releases the deferred second response at the new epoch.
     */
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(client), ack1, (int)ack1len),
            (int)ack1len))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(cc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before + 1)
        || !TEST_int_eq((int)cc->statem.deferred_key_update_state,
            (int)TLS_ST_BEFORE))
        goto end;

    /* The server accepts the now-released second response. */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    /* Let the client process the server's ACK of that second response too. */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(SSL_is_init_finished(client)))
        goto end;

    /* The connection is genuinely usable afterward. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A server with its own deferred write-key install still outstanding must
 * not report itself idle just because some unrelated KeyUpdate gets
 * acknowledged along the way.
 *
 * The server's own KeyUpdate is sent and withheld behind an earlier,
 * unacknowledged ticket. The peer then sends its own, independent
 * KeyUpdate, and the server acknowledges it -- a wholly separate exchange
 * from the server's own still-pending install. That must not be mistaken
 * for the connection becoming idle: SSL_is_init_finished() must stay
 * false, and SSL_new_session_ticket()/SSL_verify_client_post_handshake()
 * must both still refuse to start. Admitting either would send it under
 * the still-current write epoch, which the peer -- already on the new
 * read epoch from installing that independent KeyUpdate -- would
 * silently drop.
 */
static int test_dtls13_server_idle_waits_for_write_key_install(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc;
    unsigned char buf[2048], discard[2048];
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The server's own KeyUpdate is sent and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_false(dtls_has_unacked_key_update(sc))
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * The client independently sends its own KeyUpdate. Acknowledging it
     * is what reaches the idle decision under test.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server must not report itself idle: its own deferred write-key
     * install is still outstanding, even though the peer's KeyUpdate is
     * now fully acknowledged.
     */
    if (!TEST_false(SSL_is_init_finished(server))
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /* Neither a new ticket nor a new authentication request may start yet. */
    if (!TEST_false(SSL_new_session_ticket(server)))
        goto end;
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_false(SSL_verify_client_post_handshake(server)))
        goto end;

    /*
     * Force the ticket's retransmit timer. The client already processed
     * the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes the fresh ACK: the deferred write key must
     * finally be installed, and the connection genuinely becomes idle.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1)
        || !TEST_true(SSL_is_init_finished(server)))
        goto end;

    /* Application data flows both ways under the new epoch. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A client with its own deferred write-key install still outstanding must
 * not report itself idle just because some unrelated post-handshake
 * message gets acknowledged along the way.
 *
 * The client's own KeyUpdate is sent and withheld behind an earlier,
 * unacknowledged PHA response. A new ticket then arrives and the client
 * acknowledges it -- a wholly separate exchange from the client's own
 * still-pending install. That must not be mistaken for the connection
 * becoming idle: SSL_is_init_finished() must stay false until the
 * withheld response is finally acknowledged and the install completes.
 */
static int test_dtls13_client_idle_waits_for_write_key_install(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048], ack1[2048];
    size_t ack1len;
    uint64_t epoch_before;
    int ret, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(cc, SSL3_CC_WRITE);

    /* Request PHA and let the client answer. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_REQUESTED))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED))
        goto end;

    /*
     * Capture the server's ACK of that response instead of delivering it
     * -- held back until the very end of this test.
     */
    ack1len = 0;
    while (BIO_ctrl_pending(SSL_get_rbio(client)) > 0) {
        ret = BIO_read(SSL_get_rbio(client), ack1 + ack1len,
            (int)(sizeof(ack1) - ack1len));
        if (!TEST_int_gt(ret, 0))
            goto end;
        ack1len += (size_t)ret;
    }
    if (!TEST_size_t_gt(ack1len, 0))
        goto end;

    /*
     * A ticket takes the client back to idle anyway, without acknowledging
     * the still-outstanding response.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(SSL_is_init_finished(client))
        || !TEST_int_eq(cc->post_handshake_auth, SSL_PHA_EXT_SENT))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The client's own KeyUpdate is sent and withheld behind the still-
     * outstanding PHA response.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(cc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_READ), epoch_before + 1))
        goto end;

    /*
     * Only the KeyUpdate's own ACK is delivered. The KeyUpdate is now
     * acked, but its write-key install is still withheld behind the PHA
     * response.
     */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(cc->d1->key_update_write_pending)
        || !TEST_false(dtls_has_unacked_key_update(cc))
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * A second ticket arrives in exactly this window. Acknowledging it
     * must not be mistaken for the connection becoming idle: the
     * client's own deferred write-key install is still outstanding.
     */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(SSL_is_init_finished(client))
        || !TEST_true(cc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Delivering the withheld PHA response's ACK completes the install. */
    if (!TEST_int_eq(BIO_write(SSL_get_rbio(client), ack1, (int)ack1len),
            (int)ack1len))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(cc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), epoch_before + 1)
        || !TEST_true(SSL_is_init_finished(client)))
        goto end;

    /* The connection is genuinely usable afterward. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * The same entry-eviction scenario as
 * test_dtls13_keyupdate_ack_survives_pha_completion_eviction() above, but
 * checking whether a completed PHA round, by itself, is mistaken for
 * permission to start something new -- a ticket or a second PHA round --
 * while the server's own deferred write-key install is still outstanding,
 * rather than whether app data can still be sent on the existing
 * connection, which that test covers.
 */
static int test_dtls13_pha_completion_eviction_blocks_new_actions(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048];
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0)))
        goto end;
    SSL_CTX_set_post_handshake_auth(cctx, 1);
    if (!TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* Request PHA. */
    SSL_set_verify(server, SSL_VERIFY_PEER, NULL);
    if (!TEST_true(SSL_verify_client_post_handshake(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Drop the client's response before the server ever sees it. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), buf, sizeof(buf)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The server's own KeyUpdate is sent and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Force the client to retransmit its still-unacknowledged PHA response. */
    cc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(client))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /*
     * The server processes the recovered Certificate + Finished. PHA
     * completes, evicting the server's own, already-acknowledged KeyUpdate
     * entry -- leaving only the still-unacknowledged ticket behind.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->post_handshake_auth, SSL_PHA_EXT_RECEIVED)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * The server must not admit a new ticket, a new authentication
     * request, or a second KeyUpdate: its own deferred write-key install
     * is still outstanding, even though PHA just completed and the
     * connection is otherwise idle.
     */
    if (!TEST_false(SSL_new_session_ticket(server))
        || !TEST_false(SSL_verify_client_post_handshake(server))
        || !TEST_false(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    /* Application data still flows normally in the meantime. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

/*
 * A reciprocal KeyUpdate requested by the peer is still subject to the
 * same pending write-key install as anything else in this window -- even
 * though nothing about requesting one goes through the public API that
 * normally guards against sending a KeyUpdate too early.
 *
 * The server's own KeyUpdate is sent and withheld behind an earlier,
 * unacknowledged ticket. The peer then asks for a reciprocal KeyUpdate
 * instead of sending its own independent one. That request must not be
 * allowed to jump the queue: it must not be treated as making the
 * connection idle, and a later write must not flush it under the
 * still-current write epoch either.
 */
static int test_dtls13_requested_key_update_waits_for_write_key_install(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *server = NULL, *client = NULL;
    SSL_CONNECTION *sc, *cc;
    unsigned char buf[2048], discard[2048];
    uint64_t epoch_before;
    int ret, dropped, testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(), DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &server, &client, NULL, NULL))
        || !TEST_true(create_ssl_connection(server, client, SSL_ERROR_NONE)))
        goto end;
    sc = SSL_CONNECTION_FROM_SSL(server);
    cc = SSL_CONNECTION_FROM_SSL(client);
    epoch_before = dtls1_get_epoch(sc, SSL3_CC_WRITE);

    /* The ticket is sent and delivered normally. */
    if (!TEST_true(SSL_new_session_ticket(server))
        || !TEST_int_eq(SSL_do_handshake(server), 1))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /* Lose the client's ACK for it; the server still sees it outstanding. */
    dropped = 0;
    while (BIO_read(SSL_get_rbio(server), discard, sizeof(discard)) > 0)
        dropped++;
    if (!TEST_int_gt(dropped, 0))
        goto end;

    /* The server's own KeyUpdate is sent and acknowledged normally. */
    if (!TEST_true(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_READ), epoch_before + 1))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_false(dtls_has_unacked_key_update(sc))
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * The public API already refuses to start a fresh KeyUpdate here,
     * confirming the server is not considered idle by that check.
     */
    if (!TEST_false(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    /*
     * The client requests a reciprocal KeyUpdate. Processing it bypasses
     * SSL_key_update() entirely: tls_process_key_update() schedules the
     * response by assigning s->key_update directly.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->key_update, SSL_KEY_UPDATE_NOT_REQUESTED)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_READ), epoch_before + 1))
        goto end;

    /*
     * The reciprocal KeyUpdate must not jump ahead of the still-pending
     * install: the server must not consider itself idle, and the write
     * epoch must not have moved.
     */
    if (!TEST_false(SSL_is_init_finished(server))
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * A write attempt must not flush the scheduled KeyUpdate under the
     * still-current epoch either.
     */
    ret = SSL_write(server, "s", 1);
    if (!TEST_int_eq(sc->key_update, SSL_KEY_UPDATE_NOT_REQUESTED)
        || !TEST_true(sc->d1->key_update_write_pending)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before))
        goto end;

    /*
     * Force the ticket's retransmit timer. The client already processed
     * the original, so this is recognized and acknowledged as a
     * retransmission rather than reprocessed.
     */
    sc->d1->next_timeout = ossl_time_subtract(ossl_time_now(), ossl_seconds2time(1));
    if (!TEST_true(SSL_handle_events(server))
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ))
        goto end;

    /*
     * The server processes the fresh ACK: the deferred write key must
     * finally be installed. Processing an ACK is bookkeeping, not a
     * trigger to write something new on its own, so the scheduled
     * reciprocal KeyUpdate isn't flushed by this read alone -- and with it
     * still scheduled, the connection correctly isn't considered fully
     * idle yet either.
     */
    ret = SSL_read(server, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_false(sc->d1->key_update_write_pending)
        || !TEST_int_eq(sc->key_update, SSL_KEY_UPDATE_NOT_REQUESTED)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1))
        goto end;

    /*
     * A write now drives the scheduled reciprocal KeyUpdate out, at the
     * new epoch -- not before. Sending it leaves the connection waiting
     * on its own fresh ACK, same as any other KeyUpdate send, so this
     * returns WANT_READ rather than a clean success.
     */
    ret = SSL_do_handshake(server);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_int_eq(sc->key_update, SSL_KEY_UPDATE_NONE)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), epoch_before + 1))
        goto end;

    /* The client receives the server's now-released reciprocal KeyUpdate. */
    ret = SSL_read(client, buf, sizeof(buf));
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_READ), epoch_before + 2))
        goto end;

    /* Application data flows both ways under the new epoch. */
    if (!TEST_int_eq(SSL_write(server, "s", 1), 1)
        || !TEST_int_eq(SSL_read(client, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 's')
        || !TEST_int_eq(SSL_write(client, "c", 1), 1)
        || !TEST_int_eq(SSL_read(server, buf, 1), 1)
        || !TEST_uchar_eq(buf[0], 'c'))
        goto end;

    testresult = 1;
end:
    SSL_free(server);
    SSL_free(client);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_dtls_crypt_sequence_number, OSSL_NELEM(cipher_names));
    ADD_ALL_TESTS(test_seq_num_reconstruction, OSSL_NELEM(seq_num_tests));
#ifndef OPENSSL_NO_DTLS1_3
    ADD_ALL_TESTS(test_dtls13_ack_length, 4);
    ADD_TEST(test_dtls13_increment_epoch_max);
    ADD_ALL_TESTS(test_dtls13_ack_coverage, 2);
    ADD_ALL_TESTS(test_dtls13_ticket_ack_retransmit, 8);
    ADD_TEST(test_dtls13_pha_ack_retransmit);
    ADD_TEST(test_dtls13_ack_list_bound);
    ADD_ALL_TESTS(test_dtls13_ack_records, 3);
    ADD_ALL_TESTS(test_dtls13_keyupdate_ack_history, 2);
    ADD_ALL_TESTS(test_dtls13_finished_ack_history, 2);
    ADD_ALL_TESTS(test_dtls13_ticket_ack_history_fragmented, 2);
    ADD_TEST(test_dtls13_interrupted_retransmit_range);
    ADD_TEST(test_dtls13_ack_bitmap_oob);
    ADD_TEST(test_dtls13_finished_ack_loss_recovers);
    ADD_ALL_TESTS(test_dtls13_keyupdate_ack_loss_recovers, 2);
    ADD_TEST(test_dtls13_prev_epoch_rl_buffer_freed);
    ADD_TEST(test_dtls_prev_epoch_allows_type);
    ADD_TEST(test_dtls_record_from_retained_epoch);
    ADD_ALL_TESTS(test_dtls13_out_of_seq_retained_epoch, 3);
    ADD_TEST(test_dtls13_retained_epoch_seq_match);
    ADD_TEST(test_dtls13_retained_epoch_app_data_rejected);
    ADD_TEST(test_dtls13_retained_epoch_ack_authority);
    ADD_ALL_TESTS(test_dtls13_keyupdate_preserves_flight, 2);
    ADD_TEST(test_dtls13_cert_req_preserves_flight);
    ADD_ALL_TESTS(test_dtls13_pha_keyupdate_shared_wrl, 2);
    ADD_TEST(test_dtls13_cert_req_finished_preserves_ticket);
    ADD_TEST(test_dtls13_cert_req_explicit_ack_preserves_ticket);
    ADD_TEST(test_dtls13_server_keyupdate_preserves_ack);
    ADD_TEST(test_dtls13_server_keyupdate_preserves_pha);
    ADD_TEST(test_dtls13_server_keyupdate_preserves_pha_ticket);
    ADD_TEST(test_dtls13_server_keyupdate_pha_ticket_survives_retransmit);
    ADD_TEST(test_dtls13_keyupdate_ack_defers_write_keys);
    ADD_TEST(test_dtls13_keyupdate_ack_defers_write_keys_ticket_ack_lost);
    ADD_TEST(test_dtls13_keyupdate_ack_survives_entry_eviction);
    ADD_TEST(test_dtls13_keyupdate_ack_survives_pha_completion_eviction);
    ADD_TEST(test_dtls13_keyupdate_install_on_pha_cert_req_retirement);
    ADD_TEST(test_dtls13_pha_ack_stops_timer);
    ADD_TEST(test_dtls13_pha_second_request_survives_buffered_dispatch);
    ADD_TEST(test_dtls13_pha_defer_waits_for_write_key_install);
    ADD_TEST(test_dtls13_server_idle_waits_for_write_key_install);
    ADD_TEST(test_dtls13_client_idle_waits_for_write_key_install);
    ADD_TEST(test_dtls13_pha_completion_eviction_blocks_new_actions);
    ADD_TEST(test_dtls13_requested_key_update_waits_for_write_key_install);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_maybe_retry_free();
}
