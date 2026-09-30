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
     * The server has already moved to the next read epoch and discarded the
     * old one, so it cannot authenticate this retransmission and never
     * produces a replacement ACK. This is the assertion that must flip once
     * the previous read epoch is retained: a fresh ACK should appear here.
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
     * The receiver has already moved to the next read epoch and discarded
     * the old one, so it cannot authenticate this retransmission and never
     * produces a replacement ACK. This is the assertion that must flip once
     * the previous read epoch is retained: a fresh ACK should appear here.
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
 * dtls_process_ack() removes matching entries from the retransmission queue
 * without checking which epoch authenticated the ACK. This test fails until
 * the ACK path enforces the handshake/application protection boundary.
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
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_maybe_retry_free();
}
