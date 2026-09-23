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
                || !TEST_ptr(recnum = ossl_list_record_number_head(&unacked->rec_nums))
                || !TEST_uint64_t_gt(recnum->seqnum, oldseq))
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

            if (fragmented ? !TEST_size_t_gt(records, 1) : !TEST_size_t_eq(records, 1))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(sender), 0))
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
    ADD_TEST(test_dtls13_finished_ack_loss_recovers);
    ADD_ALL_TESTS(test_dtls13_keyupdate_ack_loss_recovers, 2);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_maybe_retry_free();
}
