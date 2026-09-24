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
        if (!TEST_int_gt(DTLSv1_handle_timeout(server), 0))
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
            || !TEST_int_eq(DTLSv1_handle_timeout(server), 0))
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

        /* Nothing should have gone out at the new epoch yet. */
        if (!TEST_size_t_eq(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
        goto end;
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0))
        goto end;

    /*
     * Now the application requests a KeyUpdate. It is sent under the
     * current epoch's keys, before the connection moves on to the next
     * epoch.
     */
    if (!TEST_true(SSL_key_update(client, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;
    ret = SSL_do_handshake(client);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 3))
        goto end;

    /*
     * Confirm the premise: Finished and KeyUpdate were sent under the
     * identical epoch's keys, and the connection has since moved on to the
     * next epoch.
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
        if (!TEST_int_gt(DTLSv1_handle_timeout(client), 0))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(server), 0))
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
     * The server processes the client's KeyUpdate. Its own KeyUpdate is
     * still unacknowledged and its new write keys are still not installed,
     * so it must still refuse to start a second KeyUpdate of its own -- but
     * it immediately acknowledges the client's KeyUpdate under its current,
     * still-valid keys rather than holding it back.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(client)), 0)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 1)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), s_wepoch)
        || !TEST_false(SSL_key_update(server, SSL_KEY_UPDATE_NOT_REQUESTED)))
        goto end;

    /*
     * The client processes the server's KeyUpdate first, acknowledging it
     * immediately for the same reason. Its own KeyUpdate is still
     * unacknowledged at this point -- the server's acknowledgment of it,
     * though already sent, is a separate already-queued item that this
     * call does not also reach.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 1)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), c_wepoch)
        || !TEST_size_t_gt(BIO_ctrl_pending(SSL_get_rbio(server)), 0))
        goto end;

    /*
     * The client now processes the server's acknowledgment of its own
     * KeyUpdate. That completes the client's KeyUpdate: its new write
     * keys are installed and its retransmit entry is retired.
     */
    ret = SSL_read(client, buf, 1);
    if (!TEST_int_eq(SSL_get_error(client, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&cc->d1->sent_messages), 0)
        || !TEST_uint64_t_eq(dtls1_get_epoch(cc, SSL3_CC_WRITE), c_wepoch + 1))
        goto end;

    /*
     * The server processes the client's acknowledgment of its own
     * KeyUpdate. That completes the server's KeyUpdate too: both sides are
     * now fully resolved, with no deadlock.
     */
    ret = SSL_read(server, buf, 1);
    if (!TEST_int_eq(SSL_get_error(server, ret), SSL_ERROR_WANT_READ)
        || !TEST_size_t_eq(pqueue_size(&sc->d1->sent_messages), 0)
        || !TEST_uint64_t_eq(dtls1_get_epoch(sc, SSL3_CC_WRITE), s_wepoch + 1))
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
    if (!TEST_int_gt(DTLSv1_handle_timeout(server), 0))
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
    ADD_ALL_TESTS(test_dtls13_keyupdate_preserves_flight, 2);
    ADD_TEST(test_dtls13_cert_req_preserves_flight);
    ADD_ALL_TESTS(test_dtls13_pha_keyupdate_shared_wrl, 2);
    ADD_TEST(test_dtls13_cert_req_finished_preserves_ticket);
    ADD_TEST(test_dtls13_server_keyupdate_preserves_ack);
    ADD_TEST(test_dtls13_server_keyupdate_preserves_pha);
#endif
    return 1;
}

void cleanup_tests(void)
{
    bio_s_maybe_retry_free();
}
