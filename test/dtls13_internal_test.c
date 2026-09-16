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
#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

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
#endif /* OPENSSL_NO_DTLS1_3 */

#if !defined(OPENSSL_NO_DTLS1_3) && !defined(OPENSSL_NO_SOCK)
/*
 * Fake URXE (unprocessed receive element) queue used to test
 * tls_default_read_n_urxe(), the DTLS listener's URXE-backed read path.
 */
#define FAKE_URXE_MAX 4

typedef struct fake_urxe_st {
    unsigned char *data;
    size_t len;
} FAKE_URXE;

typedef struct fake_urxe_queue_st {
    FAKE_URXE queue[FAKE_URXE_MAX];
    size_t queue_len;
    size_t next_fetch;
    int get_calls;
    int release_count[FAKE_URXE_MAX];
} FAKE_URXE_QUEUE;

static int fake_get_urxe_packet(void *cbarg, unsigned char **data,
    size_t *len, void **packet_handle)
{
    FAKE_URXE_QUEUE *q = cbarg;

    if (q->next_fetch >= q->queue_len)
        return 0;

    *data = q->queue[q->next_fetch].data;
    *len = q->queue[q->next_fetch].len;
    /* The queue slot's own address doubles as the fake handle */
    *packet_handle = &q->queue[q->next_fetch];
    q->next_fetch++;
    q->get_calls++;
    return 1;
}

static void fake_release_urxe_packet(void *cbarg, void *packet_handle)
{
    FAKE_URXE_QUEUE *q = cbarg;
    size_t idx = (FAKE_URXE *)packet_handle - q->queue;

    if (ossl_assert(idx < FAKE_URXE_MAX))
        q->release_count[idx]++;
}

static OSSL_RECORD_LAYER *new_fake_urxe_rl(FAKE_URXE_QUEUE *q)
{
    OSSL_RECORD_LAYER *rl = OPENSSL_zalloc(sizeof(*rl));

    if (rl == NULL)
        return NULL;

    rl->isdtls = 1;
    rl->use_urxe = 1;
    rl->get_urxe_packet = fake_get_urxe_packet;
    rl->release_urxe_packet = fake_release_urxe_packet;
    rl->cbarg = q;

    /*
     * A real record layer gets these from tls_int_new_record_layer(). Set
     * them explicitly so dtls_get_more_records() can process a plaintext
     * epoch-0 record the same way a listener's freshly-created connection
     * does, before any version or cipher has been negotiated.
     */
    rl->funcs = &dtls_any_funcs;
    rl->version = DTLS_ANY_VERSION;
    rl->is_first_record = 1;
    rl->max_frag_len = SSL3_RT_MAX_PLAIN_LENGTH;

    return rl;
}

/*
 * Builds one classic (non-DTLS-1.3-unified-header) record -- header plus
 * payload -- into buf, and returns its total length. A listener's record
 * layer starts out at DTLS_ANY_VERSION with no cipher installed, so an
 * epoch-0 record is plaintext and uses this classic header rather than the
 * DTLS 1.3 unified one.
 */
static size_t build_dtls_record(unsigned char *buf, unsigned char type,
    unsigned char seq, const unsigned char *payload, size_t payload_len)
{
    buf[0] = type;
    buf[1] = (DTLS1_2_VERSION >> 8) & 0xff;
    buf[2] = DTLS1_2_VERSION & 0xff;
    buf[3] = 0; /* epoch, high byte */
    buf[4] = 0; /* epoch, low byte */
    memset(buf + 5, 0, 5); /* sequence number, high 5 bytes */
    buf[10] = seq; /* sequence number, low byte */
    buf[11] = (unsigned char)((payload_len >> 8) & 0xff);
    buf[12] = (unsigned char)(payload_len & 0xff);
    if (payload_len > 0)
        memcpy(buf + DTLS1_RT_HEADER_LENGTH, payload, payload_len);
    return DTLS1_RT_HEADER_LENGTH + payload_len;
}

/*
 * A single UDP datagram can carry more than one DTLS record, so the URXE
 * must stay held until every record in it has been processed -- releasing
 * it after just the first would inadvertently corrupt the records still
 * behind it.
 */
static int test_urxe_multi_record_no_premature_release(void)
{
    OSSL_RECORD_LAYER *rl = NULL;
    FAKE_URXE_QUEUE q;
    static const unsigned char payload1[] = { 'A', 'A', 'A', 'A' };
    static const unsigned char payload2[] = { 'B', 'B', 'B', 'B' };
    unsigned char datagram[2 * (DTLS1_RT_HEADER_LENGTH + sizeof(payload1))];
    size_t rec1_len, rec2_len;
    int testresult = 0;

    rec1_len = build_dtls_record(datagram, SSL3_RT_HANDSHAKE, 0,
        payload1, sizeof(payload1));
    rec2_len = build_dtls_record(datagram + rec1_len, SSL3_RT_HANDSHAKE, 1,
        payload2, sizeof(payload2));

    memset(&q, 0, sizeof(q));
    q.queue[0].data = datagram;
    q.queue[0].len = rec1_len + rec2_len;
    q.queue_len = 1;

    if (!TEST_ptr(rl = new_fake_urxe_rl(&q)))
        goto end;

    /* Record 1 */
    if (!TEST_int_eq(dtls_get_more_records(rl), OSSL_RECORD_RETURN_SUCCESS)
        || !TEST_size_t_eq(rl->rrec[0].length, sizeof(payload1))
        || !TEST_mem_eq(rl->rrec[0].data, rl->rrec[0].length,
            payload1, sizeof(payload1)))
        goto end;

    /* A URXE-backed read record layer must never allocate rl->rbuf */
    if (!TEST_ptr_null(rl->rbuf.buf))
        goto end;

    /*
     * Mark the record as handed to the app and release it, standing in for
     * ssl_release_record() (ssl/record/rec_layer_s3.c), which is what
     * really calls tls_release_record() once SSL_read() has copied the
     * record's data out to the caller.
     */
    rl->curr_rec = 1;
    if (!TEST_int_eq(tls_release_record(rl, &rl->rrec[0], rl->rrec[0].length),
            OSSL_RECORD_RETURN_SUCCESS))
        goto end;

    /* Record 2 is still unread -- the URXE must not have been released yet */
    if (!TEST_int_eq(q.get_calls, 1)
        || !TEST_int_eq(q.release_count[0], 0)
        || !TEST_size_t_eq(rl->urxe_left, rec2_len))
        goto end;

    /* Record 2, draining the datagram exactly */
    if (!TEST_int_eq(dtls_get_more_records(rl), OSSL_RECORD_RETURN_SUCCESS)
        || !TEST_size_t_eq(rl->rrec[0].length, sizeof(payload2))
        || !TEST_mem_eq(rl->rrec[0].data, rl->rrec[0].length,
            payload2, sizeof(payload2)))
        goto end;

    /*
     * Mark the record as handed to the app and release it, standing in for
     * ssl_release_record() (ssl/record/rec_layer_s3.c), which is what
     * really calls tls_release_record() once SSL_read() has copied the
     * record's data out to the caller.
     */
    rl->curr_rec = 1;
    if (!TEST_int_eq(tls_release_record(rl, &rl->rrec[0], rl->rrec[0].length),
            OSSL_RECORD_RETURN_SUCCESS))
        goto end;

    /*
     * Now that the whole datagram is drained, the URXE must be released --
     * exactly once, and no second fetch should ever have been needed for
     * it (both records came from the one held URXE).
     */
    if (!TEST_int_eq(q.get_calls, 1)
        || !TEST_int_eq(q.release_count[0], 1)
        || !TEST_size_t_eq(rl->urxe_left, 0))
        goto end;

    testresult = 1;
end:
    tls_free(rl);
    return testresult;
}

/*
 * A record can be dropped internally (e.g. a zero-length record, or one
 * that fails to decrypt) without tls_release_record() ever being called on
 * it. When that happens, the next read must release its URXE itself before
 * fetching a new one, or the handle leaks.
 */
static int test_urxe_discarded_record_releases_before_next_fetch(void)
{
    OSSL_RECORD_LAYER *rl = NULL;
    FAKE_URXE_QUEUE q;
    static const unsigned char payload[] = { 'C', 'C', 'C', 'C' };
    unsigned char datagram1[DTLS1_RT_HEADER_LENGTH];
    unsigned char datagram2[DTLS1_RT_HEADER_LENGTH + sizeof(payload)];
    int testresult = 0;

    /* A zero-length record: read in full, then silently dropped */
    build_dtls_record(datagram1, SSL3_RT_HANDSHAKE, 0, NULL, 0);
    build_dtls_record(datagram2, SSL3_RT_HANDSHAKE, 1, payload, sizeof(payload));

    memset(&q, 0, sizeof(q));
    q.queue[0].data = datagram1;
    q.queue[0].len = sizeof(datagram1);
    q.queue[1].data = datagram2;
    q.queue[1].len = sizeof(datagram2);
    q.queue_len = 2;

    if (!TEST_ptr(rl = new_fake_urxe_rl(&q)))
        goto end;

    /*
     * dtls_get_more_records() reads and drops the first (empty) record
     * internally, then keeps going until it has a real one to return --
     * releasing the first URXE and fetching the second along the way.
     */
    if (!TEST_int_eq(dtls_get_more_records(rl), OSSL_RECORD_RETURN_SUCCESS)
        || !TEST_size_t_eq(rl->rrec[0].length, sizeof(payload))
        || !TEST_mem_eq(rl->rrec[0].data, rl->rrec[0].length,
            payload, sizeof(payload)))
        goto end;

    /* A URXE-backed read record layer must never allocate rl->rbuf */
    if (!TEST_ptr_null(rl->rbuf.buf))
        goto end;

    if (!TEST_int_eq(q.get_calls, 2)
        || !TEST_int_eq(q.release_count[0], 1)
        || !TEST_int_eq(q.release_count[1], 0))
        goto end;

    /*
     * Mark the record as handed to the app and release it, standing in for
     * ssl_release_record() (ssl/record/rec_layer_s3.c), which is what
     * really calls tls_release_record() once SSL_read() has copied the
     * record's data out to the caller.
     */
    rl->curr_rec = 1;
    if (!TEST_int_eq(tls_release_record(rl, &rl->rrec[0], rl->rrec[0].length),
            OSSL_RECORD_RETURN_SUCCESS))
        goto end;

    if (!TEST_int_eq(q.release_count[0], 1)
        || !TEST_int_eq(q.release_count[1], 1))
        goto end;

    testresult = 1;
end:
    tls_free(rl);
    return testresult;
}

/*
 * Verifies tls_free() forwards any bytes an epoch's record layer never got
 * a chance to examine before being torn down, rather than silently
 * dropping them. If the held URXE's remaining bytes belong to the next
 * epoch (e.g. the last record of this epoch and the first of the next
 * arrived coalesced in one datagram, which rfc9147's wire format permits
 * even though this library's own sender never produces it), dropping them
 * would leave a gap the peer has to retransmit into.
 */
static int test_urxe_teardown_forwards_undrained_bytes(void)
{
    OSSL_RECORD_LAYER *rl = NULL;
    FAKE_URXE_QUEUE q;
    static const unsigned char payload[] = { 'D', 'D', 'D', 'D' };
    /* Stand-in for a record this epoch's record layer never looks at */
    static const unsigned char untouched[] = { 0xaa, 0xbb, 0xcc, 0xdd };
    unsigned char datagram[DTLS1_RT_HEADER_LENGTH + sizeof(payload)
        + sizeof(untouched)];
    unsigned char forwarded[sizeof(untouched)];
    size_t rec_len, read_back;
    BIO *next = NULL;
    int testresult = 0;

    rec_len = build_dtls_record(datagram, SSL3_RT_HANDSHAKE, 0,
        payload, sizeof(payload));
    memcpy(datagram + rec_len, untouched, sizeof(untouched));

    memset(&q, 0, sizeof(q));
    q.queue[0].data = datagram;
    q.queue[0].len = rec_len + sizeof(untouched);
    q.queue_len = 1;

    if (!TEST_ptr(rl = new_fake_urxe_rl(&q)))
        goto end;

    if (!TEST_ptr(next = BIO_new(BIO_s_mem())))
        goto end;
    /* rl takes its own reference, mirroring tls_int_new_record_layer(); we
     * keep our own so we can still read from it after tls_free() drops
     * rl's. */
    if (!TEST_true(BIO_up_ref(next)))
        goto end;
    rl->next = next;

    /*
     * Process the one real record normally, but leave the trailing bytes
     * completely unexamined -- as if this epoch's record layer got what it
     * needed and moved on without asking dtls_get_more_records() for more.
     */
    if (!TEST_int_eq(dtls_get_more_records(rl), OSSL_RECORD_RETURN_SUCCESS)
        || !TEST_size_t_eq(rl->rrec[0].length, sizeof(payload))
        || !TEST_size_t_eq(rl->urxe_left, sizeof(untouched)))
        goto end;

    /* A URXE-backed read record layer must never allocate rl->rbuf */
    if (!TEST_ptr_null(rl->rbuf.buf))
        goto end;

    /*
     * Mark the record as handed to the app and release it, standing in for
     * ssl_release_record() (ssl/record/rec_layer_s3.c), which is what
     * really calls tls_release_record() once SSL_read() has copied the
     * record's data out to the caller.
     */
    rl->curr_rec = 1;
    if (!TEST_int_eq(tls_release_record(rl, &rl->rrec[0], rl->rrec[0].length),
            OSSL_RECORD_RETURN_SUCCESS))
        goto end;

    /*
     * The untouched bytes still remain, so tls_release_record() must not
     * have released the URXE yet -- tls_free() is what's under test here.
     */
    if (!TEST_int_eq(q.release_count[0], 0))
        goto end;

    if (!TEST_true(tls_free(rl)))
        goto end;
    rl = NULL; /* tls_free() already released it */

    if (!TEST_true(BIO_read_ex(next, forwarded, sizeof(forwarded),
            &read_back))
        || !TEST_size_t_eq(read_back, sizeof(untouched))
        || !TEST_mem_eq(forwarded, sizeof(untouched), untouched,
            sizeof(untouched)))
        goto end;

    if (!TEST_int_eq(q.release_count[0], 1))
        goto end;

    testresult = 1;
end:
    tls_free(rl);
    BIO_free(next);
    return testresult;
}
#endif /* !OPENSSL_NO_DTLS1_3 && !OPENSSL_NO_SOCK */

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_dtls_crypt_sequence_number, OSSL_NELEM(cipher_names));
    ADD_ALL_TESTS(test_seq_num_reconstruction, OSSL_NELEM(seq_num_tests));
#ifndef OPENSSL_NO_DTLS1_3
    ADD_TEST(test_dtls13_increment_epoch_max);
#endif
#if !defined(OPENSSL_NO_DTLS1_3) && !defined(OPENSSL_NO_SOCK)
    ADD_TEST(test_urxe_multi_record_no_premature_release);
    ADD_TEST(test_urxe_discarded_record_releases_before_next_fetch);
    ADD_TEST(test_urxe_teardown_forwards_undrained_bytes);
#endif
    return 1;
}
