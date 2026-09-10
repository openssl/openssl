/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "internal/packet.h"
#include "internal/quic_record_rx.h"
#include "internal/quic_stream.h"
#include "../ssl/quic/quic_record_rx_local.h"
#include "testutil.h"

/*
 * A received packet as the stream code sees it, without a QRX behind it.
 * The reference the caller keeps is never released by the stream code, so
 * the reference count never reaches zero and the packet is never recycled
 * through the QRX it does not have. It is freed with pkt_test_free() once
 * the test is done with it.
 */
static OSSL_QRX_PKT *pkt_test_new(size_t datagram_len)
{
    RXE *rxe = OPENSSL_zalloc(sizeof(*rxe));

    if (rxe == NULL)
        return NULL;

    rxe->refcount = 1;
    rxe->datagram_len = datagram_len;
    rxe->pkt.datagram_len = datagram_len;
    return &rxe->pkt;
}

/* The number of references held on a packet, including the caller's own. */
static size_t pkt_test_refcount(const OSSL_QRX_PKT *pkt)
{
    return ((const RXE *)pkt)->refcount;
}

static void pkt_test_free(OSSL_QRX_PKT *pkt)
{
    OPENSSL_free((RXE *)pkt);
}

static int compare_iov(const unsigned char *ref, size_t ref_len,
    const OSSL_QTX_IOVEC *iov, size_t iov_len)
{
    size_t i, total_len = 0;
    const unsigned char *cur = ref;

    for (i = 0; i < iov_len; ++i)
        total_len += iov[i].buf_len;

    if (ref_len != total_len)
        return 0;

    for (i = 0; i < iov_len; ++i) {
        if (memcmp(cur, iov[i].buf, iov[i].buf_len))
            return 0;

        cur += iov[i].buf_len;
    }

    return 1;
}

static const unsigned char data_1[] = {
    0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
    0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f
};

static int test_sstream_simple(void)
{
    int testresult = 0;
    QUIC_SSTREAM *sstream = NULL;
    OSSL_QUIC_FRAME_STREAM hdr;
    OSSL_QTX_IOVEC iov[2];
    size_t num_iov = 0, wr = 0, i, init_size = 8192;

    if (!TEST_ptr(sstream = ossl_quic_sstream_new(init_size)))
        goto err;

    /* A stream with nothing yet appended is totally acked */
    if (!TEST_true(ossl_quic_sstream_is_totally_acked(sstream)))
        goto err;

    /* Should not have any data yet */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_false(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov)))
        goto err;

    /* Append data */
    if (!TEST_true(ossl_quic_sstream_append(sstream, data_1, sizeof(data_1),
            &wr))
        || !TEST_size_t_eq(wr, sizeof(data_1)))
        goto err;

    /* No longer totally acked */
    if (!TEST_false(ossl_quic_sstream_is_totally_acked(sstream)))
        goto err;

    /* Read data */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov))
        || !TEST_size_t_gt(num_iov, 0)
        || !TEST_uint64_t_eq(hdr.offset, 0)
        || !TEST_uint64_t_eq(hdr.len, sizeof(data_1))
        || !TEST_false(hdr.is_fin))
        goto err;

    if (!TEST_true(compare_iov(data_1, sizeof(data_1), iov, num_iov)))
        goto err;

    /* Mark data as half transmitted */
    if (!TEST_true(ossl_quic_sstream_mark_transmitted(sstream, 0, 7)))
        goto err;

    /* Read data */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov))
        || !TEST_size_t_gt(num_iov, 0)
        || !TEST_uint64_t_eq(hdr.offset, 8)
        || !TEST_uint64_t_eq(hdr.len, sizeof(data_1) - 8)
        || !TEST_false(hdr.is_fin))
        goto err;

    if (!TEST_true(compare_iov(data_1 + 8, sizeof(data_1) - 8, iov, num_iov)))
        goto err;

    if (!TEST_true(ossl_quic_sstream_mark_transmitted(sstream, 8, 15)))
        goto err;

    /* Read more data; should not be any more */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_false(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov)))
        goto err;

    /* Now we have lost bytes 4-6 */
    if (!TEST_true(ossl_quic_sstream_mark_lost(sstream, 4, 6)))
        goto err;

    /* Should be able to read them */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov))
        || !TEST_size_t_gt(num_iov, 0)
        || !TEST_uint64_t_eq(hdr.offset, 4)
        || !TEST_uint64_t_eq(hdr.len, 3)
        || !TEST_false(hdr.is_fin))
        goto err;

    if (!TEST_true(compare_iov(data_1 + 4, 3, iov, num_iov)))
        goto err;

    /* Retransmit */
    if (!TEST_true(ossl_quic_sstream_mark_transmitted(sstream, 4, 6)))
        goto err;

    /* Read more data; should not be any more */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_false(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov)))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_sstream_get_buffer_used(sstream), 16))
        goto err;

    /* Data has been acknowledged, space should be not be freed yet */
    if (!TEST_true(ossl_quic_sstream_mark_acked(sstream, 1, 7))
        || !TEST_size_t_eq(ossl_quic_sstream_get_buffer_used(sstream), 16))
        goto err;

    /* Now data should be freed */
    if (!TEST_true(ossl_quic_sstream_mark_acked(sstream, 0, 0))
        || !TEST_size_t_eq(ossl_quic_sstream_get_buffer_used(sstream), 8))
        goto err;

    if (!TEST_true(ossl_quic_sstream_mark_acked(sstream, 0, 15))
        || !TEST_size_t_eq(ossl_quic_sstream_get_buffer_used(sstream), 0))
        goto err;

    /* Now FIN */
    ossl_quic_sstream_fin(sstream);

    /* Get FIN frame */
    for (i = 0; i < 2; ++i) {
        num_iov = OSSL_NELEM(iov);
        if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
                &num_iov))
            || !TEST_uint64_t_eq(hdr.offset, 16)
            || !TEST_uint64_t_eq(hdr.len, 0)
            || !TEST_true(hdr.is_fin)
            || !TEST_size_t_eq(num_iov, 0))
            goto err;
    }

    if (!TEST_true(ossl_quic_sstream_mark_transmitted_fin(sstream, 16)))
        goto err;

    /* Read more data; FIN should not be returned any more */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_false(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov)))
        goto err;

    /* Lose FIN frame */
    if (!TEST_true(ossl_quic_sstream_mark_lost_fin(sstream)))
        goto err;

    /* Get FIN frame */
    for (i = 0; i < 2; ++i) {
        num_iov = OSSL_NELEM(iov);
        if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
                &num_iov))
            || !TEST_uint64_t_eq(hdr.offset, 16)
            || !TEST_uint64_t_eq(hdr.len, 0)
            || !TEST_true(hdr.is_fin)
            || !TEST_size_t_eq(num_iov, 0))
            goto err;
    }

    if (!TEST_true(ossl_quic_sstream_mark_transmitted_fin(sstream, 16)))
        goto err;

    /* Read more data; FIN should not be returned any more */
    num_iov = OSSL_NELEM(iov);
    if (!TEST_false(ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov,
            &num_iov)))
        goto err;

    /* Acknowledge fin. */
    if (!TEST_true(ossl_quic_sstream_mark_acked_fin(sstream)))
        goto err;

    if (!TEST_true(ossl_quic_sstream_is_totally_acked(sstream)))
        goto err;

    testresult = 1;
err:
    ossl_quic_sstream_free(sstream);
    return testresult;
}

static int test_sstream_bulk(int idx)
{
    int testresult = 0;
    QUIC_SSTREAM *sstream = NULL;
    OSSL_QUIC_FRAME_STREAM hdr;
    OSSL_QTX_IOVEC iov[2];
    size_t i, j, num_iov = 0, init_size = 8192, l;
    size_t consumed = 0, total_written = 0, rd, cur_rd, expected = 0, start_at;
    unsigned char *src_buf = NULL, *dst_buf = NULL;
    unsigned char *ref_src_buf = NULL, *ref_dst_buf = NULL;
    unsigned char *ref_dst_cur, *ref_src_cur, *dst_cur;

    if (!TEST_ptr(sstream = ossl_quic_sstream_new(init_size)))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_sstream_get_buffer_size(sstream), init_size))
        goto err;

    if (!TEST_ptr(src_buf = OPENSSL_zalloc(init_size)))
        goto err;

    if (!TEST_ptr(dst_buf = OPENSSL_malloc(init_size)))
        goto err;

    if (!TEST_ptr(ref_src_buf = OPENSSL_malloc(init_size)))
        goto err;

    if (!TEST_ptr(ref_dst_buf = OPENSSL_malloc(init_size)))
        goto err;

    /*
     * Append a preliminary buffer to allow later code to exercise wraparound.
     */
    if (!TEST_true(ossl_quic_sstream_append(sstream, src_buf, init_size / 2,
            &consumed))
        || !TEST_size_t_eq(consumed, init_size / 2)
        || !TEST_true(ossl_quic_sstream_mark_transmitted(sstream, 0,
            init_size / 2 - 1))
        || !TEST_true(ossl_quic_sstream_mark_acked(sstream, 0,
            init_size / 2 - 1)))
        goto err;

    start_at = init_size / 2;

    /* Generate a random buffer. */
    for (i = 0; i < init_size; ++i)
        src_buf[i] = (unsigned char)(test_random() & 0xFF);

    /* Append bytes into the buffer in chunks of random length. */
    ref_src_cur = ref_src_buf;
    do {
        l = (test_random() % init_size) + 1;
        if (!TEST_true(ossl_quic_sstream_append(sstream, src_buf, l, &consumed)))
            goto err;

        memcpy(ref_src_cur, src_buf, consumed);
        ref_src_cur += consumed;
        total_written += consumed;
    } while (consumed > 0);

    if (!TEST_size_t_eq(ossl_quic_sstream_get_buffer_used(sstream), init_size)
        || !TEST_size_t_eq(ossl_quic_sstream_get_buffer_avail(sstream), 0))
        goto err;

    /*
     * Randomly select bytes out of the buffer by marking them as transmitted.
     * Record the remaining bytes, which should be the sequence of bytes
     * returned.
     */
    ref_src_cur = ref_src_buf;
    ref_dst_cur = ref_dst_buf;
    for (i = 0; i < total_written; ++i) {
        if ((test_random() & 1) != 0) {
            *ref_dst_cur++ = *ref_src_cur;
            ++expected;
        } else if (!TEST_true(ossl_quic_sstream_mark_transmitted(sstream,
                       start_at + i,
                       start_at + i)))
            goto err;

        ++ref_src_cur;
    }

    /* Exercise resize. */
    if (!TEST_true(ossl_quic_sstream_set_buffer_size(sstream, init_size * 2))
        || !TEST_true(ossl_quic_sstream_set_buffer_size(sstream, init_size)))
        goto err;

    /* Readout and verification. */
    dst_cur = dst_buf;
    for (i = 0, rd = 0; rd < expected; ++i) {
        num_iov = OSSL_NELEM(iov);
        if (!TEST_true(ossl_quic_sstream_get_stream_frame(sstream, i, &hdr, iov,
                &num_iov)))
            goto err;

        cur_rd = 0;
        for (j = 0; j < num_iov; ++j) {
            if (!TEST_size_t_le(iov[j].buf_len + rd, expected))
                goto err;

            memcpy(dst_cur, iov[j].buf, iov[j].buf_len);
            dst_cur += iov[j].buf_len;
            cur_rd += iov[j].buf_len;
        }

        if (!TEST_uint64_t_eq(cur_rd, hdr.len))
            goto err;

        rd += cur_rd;
    }

    if (!TEST_mem_eq(dst_buf, rd, ref_dst_buf, expected))
        goto err;

    testresult = 1;
err:
    OPENSSL_free(src_buf);
    OPENSSL_free(dst_buf);
    OPENSSL_free(ref_src_buf);
    OPENSSL_free(ref_dst_buf);
    ossl_quic_sstream_free(sstream);
    return testresult;
}

static int test_single_copy_read(QUIC_RSTREAM *qrs,
    unsigned char *buf, size_t size,
    size_t *readbytes, int *fin)
{
    const unsigned char *record;
    size_t rec_len;

    *readbytes = 0;

    for (;;) {
        if (!ossl_quic_rstream_get_record(qrs, &record, &rec_len, fin))
            return 0;
        if (rec_len == 0)
            break;
        if (rec_len > size) {
            rec_len = size;
            *fin = 0;
        }
        memcpy(buf, record, rec_len);
        size -= rec_len;
        *readbytes += rec_len;
        buf += rec_len;

        if (!ossl_quic_rstream_release_record(qrs, rec_len))
            return 0;
        if (*fin || size == 0)
            break;
    }

    return 1;
}

static const unsigned char simple_data[] = "Hello world! And thank you for all the fish!";

static int test_rstream_simple(int idx)
{
    QUIC_RSTREAM *rstream = NULL;
    OSSL_QRX_PKT *pkt[8] = { NULL };
    int ret = 0;
    unsigned char buf[sizeof(simple_data)];
    size_t readbytes = 0, avail = 0, i;
    int fin = 0;
    int use_sc = (idx & 1) != 0;
    int use_rbuf = (idx & 2) != 0;
    int (*read_fn)(QUIC_RSTREAM *, unsigned char *, size_t, size_t *,
        int *)
        = use_sc ? test_single_copy_read
                 : ossl_quic_rstream_read;

    /* every frame arrives in a packet, as it does in production */
    for (i = 0; i < OSSL_NELEM(pkt); ++i)
        if (!TEST_ptr(pkt[i] = pkt_test_new(1200)))
            goto err;

    if (!TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[0], 5,
            simple_data + 5, 10, 0))
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[1],
            sizeof(simple_data) - 1,
            simple_data + sizeof(simple_data) - 1,
            1, 1))
        || !TEST_true(ossl_quic_rstream_peek(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 0)
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[2],
            sizeof(simple_data) - 10,
            simple_data + sizeof(simple_data) - 10,
            10, 1))
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[3], 0,
            simple_data, 1, 0))
        || !TEST_true(ossl_quic_rstream_peek(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 1)
        || !TEST_mem_eq(buf, 1, simple_data, 1)
        || (use_rbuf && !TEST_false(ossl_quic_rstream_move_to_rbuf(rstream)))
        || (use_rbuf
            && !TEST_true(ossl_quic_rstream_resize_rbuf(rstream,
                sizeof(simple_data))))
        || (use_rbuf && !TEST_true(ossl_quic_rstream_move_to_rbuf(rstream)))
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[4],
            0, simple_data,
            10, 0))
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[5],
            sizeof(simple_data),
            NULL,
            0, 1))
        || !TEST_true(ossl_quic_rstream_peek(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 15)
        || !TEST_mem_eq(buf, 15, simple_data, 15)
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[6],
            15,
            simple_data + 15,
            sizeof(simple_data) - 15, 1))
        || !TEST_true(ossl_quic_rstream_available(rstream, &avail, &fin))
        || !TEST_true(fin)
        || !TEST_size_t_eq(avail, sizeof(simple_data))
        || !TEST_true(read_fn(rstream, buf, 2, &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 2)
        || !TEST_mem_eq(buf, 2, simple_data, 2)
        || !TEST_true(read_fn(rstream, buf + 2, 12, &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 12)
        || !TEST_mem_eq(buf + 2, 12, simple_data + 2, 12)
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[7],
            sizeof(simple_data),
            NULL,
            0, 1))
        || (use_rbuf
            && !TEST_true(ossl_quic_rstream_resize_rbuf(rstream,
                2 * sizeof(simple_data))))
        || (use_rbuf && !TEST_true(ossl_quic_rstream_move_to_rbuf(rstream)))
        || !TEST_true(read_fn(rstream, buf + 14, 5, &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 5)
        || !TEST_mem_eq(buf, 14 + 5, simple_data, 14 + 5)
        || !TEST_true(read_fn(rstream, buf + 14 + 5, sizeof(buf) - 14 - 5,
            &readbytes, &fin))
        || !TEST_true(fin)
        || !TEST_size_t_eq(readbytes, sizeof(buf) - 14 - 5)
        || !TEST_mem_eq(buf, sizeof(buf), simple_data, sizeof(simple_data))
        || (use_rbuf && !TEST_true(ossl_quic_rstream_move_to_rbuf(rstream)))
        || !TEST_true(read_fn(rstream, buf, sizeof(buf), &readbytes, &fin))
        || !TEST_true(fin)
        || !TEST_size_t_eq(readbytes, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    /* All the references held by the stream must have been released */
    for (i = 0; i < OSSL_NELEM(pkt); ++i) {
        if (pkt[i] != NULL
            && !TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            ret = 0;
        pkt_test_free(pkt[i]);
    }
    return ret;
}

static int test_rstream_random(int idx)
{
    unsigned char *bulk_data = NULL;
    unsigned char *read_buf = NULL;
    QUIC_RSTREAM *rstream = NULL;
    OSSL_QRX_PKT **pkts = NULL;
    size_t i, read_off, queued_min, queued_max, num_pkts = 0;
    const size_t data_size = 10000;
    /* At most two frames are queued per each of the 100 * 10 iterations */
    const size_t max_pkts = 100 * 10 * 2;
    int r, s, fin = 0, fin_set = 0;
    int ret = 0;
    size_t readbytes = 0;

    if (!TEST_ptr(bulk_data = OPENSSL_malloc(data_size))
        || !TEST_ptr(read_buf = OPENSSL_malloc(data_size))
        || !TEST_ptr(pkts = OPENSSL_zalloc(sizeof(*pkts) * max_pkts))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;

    if (idx % 3 == 0)
        ossl_quic_rstream_set_cleanse(rstream, 1);

    for (i = 0; i < data_size; ++i)
        bulk_data[i] = (unsigned char)(test_random() & 0xFF);

    read_off = queued_min = queued_max = 0;
    for (r = 0; r < 100; ++r) {
        for (s = 0; s < 10; ++s) {
            size_t off = (r * 10 + s) * 10, size = 10;
            OSSL_QRX_PKT *pkt = NULL;

            if (test_random() % 10 == 0)
                /* drop packet */
                continue;

            if (off <= queued_min && off + size > queued_min)
                queued_min = off + size;

            /* each frame arrives in its own packet */
            if (!TEST_ptr(pkt = pkt_test_new(1200)))
                goto err;
            pkts[num_pkts++] = pkt;

            if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt, off,
                    bulk_data + off,
                    size, 0)))
                goto err;
            if (queued_max < off + size)
                queued_max = off + size;

            if (test_random() % 5 != 0)
                continue;

            /* random overlapping retransmit */
            off = read_off + test_random() % 50;
            if (off > 50)
                off -= 50;
            size = test_random() % 100 + 1;
            if (off + size > data_size)
                off = data_size - size;
            if (off <= queued_min && off + size > queued_min)
                queued_min = off + size;

            /* a retransmit arrives in its own packet */
            if (!TEST_ptr(pkt = pkt_test_new(1200)))
                goto err;
            pkts[num_pkts++] = pkt;

            if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt, off,
                    bulk_data + off,
                    size, 0)))
                goto err;
            if (queued_max < off + size)
                queued_max = off + size;
        }
        if (idx % 2 == 0) {
            if (!TEST_true(test_single_copy_read(rstream, read_buf, data_size,
                    &readbytes, &fin)))
                goto err;
        } else if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
                       data_size,
                       &readbytes, &fin))) {
            goto err;
        }
        if (!TEST_size_t_ge(readbytes, queued_min - read_off)
            || !TEST_size_t_le(readbytes + read_off, data_size)
            || (idx % 3 != 0
                && !TEST_mem_eq(read_buf, readbytes, bulk_data + read_off,
                    readbytes)))
            goto err;
        read_off += readbytes;
        queued_min = read_off;
        if (test_random() % 50 == 0)
            if (!TEST_true(ossl_quic_rstream_resize_rbuf(rstream,
                    queued_max - read_off + 1))
                || !TEST_true(ossl_quic_rstream_move_to_rbuf(rstream)))
                goto err;
        if (!fin_set && queued_max >= data_size - test_random() % 200) {
            fin_set = 1;
            /* Queue empty fin frame */
            if (!TEST_true(ossl_quic_rstream_queue_data(rstream, NULL, data_size,
                    NULL, 0, 1)))
                goto err;
        }
    }

    TEST_info("Total read bytes: %zu Fin rcvd: %d", read_off, fin);

    if (idx % 3 == 0)
        for (i = 0; i < read_off; i++)
            if (!TEST_uchar_eq(bulk_data[i], 0))
                goto err;

    if (read_off == data_size && fin_set && !fin) {
        /* We might still receive the final empty frame */
        if (idx % 2 == 0) {
            if (!TEST_true(test_single_copy_read(rstream, read_buf, data_size,
                    &readbytes, &fin)))
                goto err;
        } else if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
                       data_size,
                       &readbytes, &fin))) {
            goto err;
        }
        if (!TEST_size_t_eq(readbytes, 0) || !TEST_true(fin))
            goto err;
    }

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    if (pkts != NULL) {
        /* All the references held by the stream must have been released */
        for (i = 0; i < num_pkts; ++i) {
            if (!TEST_size_t_eq(pkt_test_refcount(pkts[i]), 1))
                ret = 0;
            pkt_test_free(pkts[i]);
        }
        OPENSSL_free(pkts);
    }
    OPENSSL_free(bulk_data);
    OPENSSL_free(read_buf);
    return ret;
}

/*
 * Verify the reference counting of packets pinned by buffered stream
 * chunks and the cleansing of packet backed chunks.
 */
static int test_rstream_pkt(void)
{
    QUIC_RSTREAM *rstream = NULL;
    OSSL_QRX_PKT *pkt_a = NULL, *pkt_b = NULL, *pkt_c = NULL;
    unsigned char pdata[64], cbuf[64], buf[64];
    size_t readbytes = 0, avail = 0, i;
    int fin = 0;
    int ret = 0;

    for (i = 0; i < sizeof(pdata); ++i)
        pdata[i] = (unsigned char)(0x40 + i);

    if (!TEST_ptr(pkt_a = pkt_test_new(1200))
        || !TEST_ptr(pkt_b = pkt_test_new(1200))
        || !TEST_ptr(pkt_c = pkt_test_new(1200))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;

    /* A buffered frame holds a reference to its packet */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_a, 0,
            pdata, 10, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 2))
        goto err;

    /* Two frames from the same packet hold two references */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_a, 20,
            pdata + 20, 10, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 3))
        goto err;

    /* A frame contained in already buffered data takes no reference */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_b, 2,
            pdata + 2, 6, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_b), 1))
        goto err;

    /*
     * An overlapping frame drops the frames it covers and releases
     * their references
     */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_c, 0,
            pdata, 15, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 2)
        || !TEST_size_t_eq(pkt_test_refcount(pkt_c), 2))
        goto err;

    /* Reading past a frame releases its reference */
    if (!TEST_true(ossl_quic_rstream_available(rstream, &avail, &fin))
        || !TEST_size_t_eq(avail, 15)
        || !TEST_true(ossl_quic_rstream_read(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 15)
        || !TEST_mem_eq(buf, 15, pdata, 15)
        || !TEST_size_t_eq(pkt_test_refcount(pkt_c), 1)
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 2))
        goto err;

    /* Moving frames to the ring buffer releases their references */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_b, 15,
            pdata + 15, 5, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_b), 2)
        || !TEST_true(ossl_quic_rstream_resize_rbuf(rstream, sizeof(pdata)))
        || !TEST_true(ossl_quic_rstream_move_to_rbuf(rstream))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 1)
        || !TEST_size_t_eq(pkt_test_refcount(pkt_b), 1))
        goto err;

    /* The moved data is still readable from the ring buffer */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 15)
        || !TEST_mem_eq(buf, 15, pdata + 15, 15))
        goto err;

    /* Freeing the stream releases the references of buffered frames */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_c, 30,
            pdata + 30, 10, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_c), 2))
        goto err;
    ossl_quic_rstream_free(rstream);
    rstream = NULL;
    if (!TEST_size_t_eq(pkt_test_refcount(pkt_c), 1))
        goto err;

    /*
     * Cleansing a consumed packet backed chunk wipes exactly the chunk
     * data, leaving the surrounding bytes intact.
     */
    memset(cbuf, 0xAA, sizeof(cbuf));
    if (!TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;
    ossl_quic_rstream_set_cleanse(rstream, 1);
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_a, 0,
            cbuf + 8, 48, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 2)
        || !TEST_true(ossl_quic_rstream_read(rstream, buf, 48,
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 48)
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 1))
        goto err;
    for (i = 0; i < sizeof(cbuf); ++i)
        if (!TEST_uchar_eq(cbuf[i], i >= 8 && i < 56 ? 0 : 0xAA))
            goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    pkt_test_free(pkt_a);
    pkt_test_free(pkt_b);
    pkt_test_free(pkt_c);
    return ret;
}

/*
 * Many small contiguous frames, each pinning its own packet while the reader
 * lags behind, so a large number of packets are held at once and released only
 * as the data is finally consumed. Every byte must still read back in order and
 * every packet reference must end up released.
 */
static int test_rstream_pkt_overhead(void)
{
    QUIC_RSTREAM *rstream = NULL;
    OSSL_QRX_PKT **pkt = NULL;
    unsigned char *data = NULL, *buf = NULL;
    const size_t framesz = 8;
    const size_t nframes = 4096; /* far past a 64 KiB overhead limit */
    const size_t total = framesz * nframes;
    const size_t read_lag = 200; /* read only after this many arrive */
    size_t i, got = 0, readbytes = 0;
    int fin = 0, ret = 0;

    if (!TEST_ptr(data = OPENSSL_malloc(total))
        || !TEST_ptr(buf = OPENSSL_malloc(total))
        || !TEST_ptr(pkt = OPENSSL_zalloc(nframes * sizeof(*pkt)))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;

    for (i = 0; i < total; ++i)
        data[i] = (unsigned char)(i & 0xff);

    for (i = 0; i < nframes; ++i) {
        if (!TEST_ptr(pkt[i] = pkt_test_new(1200)))
            goto err;

        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                i * framesz, data + i * framesz, framesz,
                i == nframes - 1)))
            goto err;

        /* let the reader fall behind, then drain what has become available */
        if (i % read_lag == read_lag - 1)
            while (got < total
                && TEST_true(ossl_quic_rstream_read(rstream, buf + got,
                    total - got, &readbytes, &fin))
                && readbytes > 0)
                got += readbytes;
    }

    /* drain whatever is left and check every byte survived in order */
    while (got < total
        && TEST_true(ossl_quic_rstream_read(rstream, buf + got, total - got,
            &readbytes, &fin))
        && readbytes > 0)
        got += readbytes;

    if (!TEST_size_t_eq(got, total)
        || !TEST_true(fin)
        || !TEST_mem_eq(buf, got, data, total))
        goto err;

    /* every consumed frame has released the reference it held on its packet */
    for (i = 0; i < nframes; ++i)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    if (pkt != NULL)
        for (i = 0; i < nframes; ++i)
            pkt_test_free(pkt[i]);
    OPENSSL_free(pkt);
    OPENSSL_free(data);
    OPENSSL_free(buf);
    return ret;
}

/*
 * Reassemble a buffer delivered as small frames in a random order with
 * overlapping retransmits, each frame carrying its own copy of its bytes on
 * its own packet as a real one would. The random order drives insertion at the
 * head, the tail and the middle of the reassembly, and the frame size is swept
 * across the boundary where a design may switch how it stores a chunk, so short
 * frames and their overlaps are merged in every combination. The read back must
 * match what was sent whether or not the data is cleansed, since each frame's
 * own copy is what gets wiped, never the reference.
 */
static int test_rstream_reorder(int idx)
{
    unsigned char *data = NULL, *buf = NULL, *arena = NULL, *ap;
    QUIC_RSTREAM *rstream = NULL;
    OSSL_QRX_PKT **pkts = NULL;
    const size_t data_size = 4096;
    const size_t framesz = 1 + (size_t)(idx % 17);
    const int cleanse = (idx & 1);
    const size_t nframes = (data_size + framesz - 1) / framesz;
    size_t *order = NULL;
    size_t i, num_pkts = 0, got = 0, readbytes = 0;
    int fin = 0, ret = 0;

    if (!TEST_ptr(data = OPENSSL_malloc(data_size))
        || !TEST_ptr(buf = OPENSSL_malloc(data_size))
        || !TEST_ptr(arena = OPENSSL_malloc(3 * data_size))
        || !TEST_ptr(order = OPENSSL_malloc(nframes * sizeof(*order)))
        || !TEST_ptr(pkts = OPENSSL_zalloc(2 * nframes * sizeof(*pkts)))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, 0)))
        goto err;

    if (cleanse)
        ossl_quic_rstream_set_cleanse(rstream, 1);

    for (i = 0; i < data_size; ++i)
        data[i] = (unsigned char)(test_random() & 0xFF);

    for (i = 0; i < nframes; ++i)
        order[i] = i;
    for (i = nframes; i > 1; --i) {
        size_t j = (size_t)(test_random() % i);
        size_t tmp = order[i - 1];

        order[i - 1] = order[j];
        order[j] = tmp;
    }

    ap = arena;
    for (i = 0; i < nframes; ++i) {
        size_t off = order[i] * framesz;
        size_t size = off + framesz > data_size ? data_size - off : framesz;
        OSSL_QRX_PKT *pkt;

        if (!TEST_ptr(pkt = pkt_test_new(1200)))
            goto err;
        pkts[num_pkts++] = pkt;
        memcpy(ap, data + off, size);
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt, off, ap,
                size, 0)))
            goto err;
        ap += size;

        /* an overlapping retransmit straddling this frame and the next */
        if (off + framesz + framesz / 2 <= data_size
            && test_random() % 3 == 0) {
            size_t roff = off + framesz / 2;
            OSSL_QRX_PKT *rpkt;

            if (!TEST_ptr(rpkt = pkt_test_new(1200)))
                goto err;
            pkts[num_pkts++] = rpkt;
            memcpy(ap, data + roff, framesz);
            if (!TEST_true(ossl_quic_rstream_queue_data(rstream, rpkt, roff, ap,
                    framesz, 0)))
                goto err;
            ap += framesz;
        }
    }

    /* final empty fin frame past the last byte */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, NULL, data_size, NULL,
            0, 1)))
        goto err;

    while (got < data_size) {
        if (!TEST_true(ossl_quic_rstream_read(rstream, buf + got,
                data_size - got, &readbytes, &fin)))
            goto err;
        if (readbytes == 0)
            break;
        got += readbytes;
    }

    if (!TEST_size_t_eq(got, data_size)
        || !TEST_mem_eq(buf, got, data, data_size))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    if (pkts != NULL) {
        for (i = 0; i < num_pkts; ++i) {
            if (!TEST_size_t_eq(pkt_test_refcount(pkts[i]), 1))
                ret = 0;
            pkt_test_free(pkts[i]);
        }
        OPENSSL_free(pkts);
    }
    OPENSSL_free(order);
    OPENSSL_free(arena);
    OPENSSL_free(data);
    OPENSSL_free(buf);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_sstream_simple);
    ADD_ALL_TESTS(test_sstream_bulk, 100);
    ADD_ALL_TESTS(test_rstream_simple, 4);
    ADD_ALL_TESTS(test_rstream_random, 100);
    ADD_TEST(test_rstream_pkt);
    ADD_TEST(test_rstream_pkt_overhead);
    ADD_ALL_TESTS(test_rstream_reorder, 40);
    return 1;
}
