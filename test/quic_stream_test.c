/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <string.h>

#include "internal/packet.h"
#include "internal/quic_record_rx.h"
#include "internal/quic_stream.h"
#include "internal/quic_stream_map.h"
#include "internal/quic_ssl.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_error.h"
#include "../ssl/quic/quic_record_rx_local.h"
#include "../ssl/quic/quic_channel_local.h"
#include "internal/nelem.h"
#include "testutil.h"

#include "internal/list.h"

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

/*
 * Walks the basic sequential contract of the receive stream: a gap at
 * the head reads zero bytes without signalling the end of stream even
 * when FIN is already known, duplicate FIN frames with a matching final
 * size are accepted, available() reports the final size together with
 * FIN, partial reads flip the FIN flag exactly with the last byte and
 * reading at the end of stream stays successful. Runs once with the
 * plain read and once with the single copy record path.
 */
static int test_rstream_simple(int idx)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    OSSL_QRX_PKT *pkt[8] = { NULL };
    int ret = 0;
    unsigned char buf[sizeof(simple_data)];
    size_t readbytes = 0, avail = 0, i;
    int fin = 0;
    int use_sc = (idx & 1) != 0;
    int (*read_fn)(QUIC_RSTREAM *, unsigned char *, size_t, size_t *,
        int *)
        = use_sc ? test_single_copy_read
                 : ossl_quic_rstream_read;

    /* every frame arrives in a packet, as it does in production */
    for (i = 0; i < OSSL_NELEM(pkt); ++i)
        if (!TEST_ptr(pkt[i] = pkt_test_new(1200)))
            goto err;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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
        || !TEST_true(read_fn(rstream, buf + 14, 5, &readbytes, &fin))
        || !TEST_false(fin)
        || !TEST_size_t_eq(readbytes, 5)
        || !TEST_mem_eq(buf, 14 + 5, simple_data, 14 + 5)
        || !TEST_true(read_fn(rstream, buf + 14 + 5, sizeof(buf) - 14 - 5,
            &readbytes, &fin))
        || !TEST_true(fin)
        || !TEST_size_t_eq(readbytes, sizeof(buf) - 14 - 5)
        || !TEST_mem_eq(buf, sizeof(buf), simple_data, sizeof(simple_data))
        || !TEST_true(read_fn(rstream, buf, sizeof(buf), &readbytes, &fin))
        || !TEST_true(fin)
        || !TEST_size_t_eq(readbytes, 0))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
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
    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);
    return ret;
}

static int test_rstream_random(int idx)
{
    unsigned char *bulk_data = NULL;
    unsigned char *read_buf = NULL;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    OSSL_QRX_PKT **pkts = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
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
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

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
    ossl_quic_rstream_qparm_destroy(rsqp);
    OPENSSL_free(bulk_data);
    OPENSSL_free(read_buf);
    ossl_quic_channel_free(ch);
    return ret;
}

/*
 * Verify the reference counting of packets pinned by buffered stream
 * chunks and the cleansing of packet backed chunks.
 */
static int test_rstream_pkt(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
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
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 3)
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
        || !TEST_size_t_eq(pkt_test_refcount(pkt_a), 2))
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
    if (!TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    pkt_test_free(pkt_a);
    pkt_test_free(pkt_b);
    pkt_test_free(pkt_c);
    ossl_quic_channel_free(ch);
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
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    QUIC_CHANNEL *ch = NULL;
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
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    if (pkt != NULL)
        for (i = 0; i < nframes; ++i)
            pkt_test_free(pkt[i]);
    ossl_quic_rstream_qparm_destroy(rsqp);
    OPENSSL_free(pkt);
    OPENSSL_free(data);
    OPENSSL_free(buf);
    ossl_quic_channel_free(ch);
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
    QUIC_CHANNEL *ch = NULL;
    OSSL_QRX_PKT **pkts = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
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
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
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

    if (!TEST_int_eq(ch->protocol_error, 0))
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
    ossl_quic_rstream_qparm_destroy(rsqp);
    OPENSSL_free(order);
    OPENSSL_free(arena);
    OPENSSL_free(data);
    OPENSSL_free(buf);
    ossl_quic_channel_free(ch);
    return ret;
}

/*
 * A zero length read is a successful no-op returning zero read bytes,
 * and releasing a record without consuming any bytes succeeds likewise.
 * Neither may fail once at least one byte has been consumed, otherwise
 * quic_read_actual() turns the failed read into a fatal SSL error for
 * SSL_read_ex() called with a zero length buffer.
 */
static int test_rstream_zero_length_read(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    OSSL_QRX_PKT *pkt = NULL;
    unsigned char pdata[10], buf[10];
    const unsigned char *record = NULL;
    size_t readbytes = 0, rec_len = 0, i;
    int fin = 0;
    int ret = 0;

    for (i = 0; i < sizeof(pdata); ++i)
        pdata[i] = (unsigned char)(0x40 + i);

    if (!TEST_ptr(pkt = pkt_test_new(1200))
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt, 0,
            pdata, sizeof(pdata), 0)))
        goto err;

    /* a zero length read before anything is consumed */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 0, &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 0))
        goto err;

    /* consume some bytes so the stream offset is not zero */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 5, &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 5)
        || !TEST_mem_eq(buf, 5, pdata, 5))
        goto err;

    /* a zero length read with data pending at a nonzero offset */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 0, &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 0))
        goto err;

    /* releasing a record without consuming anything succeeds too */
    if (!TEST_true(ossl_quic_rstream_get_record(rstream, &record, &rec_len,
            &fin))
        || !TEST_size_t_eq(rec_len, 5)
        || !TEST_true(ossl_quic_rstream_release_record(rstream, 0)))
        goto err;

    /* the remaining bytes are intact and still readable */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 5)
        || !TEST_mem_eq(buf, 5, pdata + 5, 5))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    pkt_test_free(pkt);
    ossl_quic_channel_free(ch);
    return ret;
}

/*
 * A short retransmit which starts below an existing range and ends past its
 * direct storage tail chunk is small enough to slip past the full overlap
 * guard in try_dstorage(), whose append path then treats every byte below
 * the tail chunk end as duplicate. The genuinely new bytes below the range
 * start must not be dropped when the insert reports success, otherwise the
 * frame is acked, never retransmitted and the gap in the stream is permanent.
 */
static int test_rstream_dstorage_two_sided_overlap(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    OSSL_QRX_PKT *pkts[59] = { NULL };
    unsigned char pdata[64], buf[64], fill = 0xFF;
    size_t num_pkts = 0, readbytes = 0, avail = 0, i;
    int fin = 0;
    int ret = 0;

    for (i = 0; i < sizeof(pdata); ++i)
        pdata[i] = (unsigned char)(0x40 + i);

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
        goto err;

    for (i = 0; i < OSSL_NELEM(pkts); ++i)
        if (!TEST_ptr(pkts[num_pkts++] = pkt_test_new(1200)))
            goto err;

    /* a packet backed chunk [10, 11) while below the overhead limit */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[0], 10,
            pdata + 10, 1, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[0]), 2))
        goto err;

    /*
     * disjoint 1-byte frames on 1200 byte datagrams, each accounting
     * 1199 bytes of overhead, take the stream past the 64kB overhead
     * limit so that short chunks switch to direct storage
     */
    for (i = 0; i < 55; ++i)
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[1 + i],
                100 + 2 * i, &fill, 1, 0)))
            goto err;

    /*
     * [11, 12) goes to the direct storage of a new tail chunk appended
     * to the range, holding no reference to its packet
     */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[56], 11,
            pdata + 11, 1, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[56]), 1))
        goto err;

    /*
     * a 6 byte retransmit [8, 14) starts below the range [10, 12) and
     * ends past its direct storage tail chunk, the bytes [8, 10) are
     * new and must be kept
     */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[57], 8,
            pdata + 8, 6, 0)))
        goto err;

    /* deliver the head [0, 8) so everything up to 14 is contiguous */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[58], 0,
            pdata, 8, 0)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_available(rstream, &avail, &fin))
        || !TEST_size_t_eq(avail, 14)
        || !TEST_true(ossl_quic_rstream_read(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 14)
        || !TEST_mem_eq(buf, readbytes, pdata, 14))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    for (i = 0; i < num_pkts; ++i)
        pkt_test_free(pkts[i]);
    ossl_quic_channel_free(ch);
    return ret;
}

/*
 * A FIN must be rejected as a final size error when data is already
 * buffered past its offset, or when the application has consumed more
 * bytes than the final size claims. Otherwise the frames beyond the FIN
 * offset stay pinned unreadable until the stream is torn down, and a
 * FIN below the consumed offset is recorded but can never signal the
 * end of the stream to the application.
 */
static int test_rstream_fin_final_size(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    OSSL_QRX_PKT *pkt_a = NULL, *pkt_b = NULL;
    unsigned char pdata[16], buf[16];
    size_t readbytes = 0, i;
    int fin = 0;
    int ret = 0;

    for (i = 0; i < sizeof(pdata); ++i)
        pdata[i] = (unsigned char)(0x40 + i);

    /* a FIN below data which is already buffered in a higher range */
    if (!TEST_ptr(pkt_a = pkt_test_new(1200))
        || !TEST_ptr(pkt_b = pkt_test_new(1200))
        || !TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_a, 0,
            pdata, 10, 0))
        || !TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_b, 100,
            pdata, 10, 0)))
        goto err;

    if (!TEST_false(ossl_quic_rstream_queue_data(rstream, NULL, 50, NULL,
            0, 1))
        || !TEST_int_eq(ch->protocol_error, 1))
        goto err;

    ossl_quic_rstream_free(rstream);
    rstream = NULL;
    ossl_quic_rstream_qparm_destroy(rsqp);
    rsqp = NULL;
    ossl_quic_channel_free(ch);
    ch = NULL;

    /* a FIN below the offset the application has consumed already */
    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt_a, 0,
            pdata, 10, 0))
        || !TEST_true(ossl_quic_rstream_read(rstream, buf, sizeof(buf),
            &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 10))
        goto err;

    if (!TEST_false(ossl_quic_rstream_queue_data(rstream, NULL, 3, NULL,
            0, 1))
        || !TEST_int_eq(ch->protocol_error, 1))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    pkt_test_free(pkt_a);
    pkt_test_free(pkt_b);
    ossl_quic_channel_free(ch);
    return ret;
}

static int cleanse_buf_check(const unsigned char *buf, size_t size,
    size_t data_start, size_t data_end)
{
    size_t i;

    for (i = 0; i < size; ++i)
        if (!TEST_uchar_eq(buf[i],
                i >= data_start && i < data_end ? 0x00 : 0xAA)) {
            TEST_info("byte %zu", i);
            return 0;
        }

    return 1;
}

/*
 * With cleansing enabled, every dropped duplicate byte of an incoming
 * frame must be wiped in its packet buffer: a retransmit reaching below
 * the consumed offset, a retransmit consumed entirely, a duplicate
 * contained in an existing range and the tail trimmed away when a short
 * frame is prepended to a direct storage chunk. Otherwise the plaintext
 * stays in the recycled packet buffer which nothing else cleanses.
 */
static int test_rstream_cleanse_dropped_bytes(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    OSSL_QRX_PKT *pkts[60] = { NULL };
    unsigned char src_a[16], src_b[16], src_c[16], src_d[16], src_e[16];
    unsigned char buf[16], fill = 0xFF;
    size_t num_pkts = 0, readbytes = 0, i;
    int fin = 0;
    int ret = 0;

    memset(src_a, 0xAA, sizeof(src_a));
    memset(src_b, 0xAA, sizeof(src_b));
    memset(src_c, 0xAA, sizeof(src_c));
    memset(src_d, 0xAA, sizeof(src_d));
    memset(src_e, 0xAA, sizeof(src_e));
    for (i = 0; i < 10; ++i)
        src_a[3 + i] = (unsigned char)(0x40 + i);

    for (i = 0; i < OSSL_NELEM(pkts); ++i)
        if (!TEST_ptr(pkts[num_pkts++] = pkt_test_new(1200)))
            goto err;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL)))
        || !TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch))
        || !TEST_ptr(rstream = ossl_quic_rstream_new(NULL, NULL, rsqp)))
        goto err;
    ossl_quic_rstream_set_cleanse(rstream, 1);

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[0], 0,
            src_a + 3, 10, 0))
        || !TEST_true(ossl_quic_rstream_read(rstream, buf, 5, &readbytes,
            &fin))
        || !TEST_size_t_eq(readbytes, 5))
        goto err;

    /* a retransmit reaching below the consumed offset is wiped whole */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[1], 0,
            src_b + 3, 10, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[1]), 1)
        || !cleanse_buf_check(src_b, sizeof(src_b), 3, 13))
        goto err;

    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 5, &readbytes, &fin))
        || !TEST_size_t_eq(readbytes, 5))
        goto err;

    /* a fully consumed retransmit is wiped whole */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[2], 0,
            src_c + 3, 10, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[2]), 1)
        || !cleanse_buf_check(src_c, sizeof(src_c), 3, 13))
        goto err;

    /*
     * disjoint 1-byte frames on 1200 byte datagrams take the stream
     * past the overhead limit so short chunks use direct storage
     */
    for (i = 0; i < 55; ++i)
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[3 + i],
                100 + 2 * i, &fill, 1, 0)))
            goto err;

    /* the copied direct storage chunk has its source wiped already */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[58], 20,
            src_d + 3, 2, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[58]), 1)
        || !cleanse_buf_check(src_d, sizeof(src_d), 3, 5))
        goto err;

    /*
     * [18, 21) prepends [18, 20) to the direct storage chunk [20, 22)
     * and drops the duplicate byte [20, 21), all three source bytes
     * must be wiped
     */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[59], 18,
            src_e + 3, 3, 0))
        || !TEST_size_t_eq(pkt_test_refcount(pkts[59]), 1)
        || !cleanse_buf_check(src_e, sizeof(src_e), 3, 6))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ret = 1;

err:
    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    for (i = 0; i < num_pkts; ++i)
        pkt_test_free(pkts[i]);
    ossl_quic_channel_free(ch);
    return ret;
}

#define FILL_PATTERN "abcdefghijklmnopqrstuvwxyz0123456789" \
                     "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

typedef struct test_stream_chunk {
    const unsigned char *tsc_data;
    uint64_t tsc_off; /* start == offset */
    uint64_t tsc_len; /* end = offset + len */
    int tsc_fin;
    size_t tsc_chunks_exp;
    size_t tsc_ranges_exp;
} TEST_STREAM_CHUNK_T;

static int test_rstream_chunk_partial_overlap(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[7];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int fin = 0;
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * 1 range, (0, 120) with 5 stream chunks. there is a partial overlap
     * between chunks.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 32;
    tsc->tsc_chunks_exp = 5;
    tsc->tsc_ranges_exp = 1;
    send_order[6] = 0;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[24];
    tsc->tsc_off = 24;
    tsc->tsc_len = 48;
    tsc->tsc_chunks_exp = 5;
    tsc->tsc_ranges_exp = 1;
    send_order[4] = 1;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[44];
    tsc->tsc_off = 44;
    tsc->tsc_len = 20;
    tsc->tsc_chunks_exp = 4;
    tsc->tsc_ranges_exp = 1;
    send_order[3] = 2;

    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[55];
    tsc->tsc_off = 55;
    tsc->tsc_len = 50;
    tsc->tsc_chunks_exp = 1;
    tsc->tsc_ranges_exp = 1;
    send_order[0] = 3;

    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[100];
    tsc->tsc_off = 100;
    tsc->tsc_len = 19;
    tsc->tsc_chunks_exp = 3;
    tsc->tsc_ranges_exp = 1;
    send_order[2] = 4;

    tsc = &tsc_buf[5];
    tsc->tsc_data = &data[119];
    tsc->tsc_off = 119;
    tsc->tsc_len = 1;
    tsc->tsc_fin = 1;
    tsc->tsc_chunks_exp = 2;
    tsc->tsc_ranges_exp = 2;
    send_order[1] = 5;

    /*
     * add duplicate chunk, the chunk range 48, 64 exists already
     * in the range, thus no additional stream chunk will be created.
     */
    tsc = &tsc_buf[6];
    tsc->tsc_data = &data[49];
    tsc->tsc_off = 48;
    tsc->tsc_len = 16;
    tsc->tsc_chunks_exp = 5;
    tsc->tsc_ranges_exp = 1;
    send_order[5] = 6;

    /*
     * send everything except offset 0.
     */
    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf) - 1; i++) {
        pkt[i] = pkt_test_new(1200);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin))) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        /*
         * the offset 0 chunk is not transmitted in loop here,
         * make sure the stream does not become readable.
         */
        if (!TEST_true(ossl_quic_rstream_peek(rstream, read_buf,
                sizeof(read_buf), &readbytes, &fin))) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_false(fin)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(readbytes, 0)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    /*
     * although 6 chunks were inserted, we expect to find only 5 chunks
     * in range, the last chunk was duplicate.
     */
    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream), 5))
        goto err;

    /*
     * send offset 0 chunk, and try to read from stream.
     */
    pkt[i] = pkt_test_new(1200);
    if (!TEST_ptr(pkt[i]))
        goto err;
    tsc = &tsc_buf[0];
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
            tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
        goto err;

    /*
     * writing chunk offset 0 makes stream readable
     */
    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    /*
     * we expect to read 120 bytes
     */
    if (!TEST_uint64_t_eq(readbytes, 120))
        goto err;

    /*
     * the fin written by loop should be signaled too.
     */
    if (!TEST_true(fin))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

/*
 * use 64kB as datagram size to force QUIC stack
 * to rach overhead threshold for all packets used
 * by test. So all data will be moved to stream buffers
 */
#define MOVE_TRESHOLD 65535 * 2

static int test_rstream_chunk_full_overlap(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[5];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int fin;
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * 1 range, (0, 256) with 5 stream chunks. 5 chunks overlap
     * partially, The last chunk we insert overlaps the whole range.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 256;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[4] = 0;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[24];
    tsc->tsc_off = 24;
    tsc->tsc_len = 48;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 4;
    send_order[3] = 1;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[44];
    tsc->tsc_off = 44;
    tsc->tsc_len = 20;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 3;
    send_order[2] = 2;

    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[55];
    tsc->tsc_off = 55;
    tsc->tsc_len = 50;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[0] = 3;

    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[100];
    tsc->tsc_off = 100;
    tsc->tsc_len = 20;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 2;
    send_order[1] = 4;

    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf); i++) {
        pkt[i] = pkt_test_new(MOVE_TRESHOLD);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, 0)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    if (!TEST_false(fin))
        goto err;

    /*
     * we expect to read 256 bytes
     */
    if (!TEST_uint64_t_eq(readbytes, 256))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_rstream_range_overlap(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[9];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    int fin;
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * start with 5 ranges,
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 64;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[128];
    tsc->tsc_off = 128;
    tsc->tsc_len = 64;
    tsc->tsc_ranges_exp = 2;
    tsc->tsc_chunks_exp = 2;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[256];
    tsc->tsc_off = 256;
    tsc->tsc_len = 64;
    tsc->tsc_ranges_exp = 3;
    tsc->tsc_chunks_exp = 3;

    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[384];
    tsc->tsc_off = 384;
    tsc->tsc_len = 64;
    tsc->tsc_ranges_exp = 4;
    tsc->tsc_chunks_exp = 4;

    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[512];
    tsc->tsc_off = 512;
    tsc->tsc_len = 64;
    tsc->tsc_ranges_exp = 5;
    tsc->tsc_chunks_exp = 5;

    /*
     * chunk 6 appends data to last range
     */
    tsc = &tsc_buf[5];
    tsc->tsc_data = &data[548];
    tsc->tsc_off = 548;
    tsc->tsc_len = 220;
    tsc->tsc_ranges_exp = 5;
    tsc->tsc_chunks_exp = 6;

    /*
     * chunk 7 prepends data to last range
     */
    tsc = &tsc_buf[6];
    tsc->tsc_data = &data[480];
    tsc->tsc_off = 480;
    tsc->tsc_len = 64;
    tsc->tsc_chunks_exp = 7;
    tsc->tsc_ranges_exp = 5;

    /*
     * chunk 8 fully covers range 4 and partially
     * overlaps with 5
     */
    tsc = &tsc_buf[7];
    tsc->tsc_data = &data[364];
    tsc->tsc_off = 364;
    tsc->tsc_len = 500;
    /*
     * note the expected number of chunks actually decreases!!!
     * here is what happened:
     * chunk [ 364, 864 ] is going to be inserted into range number 4
     * which spans over [ 384, 448 ]. After chunk is inserted the
     * 4th range looks as follows:
     *   [ 364, 864 ], it contains 3 chunks:
     *      [ 364, 384 ]
     *      [ 384, 448 ]
     *      [ 448, 864 ]
     *
     * however the 4th range now overlaps with 5th range [ 480, 768 ].
     * the fifth range also contains 3 chunks:
     *   [ 480, 768 ]
     *      [ 480, 512 ]
     *      [ 512, 576 ]
     *      [ 576, 768 ]
     * as you can see there is a full overlap. The new range is going
     * to look as:
     *   [ 364, 864 ]
     *      [ 364, 384 ]
     *      [ 384, 448 ]
     *      [ 448, 864 ]
     * the 5th range is gone with all its ranges. the ranges 1, 2 and 3
     * where not touched so far, each of them contain one range, this
     * makes total 6 ranges.
     */
    tsc->tsc_chunks_exp = 4;
    tsc->tsc_ranges_exp = 4;

    /*
     * chunk 9 partially overlaps with the first and
     * the last range,
     */
    tsc = &tsc_buf[8];
    tsc->tsc_data = &data[32];
    tsc->tsc_off = 32;
    tsc->tsc_len = 500;
    tsc->tsc_chunks_exp = 3;
    tsc->tsc_ranges_exp = 1;

    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf); i++) {
        pkt[i] = pkt_test_new(1200);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[i];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, 0)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    if (!TEST_false(fin))
        goto err;

    /*
     * we expect to read 864 bytes
     */
    if (!TEST_uint64_t_eq(readbytes, 864))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_rstream_prepend_byte_chunks(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[6];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int fin;
    int ok = 0;

    if (sizeof(void *) != 8) {
        TEST_info("%s is implemented for 64-bit platforms only", OPENSSL_FUNC);
        return 1;
    }

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * here we test one byte stream chunks. this test verifies
     * more short stream chunks are stored in single chunk buffer.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 1;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[4] = 0;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[1];
    tsc->tsc_off = 1;
    tsc->tsc_len = 2;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[3] = 1;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[3];
    tsc->tsc_off = 3;
    tsc->tsc_len = 5;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[2] = 2;

    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[8];
    tsc->tsc_off = 8;
    tsc->tsc_len = 4;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[1] = 3;

    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[12];
    tsc->tsc_off = 12;
    tsc->tsc_len = 4;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[0] = 4;

    tsc = &tsc_buf[5];
    tsc->tsc_data = &data[12];
    tsc->tsc_off = 12;
    tsc->tsc_len = 12;
    tsc->tsc_ranges_exp = 1;
    /*
     * this chunk partially overlaps. It does not fit to stream chunk buffer
     * created earlier, therefore a new stream chunk will be created.
     */
    tsc->tsc_chunks_exp = 2;
    send_order[5] = 5;

    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf); i++) {
        pkt[i] = pkt_test_new(MOVE_TRESHOLD);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, 0)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    if (!TEST_false(fin))
        goto err;

    /*
     * we expect to read 24 bytes
     */
    if (!TEST_uint64_t_eq(readbytes, 24))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_rstream_append_byte_chunks(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[6];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int fin;
    int ok = 0;

    if (sizeof(void *) != 8) {
        TEST_info("%s is implemented for 64-bit platforms only", OPENSSL_FUNC);
        return 1;
    }

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * here we test one byte stream chunks. this test verifies
     * more short stream chunks are stored in single chunk buffer.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 1;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[0] = 0;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[1];
    tsc->tsc_off = 1;
    tsc->tsc_len = 2;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[1] = 1;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[3];
    tsc->tsc_off = 3;
    tsc->tsc_len = 5;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[2] = 2;

    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[8];
    tsc->tsc_off = 8;
    tsc->tsc_len = 4;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[3] = 3;

    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[12];
    tsc->tsc_off = 12;
    tsc->tsc_len = 4;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[4] = 4;

    tsc = &tsc_buf[5];
    tsc->tsc_data = &data[12];
    tsc->tsc_off = 12;
    tsc->tsc_len = 12;
    /*
     * this chunk partially overlaps. It does not fit to stream chunk buffer
     * created by for() loop above, therefore a new stream chunk will be created.
     */
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 2;
    send_order[5] = 5;

    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf); i++) {
        pkt[i] = pkt_test_new(MOVE_TRESHOLD);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, 0)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    /*
     * we expect to read 24 bytes
     */
    if (!TEST_uint64_t_eq(readbytes, 24))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_rstream_mix_chunks(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[7];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    size_t readbytes;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int fin;
    int ok = 0;

    if (sizeof(void *) != 8) {
        TEST_info("%s is implemented for 64-bit platforms only", OPENSSL_FUNC);
        return 1;
    }

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * we start with 4-byte nibble which at offset 8.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[8];
    tsc->tsc_off = 8;
    tsc->tsc_len = 4;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[0] = 0;

    /*
     * the next 3 byte nibble partially overlaps with
     * earlier one. it adds 1 byte. it is prepended
     */
    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[7];
    tsc->tsc_off = 7;
    tsc->tsc_len = 3;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[1] = 1;

    /*
     * the next 3 byte nibble partially overlaps with
     * range. it effectively adds 1 byte to end.
     */
    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[10];
    tsc->tsc_off = 10;
    tsc->tsc_len = 3;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[2] = 2;

    /*
     * append nibble that fully overlaps with range
     * (the new nibble is superset of existing range)
     * it effectively adds two bytes
     */
    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[6];
    tsc->tsc_off = 6;
    tsc->tsc_len = 8;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[3] = 3;

    /*
     * prepend the nibble which starts yet another range.
     */
    tsc = &tsc_buf[4];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 1;
    tsc->tsc_ranges_exp = 2;
    tsc->tsc_chunks_exp = 2;
    send_order[4] = 4;

    /*
     * nibble here appends bytes to right range. the range count and chunk
     * count must not change as new data still fit to dstorage.
     */
    tsc = &tsc_buf[5];
    tsc->tsc_data = &data[14];
    tsc->tsc_off = 14;
    tsc->tsc_len = 3;
    tsc->tsc_ranges_exp = 2;
    tsc->tsc_chunks_exp = 2;
    send_order[5] = 5;

    /*
     * send chunk that overlaps everything
     */
    tsc = &tsc_buf[6];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 24;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 2;
    send_order[6] = 6;

    /*
     * all nibbles we've sent so far must fit to single range.
     */
    assert(OSSL_NELEM(tsc_buf) == OSSL_NELEM(pkt));
    for (i = 0; i < OSSL_NELEM(tsc_buf); i++) {
        pkt[i] = pkt_test_new(MOVE_TRESHOLD);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, 0)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            sizeof(read_buf), &readbytes, &fin)))
        goto err;

    if (!TEST_uint64_t_eq(readbytes, 24))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
            goto err;

    if (!TEST_int_eq(ch->protocol_error, 0))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_final_size_violation_fin_first(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[3];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    unsigned int i;
    unsigned int send_order[OSSL_NELEM(tsc_buf)];
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * we start with 4-byte nibble which at offset 8.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[10];
    tsc->tsc_off = 10;
    tsc->tsc_len = 10;
    tsc->tsc_fin = 1;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;
    send_order[0] = 0;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[5];
    tsc->tsc_off = 5;
    tsc->tsc_len = 5;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 2;
    send_order[1] = 1;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[50];
    tsc->tsc_off = 20;
    tsc->tsc_len = 10;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 2;
    send_order[2] = 2;

    for (i = 0; i < OSSL_NELEM(tsc_buf) - 1; i++) {
        pkt[i] = pkt_test_new(1200);
        if (!TEST_ptr(pkt[i]))
            goto err;
        tsc = &tsc_buf[send_order[i]];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[i],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }
    }

    pkt[i] = pkt_test_new(1200);
    if (!TEST_ptr(pkt[i]))
        goto err;
    tsc = &tsc_buf[send_order[i]];
    if (!TEST_false(ossl_quic_rstream_queue_data(rstream, pkt[i],
            tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
            tsc->tsc_ranges_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
            tsc->tsc_chunks_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    for (i = 0; i < OSSL_NELEM(tsc_buf) - 1; i++)
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 2))
            goto err;

    if (!TEST_size_t_eq(pkt_test_refcount(pkt[i]), 1))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 1))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static int test_final_size_violation_data_first(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    TEST_STREAM_CHUNK_T tsc_buf[3];
    OSSL_QRX_PKT *pkt[OSSL_NELEM(tsc_buf)] = { 0 };
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    unsigned int i;
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    /*
     * we start with 4-byte nibble which at offset 8.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[10];
    tsc->tsc_off = 10;
    tsc->tsc_len = 10;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[5];
    tsc->tsc_off = 5;
    tsc->tsc_len = 5;
    tsc->tsc_fin = 1;
    tsc->tsc_ranges_exp = 1;
    tsc->tsc_chunks_exp = 1;

    pkt[0] = pkt_test_new(1200);
    if (!TEST_ptr(pkt[0]))
        goto err;
    tsc = &tsc_buf[0];
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[0],
            tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
        goto err;

    /*
     * check our assumptions about about reassemble process internals.
     */
    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
            tsc->tsc_ranges_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
            tsc->tsc_chunks_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    pkt[1] = pkt_test_new(1200);
    if (!TEST_ptr(pkt[1]))
        goto err;
    tsc = &tsc_buf[1];
    if (!TEST_false(ossl_quic_rstream_queue_data(rstream, pkt[1],
            tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
            tsc->tsc_ranges_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
            tsc->tsc_chunks_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(pkt_test_refcount(pkt[0]), 2))
        goto err;

    if (!TEST_size_t_eq(pkt_test_refcount(pkt[1]), 1))
        goto err;

    if (!TEST_int_eq(ch->protocol_error, 1))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(tsc_buf); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

#define FILLERS 56

static int test_trim_right(void)
{
    unsigned char data[4096];
    unsigned char read_buf[4096];
    size_t readbytes;
    TEST_STREAM_CHUNK_T tsc_buf[4];
    OSSL_QRX_PKT *pkt[FILLERS + OSSL_NELEM(tsc_buf)] = { 0 };
    unsigned char fill = 0xFF;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    TEST_STREAM_CHUNK_T *tsc;
    QUIC_RSTREAM *rstream = NULL;
    QUIC_CHANNEL *ch = NULL;
    int fin;
    unsigned int i, pktnum;
    int ok = 0;

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    for (i = 0; i < sizeof(data); i++)
        data[i] = FILL_PATTERN[i % (sizeof(FILL_PATTERN) - 1)];

    memset(tsc_buf, 0, sizeof(tsc_buf));
    memset(read_buf, 0, sizeof(read_buf));

    pktnum = 0;
    for (i = 0; i < FILLERS; i++) {
        pkt[pktnum] = pkt_test_new(1200);
        if (!TEST_ptr(pkt[pktnum]))
            goto err;

        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[pktnum],
                1024 + 2 * i, &fill, 1, 0)))
            goto err;

        pktnum++;
    }

    /*
     * send three chunks. each 64 bytes long,
     * chunks create three ranges.
     */
    tsc = &tsc_buf[0];
    tsc->tsc_data = &data[0];
    tsc->tsc_off = 0;
    tsc->tsc_len = 64;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = FILLERS + 1;
    tsc->tsc_chunks_exp = FILLERS + 1;

    tsc = &tsc_buf[1];
    tsc->tsc_data = &data[128];
    tsc->tsc_off = 128;
    tsc->tsc_len = 64;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = FILLERS + 2;
    tsc->tsc_chunks_exp = FILLERS + 2;

    tsc = &tsc_buf[2];
    tsc->tsc_data = &data[256];
    tsc->tsc_off = 256;
    tsc->tsc_len = 64;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = FILLERS + 3;
    tsc->tsc_chunks_exp = FILLERS + 3;

    for (i = 0; i < OSSL_NELEM(tsc_buf) - 1; i++) {
        pkt[pktnum] = pkt_test_new(1200);
        if (!TEST_ptr(pkt[pktnum]))
            goto err;
        tsc = &tsc_buf[i];
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[pktnum],
                tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
            goto err;

        /*
         * check our assumptions about about reassemble process internals.
         */
        if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
                tsc->tsc_ranges_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
                tsc->tsc_chunks_exp)) {
            TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
            goto err;
        }

        /*
         * the packet reference should stay at 1, because _rstream_queue_data()
         * copies data to stream buffer instead of grabbing a reference to
         * packet (advancing the packet's ref counter)
         */
        if (!TEST_size_t_eq(pkt_test_refcount(pkt[pktnum]), 1))
            goto err;
        pktnum++;
    }

    /*
     * do a partial read of 16 bytes.
     */
    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            16, &readbytes, &fin)))
        goto err;

    if (!TEST_uint64_t_eq(readbytes, 16))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, data, readbytes))
        goto err;

    /*
     * send chunk that glues three ranges together.
     */
    tsc = &tsc_buf[3];
    tsc->tsc_data = &data[63];
    tsc->tsc_off = 63;
    tsc->tsc_len = 160;
    tsc->tsc_fin = 0;
    tsc->tsc_ranges_exp = FILLERS + 2;
    tsc->tsc_chunks_exp = FILLERS + 3;

    pkt[pktnum] = pkt_test_new(1200);
    if (!TEST_ptr(pkt[pktnum]))
        goto err;
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkt[pktnum],
            tsc->tsc_off, tsc->tsc_data, tsc->tsc_len, tsc->tsc_fin)))
        goto err;

    /*
     * check our assumptions about about reassemble process internals.
     */
    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
            tsc->tsc_ranges_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
            tsc->tsc_chunks_exp)) {
        TEST_info("%s failing iteration %u", OPENSSL_FUNC, i);
        goto err;
    }

    if (!TEST_size_t_eq(pkt_test_refcount(pkt[pktnum]), 1))
        goto err;
    pktnum++;

    if (!TEST_true(ossl_quic_rstream_read(rstream, read_buf,
            4096, &readbytes, &fin)))
        goto err;

    /*
     * the ranges are still dis-joint, only 207 bytes can be read
     */
    if (!TEST_uint64_t_eq(readbytes, 207))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(read_buf, readbytes, &data[16], readbytes))
        goto err;

    ok = 1;
err:
    ossl_quic_rstream_free(rstream);

    for (i = 0; i < OSSL_NELEM(pkt); i++)
        pkt_test_free(pkt[i]);

    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);

    return ok;
}

static CRYPTO_malloc_fn malloc_save;
static CRYPTO_realloc_fn realloc_save;
static CRYPTO_free_fn free_save;

#if defined(__GNUC__) || defined(__clang__)
#define ALIGN_ALLOC_HDR __attribute((aligned(16)))
#else
#define ALIGN_ALLOC_HDR
#endif

/*
 * Increased alignment is needed, as tdc_malloc() custom allocator
 * returns memory addresses directly following a TDC_ALLOC_HDR.
 */
typedef struct ALIGN_ALLOC_HDR tdc_alloc_hdr_st {
    size_t size;
    OSSL_LIST_MEMBER(tdc, struct tdc_alloc_hdr_st);
} TDC_ALLOC_HDR;

DEFINE_LIST_OF(tdc, TDC_ALLOC_HDR);

#define TDC_EXPECTED8_SZ 8
#define TDC_EXPECTED16_SZ 16

static int tdc_watch_free;
static const unsigned char tdc_expected8[TDC_EXPECTED8_SZ + 1] = "IJKLMNOP";
static int tdc_saw_remnant_on_free;
static int tdc_watch_free;

static OSSL_LIST(tdc)
    tdc_alloc_list;

static void *tdc_malloc(size_t sz, const char *file, int line)
{
    TDC_ALLOC_HDR *h;

    if (sz == 0)
        return NULL;
    h = malloc_save(sizeof(*h) + sz, file, line);
    if (h == NULL)
        return NULL;
    h->size = sz;
    ossl_list_tdc_init_elem(h);
    ossl_list_tdc_insert_head(&tdc_alloc_list, h);
    memset(&h[1], 0, sz);

    return &h[1];
}

static int tdc_find_pattern(const unsigned char *pat, size_t plen,
    unsigned char *window, size_t win)
{
    TDC_ALLOC_HDR *h;

    OSSL_LIST_FOREACH (h, tdc, &tdc_alloc_list) {
        unsigned char *p = (unsigned char *)&h[1];
        size_t i;

        for (i = 0; i + plen <= h->size; ++i) {
            if (memcmp(p + i, pat, plen) == 0) {
                if (window != NULL && win > 0) {
                    size_t n = h->size - i;

                    if (n > win)
                        n = win;
                    memcpy(window, p + i, n);
                }
                return 1;
            }
        }
    }

    return 0;
}

static void tdc_inspect_before_free(void *ptr, size_t size)
{
    const unsigned char *p = ptr;
    size_t i;

    if (size < sizeof(tdc_expected8))
        return;

    for (i = 0; i + sizeof(tdc_expected8) <= size; ++i) {
        if (memcmp(p + i, tdc_expected8, sizeof(tdc_expected8)) == 0) {
            tdc_saw_remnant_on_free = 1;
            return;
        }
    }
}

static void tdc_free(void *ptr, const char *file, int line)
{
    TDC_ALLOC_HDR *h = (TDC_ALLOC_HDR *)ptr;

    if (ptr == NULL)
        return;
    h = &h[-1];
    if (tdc_watch_free)
        tdc_inspect_before_free(ptr, h->size);

    ossl_list_tdc_remove(&tdc_alloc_list, h);

    free_save(h, file, line);
}

static void *tdc_realloc(void *ptr, size_t sz, const char *file, int line)
{
    TDC_ALLOC_HDR *h, *nh;

    if (ptr == NULL)
        return tdc_malloc(sz, file, line);

    if (sz == 0) {
        tdc_free(ptr, file, line);
        return NULL;
    }

    h = (TDC_ALLOC_HDR *)ptr;
    h = &h[-1];

    ossl_list_tdc_remove(&tdc_alloc_list, h);
    nh = realloc(h, sizeof(*nh) + sz);
    if (nh == NULL) {
        ossl_list_tdc_insert_head(&tdc_alloc_list, h);
        return NULL;
    }
    ossl_list_tdc_insert_head(&tdc_alloc_list, nh);

    if (sz > nh->size)
        memset((unsigned char *)&nh[1] + nh->size, 0, sz - nh->size);
    nh->size = sz;

    return &nh[1];
}

static int test_dstorage_cleanse(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    QUIC_CHANNEL *ch = NULL;
    OSSL_QRX_PKT *pkts[FILLERS + 2];
    unsigned char fill = 0xFF;
    unsigned char src[TDC_EXPECTED16_SZ];
    unsigned char buf[TDC_EXPECTED16_SZ];
    unsigned char zero_buf[TDC_EXPECTED16_SZ] = { 0 };
    const unsigned char expected16[TDC_EXPECTED16_SZ + 1] = "ABCDEFGHIJKLMNOP";
    const unsigned char doubled[TDC_EXPECTED16_SZ + 1] = "IJKLMNOPIJKLMNOP";
    unsigned char window[TDC_EXPECTED16_SZ * 2];
    size_t i, npkts = 0, readbytes = 0;
    int fin = 0, ok = 0;
    int found_after_insert = 0, found_after_partial = 0;

    if (sizeof(void *) != 8) {
        TEST_info("%s is implemented for 64-bit platforms only", OPENSSL_FUNC);
        return 1;
    }

    malloc_save = NULL;
    free_save = NULL;
    realloc_save = NULL;
    CRYPTO_get_mem_functions(&malloc_save, &realloc_save, &free_save);
    ok = CRYPTO_set_mem_functions(tdc_malloc, tdc_realloc, tdc_free);
    if (!TEST_true(ok))
        goto err;
    ok = 0;

    memcpy(src, expected16, sizeof(src));

    ossl_list_tdc_init(&tdc_alloc_list);

    if (!TEST_ptr(ch = OPENSSL_zalloc(sizeof(QUIC_CHANNEL))))
        return 0;

    if (!TEST_ptr(rsqp = ossl_quic_rstream_qparm_new(ch)))
        goto err;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    ossl_quic_rstream_set_cleanse(rstream, 1);

    for (i = 0; i < FILLERS + 2; i++) {
        pkts[i] = pkt_test_new(1200);
        if (!TEST_ptr(pkts[i]))
            goto err;
        npkts++;
    }

    /*
     * Disjoint 1-byte frames on 1200-byte datagrams push packet overhead
     * past 64 KiB so the subsequent 16-byte frame takes ST_TYPE_DIRECT.
     * Offsets 100, 102, ... keep them away from the [0, 16) range.
     */
    for (i = 0; i < FILLERS; i++) {
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[i],
                100 + 2 * i, &fill, 1, 0)))
            goto err;
    }

    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream),
            FILLERS))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream),
            FILLERS))
        goto err;

    /*
     * write 16 bytes to offset zero. those bytes are going to be
     * copied to direct storage.
     */
    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[FILLERS],
            0, src, 16, 0)))
        goto err;

    /*
     * reference to packet must not increase to 2 when data are moved to stream
     * buffer/direct storage.
     */
    if (!TEST_size_t_eq(pkt_test_refcount(pkts[FILLERS]), 1))
        goto err;

    memset(window, 0, sizeof(window));
    found_after_insert = tdc_find_pattern(expected16, TDC_EXPECTED16_SZ,
        window, sizeof(window));
    if (!TEST_true(found_after_insert))
        goto err;

    /*
     * source buffer must be zeroed after chunk is added to stream.
     */
    if (!TEST_mem_eq(src, TDC_EXPECTED16_SZ, zero_buf, TDC_EXPECTED16_SZ))
        goto err;

    /*
     * read first 8 bytes, those will be overwritten by 0.
     * memmove() should overwrite ABCDEFGH, by IJKLMNOP.
     */
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 8, &readbytes, &fin)))
        goto err;

    if (!TEST_size_t_eq(readbytes, 8))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(buf, 8, expected16, 8))
        goto err;

    /*
     * check the pattern was moved, there is nothing like
     * IJKLMNOPIJKLMNOP
     */
    memset(window, 0, sizeof(window));
    found_after_partial = tdc_find_pattern(doubled, sizeof(doubled),
        window, sizeof(window));
    if (!TEST_false(found_after_partial))
        goto err;

    /*
     * read next 8 bytes, and check it got zeroed.
     */
    tdc_watch_free = 1;
    tdc_saw_remnant_on_free = 0;
    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, 8, &readbytes, &fin)))
        goto err;

    if (!TEST_size_t_eq(readbytes, 8))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(buf, TDC_EXPECTED8_SZ, tdc_expected8, TDC_EXPECTED8_SZ))
        goto err;
    tdc_watch_free = 0;

    if (!TEST_false(found_after_partial || tdc_saw_remnant_on_free))
        goto err;

    ok = 1;
err:
    tdc_watch_free = 0;

    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);

    for (i = 0; i < npkts; ++i)
        pkt_test_free(pkts[i]);

    ossl_quic_channel_free(ch);

    CRYPTO_set_mem_functions(malloc_save, realloc_save, free_save);

    return ok;
}

/*
 * Increased alignment is needed, as tho_malloc() custom allocator
 * returns memory addresses directly following a THO_ALLOC_HDR.
 */
typedef struct ALIGN_ALLOC_HDR tho_alloc_hdr_st {
    size_t size;
    const char *file;
    int from_reas;
    OSSL_LIST_MEMBER(tho, struct tho_alloc_hdr_st);
} THO_ALLOC_HDR;

DEFINE_LIST_OF(tho, THO_ALLOC_HDR);

#define THO_FRAME_LEN 1024
#define THO_N_SLIDES 256

static size_t tho_reas_live, tho_reas_peak;
static size_t tho_heap1024_live, tho_heap1024_peak;
static int tho_tracking;

static OSSL_LIST(tho)
    tho_alloc_list;

static int tho_from_reas_file(const char *file)
{
    return file != NULL && strstr(file, "quic_strm_reas.c") != NULL;
}

static void *tho_malloc(size_t sz, const char *file, int line)
{
    THO_ALLOC_HDR *h;
    void *p;

    if (sz == 0)
        return NULL;

    h = malloc_save(sizeof(*h) + sz, file, line);
    if (h == NULL)
        return NULL;

    h->size = sz;
    h->file = file;
    h->from_reas = tho_tracking && tho_from_reas_file(file);
    ossl_list_tho_init_elem(h);

    p = &h[1];
    memset(p, 0, sz);

    if (h->from_reas) {
        ossl_list_tho_insert_head(&tho_alloc_list, h);
        tho_reas_live += sz;
        if (tho_reas_live > tho_reas_peak)
            tho_reas_peak = tho_reas_live;
        if (sz == THO_FRAME_LEN) {
            tho_heap1024_live++;
            if (tho_heap1024_live > tho_heap1024_peak)
                tho_heap1024_peak = tho_heap1024_live;
        }
    }

    return p;
}

static void tho_free(void *ptr, const char *file, int line)
{
    THO_ALLOC_HDR *h = (THO_ALLOC_HDR *)ptr;

    if (ptr == NULL)
        return;

    h = &h[-1];
    if (h->from_reas) {
        ossl_list_tho_remove(&tho_alloc_list, h);
        tho_reas_live -= h->size;
        if (h->size == THO_FRAME_LEN && tho_heap1024_live > 0)
            tho_heap1024_live--;
    }

    free_save(h, file, line);
}

static void *tho_realloc(void *ptr, size_t sz, const char *file, int line)
{
    THO_ALLOC_HDR *h, *nh;
    size_t old_sz;
    void *p;

    if (ptr == NULL)
        return tho_malloc(sz, file, line);

    if (sz == 0) {
        tho_free(ptr, file, line);
        return NULL;
    }

    h = (THO_ALLOC_HDR *)ptr;
    h = &h[-1];
    old_sz = h->size;

    if (h->from_reas)
        ossl_list_tho_remove(&tho_alloc_list, h);

    nh = realloc_save(h, sizeof(*nh) + sz, file, line);
    if (nh == NULL) {
        if (h->from_reas)
            ossl_list_tho_insert_head(&tho_alloc_list, h);
        return NULL;
    }

    if (nh->from_reas) {
        ossl_list_tho_insert_head(&tho_alloc_list, nh);
        tho_reas_live -= old_sz;
        tho_reas_live += sz;
        if (tho_reas_live > tho_reas_peak)
            tho_reas_peak = tho_reas_live;
        if (old_sz == THO_FRAME_LEN && tho_heap1024_live > 0)
            tho_heap1024_live--;
        if (sz == THO_FRAME_LEN) {
            tho_heap1024_live++;
            if (tho_heap1024_live > tho_heap1024_peak)
                tho_heap1024_peak = tho_heap1024_live;
        }
    }

    p = &nh[1];
    if (sz > old_sz)
        memset((unsigned char *)p + old_sz, 0, sz - old_sz);

    return p;
}

static int test_heap_overlap(void)
{
    QUIC_RSTREAM *rstream = NULL;
    QUIC_RSTREAM_QPARM *rsqp = NULL;
    QUIC_CHANNEL *ch = NULL;
    unsigned char *data = NULL, *buf = NULL;
    OSSL_QRX_PKT *pkts[THO_N_SLIDES + 1] = { 0 };
    OSSL_QRX_PKT *gap = NULL;
    /* byte 0, then [1, 1025), last slide ends at 1 + FRAME_LEN + N_SLIDES */
    const size_t data_span = 1 + THO_FRAME_LEN + THO_N_SLIDES;
    size_t i, npkts = 0, readbytes = 0;
    int fin = 0, ok = 0;
    size_t first_heap_at = 0;

    malloc_save = NULL;
    free_save = NULL;
    realloc_save = NULL;
    CRYPTO_get_mem_functions(&malloc_save, &realloc_save, &free_save);
    if (!CRYPTO_set_mem_functions(tho_malloc, tho_realloc, tho_free)) {
        return 0;
    }

    ossl_list_tho_init(&tho_alloc_list);

    data = OPENSSL_malloc(data_span);
    if (!TEST_ptr(data))
        goto err;

    buf = OPENSSL_malloc(data_span);
    if (!TEST_ptr(buf))
        goto err;

    ch = OPENSSL_zalloc(sizeof(*ch));
    if (!TEST_ptr(ch))
        goto err;

    rsqp = ossl_quic_rstream_qparm_new(ch);
    if (!TEST_ptr(rsqp))
        goto err;

    tho_tracking = 1;

    rstream = ossl_quic_rstream_new(NULL, NULL, rsqp);
    if (!TEST_ptr(rstream))
        goto err;

    pkts[npkts] = pkt_test_new(1200);
    if (!TEST_ptr(pkts[npkts]))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[npkts], 1,
            &data[1], THO_FRAME_LEN, 0)))
        goto err;
    npkts++;

    if (!TEST_size_t_eq(ossl_quic_rstream_get_range_count(rstream), 1))
        goto err;

    if (!TEST_size_t_eq(ossl_quic_rstream_get_chunk_count(rstream), 1))
        goto err;

    for (i = 0; i < THO_N_SLIDES; i++) {
        uint64_t off = 2 + i;

        pkts[npkts] = pkt_test_new(1200);
        if (!TEST_ptr(pkts[npkts]))
            goto err;
        if (!TEST_true(ossl_quic_rstream_queue_data(rstream, pkts[npkts], off,
                data + off, THO_FRAME_LEN, 0)))
            goto err;
        npkts++;

        if (first_heap_at == 0 && tho_heap1024_live > 0)
            first_heap_at = i + 1;
    }

    if (!TEST_size_t_lt(tho_heap1024_peak, 8)
        || !TEST_size_t_le(tho_heap1024_live * THO_FRAME_LEN,
            (THO_FRAME_LEN + THO_N_SLIDES) * 4))
        goto err;

    gap = pkt_test_new(1200);
    if (!TEST_ptr(gap))
        goto err;

    if (!TEST_true(ossl_quic_rstream_queue_data(rstream, gap, 0, data, 1, 0)))
        goto err;

    if (!TEST_true(ossl_quic_rstream_read(rstream, buf, data_span, &readbytes, &fin)))
        goto err;

    if (!TEST_size_t_eq(readbytes, data_span))
        goto err;

    if (!TEST_false(fin))
        goto err;

    if (!TEST_mem_eq(buf, readbytes, data, data_span))
        goto err;

    ok = 1;
err:

    pkt_test_free(gap);

    for (i = 0; i < npkts; i++)
        pkt_test_free(pkts[i]);

    ossl_quic_rstream_free(rstream);
    ossl_quic_rstream_qparm_destroy(rsqp);
    ossl_quic_channel_free(ch);
    OPENSSL_free(buf);
    OPENSSL_free(data);
    CRYPTO_set_mem_functions(malloc_save, realloc_save, free_save);

    return ok;
}

/* A real channel supplies the stream-map role and receive-buffer policy. */
typedef struct {
    QUIC_STREAM_MAP map;
    QUIC_CHANNEL *ch;
    QUIC_RSTREAM_QPARM *qparm;
    QUIC_RXFC connection, max_bidi, max_uni;
    QUIC_TXFC tx_connection;
    int have_map;
} GC_FIXTURE;

static OSSL_TIME gc_now(void *arg)
{
    return ossl_seconds2time(1000);
}

static void gc_fixture_cleanup(GC_FIXTURE *f)
{
    if (f->have_map)
        ossl_quic_stream_map_cleanup(&f->map);
    ossl_quic_rstream_qparm_destroy(f->qparm);
    ossl_quic_channel_free(f->ch);
}

static int gc_fixture_init(GC_FIXTURE *f)
{
    QUIC_CHANNEL_ARGS args = { 0 };

    memset(f, 0, sizeof(*f));
    if (!TEST_ptr(f->ch = ossl_quic_channel_alloc(&args))
        || !TEST_ptr(f->qparm = ossl_quic_rstream_qparm_new(f->ch))
        || !TEST_true(ossl_quic_txfc_init(&f->tx_connection, NULL))
        || !TEST_true(ossl_quic_rxfc_init(&f->connection, NULL,
            16, 16, gc_now, NULL))
        || !TEST_true(ossl_quic_rxfc_init_standalone(&f->max_bidi,
            32, gc_now, NULL))
        || !TEST_true(ossl_quic_rxfc_init_standalone(&f->max_uni,
            32, gc_now, NULL))
        || !TEST_true(ossl_quic_stream_map_init(&f->map, NULL, NULL,
            &f->max_bidi, &f->max_uni, f->ch)))
        return 0;
    f->have_map = 1;
    return 1;
}

static QUIC_STREAM *gc_stream_new(GC_FIXTURE *f, uint64_t id)
{
    QUIC_STREAM *s = ossl_quic_stream_map_alloc(&f->map, id, id & 3);

    if (!TEST_ptr(s))
        return NULL;
    if (!ossl_quic_stream_is_local_init(s)
        && !TEST_true(ossl_quic_rxfc_on_rx_stream_frame(
            ossl_quic_stream_is_bidi(s) ? &f->max_bidi : &f->max_uni,
            (id >> 2) + 1, 0)))
        return NULL;
    if (ossl_quic_stream_has_send(s)
        && (!TEST_ptr(s->sstream = ossl_quic_sstream_new(256))
            || !TEST_true(ossl_quic_txfc_init(&s->txfc, &f->tx_connection))))
        return NULL;
    if (ossl_quic_stream_has_recv(s)
        && (!TEST_true(ossl_quic_rxfc_init(&s->rxfc, &f->connection,
                16, 16, gc_now, NULL))
            || !TEST_ptr(s->rstream = ossl_quic_rstream_new(NULL, NULL,
                             f->qparm))))
        return NULL;
    return s;
}

/* Complete the send side by the same notifications used after a FIN ACK. */
static int gc_finish_send(GC_FIXTURE *f, QUIC_STREAM *s, int ack)
{
    if (!ossl_quic_stream_has_send(s))
        return 1;
    ossl_quic_sstream_fin(s->sstream);
    if (!TEST_true(ossl_quic_stream_map_ensure_send_part_id(&f->map, s))
        || !TEST_true(ossl_quic_sstream_mark_transmitted_fin(s->sstream, 0))
        || !TEST_true(ossl_quic_stream_map_notify_all_data_sent(&f->map, s)))
        return 0;
    if (ack
        && (!TEST_true(ossl_quic_sstream_mark_acked_fin(s->sstream))
            || !TEST_true(ossl_quic_stream_map_notify_totally_acked(&f->map, s))))
        return 0;
    return 1;
}

/*
 * Terminal DATA/RESET and both unidirectional stream types must be collected.
 * Unknown final size, unacknowledged sends, API and accept owners must survive.
 */
static int test_stream_map_gc_states(int idx)
{
    GC_FIXTURE f;
    QUIC_STREAM *s = NULL;
    uint64_t id = idx == 6 ? 2 : (idx == 7 || idx == 11 ? 3 : 0);
    int testresult = 0, collect = idx < 8 || idx == 13;

    if (!gc_fixture_init(&f)
        || !TEST_ptr(s = gc_stream_new(&f, id))
        || (idx < 13 && !gc_finish_send(&f, s, idx != 8)))
        goto err;
    if (idx >= 13
        && (!TEST_true(ossl_quic_stream_map_reset_stream_send_part(&f.map, s, 7))
            || (idx == 13
                && !TEST_true(ossl_quic_stream_map_notify_reset_stream_acked(&f.map, s)))))
        goto err;
    if (ossl_quic_stream_has_recv(s)) {
        if (idx == 9) {
            /* STOP ACK cannot invent a final size for a still-open peer. */
            if (!TEST_true(ossl_quic_stream_map_stop_sending_recv_part(&f.map, s, 0)))
                goto err;
            s->acked_stop_sending = 1;
            s->want_stop_sending = 0;
        } else {
            if (!TEST_true(ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc, 8, 1)))
                goto err;
            if (idx == 2 || idx == 3) {
                if (!TEST_true(ossl_quic_stream_map_notify_reset_recv_part(&f.map, s, 7, 8)))
                    goto err;
                if (idx == 3
                    && !TEST_true(ossl_quic_stream_map_notify_app_read_reset_recv_part(&f.map, s)))
                    goto err;
            } else {
                if (!TEST_true(ossl_quic_stream_map_notify_size_known_recv_part(&f.map, s, 8)))
                    goto err;
                if (idx == 4 || idx == 5 || idx == 12) {
                    if (!TEST_true(ossl_quic_stream_map_stop_sending_recv_part(&f.map, s, 0)))
                        goto err;
                    s->acked_stop_sending = idx != 12;
                    s->want_stop_sending = idx == 12;
                } else {
                    if (!TEST_true(ossl_quic_stream_map_notify_totally_received(&f.map, s)))
                        goto err;
                    if (idx != 1
                        && (!TEST_true(ossl_quic_rxfc_on_retire(&s->rxfc, 8, ossl_ms2time(10)))
                            || !TEST_true(ossl_quic_stream_map_notify_totally_read(&f.map, s))))
                        goto err;
                }
            }
        }
    }
    if (idx == 5
        && !TEST_true(ossl_quic_rxfc_on_retire(&s->rxfc, 3, ossl_ms2time(10))))
        goto err;
    if (idx == 11)
        ossl_quic_stream_map_push_accept_queue(&f.map, s);
    /* deleted is set only after the last API/accept owner has disappeared. */
    s->deleted = idx != 10 && idx != 11;
    ossl_quic_stream_map_update_state(&f.map, s);
    if (!TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_int_eq(ossl_quic_stream_map_get_by_id(&f.map, id) == NULL, collect))
        goto err;
    if (collect
        && (!TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.connection), id == 2 ? 0 : 8)
            || !TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
            || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.connection), id == 2 ? 0 : 8)
            || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.max_bidi), 0)
            || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.max_uni), id == 3)))
        goto err;
    if (idx == 11
        && !TEST_size_t_eq(ossl_quic_stream_map_get_accept_queue_len(&f.map, 1), 1))
        goto err;
    testresult = 1;
err:
    gc_fixture_cleanup(&f);
    return testresult;
}

static int test_stream_map_gc_multiple(void)
{
    GC_FIXTURE f;
    QUIC_STREAM *s = NULL;
    size_t i;
    int testresult = 0;

    if (!gc_fixture_init(&f))
        goto err;
    for (i = 0; i < 8; ++i) {
        if (!TEST_ptr(s = gc_stream_new(&f, 4 * i))
            || !gc_finish_send(&f, s, 1)
            || !TEST_true(ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc, 0, 1))
            || !TEST_true(ossl_quic_stream_map_notify_size_known_recv_part(&f.map, s, 0))
            || !TEST_true(ossl_quic_stream_map_notify_totally_received(&f.map, s)))
            goto err;
        s->deleted = i != 3;
        ossl_quic_stream_map_update_state(&f.map, s);
    }
    if (!TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_size_t_eq(OPENSSL_LH_num_items((OPENSSL_LHASH *)f.map.map), 1)
        || !TEST_ptr(ossl_quic_stream_map_get_by_id(&f.map, 12))
        || !TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_size_t_eq(OPENSSL_LH_num_items((OPENSSL_LHASH *)f.map.map), 1))
        goto err;
    testresult = 1;
err:
    gc_fixture_cleanup(&f);
    return testresult;
}

/* A failed retirement must retain the object, rather than lose its credit. */
static int test_stream_map_gc_retire_error(int idx)
{
    GC_FIXTURE f;
    QUIC_STREAM *s = NULL;
    int testresult = 0;

    if (!gc_fixture_init(&f)
        || !TEST_ptr(s = gc_stream_new(&f, idx))
        || !gc_finish_send(&f, s, 1)
        || !TEST_true(ossl_quic_rxfc_on_rx_stream_frame(&s->rxfc, 8, 1))
        || !TEST_true(ossl_quic_stream_map_notify_size_known_recv_part(&f.map, s, 8)))
        goto err;
    s->acked_stop_sending = 1;
    s->deleted = 1;
    ossl_quic_stream_map_update_state(&f.map, s);
    /* Inject inconsistent internal accounting at the error boundary. */
    if (idx == 0)
        s->rxfc.rwm = 9;
    else
        f.max_bidi.rwm = 1;
    if (!TEST_false(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_ptr_eq(ossl_quic_stream_map_get_by_id(&f.map, idx), s)
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.connection), idx == 0 ? 0 : 8))
        goto err;
    if (idx == 0)
        s->rxfc.rwm = 0;
    else
        f.max_bidi.rwm = 0;
    if (!TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_ptr_null(ossl_quic_stream_map_get_by_id(&f.map, idx))
        || !TEST_true(ossl_quic_stream_map_gc(&f.map, ossl_ms2time(10)))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.connection), 8)
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.max_bidi), idx))
        goto err;
    testresult = 1;
err:
    gc_fixture_cleanup(&f);
    return testresult;
}

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    QUIC_CHANNEL *ch;
    QUIC_STREAM *stream;
    RXE *packets[4];
    QUIC_PKT_HDR headers[4];
    unsigned char wire[4][16];
    size_t used;
} GC_RX_FIXTURE;

static int gc_rx_init(GC_RX_FIXTURE *f, int create_stream)
{
    QUIC_STREAM *s;

    memset(f, 0, sizeof(*f));
    if (!TEST_ptr(f->ctx = SSL_CTX_new(OSSL_QUIC_client_method()))
        || !TEST_ptr(f->ssl = SSL_new(f->ctx))
        || !TEST_true(SSL_set_default_stream_mode(f->ssl, SSL_DEFAULT_STREAM_MODE_NONE))
        || !TEST_ptr(f->ch = ossl_quic_conn_get_channel(f->ssl)))
        return 0;
    if (!create_stream)
        return 1;
    if (!TEST_ptr(f->stream = ossl_quic_stream_map_alloc(&f->ch->qsm, 0, 0)))
        return 0;
    s = f->stream;
    if (!TEST_ptr(s->sstream = ossl_quic_sstream_new(256))
        || !TEST_true(ossl_quic_txfc_init(&s->txfc, &f->ch->conn_txfc))
        || !TEST_true(ossl_quic_rxfc_init(&s->rxfc, &f->ch->conn_rxfc,
            16, 16, gc_now, NULL))
        || !TEST_ptr(s->rstream = ossl_quic_rstream_new(NULL, NULL, f->ch->rsqp))
        || !TEST_true(ossl_quic_stream_map_reset_stream_send_part(&f->ch->qsm, s, 0))
        || !TEST_true(ossl_quic_stream_map_notify_reset_stream_acked(&f->ch->qsm, s)))
        return 0;
    return 1;
}

static int gc_rx_frame(GC_RX_FIXTURE *f, const unsigned char *wire, size_t len)
{
    size_t i = f->used;
    RXE *rxe;

    if (!TEST_size_t_lt(i, OSSL_NELEM(f->packets))
        || !TEST_size_t_le(len, sizeof(f->wire[0]))
        || !TEST_ptr(rxe = OPENSSL_zalloc(sizeof(*rxe))))
        return 0;
    f->packets[f->used++] = rxe;
    memcpy(f->wire[i], wire, len);
    f->headers[i].type = QUIC_PKT_TYPE_1RTT;
    f->headers[i].data = f->wire[i];
    f->headers[i].len = len;
    rxe->refcount = 1;
    rxe->datagram_len = rxe->pkt.datagram_len = len;
    rxe->pkt.hdr = &f->headers[i];
    rxe->pkt.time = ossl_time_now();
    rxe->pkt.pn = i;
    return ossl_quic_handle_frames(f->ch, &rxe->pkt);
}

static int gc_rx_cleanup(GC_RX_FIXTURE *f)
{
    size_t i;
    int ok = 1;

    SSL_free(f->ssl);
    SSL_CTX_free(f->ctx);
    for (i = 0; i < f->used; ++i) {
        if (!TEST_size_t_eq(f->packets[i]->refcount, 1))
            ok = 0;
        OPENSSL_free(f->packets[i]);
    }
    return ok;
}

/* Real STREAM decoding, including a FIN with a nonzero unread gap. */
static int test_stream_gc_receive_progress(int idx)
{
    static const unsigned char empty_fin[] = { 0x0b, 0, 0 };
    static const unsigned char gap_fin[] = { 0x0f, 0, 8, 0 };
    static const unsigned char tail[] = { 0x0f, 0, 4, 4, 5, 6, 7, 8 };
    static const unsigned char head[] = { 0x0a, 0, 4, 1, 2, 3, 4 };
    static const unsigned char reset[] = { 0x04, 0, 7, 12 };
    GC_RX_FIXTURE f;
    QUIC_STREAM *s;
    unsigned char buf[4];
    size_t readbytes = 0;
    int fin = 0, testresult = 0;
    uint64_t final_size = idx == 0 ? 0 : (idx == 3 ? 12 : 8);

    if (!gc_rx_init(&f, 1))
        goto err;
    s = f.stream;
    if (idx == 1) {
        if (!TEST_true(ossl_quic_stream_map_stop_sending_recv_part(&f.ch->qsm, s, 0)))
            goto err;
        s->acked_stop_sending = 1;
        s->want_stop_sending = 0;
    }
    if (idx == 3) {
        if (!TEST_true(gc_rx_frame(&f, head, sizeof(head)))
            || !TEST_true(ossl_quic_rstream_read(s->rstream, buf, sizeof(buf),
                &readbytes, &fin))
            || !TEST_size_t_eq(readbytes, sizeof(buf))
            || !TEST_false(fin)
            || !TEST_true(ossl_quic_rxfc_on_retire(&s->rxfc, readbytes, ossl_ms2time(10)))
            || !TEST_true(ossl_quic_stream_map_stop_sending_recv_part(&f.ch->qsm, s, 0)))
            goto err;
        s->acked_stop_sending = 1;
        s->want_stop_sending = 0;
        s->deleted = 1;
        ossl_quic_stream_map_update_state(&f.ch->qsm, s);
        if (!TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
            || !TEST_ptr_eq(ossl_quic_stream_map_get_by_id(&f.ch->qsm, 0), s)
            || !TEST_true(gc_rx_frame(&f, reset, sizeof(reset))))
            goto err;
    } else {
        s->deleted = 1;
        if (!TEST_true(gc_rx_frame(&f, idx == 0 ? empty_fin : (idx == 1 ? gap_fin : tail),
                idx == 0 ? sizeof(empty_fin) : (idx == 1 ? sizeof(gap_fin) : sizeof(tail)))))
            goto err;
        if (idx == 2
            && (!TEST_false(s->ready_for_gc)
                || !TEST_true(gc_rx_frame(&f, head, sizeof(head)))))
            goto err;
    }
    if (!TEST_true(s->ready_for_gc)
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_swm(&f.ch->conn_rxfc), final_size)
        || !TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
        || !TEST_ptr_null(ossl_quic_stream_map_get_by_id(&f.ch->qsm, 0))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.ch->conn_rxfc), final_size)
        || !TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(&f.ch->conn_rxfc), final_size))
        goto err;
    testresult = 1;
err:
    return gc_rx_cleanup(&f) && testresult;
}

static int test_stream_gc_receive_guards(int idx)
{
    static const unsigned char fin[] = { 0x0f, 0, 8, 0 };
    static const unsigned char bad_reset[] = { 0x04, 0, 0, 7 };
    static const unsigned char over_credit[] = { 0x0e, 0, 17, 0 };
    GC_RX_FIXTURE f;
    const QUIC_TERMINATE_CAUSE *cause;
    int testresult = 0;

    if (!gc_rx_init(&f, 1)
        || !TEST_true(ossl_quic_stream_map_stop_sending_recv_part(&f.ch->qsm, f.stream, 0)))
        goto err;
    if (idx == 0 && !TEST_true(gc_rx_frame(&f, fin, sizeof(fin))))
        goto err;
    if (!TEST_false(gc_rx_frame(&f, idx == 0 ? bad_reset : over_credit, sizeof(bad_reset)))
        || !TEST_ptr(cause = ossl_quic_channel_get_terminate_cause(f.ch))
        || !TEST_uint64_t_eq(cause->error_code,
            idx == 0 ? OSSL_QUIC_ERR_FINAL_SIZE_ERROR : OSSL_QUIC_ERR_FLOW_CONTROL_ERROR))
        goto err;
    testresult = 1;
err:
    return gc_rx_cleanup(&f) && testresult;
}

static int test_stream_gc_stream_credit(int idx)
{
    GC_RX_FIXTURE f;
    QUIC_STREAM *s;
    QUIC_RXFC *count;
    SSL *accepted = NULL;
    const QUIC_TERMINATE_CAUSE *cause;
    int is_uni = idx & 1, reject = idx >> 1, i, testresult = 0;
    unsigned char id = is_uni ? 3 : 1;
    unsigned char opened[] = { 0x0a, id, 0, 0x0a, id + 4, 0 };
    unsigned char fin[] = { 0x0b, id, 0 };
    unsigned char reset[] = { 0x04, id, 0, 0 };
    unsigned char next[] = { 0x0b, id, 0, 0x0a, id + 8, 0 };
    unsigned char over_limit[] = { 0x0a, id + 12, 0 };

    if (!gc_rx_init(&f, 0)
        || !TEST_true(ossl_quic_channel_set_max_streams_request(f.ch, 2, is_uni))
        || !TEST_true(SSL_set_incoming_stream_policy(f.ssl,
            reject ? SSL_INCOMING_STREAM_POLICY_REJECT : SSL_INCOMING_STREAM_POLICY_ACCEPT, 0))
        || !TEST_true(gc_rx_frame(&f, opened, sizeof(opened))))
        goto err;
    count = is_uni ? &f.ch->max_streams_uni_rxfc : &f.ch->max_streams_bidi_rxfc;
    for (i = 0; i < 2; ++i) {
        if (!reject) {
            if (!TEST_ptr(accepted = SSL_accept_stream(f.ssl, SSL_ACCEPT_STREAM_NO_BLOCK)))
                goto err;
            SSL_free(accepted);
            accepted = NULL;
        }
        if (!TEST_ptr(s = ossl_quic_stream_map_get_by_id(&f.ch->qsm, id + 4 * i)))
            goto err;
        /* Controlled ACK state; packet ACK processing is covered by TXP tests. */
        s->acked_stop_sending = 1;
        s->want_stop_sending = 0;
        if (!is_uni
            && !TEST_true(ossl_quic_stream_map_notify_reset_stream_acked(&f.ch->qsm, s)))
            goto err;
        ossl_quic_stream_map_update_state(&f.ch->qsm, s);
    }
    if (!TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(count), 0)
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_cwm(count), 2)
        || !TEST_size_t_eq(OPENSSL_LH_num_items((OPENSSL_LHASH *)f.ch->qsm.map), 2)
        || !TEST_true(gc_rx_frame(&f, reject ? reset : fin, reject ? sizeof(reset) : sizeof(fin)))
        || !TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
        || !TEST_ptr_null(ossl_quic_stream_map_get_by_id(&f.ch->qsm, id))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(count), 1)
        || !TEST_true(gc_rx_frame(&f, next, sizeof(next)))
        || !TEST_ptr(ossl_quic_stream_map_get_by_id(&f.ch->qsm, id + 8))
        || !TEST_true(ossl_quic_stream_map_gc(&f.ch->qsm, ossl_ms2time(10)))
        || !TEST_uint64_t_eq(ossl_quic_rxfc_get_rwm(count), 1)
        || !TEST_false(gc_rx_frame(&f, over_limit, sizeof(over_limit)))
        || !TEST_ptr(cause = ossl_quic_channel_get_terminate_cause(f.ch))
        || !TEST_uint64_t_eq(cause->error_code, OSSL_QUIC_ERR_STREAM_LIMIT_ERROR)
        || !TEST_size_t_eq(OPENSSL_LH_num_items((OPENSSL_LHASH *)f.ch->qsm.map), 2))
        goto err;
    testresult = 1;
err:
    SSL_free(accepted);
    return gc_rx_cleanup(&f) && testresult;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_stream_map_gc_states, 15);
    ADD_TEST(test_stream_map_gc_multiple);
    ADD_ALL_TESTS(test_stream_map_gc_retire_error, 2);
    ADD_ALL_TESTS(test_stream_gc_receive_progress, 4);
    ADD_ALL_TESTS(test_stream_gc_receive_guards, 2);
    ADD_ALL_TESTS(test_stream_gc_stream_credit, 4);
    ADD_TEST(test_sstream_simple);
    ADD_ALL_TESTS(test_sstream_bulk, 100);
    ADD_ALL_TESTS(test_rstream_simple, 2);
    ADD_ALL_TESTS(test_rstream_random, 100);
    ADD_TEST(test_rstream_pkt);
    ADD_TEST(test_rstream_pkt_overhead);
    ADD_ALL_TESTS(test_rstream_reorder, 40);
    ADD_TEST(test_rstream_dstorage_two_sided_overlap);
    ADD_TEST(test_rstream_zero_length_read);
    ADD_TEST(test_rstream_fin_final_size);
    ADD_TEST(test_rstream_cleanse_dropped_bytes);
    ADD_TEST(test_rstream_chunk_partial_overlap);
    ADD_TEST(test_rstream_chunk_full_overlap);
    ADD_TEST(test_rstream_range_overlap);
    ADD_TEST(test_rstream_prepend_byte_chunks);
    ADD_TEST(test_rstream_append_byte_chunks);
    ADD_TEST(test_rstream_mix_chunks);
    ADD_TEST(test_final_size_violation_fin_first);
    ADD_TEST(test_final_size_violation_data_first);
    ADD_TEST(test_trim_right);
    ADD_TEST(test_dstorage_cleanse);
    ADD_TEST(test_heap_overlap);

    return 1;
}
