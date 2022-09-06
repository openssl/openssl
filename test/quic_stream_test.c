/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include "internal/packet.h"
#include "internal/quic_stream.h"
#include "testutil.h"

static int compare_iov(const unsigned char *ref, size_t ref_len,
                       const OSSL_QTX_IOVEC *iov, size_t iov_len)
{
    size_t i, total_len = 0;
    const unsigned char *cur = ref;

    for (i = 0; i < iov_len; ++i)
        total_len += iov[i].buf_len;

    if (ref_len != total_len) {
        fprintf(stderr, "# expected %lu == %lu\n", ref_len, total_len);
        return 0;
    }

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

static int test_simple(void)
{
    int testresult = 0;
    QUIC_SSTREAM *sstream = NULL;
    OSSL_QUIC_FRAME_STREAM hdr;
    OSSL_QTX_IOVEC iov[2];
    size_t num_iov = 0, wr = 0, i, init_size = 8192;

    if (!TEST_ptr(sstream = ossl_quic_sstream_new(init_size)))
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

    testresult = 1;
err:
    ossl_quic_sstream_free(sstream);
    return testresult;
}

static int test_bulk(int idx)
{
    int testresult = 0;
    QUIC_SSTREAM *sstream = NULL;
    OSSL_QUIC_FRAME_STREAM hdr;
    OSSL_QTX_IOVEC iov[2];
    size_t i, num_iov = 0, init_size = 8192, total_written = 0, l;
    size_t consumed = 0, rd, expected = 0;
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
        ref_src_cur     += consumed;
        total_written   += consumed;
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
    for (i = 0; i < consumed; ++i) {
        if ((test_random() & 1) != 0) {
            *ref_dst_cur++ = *ref_src_cur;
            ++expected;
        } else if (!TEST_true(ossl_quic_sstream_mark_transmitted(sstream, i, i)))
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

        for (i = 0; i < num_iov; ++i) {
            if (!TEST_size_t_le(iov[i].buf_len + rd, expected))
                goto err;

            memcpy(dst_cur, iov[i].buf, iov[i].buf_len);
            dst_cur += iov[i].buf_len;
            rd      += iov[i].buf_len;
        }

        if (!TEST_uint64_t_eq(rd, hdr.len))
            goto err;
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

int setup_tests(void)
{
    ADD_TEST(test_simple);
    ADD_ALL_TESTS(test_bulk, 100);
    return 1;
}
