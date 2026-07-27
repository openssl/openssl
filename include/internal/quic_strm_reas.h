/*
 * Copyright 2022-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_STRM_REAS_H
#define OSSL_QUIC_STRM_REAS_H

#include "internal/common.h"
#include "internal/uint_set.h"
#include "internal/quic_record_rx.h"

#ifndef OPENSSL_NO_QUIC
#include "internal/ossl_rbtree.h"

typedef struct stream_range_st STREAM_RANGE;

typedef struct sframe_set_t {
    OSSL_RBT_HEAD(srange, sframe_set_t)
    ranges;
    /* Is the tail frame final. */
    unsigned int fin;
    uint64_t fin_off;
    /* Number of stream frames in the list. */
    size_t stream_ranges;
    size_t stream_chunks;
    /* Offset of data not yet dropped */
    uint64_t offset;
    /* Cleanse data on release? */
    int cleanse;
    int move_buffers;
    /*
     * current allocation overhead of stream buffers.
     * By default the data delivered in stream chunk are not
     * copied from packet buffer to stream buffer. On hand,
     * this saves a one copy operation, on the other hand,
     * it may cause QUIC stack to hold a lot more memory
     * for stream data than actually required.
     * Consider packet with more than one frame The packet
     * is full (packet size == MTU of media). There is
     * a stream frame with 1 byte of application data, then
     * there are other stream frames or padding frames.
     * The packet is kept in memory until the 1byte stream
     * chunk is consumed by app. The allocation overhead
     * in this case is MTU - 1 (packet size - length of
     * stream chunk).
     */
    size_t pkt_buf_overhead_sz;
} SFRAME_SET;

/*
 * Initializes the stream frame list fs.
 */
void ossl_sframe_set_init(SFRAME_SET *fs);

/*
 * Destroys the stream frame list fs releasing any data
 * still present inside it.
 */
void ossl_sframe_set_destroy_ranges(SFRAME_SET *fs);

/*
 * Insert a stream frame data into the list.
 * The data covers an offset range (range.start is inclusive,
 * range.end is exclusive).
 * fin should be set if this is the final frame of the stream.
 * Returns an error if a frame cannot be inserted - due to
 * STREAM_FRAME allocation error, or in case of erroneous
 * fin flag.
 */
int ossl_sframe_set_insert(SFRAME_SET *fs, UINT_RANGE *range,
    OSSL_QRX_PKT *pkt,
    const unsigned char *data, int fin);

/*
 * Iterator to peek at the contiguous frames at the beginning
 * of the frame set (the first stream range).
 * The *data covers an offset range (range.start is inclusive,
 * range.end is exclusive).
 * *fin is set if this is the final frame of the stream.
 * Opaque iterator *iter can be used to peek at the subsequent
 * frame if there is any without any gap before it.
 * Returns 1 on success.
 * Returns 0 if there is no further contiguous frame. In that
 * case *fin is set, if the end of the stream is reached.
 */
int ossl_sframe_set_peek(SFRAME_SET *fs, void **iter,
    UINT_RANGE *range, const unsigned char **data,
    int *fin);

/*
 * Drop all frames up to the offset limit.
 * Also unlocks the head frame if locked.
 * Returns 1 on success.
 * Returns 0 when trying to drop frames at offsets that were not
 * received yet. (ossl_assert() is used to check, so this is an invalid call.)
 */
int ossl_sframe_set_drop_frames(SFRAME_SET *fs, uint64_t limit);

/*
 * moves reading offset to new position, discarding all consumed
 * chunks (which end offset is less than offset).
 */
int ossl_sframe_set_move_offset(SFRAME_SET *fs, uint64_t offset);

#endif

#endif
