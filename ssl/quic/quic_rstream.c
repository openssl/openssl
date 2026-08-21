/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
#include <openssl/err.h>
#include "internal/common.h"
#include "internal/time.h"
#include "internal/quic_stream.h"
#include "internal/quic_sf_list.h"

/*
 * Stream data normally stays in the packet it arrived in, which avoids a copy
 * but keeps the packet referenced and needs a frame list entry per frame. Once
 * a stream accumulates enough frames the data is copied to the buffer below
 * instead, which releases the packets and lets contiguous frames merge.
 *
 * The buffer is a list of fixed size chunks ordered by stream offset. Chunks
 * are aligned to a multiple of SBUF_CHUNK_SIZE and are allocated when first
 * written to, so the memory used follows the data actually buffered.
 */
#define SBUF_CHUNK_SIZE 4096

#define SBUF_BASE(off) ((off) - (off) % SBUF_CHUNK_SIZE)

struct sbuf_chunk_st {
    struct sbuf_chunk_st *next;
    /* stream offset of the first byte, always chunk aligned */
    uint64_t base;
    unsigned char data[SBUF_CHUNK_SIZE];
};

typedef struct sbuf_st {
    /* chunks in ascending base order */
    struct sbuf_chunk_st *head;
    /* chunk used last, keeps appending off the list walk */
    struct sbuf_chunk_st *cursor;
} SBUF;

/* Number of frames added before the data is copied to the stream buffer. */
#define RSTREAM_MOVE_THRESHOLD 32

/*
 * Shorter runs of contiguous data are left in their packets. Copying them would
 * hold a whole chunk for very little, so this bounds what a chunk can waste at
 * SBUF_CHUNK_SIZE / SBUF_MIN_COPY_LEN.
 */
#define SBUF_MIN_COPY_LEN (SBUF_CHUNK_SIZE / 4)

struct quic_rstream_st {
    SFRAME_LIST fl;
    QUIC_RXFC *rxfc;
    OSSL_STATM *statm;
    UINT_RANGE head_range;
    SBUF sbuf;
    size_t frames_at_last_move;
    size_t pinned_at_last_move;
};

static void sbuf_init(SBUF *sb)
{
    sb->head = sb->cursor = NULL;
}

static void sbuf_destroy(SBUF *sb, int cleanse)
{
    struct sbuf_chunk_st *c, *next;

    for (c = sb->head; c != NULL; c = next) {
        next = c->next;
        if (cleanse)
            OPENSSL_cleanse(c->data, sizeof(c->data));
        OPENSSL_free(c);
    }

    sb->head = sb->cursor = NULL;
}

static struct sbuf_chunk_st *sbuf_get_chunk(SBUF *sb, uint64_t base, int create)
{
    struct sbuf_chunk_st *prev = NULL, *c, *new_chunk;

    c = (sb->cursor != NULL && sb->cursor->base <= base) ? sb->cursor : sb->head;

    for (; c != NULL && c->base < base; c = c->next)
        prev = c;

    if (c != NULL && c->base == base) {
        sb->cursor = c;
        return c;
    }

    if (!create)
        return NULL;

    new_chunk = OPENSSL_zalloc(sizeof(*new_chunk));
    if (new_chunk == NULL)
        return NULL;

    new_chunk->base = base;
    new_chunk->next = c;
    if (prev != NULL)
        prev->next = new_chunk;
    else
        sb->head = new_chunk;

    sb->cursor = new_chunk;
    return new_chunk;
}

static int sbuf_write(SBUF *sb, uint64_t offset, const unsigned char *buf,
    size_t len)
{
    while (len > 0) {
        struct sbuf_chunk_st *c = sbuf_get_chunk(sb, SBUF_BASE(offset), 1);
        size_t idx, l;

        if (c == NULL)
            return 0;

        idx = (size_t)(offset - c->base);
        l = SBUF_CHUNK_SIZE - idx;
        if (l > len)
            l = len;

        memcpy(c->data + idx, buf, l);
        offset += l;
        buf += l;
        len -= l;
    }

    return 1;
}

/*
 * Returns a pointer to the buffered byte at offset, with *max_len set to the
 * number of bytes contiguous with it. The caller knows how many of those bytes
 * were actually received.
 */
static const unsigned char *sbuf_get_ptr(SBUF *sb, uint64_t offset,
    size_t *max_len)
{
    struct sbuf_chunk_st *c = sbuf_get_chunk(sb, SBUF_BASE(offset), 0);
    size_t idx;

    if (c == NULL)
        return NULL;

    idx = (size_t)(offset - c->base);
    *max_len = SBUF_CHUNK_SIZE - idx;
    return c->data + idx;
}

static void sbuf_free_upto(SBUF *sb, uint64_t offset, int cleanse)
{
    struct sbuf_chunk_st *c;

    while ((c = sb->head) != NULL && c->base + SBUF_CHUNK_SIZE <= offset) {
        sb->head = c->next;
        if (sb->cursor == c)
            sb->cursor = NULL;
        if (cleanse)
            OPENSSL_cleanse(c->data, sizeof(c->data));
        OPENSSL_free(c);
    }
}

QUIC_RSTREAM *ossl_quic_rstream_new(QUIC_RXFC *rxfc, OSSL_STATM *statm)
{
    QUIC_RSTREAM *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL)
        return NULL;

    sbuf_init(&ret->sbuf);
    ossl_sframe_list_init(&ret->fl);
    ret->rxfc = rxfc;
    ret->statm = statm;
    return ret;
}

void ossl_quic_rstream_free(QUIC_RSTREAM *qrs)
{
    int cleanse;

    if (qrs == NULL)
        return;

    cleanse = qrs->fl.cleanse;
    ossl_sframe_list_destroy(&qrs->fl);
    sbuf_destroy(&qrs->sbuf, cleanse);
    OPENSSL_free(qrs);
}

static int write_at_sbuf_cb(uint64_t logical_offset, const unsigned char *buf,
    size_t buf_len, void *cb_arg)
{
    return sbuf_write(cb_arg, logical_offset, buf, buf_len);
}

int ossl_quic_rstream_queue_data(QUIC_RSTREAM *qrs, OSSL_QRX_PKT *pkt,
    uint64_t offset,
    const unsigned char *data, uint64_t data_len,
    int fin)
{
    UINT_RANGE range;
    int move_pinned;

    if ((data == NULL && data_len != 0) || (data_len == 0 && fin == 0)) {
        /* empty frame allowed only at the end of the stream */
        ERR_raise(ERR_LIB_SSL, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    range.start = offset;
    range.end = offset + data_len;

    if (!ossl_sframe_list_insert(&qrs->fl, &range, pkt, data, fin))
        return 0;

    if (qrs->frames_at_last_move > qrs->fl.num_frames)
        qrs->frames_at_last_move = qrs->fl.num_frames;
    if (qrs->pinned_at_last_move > qrs->fl.num_pinned)
        qrs->pinned_at_last_move = qrs->fl.num_pinned;

    /*
     * Once too many frames pin the packet they arrived in, they are all
     * copied out however little they are worth moving. Only a pin count
     * that grew since the last move triggers this, so frames that cannot
     * be copied do not make every insert walk the list.
     */
    move_pinned = qrs->fl.num_pinned > SFRAME_LIST_MAX_PINNED_FRAMES
        && qrs->fl.num_pinned > qrs->pinned_at_last_move;

    /*
     * Copying is best effort, frames we fail to copy just keep referencing
     * their packet.
     */
    if (move_pinned
        || qrs->fl.num_frames >= qrs->frames_at_last_move + RSTREAM_MOVE_THRESHOLD) {
        (void)ossl_sframe_list_move_data(&qrs->fl, SBUF_MIN_COPY_LEN,
            move_pinned, write_at_sbuf_cb, &qrs->sbuf);
        qrs->frames_at_last_move = qrs->fl.num_frames;
        qrs->pinned_at_last_move = qrs->fl.num_pinned;
    }

    return 1;
}

static int read_internal(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
    size_t *readbytes, int *fin, int drop)
{
    void *iter = NULL;
    UINT_RANGE range;
    const unsigned char *data;
    uint64_t offset = 0;
    size_t readbytes_ = 0;
    int fin_ = 0, ret = 1;

    while (ossl_sframe_list_peek(&qrs->fl, &iter, &range, &data, &fin_)) {
        size_t l = (size_t)(range.end - range.start);

        if (l > size) {
            l = size;
            fin_ = 0;
        }
        offset = range.start + l;
        if (l == 0)
            break;

        if (data == NULL) {
            /* the data was copied to the stream buffer, which is chunked */
            uint64_t data_off = range.start;

            while (l > 0) {
                size_t max_len, chunk_len;

                data = sbuf_get_ptr(&qrs->sbuf, data_off, &max_len);
                if (!ossl_assert(data != NULL))
                    return 0;

                chunk_len = max_len < l ? max_len : l;
                memcpy(buf, data, chunk_len);
                size -= chunk_len;
                buf += chunk_len;
                readbytes_ += chunk_len;
                l -= chunk_len;
                data_off += chunk_len;
            }
        } else {
            memcpy(buf, data, l);
            size -= l;
            buf += l;
            readbytes_ += l;
        }

        if (size == 0)
            break;
    }

    if (drop && offset != 0) {
        ret = ossl_sframe_list_drop_frames(&qrs->fl, offset);
        sbuf_free_upto(&qrs->sbuf, offset, qrs->fl.cleanse);
    }

    if (ret) {
        *readbytes = readbytes_;
        *fin = fin_;
    }

    return ret;
}

static OSSL_TIME get_rtt(QUIC_RSTREAM *qrs)
{
    OSSL_TIME rtt;

    if (qrs->statm != NULL) {
        OSSL_RTT_INFO rtt_info;

        ossl_statm_get_rtt_info(qrs->statm, &rtt_info);
        rtt = rtt_info.smoothed_rtt;
    } else {
        rtt = ossl_time_zero();
    }
    return rtt;
}

int ossl_quic_rstream_read(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
    size_t *readbytes, int *fin)
{
    OSSL_TIME rtt = get_rtt(qrs);

    if (!read_internal(qrs, buf, size, readbytes, fin, 1))
        return 0;

    if (qrs->rxfc != NULL
        && !ossl_quic_rxfc_on_retire(qrs->rxfc, *readbytes, rtt))
        return 0;

    return 1;
}

int ossl_quic_rstream_peek(QUIC_RSTREAM *qrs, unsigned char *buf, size_t size,
    size_t *readbytes, int *fin)
{
    return read_internal(qrs, buf, size, readbytes, fin, 0);
}

int ossl_quic_rstream_available(QUIC_RSTREAM *qrs, size_t *avail, int *fin)
{
    void *iter = NULL;
    UINT_RANGE range;
    const unsigned char *data;
    uint64_t avail_ = 0;

    while (ossl_sframe_list_peek(&qrs->fl, &iter, &range, &data, fin))
        avail_ += range.end - range.start;

#if SIZE_MAX < UINT64_MAX
    *avail = avail_ > SIZE_MAX ? SIZE_MAX : (size_t)avail_;
#else
    *avail = (size_t)avail_;
#endif
    return 1;
}

int ossl_quic_rstream_get_record(QUIC_RSTREAM *qrs,
    const unsigned char **record, size_t *rec_len,
    int *fin)
{
    const unsigned char *record_ = NULL;
    size_t rec_len_, max_len;

    if (!ossl_sframe_list_lock_head(&qrs->fl, &qrs->head_range, &record_, fin)) {
        /* No head frame to lock and return */
        *record = NULL;
        *rec_len = 0;
        return 1;
    }

    /* if final empty frame, we drop it immediately */
    if (qrs->head_range.end == qrs->head_range.start) {
        if (!ossl_assert(*fin))
            return 0;
        if (!ossl_sframe_list_drop_frames(&qrs->fl, qrs->head_range.end))
            return 0;
    }

    rec_len_ = (size_t)(qrs->head_range.end - qrs->head_range.start);

    if (record_ == NULL && rec_len_ != 0) {
        record_ = sbuf_get_ptr(&qrs->sbuf, qrs->head_range.start, &max_len);
        if (!ossl_assert(record_ != NULL))
            return 0;
        if (max_len < rec_len_) {
            rec_len_ = max_len;
            qrs->head_range.end = qrs->head_range.start + max_len;
        }
    }

    *rec_len = rec_len_;
    *record = record_;
    return 1;
}

int ossl_quic_rstream_release_record(QUIC_RSTREAM *qrs, size_t read_len)
{
    uint64_t offset;

    if (!ossl_sframe_list_is_head_locked(&qrs->fl))
        return 0;

    if (read_len > qrs->head_range.end - qrs->head_range.start) {
        if (read_len != SIZE_MAX)
            return 0;
        offset = qrs->head_range.end;
    } else {
        offset = qrs->head_range.start + read_len;
    }

    if (!ossl_sframe_list_drop_frames(&qrs->fl, offset))
        return 0;

    sbuf_free_upto(&qrs->sbuf, offset, qrs->fl.cleanse);

    if (qrs->rxfc != NULL) {
        OSSL_TIME rtt = get_rtt(qrs);

        if (!ossl_quic_rxfc_on_retire(qrs->rxfc, offset, rtt))
            return 0;
    }

    return 1;
}

void ossl_quic_rstream_set_cleanse(QUIC_RSTREAM *qrs, int cleanse)
{
    qrs->fl.cleanse = cleanse;
}
