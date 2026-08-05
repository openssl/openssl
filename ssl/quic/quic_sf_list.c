/*
 * Copyright 2022-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/uint_set.h"
#include "internal/common.h"
#include "internal/quic_sf_list.h"

struct stream_frame_st {
    struct stream_frame_st *prev, *next;
    UINT_RANGE range;
    OSSL_QRX_PKT *pkt;
    const unsigned char *data;
};

static void stream_frame_free(SFRAME_LIST *fl, STREAM_FRAME *sf)
{
    if (fl->cleanse && sf->data != NULL)
        OPENSSL_cleanse((unsigned char *)sf->data,
            (size_t)(sf->range.end - sf->range.start));
    ossl_qrx_pkt_release(sf->pkt);
    OPENSSL_free(sf);
}

static STREAM_FRAME *stream_frame_new(UINT_RANGE *range, OSSL_QRX_PKT *pkt,
    const unsigned char *data)
{
    STREAM_FRAME *sf = OPENSSL_zalloc(sizeof(*sf));

    if (sf == NULL)
        return NULL;

    if (pkt != NULL)
        ossl_qrx_pkt_up_ref(pkt);

    sf->range = *range;
    sf->pkt = pkt;
    sf->data = data;

    return sf;
}

void ossl_sframe_list_init(SFRAME_LIST *fl)
{
    memset(fl, 0, sizeof(*fl));
}

void ossl_sframe_list_destroy(SFRAME_LIST *fl)
{
    STREAM_FRAME *sf, *next_frame;

    for (sf = fl->head; sf != NULL; sf = next_frame) {
        next_frame = sf->next;
        stream_frame_free(fl, sf);
    }
}

/* end is the end of the range about to be added to the list */
static int sframe_list_too_fragmented(const SFRAME_LIST *fl, uint64_t end)
{
    uint64_t span;

    if (fl->num_frames >= SFRAME_LIST_MAX_FRAGMENTATION)
        return 1;

    if (fl->num_frames < SFRAME_LIST_MIN_FRAGMENTATION)
        return 0;

    if (fl->tail != NULL && fl->tail->range.end > end)
        end = fl->tail->range.end;
    span = end - fl->offset;

    return fl->num_frames * (uint64_t)SFRAME_LIST_MIN_AVG_SPAN > span;
}

static int append_frame(SFRAME_LIST *fl, UINT_RANGE *range,
    OSSL_QRX_PKT *pkt,
    const unsigned char *data)
{
    STREAM_FRAME *new_frame;

    if (sframe_list_too_fragmented(fl, range->end))
        return 0;

    if ((new_frame = stream_frame_new(range, pkt, data)) == NULL)
        return 0;
    new_frame->prev = fl->tail;
    if (fl->tail != NULL)
        fl->tail->next = new_frame;
    fl->tail = new_frame;
    ++fl->num_frames;
    return 1;
}

int ossl_sframe_list_insert(SFRAME_LIST *fl, UINT_RANGE *range,
    OSSL_QRX_PKT *pkt,
    const unsigned char *data, int fin)
{
    STREAM_FRAME *sf, *new_frame, *prev_frame, *next_frame;
#ifndef NDEBUG
    uint64_t curr_end = fl->tail != NULL ? fl->tail->range.end
                                         : fl->offset;

    /* This check for FINAL_SIZE_ERROR is handled by QUIC FC already */
    assert((!fin || curr_end <= range->end)
        && (!fl->fin || curr_end >= range->end));
#endif

    if (fl->offset >= range->end)
        goto end;

    /* nothing there yet */
    if (fl->tail == NULL) {
        fl->tail = fl->head = stream_frame_new(range, pkt, data);
        if (fl->tail == NULL)
            return 0;

        ++fl->num_frames;
        goto end;
    }

    /* optimize insertion at the end */
    if (fl->tail->range.start < range->start) {
        if (fl->tail->range.end >= range->end)
            goto end;

        if (!append_frame(fl, range, pkt, data))
            return 0;
        goto end;
    }

    prev_frame = NULL;
    for (sf = fl->head; sf != NULL && sf->range.start < range->start;
        sf = sf->next)
        prev_frame = sf;

    if (!ossl_assert(sf != NULL))
        /* frame list invariant broken */
        return 0;

    if (prev_frame != NULL && prev_frame->range.end >= range->end)
        goto end;

    /*
     * Now we must create a new frame although in the end we might drop it,
     * because we will be potentially dropping existing overlapping frames.
     */
    new_frame = stream_frame_new(range, pkt, data);
    if (new_frame == NULL)
        return 0;

    for (next_frame = sf;
        next_frame != NULL && next_frame->range.end <= range->end;) {
        STREAM_FRAME *drop_frame = next_frame;

        /* the reader still holds the data of a locked head */
        assert(!fl->head_locked || drop_frame != fl->head);

        next_frame = next_frame->next;
        if (next_frame != NULL)
            next_frame->prev = drop_frame->prev;
        if (prev_frame != NULL)
            prev_frame->next = drop_frame->next;
        if (fl->head == drop_frame)
            fl->head = next_frame;
        if (fl->tail == drop_frame)
            fl->tail = prev_frame;
        --fl->num_frames;
        stream_frame_free(fl, drop_frame);
    }

    /* check whether the new_frame is redundant because there is no gap */
    if (next_frame != NULL && prev_frame != NULL
        && next_frame->range.start <= prev_frame->range.end) {
        stream_frame_free(fl, new_frame);
        goto end;
    }

    /* the frame count only grows past this point */
    if (sframe_list_too_fragmented(fl, range->end)) {
        stream_frame_free(fl, new_frame);
        return 0;
    }

    if (next_frame != NULL)
        next_frame->prev = new_frame;
    else
        fl->tail = new_frame;

    new_frame->next = next_frame;
    new_frame->prev = prev_frame;

    if (prev_frame != NULL)
        prev_frame->next = new_frame;
    else
        fl->head = new_frame;

    ++fl->num_frames;

end:
    fl->fin = fin || fl->fin;

    return 1;
}

int ossl_sframe_list_peek(const SFRAME_LIST *fl, void **iter,
    UINT_RANGE *range, const unsigned char **data,
    int *fin)
{
    STREAM_FRAME *sf = *iter;
    uint64_t start;

    if (sf == NULL) {
        start = fl->offset;
        sf = fl->head;
    } else {
        start = sf->range.end;
        sf = sf->next;
    }

    range->start = start;

    if (sf == NULL || sf->range.start > start
        || !ossl_assert(start < sf->range.end)) {
        range->end = start;
        *data = NULL;
        *iter = NULL;
        /* set fin only if we are at the end */
        *fin = sf == NULL ? fl->fin : 0;
        return 0;
    }

    range->end = sf->range.end;
    if (sf->data != NULL)
        *data = sf->data + (start - sf->range.start);
    else
        *data = NULL;
    *fin = sf->next == NULL ? fl->fin : 0;
    *iter = sf;
    return 1;
}

int ossl_sframe_list_drop_frames(SFRAME_LIST *fl, uint64_t limit)
{
    STREAM_FRAME *sf;

    /* offset cannot move back or past the data received */
    if (!ossl_assert(limit >= fl->offset)
        || !ossl_assert(fl->tail == NULL
            || limit <= fl->tail->range.end)
        || !ossl_assert(fl->tail != NULL
            || limit == fl->offset))
        return 0;

    fl->offset = limit;

    for (sf = fl->head; sf != NULL && sf->range.end <= limit;) {
        STREAM_FRAME *drop_frame = sf;

        sf = sf->next;
        --fl->num_frames;
        stream_frame_free(fl, drop_frame);
    }
    fl->head = sf;

    if (sf != NULL)
        sf->prev = NULL;
    else
        fl->tail = NULL;

    fl->head_locked = 0;

    return 1;
}

int ossl_sframe_list_lock_head(SFRAME_LIST *fl, UINT_RANGE *range,
    const unsigned char **data,
    int *fin)
{
    int ret;
    void *iter = NULL;

    if (fl->head_locked)
        return 0;

    ret = ossl_sframe_list_peek(fl, &iter, range, data, fin);
    if (ret)
        fl->head_locked = 1;
    return ret;
}

int ossl_sframe_list_is_head_locked(SFRAME_LIST *fl)
{
    return fl->head_locked;
}

/*
 * Whether a run of contiguous frames spanning start to last->range.end is
 * worth moving to the side storage. A short run surrounded by empty space is
 * not, as moving it would hold a whole side storage block for very little
 * data, so it stays in the packets it arrived in and is moved once it grows
 * or the space around it fills in. Until then its frames keep their data and
 * packet reference, which is how every frame is read before it is moved, so
 * the reader is unaffected.
 */
static int run_worth_moving(const STREAM_FRAME *last, uint64_t start,
    uint64_t prev_end, uint64_t min_run_len)
{
    uint64_t run_len = last->range.end - start;
    uint64_t gap_before = start - prev_end;
    /* space past the last frame is where the rest of the stream goes */
    uint64_t gap_after = last->next != NULL
        ? last->next->range.start - last->range.end
        : 0;

    if (run_len >= min_run_len)
        return 1;

    /* space farther than min_run_len away could not share a block anyway */
    if (gap_before > min_run_len)
        gap_before = min_run_len;
    if (gap_after > min_run_len)
        gap_after = min_run_len;

    return run_len * SFRAME_LIST_MIN_MOVE_FILL
        >= gap_before + run_len + gap_after;
}

int ossl_sframe_list_move_data(SFRAME_LIST *fl, uint64_t min_run_len,
    sframe_list_write_at_cb *write_at_cb,
    void *cb_arg)
{
    STREAM_FRAME *sf = fl->head;
    uint64_t prev_end = fl->offset;

    if (sf == NULL)
        return 1;

    if (fl->head_locked)
        sf = sf->next;

    while (sf != NULL) {
        STREAM_FRAME *last = sf, *cur, *next_frame;
        uint64_t limit = sf->range.start > fl->offset ? sf->range.start
                                                      : fl->offset;

        /* find the last frame of the run of contiguous frames from sf */
        while (last->next != NULL && last->next->range.start <= last->range.end)
            last = last->next;

        if (!run_worth_moving(last, limit, prev_end, min_run_len)) {
            prev_end = last->range.end;
            sf = last->next;
            continue;
        }

        /* move the data of each frame in the run out of its packet */
        for (cur = sf;; cur = cur->next) {
            if (cur->data != NULL) {
                const unsigned char *data = cur->data;
                size_t len;

                /* frames in a run may overlap, write only what is new */
                if (limit > cur->range.start)
                    data += (size_t)(limit - cur->range.start);
                len = (size_t)(cur->range.end - limit);

                if (!write_at_cb(limit, data, len, cb_arg))
                    /* data did not fit */
                    return 0;

                if (fl->cleanse)
                    OPENSSL_cleanse((unsigned char *)cur->data,
                        (size_t)(cur->range.end - cur->range.start));

                /* release the packet */
                cur->data = NULL;
                ossl_qrx_pkt_release(cur->pkt);
                cur->pkt = NULL;
            }

            limit = cur->range.end;
            if (cur == last)
                break;
        }

        /* the moved run is contiguous, merge it into its first frame */
        next_frame = last->next;
        sf->range.end = last->range.end;
        while (sf->next != next_frame) {
            cur = sf->next;
            sf->next = cur->next;
            --fl->num_frames;
            stream_frame_free(fl, cur);
        }
        if (next_frame != NULL)
            next_frame->prev = sf;
        else
            fl->tail = sf;

        prev_end = sf->range.end;
        sf = next_frame;
    }

    return 1;
}
