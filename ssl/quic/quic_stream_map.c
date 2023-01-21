/*
* Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/

#include "internal/quic_stream_map.h"
#include "internal/nelem.h"

/* QUIC Stream
 * ===========
 */

int ossl_quic_stream_stop_sending(QUIC_STREAM *s, uint64_t aec)
{
    if (s->stop_sending)
        return 0;

    s->stop_sending_aec     = aec;
    s->stop_sending         = 1;
    s->want_stop_sending    = 1;
    return 1;
}

int ossl_quic_stream_reset(QUIC_STREAM *s, uint64_t aec)
{
    if (s->reset_stream)
        return 0;

    s->reset_stream_aec     = aec;
    s->reset_stream         = 1;
    s->want_reset_stream    = 1;
    return 1;
}

/*
 * QUIC Stream Map
 * ===============
 */
DEFINE_LHASH_OF_EX(QUIC_STREAM);

/* Circular list management. */
static void list_insert_tail(QUIC_STREAM_LIST_NODE *l,
                             QUIC_STREAM_LIST_NODE *n)
{
    /* Must not be in list. */
    assert(n->prev == NULL && n->next == NULL);

    n->prev = l->prev;
    n->prev->next = n;
    l->prev = n;
    n->next = l;
}

static void list_remove(QUIC_STREAM_LIST_NODE *l,
                        QUIC_STREAM_LIST_NODE *n)
{
    assert(n->prev != NULL && n->next != NULL
           && n->prev != n && n->next != n);

    n->prev->next = n->next;
    n->next->prev = n->prev;
    n->next = n->prev = NULL;
}

static QUIC_STREAM *active_next(QUIC_STREAM_LIST_NODE *l, QUIC_STREAM *s)
{
    QUIC_STREAM_LIST_NODE *n = s->active_node.next;

    if (n == l)
        n = n->next;
    if (n == l)
        return NULL;
    return (QUIC_STREAM *)n;
}

static unsigned long hash_stream(const QUIC_STREAM *s)
{
    return (unsigned long)s->id;
}

static int cmp_stream(const QUIC_STREAM *a, const QUIC_STREAM *b)
{
    if (a->id < b->id)
        return -1;
    if (a->id > b->id)
        return 1;
    return 0;
}

int ossl_quic_stream_map_init(QUIC_STREAM_MAP *qsm,
                              uint64_t (*get_stream_limit_cb)(int uni, void *arg),
                              void *get_stream_limit_cb_arg)
{
    qsm->map = lh_QUIC_STREAM_new(hash_stream, cmp_stream);
    qsm->active_list.prev = qsm->active_list.next = &qsm->active_list;
    qsm->rr_stepping = 1;
    qsm->rr_counter  = 0;
    qsm->rr_cur      = NULL;

    qsm->get_stream_limit_cb        = get_stream_limit_cb;
    qsm->get_stream_limit_cb_arg    = get_stream_limit_cb_arg;
    return 1;
}

static void release_each(QUIC_STREAM *stream, void *arg)
{
    QUIC_STREAM_MAP *qsm = arg;

    ossl_quic_stream_map_release(qsm, stream);
}

void ossl_quic_stream_map_cleanup(QUIC_STREAM_MAP *qsm)
{
    ossl_quic_stream_map_visit(qsm, release_each, qsm);

    lh_QUIC_STREAM_free(qsm->map);
    qsm->map = NULL;
}

void ossl_quic_stream_map_visit(QUIC_STREAM_MAP *qsm,
                                void (*visit_cb)(QUIC_STREAM *stream, void *arg),
                                void *visit_cb_arg)
{
    lh_QUIC_STREAM_doall_arg(qsm->map, visit_cb, visit_cb_arg);
}

QUIC_STREAM *ossl_quic_stream_map_alloc(QUIC_STREAM_MAP *qsm,
                                        uint64_t stream_id,
                                        int type)
{
    QUIC_STREAM *s;
    QUIC_STREAM key;

    key.id = stream_id;

    s = lh_QUIC_STREAM_retrieve(qsm->map, &key);
    if (s != NULL)
        return NULL;

    s = OPENSSL_zalloc(sizeof(*s));
    if (s == NULL)
        return NULL;

    s->id   = stream_id;
    s->type = type;
    lh_QUIC_STREAM_insert(qsm->map, s);
    return s;
}

void ossl_quic_stream_map_release(QUIC_STREAM_MAP *qsm, QUIC_STREAM *stream)
{
    if (stream == NULL)
        return;

    ossl_quic_sstream_free(stream->sstream);
    stream->sstream = NULL;

    ossl_quic_rstream_free(stream->rstream);
    stream->rstream = NULL;

    lh_QUIC_STREAM_delete(qsm->map, stream);
    OPENSSL_free(stream);
}

QUIC_STREAM *ossl_quic_stream_map_get_by_id(QUIC_STREAM_MAP *qsm,
                                            uint64_t stream_id)
{
    QUIC_STREAM key;

    key.id = stream_id;

    return lh_QUIC_STREAM_retrieve(qsm->map, &key);
}

static void stream_map_mark_active(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s)
{
    if (s->active)
        return;

    list_insert_tail(&qsm->active_list, &s->active_node);

    if (qsm->rr_cur == NULL)
        qsm->rr_cur = s;

    s->active = 1;
}

static void stream_map_mark_inactive(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s)
{
    if (!s->active)
        return;

    list_remove(&qsm->active_list, &s->active_node);

    if (qsm->rr_cur == s)
        qsm->rr_cur = active_next(&qsm->active_list, s);
    if (qsm->rr_cur == s)
        qsm->rr_cur = NULL;

    s->active = 0;
}

void ossl_quic_stream_map_set_rr_stepping(QUIC_STREAM_MAP *qsm, size_t stepping)
{
    qsm->rr_stepping = stepping;
    qsm->rr_counter  = 0;
}

static int stream_has_data_to_send(QUIC_STREAM *s)
{
    OSSL_QUIC_FRAME_STREAM shdr;
    OSSL_QTX_IOVEC iov[2];
    size_t num_iov;
    uint64_t fc_credit, fc_swm, fc_limit;

    if (s->sstream == NULL)
        return 0;

    /*
     * We cannot determine if we have data to send simply by checking if
     * ossl_quic_txfc_get_credit() is zero, because we may also have older
     * stream data we need to retransmit. The SSTREAM returns older data first,
     * so we do a simple comparison of the next chunk the SSTREAM wants to send
     * against the TXFC CWM.
     */
    num_iov = OSSL_NELEM(iov);
    if (!ossl_quic_sstream_get_stream_frame(s->sstream, 0, &shdr, iov,
                                            &num_iov))
        return 0;

    fc_credit = ossl_quic_txfc_get_credit(&s->txfc);
    fc_swm    = ossl_quic_txfc_get_swm(&s->txfc);
    fc_limit  = fc_swm + fc_credit;

    return (shdr.is_fin && shdr.len == 0) || shdr.offset < fc_limit;
}

void ossl_quic_stream_map_update_state(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s)
{
    int should_be_active, allowed_by_stream_limit = 1;

    if (qsm->get_stream_limit_cb != NULL
        && (s->type & QUIC_STREAM_INITIATOR_CLIENT) != 0) {
        int uni = ((s->type & QUIC_STREAM_DIR_UNI) != 0);
        uint64_t stream_limit, stream_ordinal = s->id >> 2;

        stream_limit
            = qsm->get_stream_limit_cb(uni, qsm->get_stream_limit_cb_arg);

        allowed_by_stream_limit = (stream_ordinal < stream_limit);
    }

    should_be_active
        = allowed_by_stream_limit
        && !s->peer_stop_sending
        && !s->peer_reset_stream
        && ((s->rstream != NULL
            && (s->want_max_stream_data
                || ossl_quic_rxfc_has_cwm_changed(&s->rxfc, 0)))
            || s->want_stop_sending
            || s->want_reset_stream
            || stream_has_data_to_send(s));

    if (should_be_active)
        stream_map_mark_active(qsm, s);
    else
        stream_map_mark_inactive(qsm, s);
}

/*
 * QUIC Stream Iterator
 * ====================
 */
void ossl_quic_stream_iter_init(QUIC_STREAM_ITER *it, QUIC_STREAM_MAP *qsm,
                                int advance_rr)
{
    it->qsm    = qsm;
    it->stream = it->first_stream = qsm->rr_cur;
    if (advance_rr && it->stream != NULL
        && ++qsm->rr_counter >= qsm->rr_stepping) {
        qsm->rr_counter = 0;
        qsm->rr_cur     = active_next(&qsm->active_list, qsm->rr_cur);
    }
}

void ossl_quic_stream_iter_next(QUIC_STREAM_ITER *it)
{
    if (it->stream == NULL)
        return;

    it->stream = active_next(&it->qsm->active_list, it->stream);
    if (it->stream == it->first_stream)
        it->stream = NULL;
}
