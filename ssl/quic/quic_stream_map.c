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
    assert(n->prev == NULL && n->next == NULL
           && l->prev != NULL && l->next != NULL);

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

static QUIC_STREAM *list_next(QUIC_STREAM_LIST_NODE *l, QUIC_STREAM_LIST_NODE *n,
                              size_t off)
{
    assert(n->prev != NULL && n->next != NULL
           && (n == l || (n->prev != n && n->next != n))
           && l->prev != NULL && l->next != NULL);

    n = n->next;

    if (n == l)
        n = n->next;
    if (n == l)
        return NULL;

    assert(n != NULL);

    return (QUIC_STREAM *)(((char *)n) - off);
}

#define active_next(l, s)       list_next((l), &(s)->active_node, \
                                          offsetof(QUIC_STREAM, active_node))
#define accept_next(l, s)       list_next((l), &(s)->accept_node, \
                                          offsetof(QUIC_STREAM, accept_node))
#define ready_for_gc_next(l, s) list_next((l), &(s)->ready_for_gc_node, \
                                          offsetof(QUIC_STREAM, ready_for_gc_node))
#define accept_head(l)          list_next((l), (l), \
                                          offsetof(QUIC_STREAM, accept_node))
#define ready_for_gc_head(l)    list_next((l), (l), \
                                          offsetof(QUIC_STREAM, ready_for_gc_node))

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
                              void *get_stream_limit_cb_arg,
                              QUIC_RXFC *max_streams_bidi_rxfc,
                              QUIC_RXFC *max_streams_uni_rxfc,
                              int is_server)
{
    qsm->map = lh_QUIC_STREAM_new(hash_stream, cmp_stream);
    qsm->active_list.prev = qsm->active_list.next = &qsm->active_list;
    qsm->accept_list.prev = qsm->accept_list.next = &qsm->accept_list;
    qsm->ready_for_gc_list.prev = qsm->ready_for_gc_list.next
        = &qsm->ready_for_gc_list;
    qsm->rr_stepping = 1;
    qsm->rr_counter  = 0;
    qsm->rr_cur      = NULL;
    qsm->num_accept  = 0;

    qsm->get_stream_limit_cb        = get_stream_limit_cb;
    qsm->get_stream_limit_cb_arg    = get_stream_limit_cb_arg;
    qsm->max_streams_bidi_rxfc      = max_streams_bidi_rxfc;
    qsm->max_streams_uni_rxfc       = max_streams_uni_rxfc;
    qsm->is_server                  = is_server;
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

    if (stream->active_node.next != NULL)
        list_remove(&qsm->active_list, &stream->active_node);
    if (stream->accept_node.next != NULL)
        list_remove(&qsm->accept_list, &stream->accept_node);
    if (stream->ready_for_gc_node.next != NULL)
        list_remove(&qsm->ready_for_gc_list, &stream->ready_for_gc_node);

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

    if (qsm->rr_cur == s)
        qsm->rr_cur = active_next(&qsm->active_list, s);
    if (qsm->rr_cur == s)
        qsm->rr_cur = NULL;

    list_remove(&qsm->active_list, &s->active_node);

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

static int qsm_ready_for_gc(QUIC_STREAM_MAP *qsm, QUIC_STREAM *qs)
{
    int recv_stream_fully_drained = 0; /* TODO(QUIC): Optimisation */

    /*
     * If sstream has no FIN, we auto-reset it at marked-for-deletion time, so
     * we don't need to worry about that here.
     */
    assert(!qs->deleted
           || qs->sstream == NULL
           || qs->reset_stream
           || ossl_quic_sstream_get_final_size(qs->sstream, NULL));

    return
        qs->deleted
        && (qs->rstream == NULL
            || recv_stream_fully_drained
            || qs->acked_stop_sending)
        && (qs->sstream == NULL
            || (!qs->reset_stream
                && ossl_quic_sstream_is_totally_acked(qs->sstream))
            || (qs->reset_stream
                && qs->acked_reset_stream));
}

void ossl_quic_stream_map_update_state(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s)
{
    int should_be_active, allowed_by_stream_limit = 1;

    if (qsm->get_stream_limit_cb != NULL
        && ossl_quic_stream_is_server_init(s) == qsm->is_server) {
        int uni = !ossl_quic_stream_is_bidi(s);
        uint64_t stream_limit, stream_ordinal = s->id >> 2;

        stream_limit
            = qsm->get_stream_limit_cb(uni, qsm->get_stream_limit_cb_arg);

        allowed_by_stream_limit = (stream_ordinal < stream_limit);
    }

    if (!s->ready_for_gc) {
        s->ready_for_gc = qsm_ready_for_gc(qsm, s);
        if (s->ready_for_gc)
            list_insert_tail(&qsm->ready_for_gc_list, &s->ready_for_gc_node);
    }

    should_be_active
        = allowed_by_stream_limit
        && !s->ready_for_gc
        && ((!s->peer_reset_stream && s->rstream != NULL
             && (s->want_max_stream_data
                 || ossl_quic_rxfc_has_cwm_changed(&s->rxfc, 0)))
            || s->want_stop_sending
            || s->want_reset_stream
            || (!s->peer_stop_sending && stream_has_data_to_send(s)));

    if (should_be_active)
        stream_map_mark_active(qsm, s);
    else
        stream_map_mark_inactive(qsm, s);
}

int ossl_quic_stream_map_reset_stream_send_part(QUIC_STREAM_MAP *qsm,
                                                QUIC_STREAM *qs,
                                                uint64_t aec)
{
    if (qs->reset_stream)
        return 0;

    qs->reset_stream        = 1;
    qs->reset_stream_aec    = aec;
    qs->want_reset_stream   = 1;

    ossl_quic_stream_map_update_state(qsm, qs);
    return 1;
}

int ossl_quic_stream_map_stop_sending_recv_part(QUIC_STREAM_MAP *qsm,
                                                QUIC_STREAM *qs,
                                                uint64_t aec)
{
    if (qs->stop_sending)
        return 0;

    qs->stop_sending        = 1;
    qs->stop_sending_aec    = aec;
    qs->want_stop_sending   = 1;

    ossl_quic_stream_map_update_state(qsm, qs);
    return 1;
}

QUIC_STREAM *ossl_quic_stream_map_peek_accept_queue(QUIC_STREAM_MAP *qsm)
{
    return accept_head(&qsm->accept_list);
}

void ossl_quic_stream_map_push_accept_queue(QUIC_STREAM_MAP *qsm,
                                            QUIC_STREAM *s)
{
    list_insert_tail(&qsm->accept_list, &s->accept_node);
    ++qsm->num_accept;
}

static QUIC_RXFC *qsm_get_max_streams_rxfc(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s)
{
    return ossl_quic_stream_is_bidi(s)
        ? qsm->max_streams_bidi_rxfc
        : qsm->max_streams_uni_rxfc;
}

void ossl_quic_stream_map_remove_from_accept_queue(QUIC_STREAM_MAP *qsm,
                                                   QUIC_STREAM *s,
                                                   OSSL_TIME rtt)
{
    QUIC_RXFC *max_streams_rxfc;

    list_remove(&qsm->accept_list, &s->accept_node);
    --qsm->num_accept;

    if ((max_streams_rxfc = qsm_get_max_streams_rxfc(qsm, s)) != NULL)
        ossl_quic_rxfc_on_retire(max_streams_rxfc, 1, rtt);
}

size_t ossl_quic_stream_map_get_accept_queue_len(QUIC_STREAM_MAP *qsm)
{
    return qsm->num_accept;
}

void ossl_quic_stream_map_gc(QUIC_STREAM_MAP *qsm)
{
    QUIC_STREAM *qs, *qs_head, *qsn = NULL;

    for (qs = qs_head = ready_for_gc_head(&qsm->ready_for_gc_list);
         qs != NULL && qs != qs_head;
         qs = qsn)
    {
         qsn = ready_for_gc_next(&qsm->ready_for_gc_list, qs);

         ossl_quic_stream_map_release(qsm, qs);
    }
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
