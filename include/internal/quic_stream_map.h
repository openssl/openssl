/*
* Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/

#ifndef OSSL_INTERNAL_QUIC_STREAM_MAP_H
# define OSSL_INTERNAL_QUIC_STREAM_MAP_H
# pragma once

# include "internal/e_os.h"
# include "internal/time.h"
# include "internal/quic_types.h"
# include "internal/quic_stream.h"
# include "internal/quic_fc.h"
# include <openssl/lhash.h>

# ifndef OPENSSL_NO_QUIC

/*
 * QUIC Stream
 * ===========
 *
 * Logical QUIC stream composing all relevant send and receive components.
 */
typedef struct quic_stream_st QUIC_STREAM;

typedef struct quic_stream_list_node_st QUIC_STREAM_LIST_NODE;

struct quic_stream_list_node_st {
    QUIC_STREAM_LIST_NODE *prev, *next;
};

struct quic_stream_st {
    QUIC_STREAM_LIST_NODE active_node; /* for use by QUIC_STREAM_MAP */
    QUIC_STREAM_LIST_NODE accept_node; /* accept queue of remotely-created streams */
    QUIC_STREAM_LIST_NODE ready_for_gc_node; /* queue of streams now ready for GC */

    /* Temporary link used by TXP. */
    QUIC_STREAM    *txp_next;

    /*
     * QUIC Stream ID. Do not assume that this encodes a type as this is a
     * version-specific property and may change between QUIC versions; instead,
     * use the type field.
     */
    uint64_t        id;

    /*
     * Application Error Code (AEC) used for STOP_SENDING frame.
     * This is only valid if stop_sending is 1.
     */
    uint64_t        stop_sending_aec;

    /*
     * Application Error Code (AEC) used for RESET_STREAM frame.
     * This is only valid if reset_stream is 1.
     */
    uint64_t        reset_stream_aec;

    /*
     * Application Error Code (AEC) for incoming STOP_SENDING frame.
     * This is only valid if peer_stop_sending is 1.
     */
    uint64_t        peer_stop_sending_aec;

    /*
     * Application Error Code (AEC) for incoming RESET_STREAM frame.
     * This is only valid if peer_reset_stream is 1.
     */
    uint64_t        peer_reset_stream_aec;

    /* Temporary value used by TXP. */
    uint64_t        txp_txfc_new_credit_consumed;

    QUIC_SSTREAM    *sstream;   /* NULL if RX-only */
    QUIC_RSTREAM    *rstream;   /* NULL if TX only */
    QUIC_TXFC       txfc;       /* NULL if RX-only */
    QUIC_RXFC       rxfc;       /* NULL if TX-only */
    unsigned int    type   : 8; /* QUIC_STREAM_INITIATOR_*, QUIC_STREAM_DIR_* */
    unsigned int    active : 1;

    /*
     * Has STOP_SENDING been requested (by us)? Note that this is not the same
     * as want_stop_sending below, as a STOP_SENDING frame may already have been
     * sent and fully acknowledged.
     */
    unsigned int    stop_sending            : 1;

    /*
     * Has RESET_STREAM been requested (by us)? Works identically to
     * STOP_SENDING for transmission purposes.
     */
    unsigned int    reset_stream            : 1;

    /* Has our peer sent a STOP_SENDING frame? */
    unsigned int    peer_stop_sending       : 1;
    /* Has our peer sent a RESET_STREAM frame? */
    unsigned int    peer_reset_stream       : 1;

    /* Temporary flags used by TXP. */
    unsigned int    txp_sent_fc             : 1;
    unsigned int    txp_sent_stop_sending   : 1;
    unsigned int    txp_sent_reset_stream   : 1;
    unsigned int    txp_drained             : 1;
    unsigned int    txp_blocked             : 1;

    /* Frame regeneration flags. */
    unsigned int    want_max_stream_data    : 1; /* used for regen only */
    unsigned int    want_stop_sending       : 1; /* used for gen or regen */
    unsigned int    want_reset_stream       : 1; /* used for gen or regen */

    /* Flags set when frames *we* sent were acknowledged. */
    unsigned int    acked_stop_sending      : 1;
    unsigned int    acked_reset_stream      : 1;

    /* A FIN has been retired from the rstream buffer. */
    unsigned int    recv_fin_retired        : 1;

    /*
     * The stream's XSO has been deleted. Pending GC.
     *
     * Here is how stream deletion works:
     *
     *   - A QUIC_STREAM cannot be deleted until it is neither in the accept
     *     queue nor has an associated XSO. This condition occurs when and only
     *     when deleted is true.
     *
     *   - Once this is the case (i.e., no user-facing API object exposing the
     *     stream), we can delete the stream once we determine that all of our
     *     protocol obligations requiring us to keep the QUIC_STREAM around have
     *     been met.
     *
     *     The following frames relate to the streams layer for a specific
     *     stream:
     *
     *          STREAM
     *
     *              RX Obligations:
     *                  Ignore for a deleted stream.
     *
     *                  (This is different from our obligation for a
     *                  locally-initiated stream ID we have not created yet,
     *                  which we must treat as a protocol error. This can be
     *                  distinguished via a simple monotonic counter.)
     *
     *              TX Obligations:
     *                  None, once we've decided to (someday) delete the stream.
     *
     *          STOP_SENDING
     *
     *              We cannot delete the stream until we have finished informing
     *              the peer that we are not going to be listening to it
     *              anymore.
     *
     *              RX Obligations:
     *                  When we delete a stream we must have already had a FIN
     *                  or RESET_STREAM we transmitted acknowledged by the peer.
     *                  Thus we can ignore STOP_SENDING frames for deleted
     *                  streams (if they occur, they are probably just
     *                  retransmissions).
     *
     *              TX Obligations:
     *                  _Acknowledged_ receipt of a STOP_SENDING frame by the
     *                  peer (unless the peer's send part has already FIN'd).
     *
     *          RESET_STREAM
     *
     *              We cannot delete the stream until we have finished informing
     *              the peer that we are not going to be transmitting on it
     *              anymore.
     *
     *              RX Obligations:
     *                  This indicates the peer is not going to send any more
     *                  data on the stream. We don't need to care about this
     *                  since once a stream is marked for deletion we don't care
     *                  about any data it does send. We can ignore this for
     *                  deleted streams. The important criterion is that the
     *                  peer has been successfully delivered our STOP_SENDING
     *                  frame.
     *
     *              TX Obligations:
     *                  _Acknowledged_ receipt of a RESET_STREAM frame or FIN by
     *                  the peer.
     *
     *          MAX_STREAM_DATA
     *
     *              RX Obligations:
     *                 Ignore. Since we are not going to be sending any more
     *                 data on a stream once it has been marked for deletion,
     *                 we don't need to care about flow control information.
     *
     *              TX Obligations:
     *                  None.
     *
     *     In other words, our protocol obligation is simply:
     *
     *       - either:
     *         - the peer has acknowledged receipt of a STOP_SENDING frame sent
     *            by us; -or-
     *         - we have received a FIN and all preceding segments from the peer
     *
     *            [NOTE: The actual criterion required here is simply 'we have
     *            received a FIN from the peer'. However, due to reordering and
     *            retransmissions we might subsequently receive non-FIN segments
     *            out of order. The FIN means we know the peer will stop
     *            transmitting on the stream at *some* point, but by sending
     *            STOP_SENDING we can avoid these needless retransmissions we
     *            will just ignore anyway. In actuality we could just handle all
     *            cases by sending a STOP_SENDING. The strategy we choose is to
     *            only avoid sending a STOP_SENDING and rely on a received FIN
     *            when we have received all preceding data, as this makes it
     *            reasonably certain no benefit would be gained by sending
     *            STOP_SENDING.]
     *
     *            TODO(QUIC): Implement the latter case (currently we just
     *                        always do STOP_SENDING).
     *
     *         and;
     *
     *       - we have drained our send stream (for a finished send stream)
     *         and got acknowledgement all parts of it including the FIN, or
     *         sent a RESET_STREAM frame and got acknowledgement of that frame.
     *
     *      Once these conditions are met, we can GC the QUIC_STREAM.
     *
     */
    unsigned int    deleted                 : 1;
    /* Set to 1 once the above conditions are actually met. */
    unsigned int    ready_for_gc            : 1;
};

/* 
 * QUIC Stream Map
 * ===============
 *
 * The QUIC stream map:
 *
 *   - maps stream IDs to QUIC_STREAM objects;
 *   - tracks which streams are 'active' (currently have data for transmission);
 *   - allows iteration over the active streams only.
 *
 */
typedef struct quic_stream_map_st {
    LHASH_OF(QUIC_STREAM)   *map;
    QUIC_STREAM_LIST_NODE   active_list;
    QUIC_STREAM_LIST_NODE   accept_list;
    QUIC_STREAM_LIST_NODE   ready_for_gc_list;
    size_t                  rr_stepping, rr_counter, num_accept;
    QUIC_STREAM             *rr_cur;
    uint64_t                (*get_stream_limit_cb)(int uni, void *arg);
    void                    *get_stream_limit_cb_arg;
    QUIC_RXFC               *max_streams_bidi_rxfc;
    QUIC_RXFC               *max_streams_uni_rxfc;
    int                     is_server;
} QUIC_STREAM_MAP;

/*
 * get_stream_limit is a callback which is called to retrieve the current stream
 * limit for streams created by us. This mechanism is not used for
 * peer-initiated streams. If a stream's stream ID is x, a stream is allowed if
 * (x >> 2) < returned limit value; i.e., the returned value is exclusive.
 *
 * If uni is 1, get the limit for locally-initiated unidirectional streams, else
 * get the limit for locally-initiated bidirectional streams.
 *
 * If the callback is NULL, stream limiting is not applied.
 * Stream limiting is used to determine if frames can currently be produced for
 * a stream.
 */
int ossl_quic_stream_map_init(QUIC_STREAM_MAP *qsm,
                              uint64_t (*get_stream_limit_cb)(int uni, void *arg),
                              void *get_stream_limit_cb_arg,
                              QUIC_RXFC *max_streams_bidi_rxfc,
                              QUIC_RXFC *max_streams_uni_rxfc,
                              int is_server);

/*
 * Any streams still in the map will be released as though
 * ossl_quic_stream_map_release was called on them.
 */
void ossl_quic_stream_map_cleanup(QUIC_STREAM_MAP *qsm);

#define QUIC_STREAM_INITIATOR_CLIENT        0
#define QUIC_STREAM_INITIATOR_SERVER        1
#define QUIC_STREAM_INITIATOR_MASK          1

#define QUIC_STREAM_DIR_BIDI                0
#define QUIC_STREAM_DIR_UNI                 2
#define QUIC_STREAM_DIR_MASK                2

static ossl_inline ossl_unused int ossl_quic_stream_is_server_init(QUIC_STREAM *s)
{
    return (s->type & QUIC_STREAM_INITIATOR_MASK) == QUIC_STREAM_INITIATOR_SERVER;
}

static ossl_inline ossl_unused int ossl_quic_stream_is_bidi(QUIC_STREAM *s)
{
    return (s->type & QUIC_STREAM_DIR_MASK) == QUIC_STREAM_DIR_BIDI;
}

/*
 * Allocate a new stream. type is a combination of one QUIC_STREAM_INITIATOR_*
 * value and one QUIC_STREAM_DIR_* value. Note that clients can e.g. allocate
 * server-initiated streams as they will need to allocate a QUIC_STREAM
 * structure to track any stream created by the server, etc.
 *
 * stream_id must be a valid value. Returns NULL if a stream already exists
 * with the given ID.
 */
QUIC_STREAM *ossl_quic_stream_map_alloc(QUIC_STREAM_MAP *qsm,
                                        uint64_t stream_id,
                                        int type);

/*
 * Releases a stream object. Note that this must only be done once the teardown
 * process is entirely complete and the object will never be referenced again.
 */
void ossl_quic_stream_map_release(QUIC_STREAM_MAP *qsm, QUIC_STREAM *stream);

/*
 * Calls visit_cb() for each stream in the map. visit_cb_arg is an opaque
 * argument which is passed through.
 */
void ossl_quic_stream_map_visit(QUIC_STREAM_MAP *qsm,
                                void (*visit_cb)(QUIC_STREAM *stream, void *arg),
                                void *visit_cb_arg);

/*
 * Retrieves a stream by stream ID. Returns NULL if it does not exist.
 */
QUIC_STREAM *ossl_quic_stream_map_get_by_id(QUIC_STREAM_MAP *qsm,
                                            uint64_t stream_id);

/*
 * Marks the given stream as active or inactive based on its state. Idempotent.
 *
 * When a stream is marked active, it becomes available in the iteration list,
 * and when a stream is marked inactive, it no longer appears in the iteration
 * list.
 *
 * Calling this function invalidates any iterator currently pointing at the
 * given stream object, but iterators not currently pointing at the given stream
 * object are not invalidated.
 */
void ossl_quic_stream_map_update_state(QUIC_STREAM_MAP *qsm, QUIC_STREAM *s);

/*
 * Sets the RR stepping value, n. The RR rotation will be advanced every n
 * packets. The default value is 1.
 */
void ossl_quic_stream_map_set_rr_stepping(QUIC_STREAM_MAP *qsm, size_t stepping);

/*
 * Resets the sending part of a stream.
 *
 * Returns 1 if the sending part of a stream was not already reset.
 * Returns 0 otherwise, which need not be considered an error.
 */
int ossl_quic_stream_map_reset_stream_send_part(QUIC_STREAM_MAP *qsm,
                                                QUIC_STREAM *qs,
                                                uint64_t aec);

/*
 * Marks the receiving part of a stream for STOP_SENDING.
 *
 * Returns  1 if the receiving part of a stream was not already marked for
 * STOP_SENDING.
 * Returns 0 otherwise, which need not be considered an error.
 */
int ossl_quic_stream_map_stop_sending_recv_part(QUIC_STREAM_MAP *qsm,
                                                QUIC_STREAM *qs,
                                                uint64_t aec);

/*
 * Adds a stream to the accept queue.
 */
void ossl_quic_stream_map_push_accept_queue(QUIC_STREAM_MAP *qsm,
                                            QUIC_STREAM *s);

/*
 * Returns the next item to be popped from the accept queue, or NULL if it is
 * empty.
 */
QUIC_STREAM *ossl_quic_stream_map_peek_accept_queue(QUIC_STREAM_MAP *qsm);

/*
 * Removes a stream from the accept queue. rtt is the estimated connection RTT.
 * The stream is retired for the purposes of MAX_STREAMS RXFC.
 *
 * Precondition: s is in the accept queue.
 */
void ossl_quic_stream_map_remove_from_accept_queue(QUIC_STREAM_MAP *qsm,
                                                   QUIC_STREAM *s,
                                                   OSSL_TIME rtt);

/* Returns the length of the accept queue. */
size_t ossl_quic_stream_map_get_accept_queue_len(QUIC_STREAM_MAP *qsm);

/*
 * Delete streams ready for GC. Pointers to those QUIC_STREAM objects become
 * invalid.
 */
void ossl_quic_stream_map_gc(QUIC_STREAM_MAP *qsm);

/*
 * QUIC Stream Iterator
 * ====================
 *
 * Allows the current set of active streams to be walked using a RR-based
 * algorithm. Each time ossl_quic_stream_iter_init is called, the RR algorithm
 * is stepped. The RR algorithm rotates the iteration order such that the next
 * active stream is returned first after n calls to ossl_quic_stream_iter_init,
 * where n is the stepping value configured via
 * ossl_quic_stream_map_set_rr_stepping.
 *
 * Suppose there are three active streams and the configured stepping is n:
 *
 *   Iteration 0n:  [Stream 1] [Stream 2] [Stream 3]
 *   Iteration 1n:  [Stream 2] [Stream 3] [Stream 1]
 *   Iteration 2n:  [Stream 3] [Stream 1] [Stream 2]
 *
 */
typedef struct quic_stream_iter_st {
    QUIC_STREAM_MAP     *qsm;
    QUIC_STREAM         *first_stream, *stream;
} QUIC_STREAM_ITER;

/*
 * Initialise an iterator, advancing the RR algorithm as necessary (if
 * advance_rr is 1). After calling this, it->stream will be the first stream in
 * the iteration sequence, or NULL if there are no active streams.
 */
void ossl_quic_stream_iter_init(QUIC_STREAM_ITER *it, QUIC_STREAM_MAP *qsm,
                                int advance_rr);

/*
 * Advances to next stream in iteration sequence. You do not need to call this
 * immediately after calling ossl_quic_stream_iter_init(). If the end of the
 * list is reached, it->stream will be NULL after calling this.
 */
void ossl_quic_stream_iter_next(QUIC_STREAM_ITER *it);

# endif

#endif
