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

    /* A FIN has been retired from the rstream buffer. */
    unsigned int    recv_fin_retired        : 1;
};

/*
 * Marks a stream for STOP_SENDING. aec is the application error code (AEC).
 * This can only fail if it has already been called.
 */
int ossl_quic_stream_stop_sending(QUIC_STREAM *s, uint64_t aec);

/*
 * Marks a stream for reset. aec is the application error code (AEC).
 * This can only fail if it has already been called.
 */
int ossl_quic_stream_reset(QUIC_STREAM *s, uint64_t aec);

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
    size_t                  rr_stepping, rr_counter;
    QUIC_STREAM             *rr_cur;
    uint64_t                (*get_stream_limit_cb)(int uni, void *arg);
    void                    *get_stream_limit_cb_arg;
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
                              void *get_stream_limit_cb_arg);

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
