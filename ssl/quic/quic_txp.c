/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/quic_txp.h"
#include "internal/quic_fifd.h"
#include "internal/quic_stream_map.h"
#include "internal/common.h"
#include <openssl/err.h>

#define MIN_CRYPTO_HDR_SIZE             3

#define MIN_FRAME_SIZE_HANDSHAKE_DONE   1
#define MIN_FRAME_SIZE_MAX_DATA         2
#define MIN_FRAME_SIZE_ACK              5
#define MIN_FRAME_SIZE_CRYPTO           (MIN_CRYPTO_HDR_SIZE + 1)
#define MIN_FRAME_SIZE_STREAM           3 /* minimum useful size (for non-FIN) */
#define MIN_FRAME_SIZE_MAX_STREAMS_BIDI 2
#define MIN_FRAME_SIZE_MAX_STREAMS_UNI  2

struct ossl_quic_tx_packetiser_st {
    OSSL_QUIC_TX_PACKETISER_ARGS args;

    /*
     * Opaque initial token blob provided by caller. TXP frees using the
     * callback when it is no longer needed.
     */
    const unsigned char             *initial_token;
    size_t                          initial_token_len;
    ossl_quic_initial_token_free_fn *initial_token_free_cb;
    void                            *initial_token_free_cb_arg;

    /* Subcomponents of the TXP that we own. */
    QUIC_FIFD       fifd;       /* QUIC Frame-in-Flight Dispatcher */

    /* Internal state. */
    uint64_t        next_pn[QUIC_PN_SPACE_NUM]; /* Next PN to use in given PN space. */
    OSSL_TIME       last_tx_time;               /* Last time a packet was generated, or 0. */

    /* Internal state - frame (re)generation flags. */
    unsigned int    want_handshake_done     : 1;
    unsigned int    want_max_data           : 1;
    unsigned int    want_max_streams_bidi   : 1;
    unsigned int    want_max_streams_uni    : 1;

    /* Internal state - frame (re)generation flags - per PN space. */
    unsigned int    want_ack                : QUIC_PN_SPACE_NUM;
    unsigned int    force_ack_eliciting     : QUIC_PN_SPACE_NUM;

    /*
     * Internal state - connection close terminal state.
     * Once this is set, it is not unset unlike other want_ flags - we keep
     * sending it in every packet.
     */
    unsigned int    want_conn_close         : 1;

    /* Has the handshake been completed? */
    unsigned int    handshake_complete      : 1;

    OSSL_QUIC_FRAME_CONN_CLOSE  conn_close_frame;

    /* Internal state - packet assembly. */
    unsigned char   *scratch;       /* scratch buffer for packet assembly */
    size_t          scratch_len;    /* number of bytes allocated for scratch */
    OSSL_QTX_IOVEC  *iovec;         /* scratch iovec array for use with QTX */
    size_t          alloc_iovec;    /* size of iovec array */
};

/*
 * The TX helper records state used while generating frames into packets. It
 * enables serialization into the packet to be done "transactionally" where
 * serialization of a frame can be rolled back if it fails midway (e.g. if it
 * does not fit).
 */
struct tx_helper {
    OSSL_QUIC_TX_PACKETISER *txp;
    /*
     * The Maximum Packet Payload Length in bytes. This is the amount of
     * space we have to generate frames into.
     */
    size_t max_ppl;
    /*
     * Number of bytes we have generated so far.
     */
    size_t bytes_appended;
    /*
     * Number of scratch bytes in txp->scratch we have used so far. Some iovecs
     * will reference this scratch buffer. When we need to use more of it (e.g.
     * when we need to put frame headers somewhere), we append to the scratch
     * buffer, resizing if necessary, and increase this accordingly.
     */
    size_t scratch_bytes;
    /*
     * Bytes reserved in the MaxPPL budget. We keep this number of bytes spare
     * until reserve_allowed is set to 1. Currently this is always at most 1, as
     * a PING frame takes up one byte and this mechanism is only used to ensure
     * we can encode a PING frame if we have been asked to ensure a packet is
     * ACK-eliciting and we are unusure if we are going to add any other
     * ACK-eliciting frames before we reach our MaxPPL budget.
     */
    size_t reserve;
    /*
     * Number of iovecs we have currently appended. This is the number of
     * entries valid in txp->iovec.
     */
    size_t num_iovec;
    /*
     * Whether we are allowed to make use of the reserve bytes in our MaxPPL
     * budget. This is used to ensure we have room to append a PING frame later
     * if we need to. Once we know we will not need to append a PING frame, this
     * is set to 1.
     */
    unsigned int reserve_allowed : 1;
    /*
     * Set to 1 if we have appended a STREAM frame with an implicit length. If
     * this happens we should never append another frame after that frame as it
     * cannot be validly encoded. This is just a safety check.
     */
    unsigned int done_implicit : 1;
    struct {
        /*
         * The fields in this structure are valid if active is set, which means
         * that a serialization transaction is currently in progress.
         */
        unsigned char   *data;
        WPACKET         wpkt;
        unsigned int    active : 1;
    } txn;
};

static void tx_helper_rollback(struct tx_helper *h);
static int txp_ensure_iovec(OSSL_QUIC_TX_PACKETISER *txp, size_t num);

/* Initialises the TX helper. */
static int tx_helper_init(struct tx_helper *h, OSSL_QUIC_TX_PACKETISER *txp,
                          size_t max_ppl, size_t reserve)
{
    if (reserve > max_ppl)
        return 0;

    h->txp                  = txp;
    h->max_ppl              = max_ppl;
    h->reserve              = reserve;
    h->num_iovec            = 0;
    h->bytes_appended       = 0;
    h->scratch_bytes        = 0;
    h->reserve_allowed      = 0;
    h->done_implicit        = 0;
    h->txn.data             = NULL;
    h->txn.active           = 0;

    if (max_ppl > h->txp->scratch_len) {
        unsigned char *scratch;

        scratch = OPENSSL_realloc(h->txp->scratch, max_ppl);
        if (scratch == NULL)
            return 0;

        h->txp->scratch     = scratch;
        h->txp->scratch_len = max_ppl;
    }

    return 1;
}

static void tx_helper_cleanup(struct tx_helper *h)
{
    if (h->txn.active)
        tx_helper_rollback(h);

    h->txp = NULL;
}

static void tx_helper_unrestrict(struct tx_helper *h)
{
    h->reserve_allowed = 1;
}

/*
 * Append an extent of memory to the iovec list. The memory must remain
 * allocated until we finish generating the packet and call the QTX.
 *
 * In general, the buffers passed to this function will be from one of two
 * ranges:
 *
 *   - Application data contained in stream buffers managed elsewhere
 *     in the QUIC stack; or
 *
 *   - Control frame data appended into txp->scratch using tx_helper_begin and
 *     tx_helper_commit.
 *
 */
static int tx_helper_append_iovec(struct tx_helper *h,
                                  const unsigned char *buf,
                                  size_t buf_len)
{
    if (buf_len == 0)
        return 1;

    if (!ossl_assert(!h->done_implicit))
        return 0;

    if (!txp_ensure_iovec(h->txp, h->num_iovec + 1))
        return 0;

    h->txp->iovec[h->num_iovec].buf     = buf;
    h->txp->iovec[h->num_iovec].buf_len = buf_len;

    ++h->num_iovec;
    h->bytes_appended += buf_len;
    return 1;
}

/*
 * How many more bytes of space do we have left in our plaintext packet payload?
 */
static size_t tx_helper_get_space_left(struct tx_helper *h)
{
    return h->max_ppl
        - (h->reserve_allowed ? 0 : h->reserve) - h->bytes_appended;
}

/*
 * Begin a control frame serialization transaction. This allows the
 * serialization of the control frame to be backed out if it turns out it won't
 * fit. Write the control frame to the returned WPACKET. Ensure you always
 * call tx_helper_rollback or tx_helper_commit (or tx_helper_cleanup). Returns
 * NULL on failure.
 */
static WPACKET *tx_helper_begin(struct tx_helper *h)
{
    size_t space_left, len;
    unsigned char *data;

    if (!ossl_assert(!h->txn.active))
        return NULL;

    if (!ossl_assert(!h->done_implicit))
        return NULL;

    data = (unsigned char *)h->txp->scratch + h->scratch_bytes;
    len  = h->txp->scratch_len - h->scratch_bytes;

    space_left = tx_helper_get_space_left(h);
    if (!ossl_assert(space_left <= len))
        return NULL;

    if (!WPACKET_init_static_len(&h->txn.wpkt, data, len, 0))
        return NULL;

    if (!WPACKET_set_max_size(&h->txn.wpkt, space_left)) {
        WPACKET_cleanup(&h->txn.wpkt);
        return NULL;
    }

    h->txn.data     = data;
    h->txn.active   = 1;
    return &h->txn.wpkt;
}

static void tx_helper_end(struct tx_helper *h, int success)
{
    if (success)
        WPACKET_finish(&h->txn.wpkt);
    else
        WPACKET_cleanup(&h->txn.wpkt);

    h->txn.active       = 0;
    h->txn.data         = NULL;
}

/* Abort a control frame serialization transaction. */
static void tx_helper_rollback(struct tx_helper *h)
{
    if (!h->txn.active)
        return;

    tx_helper_end(h, 0);
}

/* Commit a control frame. */
static int tx_helper_commit(struct tx_helper *h)
{
    size_t l = 0;

    if (!h->txn.active)
        return 0;

    if (!WPACKET_get_total_written(&h->txn.wpkt, &l)) {
        tx_helper_end(h, 0);
        return 0;
    }

    if (!tx_helper_append_iovec(h, h->txn.data, l)) {
        tx_helper_end(h, 0);
        return 0;
    }

    h->scratch_bytes += l;
    tx_helper_end(h, 1);
    return 1;
}

static QUIC_SSTREAM *get_sstream_by_id(uint64_t stream_id, uint32_t pn_space,
                                       void *arg);
static void on_regen_notify(uint64_t frame_type, uint64_t stream_id,
                            QUIC_TXPIM_PKT *pkt, void *arg);
static int sstream_is_pending(QUIC_SSTREAM *sstream);
static int txp_el_pending(OSSL_QUIC_TX_PACKETISER *txp, uint32_t enc_level,
                          uint32_t archetype,
                          int cc_can_send,
                          uint32_t *conn_close_enc_level);
static int txp_generate_for_el(OSSL_QUIC_TX_PACKETISER *txp, uint32_t enc_level,
                               uint32_t archetype,
                               int cc_can_send,
                               int is_last_in_dgram,
                               int dgram_contains_initial,
                               int chosen_for_conn_close,
                               int *sent_ack_eliciting);
static size_t txp_determine_pn_len(OSSL_QUIC_TX_PACKETISER *txp);
static int txp_determine_ppl_from_pl(OSSL_QUIC_TX_PACKETISER *txp,
                                     size_t pl,
                                     uint32_t enc_level,
                                     size_t hdr_len,
                                     size_t *r);
static size_t txp_get_mdpl(OSSL_QUIC_TX_PACKETISER *txp);
static int txp_generate_for_el_actual(OSSL_QUIC_TX_PACKETISER *txp,
                                      uint32_t enc_level,
                                      uint32_t archetype,
                                      size_t min_ppl,
                                      size_t max_ppl,
                                      size_t pkt_overhead,
                                      QUIC_PKT_HDR *phdr,
                                      int chosen_for_conn_close,
                                      int *sent_ack_eliciting);

OSSL_QUIC_TX_PACKETISER *ossl_quic_tx_packetiser_new(const OSSL_QUIC_TX_PACKETISER_ARGS *args)
{
    OSSL_QUIC_TX_PACKETISER *txp;

    if (args == NULL
        || args->qtx == NULL
        || args->txpim == NULL
        || args->cfq == NULL
        || args->ackm == NULL
        || args->qsm == NULL
        || args->conn_txfc == NULL
        || args->conn_rxfc == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    txp = OPENSSL_zalloc(sizeof(*txp));
    if (txp == NULL)
        return NULL;

    txp->args           = *args;
    txp->last_tx_time   = ossl_time_zero();

    if (!ossl_quic_fifd_init(&txp->fifd,
                             txp->args.cfq, txp->args.ackm, txp->args.txpim,
                             get_sstream_by_id, txp,
                             on_regen_notify, txp)) {
        OPENSSL_free(txp);
        return NULL;
    }

    return txp;
}

void ossl_quic_tx_packetiser_free(OSSL_QUIC_TX_PACKETISER *txp)
{
    if (txp == NULL)
        return;

    ossl_quic_tx_packetiser_set_initial_token(txp, NULL, 0, NULL, NULL);
    ossl_quic_fifd_cleanup(&txp->fifd);
    OPENSSL_free(txp->iovec);
    OPENSSL_free(txp->conn_close_frame.reason);
    OPENSSL_free(txp->scratch);
    OPENSSL_free(txp);
}

void ossl_quic_tx_packetiser_set_initial_token(OSSL_QUIC_TX_PACKETISER *txp,
                                               const unsigned char *token,
                                               size_t token_len,
                                               ossl_quic_initial_token_free_fn *free_cb,
                                               void *free_cb_arg)
{
    if (txp->initial_token != NULL && txp->initial_token_free_cb != NULL)
        txp->initial_token_free_cb(txp->initial_token, txp->initial_token_len,
                                   txp->initial_token_free_cb_arg);

    txp->initial_token              = token;
    txp->initial_token_len          = token_len;
    txp->initial_token_free_cb      = free_cb;
    txp->initial_token_free_cb_arg  = free_cb_arg;
}

int ossl_quic_tx_packetiser_set_cur_dcid(OSSL_QUIC_TX_PACKETISER *txp,
                                         const QUIC_CONN_ID *dcid)
{
    if (dcid == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    txp->args.cur_dcid = *dcid;
    return 1;
}

int ossl_quic_tx_packetiser_set_cur_scid(OSSL_QUIC_TX_PACKETISER *txp,
                                         const QUIC_CONN_ID *scid)
{
    if (scid == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    txp->args.cur_scid = *scid;
    return 1;
}

/* Change the destination L4 address the TXP uses to send datagrams. */
int ossl_quic_tx_packetiser_set_peer(OSSL_QUIC_TX_PACKETISER *txp,
                                     const BIO_ADDR *peer)
{
    if (peer == NULL) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    txp->args.peer = *peer;
    return 1;
}

int ossl_quic_tx_packetiser_discard_enc_level(OSSL_QUIC_TX_PACKETISER *txp,
                                              uint32_t enc_level)
{
    if (enc_level >= QUIC_ENC_LEVEL_NUM) {
        ERR_raise(ERR_LIB_SSL, ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    if (enc_level != QUIC_ENC_LEVEL_0RTT)
        txp->args.crypto[ossl_quic_enc_level_to_pn_space(enc_level)] = NULL;

    return 1;
}

void ossl_quic_tx_packetiser_notify_handshake_complete(OSSL_QUIC_TX_PACKETISER *txp)
{
    txp->handshake_complete = 1;
}

void ossl_quic_tx_packetiser_schedule_handshake_done(OSSL_QUIC_TX_PACKETISER *txp)
{
    txp->want_handshake_done = 1;
}

void ossl_quic_tx_packetiser_schedule_ack_eliciting(OSSL_QUIC_TX_PACKETISER *txp,
                                                    uint32_t pn_space)
{
    txp->force_ack_eliciting |= (1UL << pn_space);
}

#define TXP_ERR_INTERNAL     0  /* Internal (e.g. alloc) error */
#define TXP_ERR_SUCCESS      1  /* Success */
#define TXP_ERR_SPACE        2  /* Not enough room for another packet */
#define TXP_ERR_INPUT        3  /* Invalid/malformed input */

int ossl_quic_tx_packetiser_has_pending(OSSL_QUIC_TX_PACKETISER *txp,
                                        uint32_t archetype,
                                        uint32_t flags)
{
    uint32_t enc_level, conn_close_enc_level = QUIC_ENC_LEVEL_NUM;
    int bypass_cc = ((flags & TX_PACKETISER_BYPASS_CC) != 0);
    int cc_can_send;

    cc_can_send
        = (bypass_cc
           || txp->args.cc_method->get_tx_allowance(txp->args.cc_data) > 0);

    for (enc_level = QUIC_ENC_LEVEL_INITIAL;
         enc_level < QUIC_ENC_LEVEL_NUM;
         ++enc_level)
        if (txp_el_pending(txp, enc_level, archetype, cc_can_send,
                           &conn_close_enc_level))
            return 1;

    return 0;
}

/*
 * Generates a datagram by polling the various ELs to determine if they want to
 * generate any frames, and generating a datagram which coalesces packets for
 * any ELs which do.
 */
int ossl_quic_tx_packetiser_generate(OSSL_QUIC_TX_PACKETISER *txp,
                                     uint32_t archetype,
                                     int *sent_ack_eliciting)
{
    uint32_t enc_level, conn_close_enc_level = QUIC_ENC_LEVEL_NUM;
    int have_pkt_for_el[QUIC_ENC_LEVEL_NUM], is_last_in_dgram, cc_can_send;
    size_t num_el_in_dgram = 0, pkts_done = 0;
    int rc;

    /*
     * If CC says we cannot send we still may be able to send any queued probes.
     */
    cc_can_send = (txp->args.cc_method->get_tx_allowance(txp->args.cc_data) > 0);

    for (enc_level = QUIC_ENC_LEVEL_INITIAL;
         enc_level < QUIC_ENC_LEVEL_NUM;
         ++enc_level) {
        have_pkt_for_el[enc_level] = txp_el_pending(txp, enc_level, archetype,
                                                    cc_can_send,
                                                    &conn_close_enc_level);
        if (have_pkt_for_el[enc_level])
            ++num_el_in_dgram;
    }

    if (num_el_in_dgram == 0)
        return TX_PACKETISER_RES_NO_PKT;

    /*
     * Should not be needed, but a sanity check in case anyone else has been
     * using the QTX.
     */
    ossl_qtx_finish_dgram(txp->args.qtx);

    for (enc_level = QUIC_ENC_LEVEL_INITIAL;
         enc_level < QUIC_ENC_LEVEL_NUM;
         ++enc_level) {
        if (!have_pkt_for_el[enc_level])
            continue;

        is_last_in_dgram = (pkts_done + 1 == num_el_in_dgram);
        rc = txp_generate_for_el(txp, enc_level, archetype, cc_can_send,
                                 is_last_in_dgram,
                                 have_pkt_for_el[QUIC_ENC_LEVEL_INITIAL],
                                 enc_level == conn_close_enc_level,
                                 sent_ack_eliciting);

        if (rc != TXP_ERR_SUCCESS) {
            /*
             * If we already successfully did at least one, make sure we report
             * this via the return code.
             */
            if (pkts_done > 0)
                break;
            else
                return TX_PACKETISER_RES_FAILURE;
        }

        ++pkts_done;
    }

    ossl_qtx_finish_dgram(txp->args.qtx);
    return TX_PACKETISER_RES_SENT_PKT;
}

struct archetype_data {
    unsigned int allow_ack                  : 1;
    unsigned int allow_ping                 : 1;
    unsigned int allow_crypto               : 1;
    unsigned int allow_handshake_done       : 1;
    unsigned int allow_path_challenge       : 1;
    unsigned int allow_path_response        : 1;
    unsigned int allow_new_conn_id          : 1;
    unsigned int allow_retire_conn_id       : 1;
    unsigned int allow_stream_rel           : 1;
    unsigned int allow_conn_fc              : 1;
    unsigned int allow_conn_close           : 1;
    unsigned int allow_cfq_other            : 1;
    unsigned int allow_new_token            : 1;
    unsigned int allow_force_ack_eliciting  : 1;
};

static const struct archetype_data archetypes[QUIC_ENC_LEVEL_NUM][TX_PACKETISER_ARCHETYPE_NUM] = {
    /* EL 0(INITIAL) */
    {
        /* EL 0(INITIAL) - Archetype 0(NORMAL) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 1,
            /*allow_crypto                    =*/ 1,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 1,
            /*allow_cfq_other                 =*/ 1,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 1,
        },
        /* EL 0(INITIAL) - Archetype 1(ACK_ONLY) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 0,
            /*allow_crypto                    =*/ 0,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 0,
            /*allow_cfq_other                 =*/ 0,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 1,
        },
    },
    /* EL 1(HANDSHAKE) */
    {
        /* EL 1(HANDSHAKE) - Archetype 0(NORMAL) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 1,
            /*allow_crypto                    =*/ 1,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 1,
            /*allow_cfq_other                 =*/ 1,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 1,
        },
        /* EL 1(HANDSHAKE) - Archetype 1(ACK_ONLY) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 0,
            /*allow_crypto                    =*/ 0,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 0,
            /*allow_cfq_other                 =*/ 0,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 1,
        },
    },
    /* EL 2(0RTT) */
    {
        /* EL 2(0RTT) - Archetype 0(NORMAL) */
        {
            /*allow_ack                       =*/ 0,
            /*allow_ping                      =*/ 1,
            /*allow_crypto                    =*/ 0,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 1,
            /*allow_retire_conn_id            =*/ 1,
            /*allow_stream_rel                =*/ 1,
            /*allow_conn_fc                   =*/ 1,
            /*allow_conn_close                =*/ 1,
            /*allow_cfq_other                 =*/ 0,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 0,
        },
        /* EL 2(0RTT) - Archetype 1(ACK_ONLY) */
        {
            /*allow_ack                       =*/ 0,
            /*allow_ping                      =*/ 0,
            /*allow_crypto                    =*/ 0,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 0,
            /*allow_cfq_other                 =*/ 0,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 0,
        },
    },
    /* EL 3(1RTT) */
    {
        /* EL 3(1RTT) - Archetype 0(NORMAL) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 1,
            /*allow_crypto                    =*/ 1,
            /*allow_handshake_done            =*/ 1,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 1,
            /*allow_retire_conn_id            =*/ 1,
            /*allow_stream_rel                =*/ 1,
            /*allow_conn_fc                   =*/ 1,
            /*allow_conn_close                =*/ 1,
            /*allow_cfq_other                 =*/ 1,
            /*allow_new_token                 =*/ 1,
            /*allow_force_ack_eliciting       =*/ 1,
        },
        /* EL 3(1RTT) - Archetype 1(ACK_ONLY) */
        {
            /*allow_ack                       =*/ 1,
            /*allow_ping                      =*/ 0,
            /*allow_crypto                    =*/ 0,
            /*allow_handshake_done            =*/ 0,
            /*allow_path_challenge            =*/ 0,
            /*allow_path_response             =*/ 0,
            /*allow_new_conn_id               =*/ 0,
            /*allow_retire_conn_id            =*/ 0,
            /*allow_stream_rel                =*/ 0,
            /*allow_conn_fc                   =*/ 0,
            /*allow_conn_close                =*/ 0,
            /*allow_cfq_other                 =*/ 0,
            /*allow_new_token                 =*/ 0,
            /*allow_force_ack_eliciting       =*/ 1,
        }
    }
};

static int txp_get_archetype_data(uint32_t enc_level,
                                  uint32_t archetype,
                                  struct archetype_data *a)
{
    if (enc_level >= QUIC_ENC_LEVEL_NUM
        || archetype >= TX_PACKETISER_ARCHETYPE_NUM)
        return 0;

    /* No need to avoid copying this as it should not exceed one int in size. */
    *a = archetypes[enc_level][archetype];
    return 1;
}

/*
 * Returns 1 if the given EL wants to produce one or more frames.
 * Always returns 0 if the given EL is discarded.
 */
static int txp_el_pending(OSSL_QUIC_TX_PACKETISER *txp, uint32_t enc_level,
                          uint32_t archetype,
                          int cc_can_send,
                          uint32_t *conn_close_enc_level)
{
    struct archetype_data a;
    uint32_t pn_space = ossl_quic_enc_level_to_pn_space(enc_level);
    QUIC_CFQ_ITEM *cfq_item;

    if (!ossl_qtx_is_enc_level_provisioned(txp->args.qtx, enc_level))
        return 0;

    if (*conn_close_enc_level > enc_level)
        *conn_close_enc_level = enc_level;

    if (!txp_get_archetype_data(enc_level, archetype, &a))
        return 0;

    /* Do we need to send a PTO probe? */
    if (a.allow_force_ack_eliciting) {
        OSSL_ACKM_PROBE_INFO *probe_info
            = ossl_ackm_get0_probe_request(txp->args.ackm);

        if ((enc_level == QUIC_ENC_LEVEL_INITIAL
             && probe_info->anti_deadlock_initial > 0)
            || (enc_level == QUIC_ENC_LEVEL_HANDSHAKE
                && probe_info->anti_deadlock_handshake > 0)
            || probe_info->pto[pn_space] > 0)
            return 1;
    }

    if (!cc_can_send)
        /* If CC says we cannot currently send, we can only send probes. */
        return 0;

    /* Does the crypto stream for this EL want to produce anything? */
    if (a.allow_crypto && sstream_is_pending(txp->args.crypto[pn_space]))
        return 1;

    /* Does the ACKM for this PN space want to produce anything? */
    if (a.allow_ack && (ossl_ackm_is_ack_desired(txp->args.ackm, pn_space)
                        || (txp->want_ack & (1UL << pn_space)) != 0))
        return 1;

    /* Do we need to force emission of an ACK-eliciting packet? */
    if (a.allow_force_ack_eliciting
        && (txp->force_ack_eliciting & (1UL << pn_space)) != 0)
        return 1;

    /* Does the connection-level RXFC want to produce a frame? */
    if (a.allow_conn_fc && (txp->want_max_data
        || ossl_quic_rxfc_has_cwm_changed(txp->args.conn_rxfc, 0)))
        return 1;

    /* Do we want to produce a MAX_STREAMS frame? */
    if (a.allow_conn_fc && (txp->want_max_streams_bidi
                            || txp->want_max_streams_uni))
        return 1;

    /* Do we want to produce a HANDSHAKE_DONE frame? */
    if (a.allow_handshake_done && txp->want_handshake_done)
        return 1;

    /* Do we want to produce a CONNECTION_CLOSE frame? */
    if (a.allow_conn_close && txp->want_conn_close &&
        *conn_close_enc_level == enc_level)
        /*
         * This is a bit of a special case since CONNECTION_CLOSE can appear in
         * most packet types, and when we decide we want to send it this status
         * isn't tied to a specific EL. So if we want to send it, we send it
         * only on the lowest non-dropped EL.
         */
        return 1;

    /* Does the CFQ have any frames queued for this PN space? */
    if (enc_level != QUIC_ENC_LEVEL_0RTT)
        for (cfq_item = ossl_quic_cfq_get_priority_head(txp->args.cfq, pn_space);
             cfq_item != NULL;
             cfq_item = ossl_quic_cfq_item_get_priority_next(cfq_item, pn_space)) {
            uint64_t frame_type = ossl_quic_cfq_item_get_frame_type(cfq_item);

            switch (frame_type) {
            case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
                if (a.allow_new_conn_id)
                    return 1;
                break;
            case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
                if (a.allow_retire_conn_id)
                    return 1;
                break;
            case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
                if (a.allow_new_token)
                    return 1;
                break;
            default:
                if (a.allow_cfq_other)
                    return 1;
                break;
            }
       }

    if (a.allow_stream_rel && txp->handshake_complete) {
        QUIC_STREAM_ITER it;

        /* If there are any active streams, 0/1-RTT wants to produce a packet.
         * Whether a stream is on the active list is required to be precise
         * (i.e., a stream is never on the active list if we cannot produce a
         * frame for it), and all stream-related frames are governed by
         * a.allow_stream_rel (i.e., if we can send one type of stream-related
         * frame, we can send any of them), so we don't need to inspect
         * individual streams on the active list, just confirm that the active
         * list is non-empty.
         */
        ossl_quic_stream_iter_init(&it, txp->args.qsm, 0);
        if (it.stream != NULL)
            return 1;
    }

    return 0;
}

static int sstream_is_pending(QUIC_SSTREAM *sstream)
{
    OSSL_QUIC_FRAME_STREAM hdr;
    OSSL_QTX_IOVEC iov[2];
    size_t num_iov = OSSL_NELEM(iov);

    return ossl_quic_sstream_get_stream_frame(sstream, 0, &hdr, iov, &num_iov);
}

/*
 * Generates a packet for a given EL, coalescing it into the current datagram.
 *
 * is_last_in_dgram and dgram_contains_initial are used to determine padding
 * requirements.
 *
 * Returns TXP_ERR_* value.
 */
static int txp_generate_for_el(OSSL_QUIC_TX_PACKETISER *txp, uint32_t enc_level,
                               uint32_t archetype,
                               int cc_can_send,
                               int is_last_in_dgram,
                               int dgram_contains_initial,
                               int chosen_for_conn_close,
                               int *sent_ack_eliciting)
{
    int must_pad = dgram_contains_initial && is_last_in_dgram;
    size_t min_dpl, min_pl, min_ppl, cmpl, cmppl, running_total;
    size_t mdpl, hdr_len, pkt_overhead, cc_limit;
    uint64_t cc_limit_;
    QUIC_PKT_HDR phdr;

    /* Determine the limit CC imposes on what we can send. */
    if (!cc_can_send) {
        /*
         * If we are called when we cannot send, this must be because we want
         * to generate a probe. In this circumstance, don't clamp based on CC.
         */
        cc_limit = SIZE_MAX;
    } else {
        /* Allow CC to clamp how much we can send. */
        cc_limit_ = txp->args.cc_method->get_tx_allowance(txp->args.cc_data);
        cc_limit = (cc_limit_ > SIZE_MAX ? SIZE_MAX : (size_t)cc_limit_);
    }

    /* Assemble packet header. */
    phdr.type           = ossl_quic_enc_level_to_pkt_type(enc_level);
    phdr.spin_bit       = 0;
    phdr.pn_len         = txp_determine_pn_len(txp);
    phdr.partial        = 0;
    phdr.fixed          = 1;
    phdr.version        = QUIC_VERSION_1;
    phdr.dst_conn_id    = txp->args.cur_dcid;
    phdr.src_conn_id    = txp->args.cur_scid;

    /*
     * We need to know the length of the payload to get an accurate header
     * length for non-1RTT packets, because the Length field found in
     * Initial/Handshake/0-RTT packets uses a variable-length encoding. However,
     * we don't have a good idea of the length of our payload, because the
     * length of the payload depends on the room in the datagram after fitting
     * the header, which depends on the size of the header.
     *
     * In general, it does not matter if a packet is slightly shorter (because
     * e.g. we predicted use of a 2-byte length field, but ended up only needing
     * a 1-byte length field). However this does matter for Initial packets
     * which must be at least 1200 bytes, which is also the assumed default MTU;
     * therefore in many cases Initial packets will be padded to 1200 bytes,
     * which means if we overestimated the header size, we will be short by a
     * few bytes and the server will ignore the packet for being too short. In
     * this case, however, such packets always *will* be padded to meet 1200
     * bytes, which requires a 2-byte length field, so we don't actually need to
     * worry about this. Thus we estimate the header length assuming a 2-byte
     * length field here, which should in practice work well in all cases.
     */
    phdr.len            = OSSL_QUIC_VLINT_2B_MAX - phdr.pn_len;

    if (enc_level == QUIC_ENC_LEVEL_INITIAL) {
        phdr.token      = txp->initial_token;
        phdr.token_len  = txp->initial_token_len;
    } else {
        phdr.token      = NULL;
        phdr.token_len  = 0;
    }

    hdr_len = ossl_quic_wire_get_encoded_pkt_hdr_len(phdr.dst_conn_id.id_len,
                                                     &phdr);
    if (hdr_len == 0)
        return TXP_ERR_INPUT;

    /* MinDPL: Minimum total datagram payload length. */
    min_dpl = must_pad ? QUIC_MIN_INITIAL_DGRAM_LEN : 0;

    /* How much data is already in the current datagram? */
    running_total = ossl_qtx_get_cur_dgram_len_bytes(txp->args.qtx);

    /* MinPL: Minimum length of the fully encoded packet. */
    min_pl = running_total < min_dpl ? min_dpl - running_total : 0;
    if ((uint64_t)min_pl > cc_limit)
        /*
         * Congestion control does not allow us to send a packet of adequate
         * size.
         */
        return TXP_ERR_SPACE;

    /* MinPPL: Minimum plaintext payload length needed to meet MinPL. */
    if (!txp_determine_ppl_from_pl(txp, min_pl, enc_level, hdr_len, &min_ppl))
        /* MinPL is less than a valid packet size, so just use a MinPPL of 0. */
        min_ppl = 0;

    /* MDPL: Maximum datagram payload length. */
    mdpl = txp_get_mdpl(txp);

    /*
     * CMPL: Maximum encoded packet size we can put into this datagram given any
     * previous packets coalesced into it.
     */
    if (running_total > mdpl)
        /* Should not be possible, but if it happens: */
        cmpl = 0;
    else
        cmpl = mdpl - running_total;

    /* Clamp CMPL based on congestion control limit. */
    if (cmpl > cc_limit)
        cmpl = cc_limit;

    /* CMPPL: Maximum amount we can put into the current datagram payload. */
    if (!txp_determine_ppl_from_pl(txp, cmpl, enc_level, hdr_len, &cmppl))
        return TXP_ERR_SPACE;

    /* Packet overhead (size of headers, AEAD tag, etc.) */
    pkt_overhead = cmpl - cmppl;

    return txp_generate_for_el_actual(txp, enc_level, archetype, min_ppl, cmppl,
                                      pkt_overhead, &phdr,
                                      chosen_for_conn_close,
                                      sent_ack_eliciting);
}

/* Determine how many bytes we should use for the encoded PN. */
static size_t txp_determine_pn_len(OSSL_QUIC_TX_PACKETISER *txp)
{
    return 4; /* TODO(QUIC) */
}

/* Determine plaintext packet payload length from payload length. */
static int txp_determine_ppl_from_pl(OSSL_QUIC_TX_PACKETISER *txp,
                                     size_t pl,
                                     uint32_t enc_level,
                                     size_t hdr_len,
                                     size_t *r)
{
    if (pl < hdr_len)
        return 0;

    pl -= hdr_len;

    if (!ossl_qtx_calculate_plaintext_payload_len(txp->args.qtx, enc_level,
                                                  pl, &pl))
        return 0;

    *r = pl;
    return 1;
}

static size_t txp_get_mdpl(OSSL_QUIC_TX_PACKETISER *txp)
{
    return ossl_qtx_get_mdpl(txp->args.qtx);
}

static QUIC_SSTREAM *get_sstream_by_id(uint64_t stream_id, uint32_t pn_space,
                                       void *arg)
{
    OSSL_QUIC_TX_PACKETISER *txp = arg;
    QUIC_STREAM *s;

    if (stream_id == UINT64_MAX)
        return txp->args.crypto[pn_space];

    s = ossl_quic_stream_map_get_by_id(txp->args.qsm, stream_id);
    if (s == NULL)
        return NULL;

    return s->sstream;
}

static void on_regen_notify(uint64_t frame_type, uint64_t stream_id,
                            QUIC_TXPIM_PKT *pkt, void *arg)
{
    OSSL_QUIC_TX_PACKETISER *txp = arg;

    switch (frame_type) {
        case OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE:
            txp->want_handshake_done = 1;
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
            txp->want_max_data = 1;
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
            txp->want_max_streams_bidi = 1;
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
            txp->want_max_streams_uni = 1;
            break;
        case OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN:
            txp->want_ack |= (1UL << pkt->ackm_pkt.pkt_space);
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
            {
                QUIC_STREAM *s
                    = ossl_quic_stream_map_get_by_id(txp->args.qsm, stream_id);

                if (s == NULL)
                    return;

                s->want_max_stream_data = 1;
                ossl_quic_stream_map_update_state(txp->args.qsm, s);
            }
            break;
        case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
            {
                QUIC_STREAM *s
                    = ossl_quic_stream_map_get_by_id(txp->args.qsm, stream_id);

                if (s == NULL)
                    return;

                s->want_stop_sending = 1;
                ossl_quic_stream_map_update_state(txp->args.qsm, s);
            }
            break;
        case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
            {
                QUIC_STREAM *s
                    = ossl_quic_stream_map_get_by_id(txp->args.qsm, stream_id);

                if (s == NULL)
                    return;

                s->want_reset_stream = 1;
                ossl_quic_stream_map_update_state(txp->args.qsm, s);
            }
            break;
        default:
            assert(0);
            break;
    }
}

static int txp_generate_pre_token(OSSL_QUIC_TX_PACKETISER *txp,
                                  struct tx_helper *h,
                                  QUIC_TXPIM_PKT *tpkt,
                                  uint32_t pn_space,
                                  struct archetype_data *a,
                                  int chosen_for_conn_close)
{
    const OSSL_QUIC_FRAME_ACK *ack;
    OSSL_QUIC_FRAME_ACK ack2;

    tpkt->ackm_pkt.largest_acked = QUIC_PN_INVALID;

    /* ACK Frames (Regenerate) */
    if (a->allow_ack
        && tx_helper_get_space_left(h) >= MIN_FRAME_SIZE_ACK
        && (txp->want_ack
            || ossl_ackm_is_ack_desired(txp->args.ackm, pn_space))
        && (ack = ossl_ackm_get_ack_frame(txp->args.ackm, pn_space)) != NULL) {
        WPACKET *wpkt = tx_helper_begin(h);

        if (wpkt == NULL)
            return 0;

        /* We do not currently support ECN */
        ack2 = *ack;
        ack2.ecn_present = 0;

        if (ossl_quic_wire_encode_frame_ack(wpkt,
                                            txp->args.ack_delay_exponent,
                                            &ack2)) {
            if (!tx_helper_commit(h))
                return 0;

            tpkt->had_ack_frame = 1;

            if (ack->num_ack_ranges > 0)
                tpkt->ackm_pkt.largest_acked = ack->ack_ranges[0].end;
        } else {
            tx_helper_rollback(h);
        }
    }

    /* CONNECTION_CLOSE Frames (Regenerate) */
    if (a->allow_conn_close && txp->want_conn_close && chosen_for_conn_close) {
        WPACKET *wpkt = tx_helper_begin(h);

        if (wpkt == NULL)
            return 0;

        if (ossl_quic_wire_encode_frame_conn_close(wpkt,
                                                   &txp->conn_close_frame)) {
            if (!tx_helper_commit(h))
                return 0;
        } else {
            tx_helper_rollback(h);
        }
    }

    return 1;
}

static int try_len(size_t space_left, size_t orig_len,
                   size_t base_hdr_len, size_t lenbytes,
                   uint64_t maxn, size_t *hdr_len, size_t *payload_len)
{
    size_t n;
    size_t maxn_ = maxn > SIZE_MAX ? SIZE_MAX : (size_t)maxn;

    *hdr_len = base_hdr_len + lenbytes;

    if (orig_len == 0 && space_left >= *hdr_len) {
        *payload_len = 0;
        return 1;
    }

    n = orig_len;
    if (n > maxn_)
        n = maxn_;
    if (n + *hdr_len > space_left)
        n = (space_left >= *hdr_len) ? space_left - *hdr_len : 0;

    *payload_len = n;
    return n > 0;
}

static int determine_len(size_t space_left, size_t orig_len,
                         size_t base_hdr_len,
                         uint64_t *hlen, uint64_t *len)
{
    int ok = 0;
    size_t chosen_payload_len = 0;
    size_t chosen_hdr_len     = 0;
    size_t payload_len[4], hdr_len[4];
    int i, valid[4] = {0};

    valid[0] = try_len(space_left, orig_len, base_hdr_len,
                       1, OSSL_QUIC_VLINT_1B_MAX,
                       &hdr_len[0], &payload_len[0]);
    valid[1] = try_len(space_left, orig_len, base_hdr_len,
                       2, OSSL_QUIC_VLINT_2B_MAX,
                       &hdr_len[1], &payload_len[1]);
    valid[2] = try_len(space_left, orig_len, base_hdr_len,
                       4, OSSL_QUIC_VLINT_4B_MAX,
                       &hdr_len[2], &payload_len[2]);
    valid[3] = try_len(space_left, orig_len, base_hdr_len,
                       8, OSSL_QUIC_VLINT_8B_MAX,
                       &hdr_len[3], &payload_len[3]);

   for (i = OSSL_NELEM(valid) - 1; i >= 0; --i)
        if (valid[i] && payload_len[i] >= chosen_payload_len) {
            chosen_payload_len = payload_len[i];
            chosen_hdr_len     = hdr_len[i];
            ok                 = 1;
        }

    *hlen = chosen_hdr_len;
    *len  = chosen_payload_len;
    return ok;
}

/*
 * Given a CRYPTO frame header with accurate chdr->len and a budget
 * (space_left), try to find the optimal value of chdr->len to fill as much of
 * the budget as possible. This is slightly hairy because larger values of
 * chdr->len cause larger encoded sizes of the length field of the frame, which
 * in turn mean less space available for payload data. We check all possible
 * encodings and choose the optimal encoding.
 */
static int determine_crypto_len(struct tx_helper *h,
                                OSSL_QUIC_FRAME_CRYPTO *chdr,
                                size_t space_left,
                                uint64_t *hlen,
                                uint64_t *len)
{
    size_t orig_len;
    size_t base_hdr_len; /* CRYPTO header length without length field */

    if (chdr->len > SIZE_MAX)
        return 0;

    orig_len = (size_t)chdr->len;

    chdr->len = 0;
    base_hdr_len = ossl_quic_wire_get_encoded_frame_len_crypto_hdr(chdr);
    chdr->len = orig_len;
    if (base_hdr_len == 0)
        return 0;

    --base_hdr_len;

    return determine_len(space_left, orig_len, base_hdr_len, hlen, len);
}

static int determine_stream_len(struct tx_helper *h,
                                OSSL_QUIC_FRAME_STREAM *shdr,
                                size_t space_left,
                                uint64_t *hlen,
                                uint64_t *len)
{
    size_t orig_len;
    size_t base_hdr_len; /* STREAM header length without length field */

    if (shdr->len > SIZE_MAX)
        return 0;

    orig_len = (size_t)shdr->len;

    shdr->len = 0;
    base_hdr_len = ossl_quic_wire_get_encoded_frame_len_stream_hdr(shdr);
    shdr->len = orig_len;
    if (base_hdr_len == 0)
        return 0;

    if (shdr->has_explicit_len)
        --base_hdr_len;

    return determine_len(space_left, orig_len, base_hdr_len, hlen, len);
}

static int txp_generate_crypto_frames(OSSL_QUIC_TX_PACKETISER *txp,
                                      struct tx_helper *h,
                                      uint32_t pn_space,
                                      QUIC_TXPIM_PKT *tpkt,
                                      int *have_ack_eliciting)
{
    size_t num_stream_iovec;
    OSSL_QUIC_FRAME_STREAM shdr = {0};
    OSSL_QUIC_FRAME_CRYPTO chdr = {0};
    OSSL_QTX_IOVEC iov[2];
    uint64_t hdr_bytes;
    WPACKET *wpkt;
    QUIC_TXPIM_CHUNK chunk = {0};
    size_t i, space_left;

    for (i = 0;; ++i) {
        space_left = tx_helper_get_space_left(h);

        if (space_left < MIN_FRAME_SIZE_CRYPTO)
            return 1; /* no point trying */

        /* Do we have any CRYPTO data waiting? */
        num_stream_iovec = OSSL_NELEM(iov);
        if (!ossl_quic_sstream_get_stream_frame(txp->args.crypto[pn_space],
                                                i, &shdr, iov,
                                                &num_stream_iovec))
            return 1; /* nothing to do */

        /* Convert STREAM frame header to CRYPTO frame header */
        chdr.offset = shdr.offset;
        chdr.len    = shdr.len;

        if (chdr.len == 0)
            return 1; /* nothing to do */

        /* Find best fit (header length, payload length) combination. */
        if (!determine_crypto_len(h, &chdr, space_left, &hdr_bytes,
                                  &chdr.len))
            return 1; /* can't fit anything */

        /*
         * Truncate IOVs to match our chosen length.
         *
         * The length cannot be more than SIZE_MAX because this length comes
         * from our send stream buffer.
         */
        ossl_quic_sstream_adjust_iov((size_t)chdr.len, iov, num_stream_iovec);

        /*
         * Ensure we have enough iovecs allocated (1 for the header, up to 2 for
         * the the stream data.)
         */
        if (!txp_ensure_iovec(txp, h->num_iovec + 3))
            return 0; /* alloc error */

        /* Encode the header. */
        wpkt = tx_helper_begin(h);
        if (wpkt == NULL)
            return 0; /* alloc error */

        if (!ossl_quic_wire_encode_frame_crypto_hdr(wpkt, &chdr)) {
            tx_helper_rollback(h);
            return 1; /* can't fit */
        }

        if (!tx_helper_commit(h))
            return 0; /* alloc error */

        /* Add payload iovecs to the helper (infallible). */
        for (i = 0; i < num_stream_iovec; ++i)
            tx_helper_append_iovec(h, iov[i].buf, iov[i].buf_len);

        *have_ack_eliciting = 1;
        tx_helper_unrestrict(h); /* no longer need PING */

        /* Log chunk to TXPIM. */
        chunk.stream_id = UINT64_MAX; /* crypto stream */
        chunk.start     = chdr.offset;
        chunk.end       = chdr.offset + chdr.len - 1;
        chunk.has_fin   = 0; /* Crypto stream never ends */
        if (!ossl_quic_txpim_pkt_append_chunk(tpkt, &chunk))
            return 0; /* alloc error */
    }
}

struct chunk_info {
    OSSL_QUIC_FRAME_STREAM shdr;
    OSSL_QTX_IOVEC iov[2];
    size_t num_stream_iovec;
    int valid;
};

static int txp_plan_stream_chunk(OSSL_QUIC_TX_PACKETISER *txp,
                                 struct tx_helper *h,
                                 QUIC_SSTREAM *sstream,
                                 QUIC_TXFC *stream_txfc,
                                 size_t skip,
                                 struct chunk_info *chunk)
{
    uint64_t fc_credit, fc_swm, fc_limit;

    chunk->num_stream_iovec = OSSL_NELEM(chunk->iov);
    chunk->valid = ossl_quic_sstream_get_stream_frame(sstream, skip,
                                                      &chunk->shdr,
                                                      chunk->iov,
                                                      &chunk->num_stream_iovec);
    if (!chunk->valid)
        return 1;

    if (!ossl_assert(chunk->shdr.len > 0 || chunk->shdr.is_fin))
        /* Should only have 0-length chunk if FIN */
        return 0;

    /* Clamp according to connection and stream-level TXFC. */
    fc_credit   = ossl_quic_txfc_get_credit(stream_txfc);
    fc_swm      = ossl_quic_txfc_get_swm(stream_txfc);
    fc_limit    = fc_swm + fc_credit;

    if (chunk->shdr.len > 0 && chunk->shdr.offset + chunk->shdr.len > fc_limit) {
        chunk->shdr.len = (fc_limit <= chunk->shdr.offset)
            ? 0 : fc_limit - chunk->shdr.offset;
        chunk->shdr.is_fin = 0;
    }

    if (chunk->shdr.len == 0 && !chunk->shdr.is_fin) {
        /*
         * Nothing to do due to TXFC. Since SSTREAM returns chunks in ascending
         * order of offset we don't need to check any later chunks, so stop
         * iterating here.
         */
        chunk->valid = 0;
        return 1;
    }

    return 1;
}

/*
 * Returns 0 on fatal error (e.g. allocation failure), 1 on success.
 * *packet_full is set to 1 if there is no longer enough room for another STREAM
 * frame, and *stream_drained is set to 1 if all stream buffers have now been
 * sent.
 */
static int txp_generate_stream_frames(OSSL_QUIC_TX_PACKETISER *txp,
                                      struct tx_helper *h,
                                      uint32_t pn_space,
                                      QUIC_TXPIM_PKT *tpkt,
                                      uint64_t id,
                                      QUIC_SSTREAM *sstream,
                                      QUIC_TXFC *stream_txfc,
                                      QUIC_STREAM *next_stream,
                                      size_t min_ppl,
                                      int *have_ack_eliciting,
                                      int *packet_full,
                                      int *stream_drained,
                                      uint64_t *new_credit_consumed)
{
    int rc = 0;
    struct chunk_info chunks[2] = {0};

    OSSL_QUIC_FRAME_STREAM *shdr;
    WPACKET *wpkt;
    QUIC_TXPIM_CHUNK chunk;
    size_t i, j, space_left;
    int needs_padding_if_implicit, can_fill_payload, use_explicit_len;
    int could_have_following_chunk;
    uint64_t orig_len;
    uint64_t hdr_len_implicit, payload_len_implicit;
    uint64_t hdr_len_explicit, payload_len_explicit;
    uint64_t fc_swm, fc_new_hwm;

    fc_swm      = ossl_quic_txfc_get_swm(stream_txfc);
    fc_new_hwm  = fc_swm;

    /*
     * Load the first two chunks if any offered by the send stream. We retrieve
     * the next chunk in advance so we can determine if we need to send any more
     * chunks from the same stream after this one, which is needed when
     * determining when we can use an implicit length in a STREAM frame.
     */
    for (i = 0; i < 2; ++i) {
        if (!txp_plan_stream_chunk(txp, h, sstream, stream_txfc, i, &chunks[i]))
            goto err;

        if (i == 0 && !chunks[i].valid) {
            /* No chunks, nothing to do. */
            *stream_drained = 1;
            rc = 1;
            goto err;
        }
    }

    for (i = 0;; ++i) {
        space_left = tx_helper_get_space_left(h);

        if (!chunks[i % 2].valid) {
            /* Out of chunks; we're done. */
            *stream_drained = 1;
            rc = 1;
            goto err;
        }

        if (space_left < MIN_FRAME_SIZE_STREAM) {
            *packet_full = 1;
            rc = 1;
            goto err;
        }

        if (!ossl_assert(!h->done_implicit))
            /*
             * Logic below should have ensured we didn't append an
             * implicit-length unless we filled the packet or didn't have
             * another stream to handle, so this should not be possible.
             */
            goto err;

        shdr = &chunks[i % 2].shdr;
        orig_len = shdr->len;
        if (i > 0)
            /* Load next chunk for lookahead. */
            if (!txp_plan_stream_chunk(txp, h, sstream, stream_txfc, i + 1,
                                       &chunks[(i + 1) % 2]))
                goto err;

        /*
         * Find best fit (header length, payload length) combination for if we
         * use an implicit length.
         */
        shdr->has_explicit_len = 0;
        hdr_len_implicit = payload_len_implicit = 0;
        if (!determine_stream_len(h, shdr, space_left,
                                  &hdr_len_implicit, &payload_len_implicit)) {
            *packet_full = 1;
            rc = 1;
            goto err; /* can't fit anything */
        }

        /*
         * If using the implicit-length representation would need padding, we
         * can't use it.
         */
        needs_padding_if_implicit = (h->bytes_appended + hdr_len_implicit
                                     + payload_len_implicit < min_ppl);

        /*
         * If there is a next stream, we don't use the implicit length so we can
         * add more STREAM frames after this one, unless there is enough data
         * for this STREAM frame to fill the packet.
         */
        can_fill_payload = (hdr_len_implicit + payload_len_implicit
                            >= space_left);

        /*
         * Is there is a stream after this one, or another chunk pending
         * transmission in this stream?
         */
        could_have_following_chunk
            = (next_stream != NULL || chunks[(i + 1) % 2].valid);

        /* Choose between explicit or implicit length representations. */
        use_explicit_len = !((can_fill_payload || !could_have_following_chunk)
                             && !needs_padding_if_implicit);

        if (use_explicit_len) {
            /*
             * Find best fit (header length, payload length) combination for if
             * we use an explicit length.
             */
            shdr->has_explicit_len = 1;
            hdr_len_explicit = payload_len_explicit = 0;
            if (!determine_stream_len(h, shdr, space_left,
                                      &hdr_len_explicit, &payload_len_explicit)) {
                *packet_full = 1;
                rc = 1;
                goto err; /* can't fit anything */
            }

            shdr->len = payload_len_explicit;
        } else {
            shdr->has_explicit_len = 0;
            shdr->len = payload_len_implicit;
        }

        /* If this is a FIN, don't keep filling the packet with more FINs. */
        if (shdr->is_fin)
            chunks[(i + 1) % 2].valid = 0;

        /* Truncate IOVs to match our chosen length. */
        ossl_quic_sstream_adjust_iov((size_t)shdr->len, chunks[i % 2].iov,
                                     chunks[i % 2].num_stream_iovec);

        /*
         * Ensure we have enough iovecs allocated (1 for the header, up to 2 for
         * the the stream data.)
         */
        if (!txp_ensure_iovec(txp, h->num_iovec + 3))
            goto err; /* alloc error */

        /* Encode the header. */
        wpkt = tx_helper_begin(h);
        if (wpkt == NULL)
            goto err; /* alloc error */

        shdr->stream_id = id;
        if (!ossl_assert(ossl_quic_wire_encode_frame_stream_hdr(wpkt, shdr))) {
            /* (Should not be possible.) */
            tx_helper_rollback(h);
            *packet_full = 1;
            rc = 1;
            goto err; /* can't fit */
        }

        if (!tx_helper_commit(h))
            goto err; /* alloc error */

        /* Add payload iovecs to the helper (infallible). */
        for (j = 0; j < chunks[i % 2].num_stream_iovec; ++j)
            tx_helper_append_iovec(h, chunks[i % 2].iov[j].buf,
                                   chunks[i % 2].iov[j].buf_len);

        *have_ack_eliciting = 1;
        tx_helper_unrestrict(h); /* no longer need PING */
        if (!shdr->has_explicit_len)
            h->done_implicit = 1;

        /* Log new TXFC credit which was consumed. */
        if (shdr->len > 0 && shdr->offset + shdr->len > fc_new_hwm)
            fc_new_hwm = shdr->offset + shdr->len;

        /* Log chunk to TXPIM. */
        chunk.stream_id         = shdr->stream_id;
        chunk.start             = shdr->offset;
        chunk.end               = shdr->offset + shdr->len - 1;
        chunk.has_fin           = shdr->is_fin;
        chunk.has_stop_sending  = 0;
        chunk.has_reset_stream  = 0;
        if (!ossl_quic_txpim_pkt_append_chunk(tpkt, &chunk))
            goto err; /* alloc error */

        if (shdr->len < orig_len) {
            /*
             * If we did not serialize all of this chunk we definitely do not
             * want to try the next chunk (and we must not mark the stream
             * as drained).
             */
            rc = 1;
            goto err;
        }
    }

err:
    *new_credit_consumed = fc_new_hwm - fc_swm;
    return rc;
}

static void txp_enlink_tmp(QUIC_STREAM **tmp_head, QUIC_STREAM *stream)
{
    stream->txp_next = *tmp_head;
    *tmp_head = stream;
}

static int txp_generate_stream_related(OSSL_QUIC_TX_PACKETISER *txp,
                                       struct tx_helper *h,
                                       uint32_t pn_space,
                                       QUIC_TXPIM_PKT *tpkt,
                                       size_t min_ppl,
                                       int *have_ack_eliciting,
                                       QUIC_STREAM **tmp_head)
{
    QUIC_STREAM_ITER it;
    void *rstream;
    WPACKET *wpkt;
    uint64_t cwm;
    QUIC_STREAM *stream, *snext;

    for (ossl_quic_stream_iter_init(&it, txp->args.qsm, 1);
         it.stream != NULL;) {

        stream = it.stream;
        ossl_quic_stream_iter_next(&it);
        snext = it.stream;

        stream->txp_sent_fc                  = 0;
        stream->txp_sent_stop_sending        = 0;
        stream->txp_sent_reset_stream        = 0;
        stream->txp_drained                  = 0;
        stream->txp_blocked                  = 0;
        stream->txp_txfc_new_credit_consumed = 0;

        rstream = stream->rstream;

        /* Stream Abort Frames (STOP_SENDING, RESET_STREAM) */
        if (stream->want_stop_sending) {
            OSSL_QUIC_FRAME_STOP_SENDING f;

            wpkt = tx_helper_begin(h);
            if (wpkt == NULL)
                return 0; /* alloc error */

            f.stream_id         = stream->id;
            f.app_error_code    = stream->stop_sending_aec;
            if (!ossl_quic_wire_encode_frame_stop_sending(wpkt, &f)) {
                tx_helper_rollback(h); /* can't fit */
                txp_enlink_tmp(tmp_head, stream);
                break;
            }

            if (!tx_helper_commit(h))
                return 0; /* alloc error */

            *have_ack_eliciting = 1;
            tx_helper_unrestrict(h); /* no longer need PING */
            stream->txp_sent_stop_sending = 1;
        }

        if (stream->want_reset_stream) {
            OSSL_QUIC_FRAME_RESET_STREAM f;

            wpkt = tx_helper_begin(h);
            if (wpkt == NULL)
                return 0; /* alloc error */

            f.stream_id         = stream->id;
            f.app_error_code    = stream->reset_stream_aec;
            f.final_size        = ossl_quic_sstream_get_cur_size(stream->sstream);
            if (!ossl_quic_wire_encode_frame_reset_stream(wpkt, &f)) {
                tx_helper_rollback(h); /* can't fit */
                txp_enlink_tmp(tmp_head, stream);
                break;
            }

            if (!tx_helper_commit(h))
                return 0; /* alloc error */

            *have_ack_eliciting = 1;
            tx_helper_unrestrict(h); /* no longer need PING */
            stream->txp_sent_reset_stream = 1;
        }

        /* Stream Flow Control Frames (MAX_STREAM_DATA) */
        if (rstream != NULL
            && (stream->want_max_stream_data
                || ossl_quic_rxfc_has_cwm_changed(&stream->rxfc, 0))) {

            wpkt = tx_helper_begin(h);
            if (wpkt == NULL)
                return 0; /* alloc error */

            cwm = ossl_quic_rxfc_get_cwm(&stream->rxfc);

            if (!ossl_quic_wire_encode_frame_max_stream_data(wpkt, stream->id,
                                                             cwm)) {
                tx_helper_rollback(h); /* can't fit */
                txp_enlink_tmp(tmp_head, stream);
                break;
            }

            if (!tx_helper_commit(h))
                return 0; /* alloc error */

            *have_ack_eliciting = 1;
            tx_helper_unrestrict(h); /* no longer need PING */
            stream->txp_sent_fc = 1;
        }

        /* Stream Data Frames (STREAM) */
        if (stream->sstream != NULL) {
            int packet_full = 0, stream_drained = 0;

            if (!txp_generate_stream_frames(txp, h, pn_space, tpkt,
                                            stream->id, stream->sstream,
                                            &stream->txfc,
                                            snext, min_ppl,
                                            have_ack_eliciting,
                                            &packet_full,
                                            &stream_drained,
                                            &stream->txp_txfc_new_credit_consumed)) {
                /* Fatal error (allocation, etc.) */
                txp_enlink_tmp(tmp_head, stream);
                return 0;
            }

            if (stream_drained)
                stream->txp_drained = 1;

            if (packet_full) {
                txp_enlink_tmp(tmp_head, stream);
                break;
            }
        }

        txp_enlink_tmp(tmp_head, stream);
    }

    return 1;
}

/*
 * Generates a packet for a given EL with the given minimum and maximum
 * plaintext packet payload lengths. Returns TXP_ERR_* value.
 */
static int txp_generate_for_el_actual(OSSL_QUIC_TX_PACKETISER *txp,
                                      uint32_t enc_level,
                                      uint32_t archetype,
                                      size_t min_ppl,
                                      size_t max_ppl,
                                      size_t pkt_overhead,
                                      QUIC_PKT_HDR *phdr,
                                      int chosen_for_conn_close,
                                      int *sent_ack_eliciting)
{
    int rc = TXP_ERR_SUCCESS;
    struct archetype_data a;
    uint32_t pn_space = ossl_quic_enc_level_to_pn_space(enc_level);
    struct tx_helper h;
    int have_helper = 0, have_ack_eliciting = 0, done_pre_token = 0;
    int require_ack_eliciting = 0;
    QUIC_CFQ_ITEM *cfq_item;
    QUIC_TXPIM_PKT *tpkt = NULL;
    OSSL_QTX_PKT pkt;
    QUIC_STREAM *tmp_head = NULL, *stream;
    OSSL_ACKM_PROBE_INFO *probe_info
        = ossl_ackm_get0_probe_request(txp->args.ackm);

    if (!txp_get_archetype_data(enc_level, archetype, &a))
        goto fatal_err;

    if (a.allow_force_ack_eliciting) {
        /*
         * Make this packet ACK-eliciting if it has been explicitly requested,
         * or if ACKM has requested a probe for this PN space.
         */
        if ((txp->force_ack_eliciting & (1UL << pn_space)) != 0
            || (enc_level == QUIC_ENC_LEVEL_INITIAL
                && probe_info->anti_deadlock_initial > 0)
            || (enc_level == QUIC_ENC_LEVEL_HANDSHAKE
                && probe_info->anti_deadlock_handshake > 0)
            || probe_info->pto[pn_space] > 0)
            require_ack_eliciting = 1;
    }

    /* Minimum cannot be bigger than maximum. */
    if (min_ppl > max_ppl)
        goto fatal_err;

    /* Maximum PN reached? */
    if (txp->next_pn[pn_space] >= (((QUIC_PN)1) << 62))
        goto fatal_err;

    if ((tpkt = ossl_quic_txpim_pkt_alloc(txp->args.txpim)) == NULL)
        goto fatal_err;

    /*
     * Initialise TX helper. If we must be ACK eliciting, reserve 1 byte for
     * PING.
     */
    if (!tx_helper_init(&h, txp, max_ppl, require_ack_eliciting ? 1 : 0))
        goto fatal_err;

    have_helper = 1;

    /*
     * Frame Serialization
     * ===================
     *
     * We now serialize frames into the packet in descending order of priority.
     */

    /* HANDSHAKE_DONE (Regenerate) */
    if (a.allow_handshake_done && txp->want_handshake_done
        && tx_helper_get_space_left(&h) >= MIN_FRAME_SIZE_HANDSHAKE_DONE) {
        WPACKET *wpkt = tx_helper_begin(&h);

        if (wpkt == NULL)
            goto fatal_err;

        if (ossl_quic_wire_encode_frame_handshake_done(wpkt)) {
            tpkt->had_handshake_done_frame = 1;
            have_ack_eliciting             = 1;

            if (!tx_helper_commit(&h))
                goto fatal_err;

            tx_helper_unrestrict(&h); /* no longer need PING */
        } else {
            tx_helper_rollback(&h);
        }
    }

    /* MAX_DATA (Regenerate) */
    if (a.allow_conn_fc
        && (txp->want_max_data
            || ossl_quic_rxfc_has_cwm_changed(txp->args.conn_rxfc, 0))
        && tx_helper_get_space_left(&h) >= MIN_FRAME_SIZE_MAX_DATA) {
        WPACKET *wpkt = tx_helper_begin(&h);
        uint64_t cwm = ossl_quic_rxfc_get_cwm(txp->args.conn_rxfc);

        if (wpkt == NULL)
            goto fatal_err;

        if (ossl_quic_wire_encode_frame_max_data(wpkt, cwm)) {
            tpkt->had_max_data_frame = 1;
            have_ack_eliciting       = 1;

            if (!tx_helper_commit(&h))
                goto fatal_err;

            tx_helper_unrestrict(&h); /* no longer need PING */
        } else {
            tx_helper_rollback(&h);
        }
    }

    /* MAX_STREAMS_BIDI (Regenerate) */
    /*
     * TODO(STREAMS): Once we support multiple streams, add stream count FC
     * and plug this in.
     */
    if (a.allow_conn_fc
        && txp->want_max_streams_bidi
        && tx_helper_get_space_left(&h) >= MIN_FRAME_SIZE_MAX_STREAMS_BIDI) {
        WPACKET *wpkt = tx_helper_begin(&h);
        uint64_t max_streams = 1; /* TODO */

        if (wpkt == NULL)
            goto fatal_err;

        if (ossl_quic_wire_encode_frame_max_streams(wpkt, /*is_uni=*/0,
                                                    max_streams)) {
            tpkt->had_max_streams_bidi_frame = 1;
            have_ack_eliciting               = 1;

            if (!tx_helper_commit(&h))
                goto fatal_err;

            tx_helper_unrestrict(&h); /* no longer need PING */
        } else {
            tx_helper_rollback(&h);
        }
    }

    /* MAX_STREAMS_UNI (Regenerate) */
    if (a.allow_conn_fc
        && txp->want_max_streams_uni
        && tx_helper_get_space_left(&h) >= MIN_FRAME_SIZE_MAX_STREAMS_UNI) {
        WPACKET *wpkt = tx_helper_begin(&h);
        uint64_t max_streams = 0; /* TODO */

        if (wpkt == NULL)
            goto fatal_err;

        if (ossl_quic_wire_encode_frame_max_streams(wpkt, /*is_uni=*/1,
                                                    max_streams)) {
            tpkt->had_max_streams_uni_frame = 1;
            have_ack_eliciting              = 1;

            if (!tx_helper_commit(&h))
                goto fatal_err;

            tx_helper_unrestrict(&h); /* no longer need PING */
        } else {
            tx_helper_rollback(&h);
        }
    }

    /* GCR Frames */
    for (cfq_item = ossl_quic_cfq_get_priority_head(txp->args.cfq, pn_space);
         cfq_item != NULL;
         cfq_item = ossl_quic_cfq_item_get_priority_next(cfq_item, pn_space)) {
        uint64_t frame_type = ossl_quic_cfq_item_get_frame_type(cfq_item);
        const unsigned char *encoded = ossl_quic_cfq_item_get_encoded(cfq_item);
        size_t encoded_len = ossl_quic_cfq_item_get_encoded_len(cfq_item);

        switch (frame_type) {
            case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
                if (!a.allow_new_conn_id)
                    continue;
                break;
            case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
                if (!a.allow_retire_conn_id)
                    continue;
                break;
            case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
                if (!a.allow_new_token)
                    continue;

                /*
                 * NEW_TOKEN frames are handled via GCR, but some
                 * Regenerate-strategy frames should come before them (namely
                 * ACK, CONNECTION_CLOSE, PATH_CHALLENGE and PATH_RESPONSE). If
                 * we find a NEW_TOKEN frame, do these now. If there are no
                 * NEW_TOKEN frames in the GCR queue we will handle these below.
                 */
                if (!done_pre_token)
                    if (txp_generate_pre_token(txp, &h, tpkt, pn_space, &a,
                                               chosen_for_conn_close))
                        done_pre_token = 1;

                break;
            default:
                if (!a.allow_cfq_other)
                    continue;
                break;
        }

        /*
         * If the frame is too big, don't try to schedule any more GCR frames in
         * this packet rather than sending subsequent ones out of order.
         */
        if (encoded_len > tx_helper_get_space_left(&h))
            break;

        if (!tx_helper_append_iovec(&h, encoded, encoded_len))
            goto fatal_err;

        ossl_quic_txpim_pkt_add_cfq_item(tpkt, cfq_item);

        if (ossl_quic_frame_type_is_ack_eliciting(frame_type)) {
            have_ack_eliciting = 1;
            tx_helper_unrestrict(&h); /* no longer need PING */
        }
    }

    /*
     * If we didn't generate ACK, CONNECTION_CLOSE, PATH_CHALLENGE or
     * PATH_RESPONSE (as desired) before, do so now.
     */
    if (!done_pre_token)
        if (txp_generate_pre_token(txp, &h, tpkt, pn_space, &a,
                                   chosen_for_conn_close))
            done_pre_token = 1;

    /* CRYPTO Frames */
    if (a.allow_crypto)
        if (!txp_generate_crypto_frames(txp, &h, pn_space, tpkt,
                                        &have_ack_eliciting))
            goto fatal_err;

    /* Stream-specific frames */
    if (a.allow_stream_rel && txp->handshake_complete)
        if (!txp_generate_stream_related(txp, &h, pn_space, tpkt, min_ppl,
                                         &have_ack_eliciting,
                                         &tmp_head))
            goto fatal_err;

    /* PING */
    tx_helper_unrestrict(&h);

    if (require_ack_eliciting && !have_ack_eliciting && a.allow_ping) {
        WPACKET *wpkt;

        wpkt = tx_helper_begin(&h);
        if (wpkt == NULL)
            goto fatal_err;

        if (!ossl_quic_wire_encode_frame_ping(wpkt)
            || !tx_helper_commit(&h))
            /*
             * We treat a request to be ACK-eliciting as a requirement, so this
             * is an error.
             */
            goto fatal_err;

        have_ack_eliciting = 1;
    }

    /* PADDING */
    if (h.bytes_appended < min_ppl) {
        WPACKET *wpkt = tx_helper_begin(&h);
        if (wpkt == NULL)
            goto fatal_err;

        if (!ossl_quic_wire_encode_padding(wpkt, min_ppl - h.bytes_appended)
            || !tx_helper_commit(&h))
            goto fatal_err;
    }

    /*
     * Dispatch
     * ========
     */
    /* ACKM Data */
    tpkt->ackm_pkt.num_bytes        = h.bytes_appended + pkt_overhead;
    tpkt->ackm_pkt.pkt_num          = txp->next_pn[pn_space];
    /* largest_acked is set in txp_generate_pre_token */
    tpkt->ackm_pkt.pkt_space        = pn_space;
    tpkt->ackm_pkt.is_inflight      = 1;
    tpkt->ackm_pkt.is_ack_eliciting = have_ack_eliciting;
    tpkt->ackm_pkt.is_pto_probe     = 0;
    tpkt->ackm_pkt.is_mtu_probe     = 0;
    tpkt->ackm_pkt.time             = ossl_time_now();

    /* Packet Information for QTX */
    pkt.hdr         = phdr;
    pkt.iovec       = txp->iovec;
    pkt.num_iovec   = h.num_iovec;
    pkt.local       = NULL;
    pkt.peer        = BIO_ADDR_family(&txp->args.peer) == AF_UNSPEC
        ? NULL : &txp->args.peer;
    pkt.pn          = txp->next_pn[pn_space];
    pkt.flags       = OSSL_QTX_PKT_FLAG_COALESCE; /* always try to coalesce */

    /* Do TX key update if needed. */
    if (enc_level == QUIC_ENC_LEVEL_1RTT) {
        uint64_t cur_pkt_count, max_pkt_count;

        cur_pkt_count = ossl_qtx_get_cur_epoch_pkt_count(txp->args.qtx, enc_level);
        max_pkt_count = ossl_qtx_get_max_epoch_pkt_count(txp->args.qtx, enc_level);

        if (cur_pkt_count >= max_pkt_count / 2)
            if (!ossl_qtx_trigger_key_update(txp->args.qtx))
                goto fatal_err;
    }

    if (!ossl_assert(h.bytes_appended > 0))
        goto fatal_err;

    /* Generate TXPIM chunks representing STOP_SENDING and RESET_STREAM frames. */
    for (stream = tmp_head; stream != NULL; stream = stream->txp_next)
        if (stream->txp_sent_stop_sending || stream->txp_sent_reset_stream) {
            /* Log STOP_SENDING chunk to TXPIM. */
            QUIC_TXPIM_CHUNK chunk;

            chunk.stream_id         = stream->id;
            chunk.start             = UINT64_MAX;
            chunk.end               = 0;
            chunk.has_fin           = 0;
            chunk.has_stop_sending  = stream->txp_sent_stop_sending;
            chunk.has_reset_stream  = stream->txp_sent_reset_stream;
            if (!ossl_quic_txpim_pkt_append_chunk(tpkt, &chunk))
                return 0; /* alloc error */
        }

    /* Dispatch to FIFD. */
    if (!ossl_quic_fifd_pkt_commit(&txp->fifd, tpkt))
        goto fatal_err;

    /* Send the packet. */
    if (!ossl_qtx_write_pkt(txp->args.qtx, &pkt))
        goto fatal_err;

    ++txp->next_pn[pn_space];

    /*
     * Record FC and stream abort frames as sent; deactivate streams which no
     * longer have anything to do.
     */
    for (stream = tmp_head; stream != NULL; stream = stream->txp_next) {
        if (stream->txp_sent_fc) {
            stream->want_max_stream_data = 0;
            ossl_quic_rxfc_has_cwm_changed(&stream->rxfc, 1);
        }

        if (stream->txp_sent_stop_sending)
            stream->want_stop_sending = 0;

        if (stream->txp_sent_reset_stream)
            stream->want_reset_stream = 0;

        if (stream->txp_txfc_new_credit_consumed > 0) {
            if (!ossl_assert(ossl_quic_txfc_consume_credit(&stream->txfc,
                                                           stream->txp_txfc_new_credit_consumed)))
                /*
                 * Should not be possible, but we should continue with our
                 * bookkeeping as we have already committed the packet to the
                 * FIFD. Just change the value we return.
                 */
                rc = TXP_ERR_INTERNAL;

            stream->txp_txfc_new_credit_consumed = 0;
        }

        /*
         * If we no longer need to generate any flow control (MAX_STREAM_DATA),
         * STOP_SENDING or RESET_STREAM frames, nor any STREAM frames (because
         * the stream is drained of data or TXFC-blocked), we can mark the
         * stream as inactive.
         */
        ossl_quic_stream_map_update_state(txp->args.qsm, stream);

        if (stream->txp_drained)
            assert(!ossl_quic_sstream_has_pending(stream->sstream));
    }

    /* We have now sent the packet, so update state accordingly. */
    if (have_ack_eliciting)
        txp->force_ack_eliciting &= ~(1UL << pn_space);

    if (tpkt->had_handshake_done_frame)
        txp->want_handshake_done = 0;

    if (tpkt->had_max_data_frame) {
        txp->want_max_data = 0;
        ossl_quic_rxfc_has_cwm_changed(txp->args.conn_rxfc, 1);
    }

    if (tpkt->had_max_streams_bidi_frame)
        txp->want_max_streams_bidi = 0;

    if (tpkt->had_max_streams_uni_frame)
        txp->want_max_streams_uni = 0;

    if (tpkt->had_ack_frame)
        txp->want_ack &= ~(1UL << pn_space);

    /*
     * Decrement probe request counts if we have sent a packet that meets
     * the requirement of a probe, namely being ACK-eliciting.
     */
    if (have_ack_eliciting) {
        if (enc_level == QUIC_ENC_LEVEL_INITIAL
            && probe_info->anti_deadlock_initial > 0)
            --probe_info->anti_deadlock_initial;

        if (enc_level == QUIC_ENC_LEVEL_HANDSHAKE
            && probe_info->anti_deadlock_handshake > 0)
            --probe_info->anti_deadlock_handshake;

        if (a.allow_force_ack_eliciting /* (i.e., not for 0-RTT) */
            && probe_info->pto[pn_space] > 0)
            --probe_info->pto[pn_space];
    }

    if (have_ack_eliciting)
        *sent_ack_eliciting = 1;

    /* Done. */
    tx_helper_cleanup(&h);
    return rc;

fatal_err:
    /*
     * Handler for fatal errors, i.e. errors causing us to abort the entire
     * packet rather than just one frame. Examples of such errors include
     * allocation errors.
     */
    if (have_helper)
        tx_helper_cleanup(&h);
    if (tpkt != NULL)
        ossl_quic_txpim_pkt_release(txp->args.txpim, tpkt);
    return TXP_ERR_INTERNAL;
}

/* Ensure the iovec array is at least num elements long. */
static int txp_ensure_iovec(OSSL_QUIC_TX_PACKETISER *txp, size_t num)
{
    OSSL_QTX_IOVEC *iovec;

    if (txp->alloc_iovec >= num)
        return 1;

    num = txp->alloc_iovec != 0 ? txp->alloc_iovec * 2 : 8;

    iovec = OPENSSL_realloc(txp->iovec, sizeof(OSSL_QTX_IOVEC) * num);
    if (iovec == NULL)
        return 0;

    txp->iovec          = iovec;
    txp->alloc_iovec    = num;
    return 1;
}

int ossl_quic_tx_packetiser_schedule_conn_close(OSSL_QUIC_TX_PACKETISER *txp,
                                                const OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    char *reason = NULL;
    size_t reason_len = f->reason_len;
    size_t max_reason_len = txp_get_mdpl(txp) / 2;

    if (txp->want_conn_close)
        return 0;

    /*
     * Arbitrarily limit the length of the reason length string to half of the
     * MDPL.
     */
    if (reason_len > max_reason_len)
        reason_len = max_reason_len;

    if (reason_len > 0) {
        reason = OPENSSL_memdup(f->reason, reason_len);
        if (reason == NULL)
            return 0;
    }

    txp->conn_close_frame               = *f;
    txp->conn_close_frame.reason        = reason;
    txp->conn_close_frame.reason_len    = reason_len;
    txp->want_conn_close                = 1;
    return 1;
}
