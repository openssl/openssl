/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/packet_quic.h"
#include "internal/nelem.h"
#include "internal/quic_wire.h"
#include "internal/quic_record_rx.h"
#include "internal/quic_ackm.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_error.h"
#include "internal/quic_fc.h"
#include "internal/quic_channel.h"
#include "internal/sockets.h"

#include "quic_local.h"
#include "quic_channel_local.h"
#include "../ssl_local.h"

/*
 * Helper functions to process different frame types.
 *
 * Typically, those that are ACK eliciting will take an OSSL_ACKM_RX_PKT
 * pointer argument, the few that aren't ACK eliciting will not.  This makes
 * them a verifiable pattern against tables where this is specified.
 */

static int depack_do_frame_padding(PACKET *pkt)
{
    /* We ignore this frame */
    ossl_quic_wire_decode_padding(pkt);
    return 1;
}

static int depack_do_frame_ping(PACKET *pkt, QUIC_CHANNEL *ch,
                                OSSL_ACKM_RX_PKT *ackm_data)
{
    /* We ignore this frame, apart from eliciting an ACK */
    if (!ossl_quic_wire_decode_frame_ping(pkt)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_PING,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;
    return 1;
}

static int depack_do_frame_ack(PACKET *pkt, QUIC_CHANNEL *ch,
                               int packet_space, OSSL_TIME received,
                               uint64_t frame_type)
{
    OSSL_QUIC_FRAME_ACK ack;
    OSSL_QUIC_ACK_RANGE *ack_ranges = NULL;
    uint64_t total_ranges = 0;
    uint32_t ack_delay_exp = ch->rx_ack_delay_exp;

    if (!ossl_quic_wire_peek_frame_ack_num_ranges(pkt, &total_ranges)
        /* In case sizeof(uint64_t) > sizeof(size_t) */
        || total_ranges > SIZE_MAX / sizeof(ack_ranges[0])
        || (ack_ranges = OPENSSL_zalloc(sizeof(ack_ranges[0])
                                        * (size_t)total_ranges)) == NULL)
        goto malformed;

    ack.ack_ranges = ack_ranges;
    ack.num_ack_ranges = (size_t)total_ranges;

    if (!ossl_quic_wire_decode_frame_ack(pkt, ack_delay_exp, &ack, NULL))
        goto malformed;

    if (!ossl_ackm_on_rx_ack_frame(ch->ackm, &ack,
                                   packet_space, received))
        goto malformed;

    OPENSSL_free(ack_ranges);
    return 1;

malformed:
    ossl_quic_channel_raise_protocol_error(ch,
                                           QUIC_ERR_FRAME_ENCODING_ERROR,
                                           frame_type,
                                           "decode error");
    OPENSSL_free(ack_ranges);
    return 0;
}

static int depack_do_frame_reset_stream(PACKET *pkt,
                                        QUIC_CHANNEL *ch,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_RESET_STREAM frame_data;
    QUIC_STREAM *stream = NULL;

    if (!ossl_quic_wire_decode_frame_reset_stream(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_RESET_STREAM,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    stream = ossl_quic_stream_map_get_by_id(&ch->qsm, frame_data.stream_id);
    if (stream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_RESET_STREAM,
                                               "RESET_STREAM frame for "
                                               "nonexistent stream");
        return 0;
    }

    if (stream->rstream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_RESET_STREAM,
                                               "RESET_STREAM frame for "
                                               "TX only stream");
        return 0;
    }

    stream->peer_reset_stream = 1;
    ossl_quic_stream_map_update_state(&ch->qsm, stream);
    return 1;
}

static int depack_do_frame_stop_sending(PACKET *pkt,
                                        QUIC_CHANNEL *ch,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_STOP_SENDING frame_data;
    QUIC_STREAM *stream = NULL;

    if (!ossl_quic_wire_decode_frame_stop_sending(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_STOP_SENDING,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    stream = ossl_quic_stream_map_get_by_id(&ch->qsm, frame_data.stream_id);
    if (stream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_STOP_SENDING,
                                               "STOP_SENDING frame for "
                                               "nonexistent stream");
        return 0;
    }

    if (stream->sstream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_STOP_SENDING,
                                               "STOP_SENDING frame for "
                                               "RX only stream");
        return 0;
    }

    stream->peer_stop_sending = 1;
    ossl_quic_stream_map_update_state(&ch->qsm, stream);
    return 1;
}

static int depack_do_frame_crypto(PACKET *pkt, QUIC_CHANNEL *ch,
                                  OSSL_QRX_PKT *parent_pkt,
                                  OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_CRYPTO f;
    QUIC_RSTREAM *rstream;

    if (!ossl_quic_wire_decode_frame_crypto(pkt, &f)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_CRYPTO,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    rstream = ch->crypto_recv[ackm_data->pkt_space];
    if (!ossl_assert(rstream != NULL))
        /*
         * This should not happen; we should only have a NULL stream here if
         * the EL has been discarded, and if the EL has been discarded we
         * shouldn't be here.
         */
        return 0;

    if (!ossl_quic_rstream_queue_data(rstream, parent_pkt,
                                      f.offset, f.data, f.len, 0))
        return 0;

    return 1;
}

static int depack_do_frame_new_token(PACKET *pkt, QUIC_CHANNEL *ch,
                                     OSSL_ACKM_RX_PKT *ackm_data)
{
    const uint8_t *token;
    size_t token_len;

    if (!ossl_quic_wire_decode_frame_new_token(pkt, &token, &token_len)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_NEW_TOKEN,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |token| to the session manager */

    return 1;
}

static int depack_do_frame_stream(PACKET *pkt, QUIC_CHANNEL *ch,
                                  OSSL_QRX_PKT *parent_pkt,
                                  OSSL_ACKM_RX_PKT *ackm_data,
                                  uint64_t frame_type)
{
    OSSL_QUIC_FRAME_STREAM frame_data;
    QUIC_STREAM *stream;
    uint64_t fce;

    if (!ossl_quic_wire_decode_frame_stream(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               frame_type,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    stream = ossl_quic_stream_map_get_by_id(&ch->qsm, frame_data.stream_id);
    if (stream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               frame_type,
                                               "STREAM frame for nonexistent "
                                               "stream");
        return 0;
    }

    if (stream->rstream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               frame_type,
                                               "STREAM frame for TX only "
                                               "stream");
        return 0;
    }

    /* Notify stream flow controller. */
    if (!ossl_quic_rxfc_on_rx_stream_frame(&stream->rxfc,
                                           frame_data.offset + frame_data.len,
                                           frame_data.is_fin)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_INTERNAL_ERROR,
                                               frame_type,
                                               "internal error (flow control)");
        return 0;
    }

    /* Has a flow control error occurred? */
    fce = ossl_quic_rxfc_get_error(&stream->rxfc, 0);
    if (fce != QUIC_ERR_NO_ERROR) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               fce,
                                               frame_type,
                                               "flow control violation");
        return 0;
    }

    /*
     * The receive stream buffer may or may not choose to consume the data
     * without copying by reffing the OSSL_QRX_PKT. In this case
     * ossl_qrx_pkt_release() will be eventually called when the data is no
     * longer needed.
     */
    if (!ossl_quic_rstream_queue_data(stream->rstream, parent_pkt,
                                      frame_data.offset,
                                      frame_data.data,
                                      frame_data.len,
                                      frame_data.is_fin))
        return 0;

    return 1;
}

static int depack_do_frame_max_data(PACKET *pkt, QUIC_CHANNEL *ch,
                                    OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_max_data(pkt, &max_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_MAX_DATA,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    ossl_quic_txfc_bump_cwm(&ch->conn_txfc, max_data);
    ossl_quic_stream_map_update_state(&ch->qsm, ch->stream0);
    return 1;
}

static int depack_do_frame_max_stream_data(PACKET *pkt,
                                           QUIC_CHANNEL *ch,
                                           OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t stream_id = 0;
    uint64_t max_stream_data = 0;
    QUIC_STREAM *stream;

    if (!ossl_quic_wire_decode_frame_max_stream_data(pkt, &stream_id,
                                                     &max_stream_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    stream = ossl_quic_stream_map_get_by_id(&ch->qsm, stream_id);
    if (stream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA,
                                               "MAX_STREAM_DATA for nonexistent "
                                               "stream");
        return 0;
    }

    if (stream->sstream == NULL) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_STREAM_STATE_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA,
                                               "MAX_STREAM_DATA for TX only "
                                               "stream");
        return 0;
    }

    ossl_quic_txfc_bump_cwm(&stream->txfc, max_stream_data);
    ossl_quic_stream_map_update_state(&ch->qsm, stream);
    return 1;
}

static int depack_do_frame_max_streams(PACKET *pkt,
                                       QUIC_CHANNEL *ch,
                                       OSSL_ACKM_RX_PKT *ackm_data,
                                       uint64_t frame_type)
{
    uint64_t max_streams = 0;

    if (!ossl_quic_wire_decode_frame_max_streams(pkt, &max_streams)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               frame_type,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    if (max_streams > (((uint64_t)1) << 60)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               frame_type,
                                               "invalid max streams value");
        return 0;
    }

    switch (frame_type) {
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
        if (max_streams > ch->max_local_streams_bidi)
            ch->max_local_streams_bidi = max_streams;

        /* Stream may now be able to send */
        ossl_quic_stream_map_update_state(&ch->qsm,
                                          ch->stream0);
        break;
    case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
        if (max_streams > ch->max_local_streams_uni)
            ch->max_local_streams_uni = max_streams;

        /* Stream may now be able to send */
        ossl_quic_stream_map_update_state(&ch->qsm,
                                          ch->stream0);
        break;
    default:
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               frame_type,
                                               "decode error");
        return 0;
    }

    return 1;
}

static int depack_do_frame_data_blocked(PACKET *pkt,
                                        QUIC_CHANNEL *ch,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_data_blocked(pkt, &max_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* No-op - informative/debugging frame. */
    return 1;
}

static int depack_do_frame_stream_data_blocked(PACKET *pkt,
                                               QUIC_CHANNEL *ch,
                                               OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t stream_id = 0;
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_stream_data_blocked(pkt, &stream_id,
                                                         &max_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* No-op - informative/debugging frame. */
    return 1;
}

static int depack_do_frame_streams_blocked(PACKET *pkt,
                                           QUIC_CHANNEL *ch,
                                           OSSL_ACKM_RX_PKT *ackm_data,
                                           uint64_t frame_type)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_streams_blocked(pkt, &max_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               frame_type,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* No-op - informative/debugging frame. */
    return 1;
}

static int depack_do_frame_new_conn_id(PACKET *pkt,
                                       QUIC_CHANNEL *ch,
                                       OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_NEW_CONN_ID frame_data;

    if (!ossl_quic_wire_decode_frame_new_conn_id(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data.data| to the ch manager */

    return 1;
}

static int depack_do_frame_retire_conn_id(PACKET *pkt,
                                          QUIC_CHANNEL *ch,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t seq_num;

    if (!ossl_quic_wire_decode_frame_retire_conn_id(pkt, &seq_num)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |seq_num| to the ch manager */
    return 1;
}

static int depack_do_frame_path_challenge(PACKET *pkt,
                                          QUIC_CHANNEL *ch,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t frame_data = 0;

    if (!ossl_quic_wire_decode_frame_path_challenge(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data| to the ch manager */

    return 1;
}

static int depack_do_frame_path_response(PACKET *pkt,
                                         QUIC_CHANNEL *ch,
                                         OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t frame_data = 0;

    if (!ossl_quic_wire_decode_frame_path_response(pkt, &frame_data)) {
        ossl_quic_channel_raise_protocol_error(ch,
                                               QUIC_ERR_FRAME_ENCODING_ERROR,
                                               OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE,
                                               "decode error");
        return 0;
    }

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data| to the ch manager */

    return 1;
}

static int depack_do_frame_conn_close(PACKET *pkt, QUIC_CHANNEL *ch)
{
    OSSL_QUIC_FRAME_CONN_CLOSE frame_data;

    if (!ossl_quic_wire_decode_frame_conn_close(pkt, &frame_data))
        return 0;

    ossl_quic_channel_on_remote_conn_close(ch, &frame_data);
    return 1;
}

static int depack_do_frame_handshake_done(PACKET *pkt,
                                          QUIC_CHANNEL *ch,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    if (!ossl_quic_wire_decode_frame_handshake_done(pkt))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    ossl_quic_channel_on_handshake_confirmed(ch);
    return 1;
}

/* Main frame processor */

static int depack_process_frames(QUIC_CHANNEL *ch, PACKET *pkt,
                                 OSSL_QRX_PKT *parent_pkt, int packet_space,
                                 OSSL_TIME received, OSSL_ACKM_RX_PKT *ackm_data)
{
    uint32_t pkt_type = parent_pkt->hdr->type;

    while (PACKET_remaining(pkt) > 0) {
        uint64_t frame_type;

        if (!ossl_quic_wire_peek_frame_header(pkt, &frame_type))
            return 0;

        switch (frame_type) {
        case OSSL_QUIC_FRAME_TYPE_PING:
            /* Allowed in all packet types */
            if (!depack_do_frame_ping(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_PADDING:
            /* Allowed in all packet types */
            if (!depack_do_frame_padding(pkt))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN:
        case OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN:
            /* ACK frames are valid everywhere except in 0RTT packets */
            if (pkt_type == QUIC_PKT_TYPE_0RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "ACK not valid in 0-RTT");
                return 0;
            }
            if (!depack_do_frame_ack(pkt, ch, packet_space, received,
                                     frame_type))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
            /* RESET_STREAM frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "RESET_STREAM not valid in "
                                                       "INITIAL/HANDSHAKE");
                return 0;
            }
            if (!depack_do_frame_reset_stream(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
            /* STOP_SENDING frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "STOP_SENDING not valid in "
                                                       "INITIAL/HANDSHAKE");
                return 0;
            }
            if (!depack_do_frame_stop_sending(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_CRYPTO:
            /* CRYPTO frames are valid everywhere except in 0RTT packets */
            if (pkt_type == QUIC_PKT_TYPE_0RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "CRYPTO frame not valid in 0-RTT");
                return 0;
            }
            if (!depack_do_frame_crypto(pkt, ch, parent_pkt, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
            /* NEW_TOKEN frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "NEW_TOKEN valid only in 1-RTT");
                return 0;
            }
            if (!depack_do_frame_new_token(pkt, ch, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_STREAM:
        case OSSL_QUIC_FRAME_TYPE_STREAM_FIN:
        case OSSL_QUIC_FRAME_TYPE_STREAM_LEN:
        case OSSL_QUIC_FRAME_TYPE_STREAM_LEN_FIN:
        case OSSL_QUIC_FRAME_TYPE_STREAM_OFF:
        case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_FIN:
        case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN:
        case OSSL_QUIC_FRAME_TYPE_STREAM_OFF_LEN_FIN:
            /* STREAM frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "STREAM valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_stream(pkt, ch, parent_pkt, ackm_data,
                                        frame_type))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
            /* MAX_DATA frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "MAX_DATA valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_max_data(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
            /* MAX_STREAM_DATA frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "MAX_STREAM_DATA valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_max_stream_data(pkt, ch, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
            /* MAX_STREAMS frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "MAX_STREAMS valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_max_streams(pkt, ch, ackm_data,
                                             frame_type))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED:
            /* DATA_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "DATA_BLOCKED valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_data_blocked(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED:
            /* STREAM_DATA_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "STREAM_DATA_BLOCKED valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_stream_data_blocked(pkt, ch, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
        case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI:
            /* STREAMS_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "STREAMS valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_streams_blocked(pkt, ch, ackm_data,
                                                 frame_type))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
            /* NEW_CONN_ID frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "NEW_CONN_ID valid only in 0/1-RTT");
            }
            if (!depack_do_frame_new_conn_id(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
            /* RETIRE_CONN_ID frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "RETIRE_CONN_ID valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_retire_conn_id(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE:
            /* PATH_CHALLENGE frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "PATH_CHALLENGE valid only in 0/1-RTT");
                return 0;
            }
            if (!depack_do_frame_path_challenge(pkt, ch, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE:
            /* PATH_RESPONSE frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "PATH_CHALLENGE valid only in 1-RTT");
                return 0;
            }
            if (!depack_do_frame_path_response(pkt, ch, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP:
            /* CONN_CLOSE_APP frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "CONN_CLOSE (APP) valid only in 0/1-RTT");
                return 0;
            }
            /* FALLTHRU */
        case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT:
            /* CONN_CLOSE_TRANSPORT frames are valid in all packets */
            if (!depack_do_frame_conn_close(pkt, ch))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE:
            /* HANDSHAKE_DONE frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT) {
                ossl_quic_channel_raise_protocol_error(ch,
                                                       QUIC_ERR_PROTOCOL_VIOLATION,
                                                       frame_type,
                                                       "HANDSHAKE_DONE valid only in 1-RTT");
                return 0;
            }
            if (!depack_do_frame_handshake_done(pkt, ch, ackm_data))
                return 0;
            break;

        default:
            /* Unknown frame type */
            ackm_data->is_ack_eliciting = 1;
            ossl_quic_channel_raise_protocol_error(ch,
                                                   QUIC_ERR_PROTOCOL_VIOLATION,
                                                   frame_type,
                                                   "Unknown frame type received");
            return 0;
        }
    }

    return 1;
}

QUIC_NEEDS_LOCK
int ossl_quic_handle_frames(QUIC_CHANNEL *ch, OSSL_QRX_PKT *qpacket)
{
    PACKET pkt;
    OSSL_ACKM_RX_PKT ackm_data;
    /*
     * ok has three states:
     * -1 error with ackm_data uninitialized
     *  0 error with ackm_data initialized
     *  1 success (ackm_data initialized)
     */
    int ok = -1;                  /* Assume the worst */

    if (ch == NULL)
        goto end;

    /* Initialize |ackm_data| (and reinitialize |ok|)*/
    memset(&ackm_data, 0, sizeof(ackm_data));
    /*
     * TODO(QUIC): ASSUMPTION: All packets that aren't special case have a
     * packet number
     */
    ackm_data.pkt_num = qpacket->pn;
    ackm_data.time = qpacket->time;
    switch (qpacket->hdr->type) {
    case QUIC_PKT_TYPE_INITIAL:
        ackm_data.pkt_space = QUIC_PN_SPACE_INITIAL;
        break;
    case QUIC_PKT_TYPE_HANDSHAKE:
        ackm_data.pkt_space = QUIC_PN_SPACE_HANDSHAKE;
        break;
    case QUIC_PKT_TYPE_0RTT:
    case QUIC_PKT_TYPE_1RTT:
        ackm_data.pkt_space = QUIC_PN_SPACE_APP;
        break;
    default:
        /*
         * Retry and Version Negotiation packets should not be passed to this
         * function.
         */
        goto end;
    }
    ok = 0;                      /* Still assume the worst */

    /* Now that special cases are out of the way, parse frames */
    if (!PACKET_buf_init(&pkt, qpacket->hdr->data, qpacket->hdr->len)
        || !depack_process_frames(ch, &pkt, qpacket,
                                  ackm_data.pkt_space, qpacket->time,
                                  &ackm_data))
        goto end;

    ok = 1;
 end:
    /*
     * TODO(QUIC): ASSUMPTION: If this function is called at all, |qpacket| is
     * a legitimate packet, even if its contents aren't.
     * Therefore, we call ossl_ackm_on_rx_packet() unconditionally, as long as
     * |ackm_data| has at least been initialized.
     */
    if (ok >= 0)
        ossl_ackm_on_rx_packet(ch->ackm, &ackm_data);

    return ok > 0;
}
