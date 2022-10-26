/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/packet.h"
#include "internal/nelem.h"
#include "internal/quic_wire.h"
#include "internal/quic_record_rx.h"
#include "internal/quic_ackm.h"
#include "internal/quic_rx_depack.h"
#include "internal/quic_record_rx_wrap.h"
#include "internal/quic_error.h"
#include "internal/quic_fc.h"
#include "internal/sockets.h"

#include "quic_local.h"
#include "../ssl_local.h"

/*
 * TODO(QUIC): ASSUMPTION: the QUIC_CONNECTION structure refers to other related
 * components, such as OSSL_ACKM and OSSL_QRX, in some manner.  These macros
 * should be used to get those components.
 */
#define GET_CONN_ACKM(c)        ((c)->ackm)
#define GET_CONN_QRX(c)         ((c)->qrx)
#define GET_CONN_STATEM(c)      ((c)->ssl.statem)

#if 0                            /* Currently unimplemented */
# define GET_CONN_ACK_DELAY_EXP(c) (QUIC_CONNECTION_get_ack_delay_exponent(c))
#else
/* 3 is the default, see RFC 9000, 18.2. Transport Parameter Definitions */
# define GET_CONN_ACK_DELAY_EXP(c) 3
#endif

/*
 * TODO(QUIC): In MVP the QUIC_CONNECTION is the only supported stream.
 */
static QUIC_STREAM *ssl_get_stream(QUIC_CONNECTION *conn, uint64_t stream_id)
{
    return stream_id == 0 ? &conn->stream : NULL;
}

/*
 * TODO(QUIC): ASSUMPTION: ssl_get_stream_type() gets a stream type from a
 * QUIC_STREAM
 */
/* Receive */
#define SSL_STREAM_TYPE_R       1
/* Send */
#define SSL_STREAM_TYPE_S       2
/* Bidirectional */
#define SSL_STREAM_TYPE_B       (SSL_STREAM_TYPE_R|SSL_STREAM_TYPE_S)
static int ssl_get_stream_type(QUIC_STREAM *stream)
{
    return SSL_STREAM_TYPE_B;
}

/*
 * We assume that queuing of the data has to be done without copying, thus
 * we get the reference counting QRX packet wrapper so it can increment the
 * reference count.  When the data is consumed (i.e. as a result of, say,
 * SSL_read()), ossl_qrx_pkt_wrap_free() must be called.
 */
static int ssl_queue_data(QUIC_STREAM *stream, OSSL_QRX_PKT_WRAP *pkt_wrap,
                          const unsigned char *data, uint64_t data_len,
                          uint64_t logical_offset, int is_fin)
{
    /* Notify stream flow controller */
    if (stream->rxfc != NULL
        && (!ossl_quic_rxfc_on_rx_stream_frame(stream->rxfc,
                                               logical_offset + data_len,
                                               is_fin)
            || ossl_quic_rxfc_get_error(stream->rxfc, 0) != QUIC_ERR_NO_ERROR))
        /* QUIC_ERR_FLOW_CONTROL_ERROR or QUIC_ERR_FINAL_SIZE detected */
        return 0;

    return stream->rstream == NULL
           || ossl_quic_rstream_queue_data(stream->rstream, pkt_wrap,
                                           logical_offset, data, data_len,
                                           is_fin);
}

/*
 * TODO(QUIC): ASSUMPTION: ssl_close_stream() detaches the QUIC_STREAM from
 * the QUIC_CONNECTION it's attached to, and then destroys that QUIC_STREAM
 * (as well as its SSL object).  |how| works the same way as in shutdown(2),
 * i.e. |SHUT_RD| closes the reader part, |SHUT_WR| closes the writer part.
 */
static int ssl_close_stream(QUIC_STREAM *stream, int how)
{
    return 1;
}

/*
 * TODO(QUIC): ASSUMPTION: ssl_close_connection() closes all the streams that
 * are attached to it, then closes the QUIC_CONNECTION as well.
 * Actual cleanup / destruction of the QUIC_CONNECTION is assumed to be done
 * higher up in the call stack (state machine, for example?).
 */
static int ssl_close_connection(QUIC_CONNECTION *connection)
{
    return 1;
}

/*
 * TODO(QUIC): ASSUMPTION: ossl_statem_set_error_state() sets an overall error
 * state in the state machine.  It's up to the state machine to determine what
 * to do with it.
 */
#define QUIC_STREAM_STATE_ERROR 1

/*
 * QUICfatal() et al is the same as SSLfatal(), but for QUIC.  We define a
 * placeholder here as long as it's not defined elsewhere.
 *
 * ossl_quic_fatal() is an error reporting building block used instead of
 * ERR_set_error().  In addition to what ERR_set_error() does, this puts
 * the state machine into an error state and sends an alert if appropriate,
 * and also closes the current connection.
 * This is a permanent error for the current connection.
 */
#ifndef QUICfatal

static void ossl_quic_fatal(QUIC_CONNECTION *c, int al, int reason,
                            const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    ERR_vset_error(ERR_LIB_SSL, reason, fmt, args);
    va_end(args);

    /*
     * TODO(QUIC): ADD CODE to set the state machine error.
     * It's assumed that you can get the state machine with
     * GET_CONN_STATEM(c)
     */

    ssl_close_connection(c);

}
# define QUICfatal(c, al, r) QUICfatal_data((c), (al), (r), NULL)
# define QUICfatal_data                                         \
    (ERR_new(),                                                 \
     ERR_set_debug(OPENSSL_FILE, OPENSSL_LINE, OPENSSL_FUNC),   \
     ossl_quic_fatal)
#endif

/* TODO(QUIC): [END: TO BE REMOVED] */

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
    return ossl_quic_wire_decode_padding(pkt);
}

static int depack_do_frame_ping(PACKET *pkt, OSSL_ACKM_RX_PKT *ackm_data)
{
    /* We ignore this frame, apart from eliciting an ACK */
    if (!ossl_quic_wire_decode_frame_ping(pkt))
        return 0;
    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;
    return 1;
}

static int depack_do_frame_ack(PACKET *pkt, QUIC_CONNECTION *connection,
                               int packet_space, OSSL_TIME received)
{
    OSSL_QUIC_FRAME_ACK ack;
    OSSL_QUIC_ACK_RANGE *ack_ranges;
    uint64_t total_ranges = 0;
    uint32_t ack_delay_exp = GET_CONN_ACK_DELAY_EXP(connection);
    int ok = 1;          /* Assume the best */

    if (!ossl_quic_wire_peek_frame_ack_num_ranges(pkt, &total_ranges)
        /* In case sizeof(uint64_t) > sizeof(size_t) */
        || total_ranges > SIZE_MAX / sizeof(ack_ranges[0])
        || (ack_ranges = OPENSSL_zalloc(sizeof(ack_ranges[0])
                                        * (size_t)total_ranges)) == NULL)
        return 0;

    ack.ack_ranges = ack_ranges;
    ack.num_ack_ranges = (size_t)total_ranges;

    if (!ossl_quic_wire_decode_frame_ack(pkt, ack_delay_exp, &ack, NULL))
        ok = 0;
    if (ok
        && !ossl_ackm_on_rx_ack_frame(GET_CONN_ACKM(connection), &ack,
                                      packet_space, received))
        ok = 0;

    OPENSSL_free(ack_ranges);
    if (!ok)
        return 0;
    return 1;
}

static int depack_do_frame_reset_stream(PACKET *pkt,
                                        QUIC_CONNECTION *connection,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_RESET_STREAM frame_data;
    QUIC_STREAM *stream = NULL;
    int stream_type = 0;

    if (!ossl_quic_wire_decode_frame_reset_stream(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    if ((stream = ssl_get_stream(connection, frame_data.stream_id)) == NULL)
        return 0;
    stream_type = ssl_get_stream_type(stream);

    ssl_close_stream(stream, SHUT_WR); /* Reuse shutdown(2) symbols */
    if ((stream_type & SSL_STREAM_TYPE_S) != 0) {
        QUICfatal(connection, QUIC_STREAM_STATE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

static int depack_do_frame_stop_sending(PACKET *pkt,
                                        QUIC_CONNECTION *connection,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_STOP_SENDING frame_data;
    QUIC_STREAM *stream = NULL;
    int stream_type = 0;

    if (!ossl_quic_wire_decode_frame_stop_sending(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    if ((stream = ssl_get_stream(connection, frame_data.stream_id)) == NULL)
        return 0;
    stream_type = ssl_get_stream_type(stream);

    ssl_close_stream(stream, SHUT_RD); /* Reuse shutdown(2) symbols */
    if ((stream_type & SSL_STREAM_TYPE_R) != 0) {
        QUICfatal(connection, QUIC_STREAM_STATE_ERROR, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    return 1;
}

static int depack_do_frame_crypto(PACKET *pkt, QUIC_CONNECTION *connection,
                                  OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_CRYPTO frame_data;

    if (!ossl_quic_wire_decode_frame_crypto(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data.data| to the handshake manager */

    return 1;
}

static int depack_do_frame_new_token(PACKET *pkt, QUIC_CONNECTION *connection,
                                     OSSL_ACKM_RX_PKT *ackm_data)
{
    const uint8_t *token;
    size_t token_len;

    if (!ossl_quic_wire_decode_frame_new_token(pkt, &token, &token_len))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |token| to the session manager */

    return 1;
}

static int depack_do_frame_stream(PACKET *pkt, QUIC_CONNECTION *connection,
                                  OSSL_QRX_PKT_WRAP *parent_pkt,
                                  OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_STREAM frame_data;
    QUIC_STREAM *stream;

    if (!ossl_quic_wire_decode_frame_stream(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /*
     * TODO(QUIC): ASSUMPTION: ssl_get_stream() gets a QUIC_STREAM from a
     * QUIC_CONNECTION by stream ID.
     */
    if ((stream = ssl_get_stream(connection, frame_data.stream_id)) == NULL)
        return 0;
    /*
     * TODO(QUIC): ASSUMPTION: ssl_queue_data() knows what to do with
     * |frame_data.offset| and |frame_data.is_fin|.
     */
    if (!ssl_queue_data(stream, parent_pkt, frame_data.data, frame_data.len,
                        frame_data.offset, frame_data.is_fin))
        return 0;
    return 1;
}

static int depack_do_frame_max_data(PACKET *pkt, QUIC_CONNECTION *connection,
                                    OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_max_data(pkt, &max_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_data| to flow control */

    return 1;
}

static int depack_do_frame_max_stream_data(PACKET *pkt,
                                           QUIC_CONNECTION *connection,
                                           OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t stream_id = 0;
    uint64_t max_stream_data = 0;

    if (!ossl_quic_wire_decode_frame_max_stream_data(pkt, &stream_id,
                                                     &max_stream_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_stream_data| to flow control */

    return 1;
}

static int depack_do_frame_max_streams(PACKET *pkt,
                                       QUIC_CONNECTION *connection,
                                       OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_streams = 0;

    if (!ossl_quic_wire_decode_frame_max_streams(pkt, &max_streams))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_streams| to the connection manager */

    return 1;
}

static int depack_do_frame_data_blocked(PACKET *pkt,
                                        QUIC_CONNECTION *connection,
                                        OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_data_blocked(pkt, &max_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_data| to flow control */

    return 1;
}

static int depack_do_frame_stream_data_blocked(PACKET *pkt,
                                               QUIC_CONNECTION *connection,
                                               OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t stream_id = 0;
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_stream_data_blocked(pkt, &stream_id,
                                                         &max_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_data| to flow control */

    return 1;
}

static int depack_do_frame_streams_blocked(PACKET *pkt,
                                           QUIC_CONNECTION *connection,
                                           OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t max_data = 0;

    if (!ossl_quic_wire_decode_frame_streams_blocked(pkt, &max_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |max_data| to connection manager */

    return 1;
}

static int depack_do_frame_new_conn_id(PACKET *pkt,
                                       QUIC_CONNECTION *connection,
                                       OSSL_ACKM_RX_PKT *ackm_data)
{
    OSSL_QUIC_FRAME_NEW_CONN_ID frame_data;

    if (!ossl_quic_wire_decode_frame_new_conn_id(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data.data| to the connection manager */

    return 1;
}

static int depack_do_frame_retire_conn_id(PACKET *pkt,
                                          QUIC_CONNECTION *connection,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t seq_num;

    if (!ossl_quic_wire_decode_frame_retire_conn_id(pkt, &seq_num))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |seq_num| to the connection manager */
    return 1;
}

static int depack_do_frame_path_challenge(PACKET *pkt,
                                          QUIC_CONNECTION *connection,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t frame_data = 0;

    if (!ossl_quic_wire_decode_frame_path_challenge(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data| to the connection manager */

    return 1;
}

static int depack_do_frame_path_response(PACKET *pkt,
                                         QUIC_CONNECTION *connection,
                                         OSSL_ACKM_RX_PKT *ackm_data)
{
    uint64_t frame_data = 0;

    if (!ossl_quic_wire_decode_frame_path_response(pkt, &frame_data))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to send |frame_data| to the connection manager */

    return 1;
}

static int depack_do_frame_conn_close(PACKET *pkt, QUIC_CONNECTION *connection)
{
    OSSL_QUIC_FRAME_CONN_CLOSE frame_data;

    if (!ossl_quic_wire_decode_frame_conn_close(pkt, &frame_data))
        return 0;

    /* TODO(QUIC): ADD CODE to send |frame_data| to the connection manager */

    return 1;
}

static int depack_do_frame_handshake_done(PACKET *pkt,
                                          QUIC_CONNECTION *connection,
                                          OSSL_ACKM_RX_PKT *ackm_data)
{
    if (!ossl_quic_wire_decode_frame_handshake_done(pkt))
        return 0;

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /* TODO(QUIC): ADD CODE to tell the handshake manager that we're done */

    return 1;
}

static int depack_do_frame_unknown_extension(PACKET *pkt,
                                             QUIC_CONNECTION *connection,
                                             OSSL_ACKM_RX_PKT *ackm_data)
{
    /*
     * According to RFC 9000, 19.21. Extension Frames, extension frames
     * should be ACK eliciting.  It might be over zealous to do so for
     * extensions OpenSSL doesn't know how to handle, but shouldn't hurt
     * either.
     */

    /* This frame makes the packet ACK eliciting */
    ackm_data->is_ack_eliciting = 1;

    /*
     * Because we have no idea how to advance to the next frame, we return 0
     * everywhere, thereby stopping the depacketizing process.
     */

    return 0;
}

/* Main frame processor */

static int depack_process_frames(QUIC_CONNECTION *connection, PACKET *pkt,
                                 OSSL_QRX_PKT_WRAP *parent_pkt, int packet_space,
                                 OSSL_TIME received, OSSL_ACKM_RX_PKT *ackm_data)
{
    uint32_t pkt_type = parent_pkt->pkt->hdr->type;

    while (PACKET_remaining(pkt) > 0) {
        uint64_t frame_type;

        if (!ossl_quic_wire_peek_frame_header(pkt, &frame_type))
            return 0;

        switch (frame_type) {
        case OSSL_QUIC_FRAME_TYPE_PING:
            /* Allowed in all packet types */
            if (!depack_do_frame_ping(pkt, ackm_data))
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
            if (pkt_type == QUIC_PKT_TYPE_0RTT)
                return 0;
            if (!depack_do_frame_ack(pkt, connection, packet_space, received))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_RESET_STREAM:
            /* RESET_STREAM frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_reset_stream(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_STOP_SENDING:
            /* STOP_SENDING frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_stop_sending(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_CRYPTO:
            /* CRYPTO frames are valid everywhere except in 0RTT packets */
            if (pkt_type == QUIC_PKT_TYPE_0RTT)
                return 0;
            if (!depack_do_frame_crypto(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_NEW_TOKEN:
            /* NEW_TOKEN frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_new_token(pkt, connection, ackm_data))
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
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_stream(pkt, connection, parent_pkt, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_MAX_DATA:
            /* MAX_DATA frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_max_data(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA:
            /* MAX_STREAM_DATA frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_max_stream_data(pkt, connection, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI:
        case OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI:
            /* MAX_STREAMS frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_max_streams(pkt, connection, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED:
            /* DATA_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_data_blocked(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED:
            /* STREAM_DATA_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_stream_data_blocked(pkt, connection, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI:
        case OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI:
            /* STREAMS_BLOCKED frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_streams_blocked(pkt, connection, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID:
            /* NEW_CONN_ID frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_new_conn_id(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID:
            /* RETIRE_CONN_ID frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_retire_conn_id(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE:
            /* PATH_CHALLENGE frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_path_challenge(pkt, connection, ackm_data))
                return 0;
            break;
        case OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE:
            /* PATH_RESPONSE frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_path_response(pkt, connection, ackm_data))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP:
            /* CONN_CLOSE_APP frames are valid in 0RTT and 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_0RTT
                && pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            /* FALLTHRU */
        case OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT:
            /* CONN_CLOSE_TRANSPORT frames are valid in all packets */
            if (!depack_do_frame_conn_close(pkt, connection))
                return 0;
            break;

        case OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE:
            /* HANDSHAKE_DONE frames are valid in 1RTT packets */
            if (pkt_type != QUIC_PKT_TYPE_1RTT)
                return 0;
            if (!depack_do_frame_handshake_done(pkt, connection, ackm_data))
                return 0;
            break;

        default:
            /* Unknown frame type. */
            if (!depack_do_frame_unknown_extension(pkt, connection, ackm_data))
                return 0;

            break;
        }
    }

    return 1;
}

int ossl_quic_handle_frames(QUIC_CONNECTION *connection, OSSL_QRX_PKT *qpacket)
{
    PACKET pkt;
    OSSL_ACKM_RX_PKT ackm_data;
    OSSL_QRX_PKT_WRAP *qpkt_wrap = NULL;
    /*
     * ok has three states:
     * -1 error with ackm_data uninitialized
     *  0 error with ackm_data initialized
     *  1 success (ackm_data initialized)
     */
    int ok = -1;                  /* Assume the worst */

    if (connection == NULL)
        goto end;

    if ((qpkt_wrap = ossl_qrx_pkt_wrap_new(qpacket)) == NULL)
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
    }
    ok = 0;                      /* Still assume the worst */

    /* Handle special cases */
    if (qpacket->hdr->type == QUIC_PKT_TYPE_RETRY) {
        /* TODO(QUIC): ADD CODE to handle a retry */
        goto success;
    } else if (qpacket->hdr->type == QUIC_PKT_TYPE_VERSION_NEG) {
        /* TODO(QUIC): ADD CODE to handle version negotiation */
        goto success;
    }

    /* Now that special cases are out of the way, parse frames */
    if (!PACKET_buf_init(&pkt, qpacket->hdr->data, qpacket->hdr->len)
        || !depack_process_frames(connection, &pkt, qpkt_wrap,
                                  ackm_data.pkt_space, qpacket->time,
                                  &ackm_data))
        goto end;

 success:
    ok = 1;
 end:
    /*
     * TODO(QUIC): ASSUMPTION: If this function is called at all, |qpacket| is
     * a legitimate packet, even if its contents aren't.
     * Therefore, we call ossl_ackm_on_rx_packet() unconditionally, as long as
     * |ackm_data| has at least been initialized.
     */
    if (ok >= 0)
        ossl_ackm_on_rx_packet(GET_CONN_ACKM(connection), &ackm_data);

    /*
     * Let go of the packet pointer in |qpkt_wrap|.  This means that the
     * reference counter can't be incremented any more.
     */
    if (qpkt_wrap != NULL)
        qpkt_wrap->pkt = NULL;

    ossl_qrx_pkt_wrap_free(GET_CONN_QRX(connection), qpkt_wrap);
    return ok > 0;
}

int ossl_quic_depacketize(QUIC_CONNECTION *connection)
{
    OSSL_QRX_PKT qpacket;

    if (connection == NULL)
        return 0;

    /* Try to read a packet from the read record layer */
    memset(&qpacket, 0, sizeof(qpacket));
    if (ossl_qrx_read_pkt(GET_CONN_QRX(connection), &qpacket) <= 0)
        return 0;

    return ossl_quic_handle_frames(connection, &qpacket);
}
