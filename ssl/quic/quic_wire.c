/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/macros.h>
#include <openssl/objects.h>
#include "quic_local.h"
#include "internal/quic_vlint.h"
#include "internal/quic_wire.h"

/*
 * QUIC Wire Format Encoding
 * =========================
 */

int ossl_quic_wire_encode_frame_padding(WPACKET *pkt, size_t num_bytes)
{
    /*
     * PADDING is frame type zero, which as a variable-length integer is
     * represented as a single zero byte. As an optimisation, just use memset.
     */
    return WPACKET_memset(pkt, 0, num_bytes);
}

static int encode_frame_hdr(WPACKET *pkt, uint64_t frame_type)
{
    return WPACKET_quic_write_vlint(pkt, frame_type);
}

int ossl_quic_wire_encode_frame_ping(WPACKET *pkt)
{
    return encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PING);
}

int ossl_quic_wire_encode_frame_ack(WPACKET *pkt,
                                    uint32_t ack_delay_exponent,
                                    const OSSL_ACKM_ACK *ack)
{
    uint64_t frame_type = ack->ecn_present ? OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN
                                           : OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN;

    uint64_t largest_ackd, first_ack_range, ack_delay_enc;
    size_t i, num_ack_ranges = ack->num_ack_ranges;

    if (num_ack_ranges == 0)
        return 0;

    ack_delay_enc   = ossl_time_divide(ossl_time_divide(ack->delay_time,
                                                        OSSL_TIME_US),
                                       1UL << ack_delay_exponent);
    largest_ackd    = ack->ack_ranges[0].end;
    first_ack_range = ack->ack_ranges[0].end - ack->ack_ranges[0].start;

    if (!encode_frame_hdr(pkt, frame_type)
            || !WPACKET_quic_write_vlint(pkt, largest_ackd)
            || !WPACKET_quic_write_vlint(pkt, ack_delay_enc)
            || !WPACKET_quic_write_vlint(pkt, num_ack_ranges - 1)
            || !WPACKET_quic_write_vlint(pkt, first_ack_range))
        return 0;

    for (i = 1; i < num_ack_ranges; ++i) {
        uint64_t gap, range_len;

        gap         = ack->ack_ranges[i - 1].start - ack->ack_ranges[i].end - 2;
        range_len   = ack->ack_ranges[i].end - ack->ack_ranges[i].start;

        if (!WPACKET_quic_write_vlint(pkt, gap)
                || !WPACKET_quic_write_vlint(pkt, range_len))
            return 0;
    }

    if (ack->ecn_present)
        if (!WPACKET_quic_write_vlint(pkt, ack->ect0)
                || !WPACKET_quic_write_vlint(pkt, ack->ect1)
                || !WPACKET_quic_write_vlint(pkt, ack->ecnce))
            return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_reset_stream(WPACKET *pkt,
                                             const OSSL_QUIC_FRAME_RESET_STREAM *f)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_RESET_STREAM)
            || !WPACKET_quic_write_vlint(pkt, f->stream_id)
            || !WPACKET_quic_write_vlint(pkt, f->app_error_code)
            || !WPACKET_quic_write_vlint(pkt, f->final_size))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_stop_sending(WPACKET *pkt,
                                             const OSSL_QUIC_FRAME_STOP_SENDING *f)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_STOP_SENDING)
            || !WPACKET_quic_write_vlint(pkt, f->stream_id)
            || !WPACKET_quic_write_vlint(pkt, f->app_error_code))
        return 0;

    return 1;
}

void *ossl_quic_wire_encode_frame_crypto(WPACKET *pkt,
                                         const OSSL_QUIC_FRAME_CRYPTO *f)
{
    unsigned char *p = NULL;

    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_CRYPTO)
            || !WPACKET_quic_write_vlint(pkt, f->offset)
            || !WPACKET_quic_write_vlint(pkt, f->len)
            || !WPACKET_allocate_bytes(pkt, f->len, &p))
        return NULL;

    if (f->data != NULL)
        memcpy(p, f->data, f->len);

    return p;
}

int ossl_quic_wire_encode_frame_new_token(WPACKET *pkt,
                                          const uint8_t *token,
                                          size_t token_len)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_NEW_TOKEN)
            || !WPACKET_quic_write_vlint(pkt, token_len)
            || !WPACKET_memcpy(pkt, token, token_len))
        return 0;

    return 1;
}

void *ossl_quic_wire_encode_frame_stream(WPACKET *pkt,
                                         const OSSL_QUIC_FRAME_STREAM *f)
{
    unsigned char *p = NULL;
    uint64_t frame_type = OSSL_QUIC_FRAME_TYPE_STREAM;

    if (f->offset != 0)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_OFF;
    if (f->has_len)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_LEN;
    if (f->is_fin)
        frame_type |= OSSL_QUIC_FRAME_FLAG_STREAM_FIN;

    if (!encode_frame_hdr(pkt, frame_type)
            || !WPACKET_quic_write_vlint(pkt, f->stream_id))
        return NULL;

    if (f->offset != 0 && !WPACKET_quic_write_vlint(pkt, f->offset))
        return NULL;

    if (f->has_len && !WPACKET_quic_write_vlint(pkt, f->len))
        return NULL;

    if (!WPACKET_allocate_bytes(pkt, f->len, &p))
        return NULL;

    if (f->data != NULL)
        memcpy(p, f->data, f->len);

    return p;
}

int ossl_quic_wire_encode_frame_max_data(WPACKET *pkt,
                                         uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_MAX_DATA)
            || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_max_stream_data(WPACKET *pkt,
                                                uint64_t stream_id,
                                                uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA)
            || !WPACKET_quic_write_vlint(pkt, stream_id)
            || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_max_streams(WPACKET *pkt,
                                            char     is_unidirectional,
                                            uint64_t max_streams)
{
    if (!encode_frame_hdr(pkt, is_unidirectional ? OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_UNI
                                                 : OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI)
            || !WPACKET_quic_write_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_data_blocked(WPACKET *pkt,
                                             uint64_t max_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED)
            || !WPACKET_quic_write_vlint(pkt, max_data))
        return 0;

    return 1;
}


int ossl_quic_wire_encode_frame_stream_data_blocked(WPACKET *pkt,
                                                    uint64_t stream_id,
                                                    uint64_t max_stream_data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED)
            || !WPACKET_quic_write_vlint(pkt, stream_id)
            || !WPACKET_quic_write_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_streams_blocked(WPACKET *pkt,
                                                char is_unidirectional,
                                                uint64_t max_streams)
{
    if (!encode_frame_hdr(pkt, is_unidirectional ? OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_UNI
                                                 : OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI)
            || !WPACKET_quic_write_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_new_conn_id(WPACKET *pkt,
                                            const OSSL_QUIC_FRAME_NEW_CONN_ID *f)
{
    if (f->conn_id_len > 20)
        return 0;

    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID)
            || !WPACKET_quic_write_vlint(pkt, f->seq_num)
            || !WPACKET_quic_write_vlint(pkt, f->retire_prior_to)
            || !WPACKET_put_bytes_u8(pkt, f->conn_id_len)
            || !WPACKET_memcpy(pkt, f->conn_id, f->conn_id_len)
            || !WPACKET_memcpy(pkt, f->stateless_reset_token,
                               sizeof(f->stateless_reset_token)))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_retire_conn_id(WPACKET *pkt,
                                               uint64_t seq_num)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID)
            || !WPACKET_quic_write_vlint(pkt, seq_num))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_path_challenge(WPACKET *pkt,
                                               uint64_t data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE)
            || !WPACKET_put_bytes_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_path_response(WPACKET *pkt,
                                              uint64_t data)
{
    if (!encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE)
            || !WPACKET_put_bytes_u64(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_conn_close(WPACKET *pkt,
                                           const OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    if (!encode_frame_hdr(pkt, f->is_app ? OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_APP
                                         : OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT)
            || !WPACKET_quic_write_vlint(pkt, f->error_code))
        return 0;

    if (!f->is_app && !WPACKET_quic_write_vlint(pkt, f->frame_type))
        return 0;

    if (!WPACKET_quic_write_vlint(pkt, f->reason_len)
            || !WPACKET_memcpy(pkt, f->reason, f->reason_len))
        return 0;

    return 1;
}

int ossl_quic_wire_encode_frame_handshake_done(WPACKET *pkt)
{
    return encode_frame_hdr(pkt, OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE);
}

uint8_t *ossl_quic_wire_encode_transport_param_bytes(WPACKET *pkt,
                                                     uint64_t id,
                                                     const uint8_t *value,
                                                     size_t value_len)
{
    uint8_t *b = NULL;

    if (!WPACKET_quic_write_vlint(pkt, id)
            || !WPACKET_quic_write_vlint(pkt, value_len)
            || !WPACKET_allocate_bytes(pkt, value_len, (unsigned char **)&b))
        return NULL;

    if (value != NULL)
        memcpy(b, value, value_len);

    return b;
}

int ossl_quic_wire_encode_transport_param_int(WPACKET *pkt,
                                              uint64_t id,
                                              uint64_t value)
{
    if (!WPACKET_quic_write_vlint(pkt, id)
            || !WPACKET_quic_write_vlint(pkt, ossl_quic_vlint_encode_len(value))
            || !WPACKET_quic_write_vlint(pkt, value))
        return 0;

    return 1;
}

/*
 * QUIC Wire Format Decoding
 * =========================
 */
int ossl_quic_wire_peek_frame_header(PACKET *pkt, uint64_t *type)
{
    return PACKET_peek_quic_vlint(pkt, type);
}

int ossl_quic_wire_skip_frame_header(PACKET *pkt, uint64_t *type)
{
    return PACKET_get_quic_vlint(pkt, type);
}

static int expect_frame_header_mask(PACKET *pkt,
                                    uint64_t expected_frame_type,
                                    uint64_t mask_bits,
                                    uint64_t *actual_frame_type)
{
    uint64_t actual_frame_type_;

    if (!ossl_quic_wire_skip_frame_header(pkt, &actual_frame_type_)
            || (actual_frame_type_ & ~mask_bits) != expected_frame_type)
        return 0;

    if (actual_frame_type != NULL)
        *actual_frame_type = actual_frame_type_;

    return 1;
}

static int expect_frame_header(PACKET *pkt, uint64_t expected_frame_type)
{
    uint64_t actual_frame_type;

    if (!ossl_quic_wire_skip_frame_header(pkt, &actual_frame_type)
            || actual_frame_type != expected_frame_type)
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_ack(PACKET *pkt,
                                    uint32_t ack_delay_exponent,
                                    OSSL_ACKM_ACK *ack,
                                    uint64_t *total_ranges) {
    uint64_t frame_type, largest_ackd, ack_delay_raw,
             ack_range_count, first_ack_range, start, end, i;

    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_ACK_WITHOUT_ECN,
                                  1, &frame_type)
            || !PACKET_get_quic_vlint(pkt, &largest_ackd)
            || !PACKET_get_quic_vlint(pkt, &ack_delay_raw)
            || !PACKET_get_quic_vlint(pkt, &ack_range_count)
            || !PACKET_get_quic_vlint(pkt, &first_ack_range))
        return 0;

    if (first_ack_range > largest_ackd)
        return 0;

    start = largest_ackd - first_ack_range;

    if (ack != NULL) {
        ack->delay_time
            = ossl_time_multiply(OSSL_TIME_US,
                                 ossl_time_multiply(ack_delay_raw,
                                                    1UL << ack_delay_exponent));

        if (ack->num_ack_ranges > 0) {
            ack->ack_ranges[0].end   = largest_ackd;
            ack->ack_ranges[0].start = start;
        }
    }

    for (i = 0; i < ack_range_count; ++i) {
        uint64_t gap, len;

        if (!PACKET_get_quic_vlint(pkt, &gap)
                || !PACKET_get_quic_vlint(pkt, &len))
            return 0;

        end = start - gap - 2;
        if (start < gap + 2 || len > end)
            return 0;

        if (ack != NULL && i + 1 < ack->num_ack_ranges) {
            ack->ack_ranges[i + 1].start = start = end - len;
            ack->ack_ranges[i + 1].end   = end;
        }
    }

    if (ack != NULL && ack_range_count + 1 < ack->num_ack_ranges)
        ack->num_ack_ranges = ack_range_count + 1;

    if (total_ranges != NULL)
        *total_ranges = ack_range_count + 1;

    if (frame_type == OSSL_QUIC_FRAME_TYPE_ACK_WITH_ECN) {
        uint64_t ect0, ect1, ecnce;

        if (!PACKET_get_quic_vlint(pkt, &ect0)
                || !PACKET_get_quic_vlint(pkt, &ect1)
                || !PACKET_get_quic_vlint(pkt, &ecnce))
            return 0;

        if (ack != NULL) {
            ack->ect0           = ect0;
            ack->ect1           = ect1;
            ack->ecnce          = ecnce;
            ack->ecn_present    = 1;
        }
    } else if (ack != NULL) {
        ack->ecn_present = 0;
    }

    return 1;
}

int ossl_quic_wire_decode_frame_reset_stream(PACKET *pkt,
                                             OSSL_QUIC_FRAME_RESET_STREAM *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_RESET_STREAM)
            || !PACKET_get_quic_vlint(pkt, &f->stream_id)
            || !PACKET_get_quic_vlint(pkt, &f->app_error_code)
            || !PACKET_get_quic_vlint(pkt, &f->final_size))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stop_sending(PACKET *pkt,
                                             OSSL_QUIC_FRAME_STOP_SENDING *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_STOP_SENDING)
            || !PACKET_get_quic_vlint(pkt, &f->stream_id)
            || !PACKET_get_quic_vlint(pkt, &f->app_error_code))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_crypto(PACKET *pkt,
                                       OSSL_QUIC_FRAME_CRYPTO *f)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_CRYPTO)
            || !PACKET_get_quic_vlint(pkt, &f->offset)
            || !PACKET_get_quic_vlint(pkt, &f->len))
        return 0;

    if (PACKET_remaining(pkt) < f->len)
        return 0;

    f->data = PACKET_data(pkt);

    if (!PACKET_forward(pkt, f->len))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_new_token(PACKET         *pkt,
                                          const uint8_t **token,
                                          size_t         *token_len)
{
    uint64_t token_len_;

    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_NEW_TOKEN)
            || !PACKET_get_quic_vlint(pkt, &token_len_))
        return 0;

    if (token_len_ > SIZE_MAX)
        return 0;

    *token      = PACKET_data(pkt);
    *token_len  = token_len_;

    if (!PACKET_forward(pkt, token_len_))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stream(PACKET *pkt,
                                       OSSL_QUIC_FRAME_STREAM *f)
{
    uint64_t frame_type;

    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_STREAM,
                                  OSSL_QUIC_FRAME_FLAG_STREAM_MASK,
                                  &frame_type)
            || !PACKET_get_quic_vlint(pkt, &f->stream_id))
        return 0;

    if ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_OFF) != 0) {
        if (!PACKET_get_quic_vlint(pkt, &f->offset))
            return 0;
    } else {
        f->offset = 0;
    }

    f->has_len = ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_LEN) != 0);
    f->is_fin  = ((frame_type & OSSL_QUIC_FRAME_FLAG_STREAM_FIN) != 0);

    if (f->has_len) {
        if (!PACKET_get_quic_vlint(pkt, &f->len))
            return 0;

        if (f->len > PACKET_remaining(pkt))
            return 0;
    } else {
        f->len = PACKET_remaining(pkt);
    }

    f->data = PACKET_data(pkt);

    if (!PACKET_forward(pkt, f->len))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_max_data(PACKET *pkt,
                                         uint64_t *max_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_MAX_DATA)
            || !PACKET_get_quic_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_max_stream_data(PACKET *pkt,
                                                uint64_t *stream_id,
                                                uint64_t *max_stream_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAM_DATA)
            || !PACKET_get_quic_vlint(pkt, stream_id)
            || !PACKET_get_quic_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_max_streams(PACKET *pkt,
                                            uint64_t *max_streams)
{
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_MAX_STREAMS_BIDI,
                                  1, NULL)
            || !PACKET_get_quic_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_data_blocked(PACKET *pkt,
                                             uint64_t *max_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_DATA_BLOCKED)
            || !PACKET_get_quic_vlint(pkt, max_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_stream_data_blocked(PACKET *pkt,
                                                    uint64_t *stream_id,
                                                    uint64_t *max_stream_data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_STREAM_DATA_BLOCKED)
            || !PACKET_get_quic_vlint(pkt, stream_id)
            || !PACKET_get_quic_vlint(pkt, max_stream_data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_streams_blocked(PACKET *pkt,
                                                uint64_t *max_streams)
{
    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_STREAMS_BLOCKED_BIDI,
                                  1, NULL)
            || !PACKET_get_quic_vlint(pkt, max_streams))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_new_conn_id(PACKET *pkt,
                                            OSSL_QUIC_FRAME_NEW_CONN_ID *f)
{
    unsigned int len;

    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_NEW_CONN_ID)
            || !PACKET_get_quic_vlint(pkt, &f->seq_num)
            || !PACKET_get_quic_vlint(pkt, &f->retire_prior_to)
            || !PACKET_get_1(pkt, &len)
            || len > 20)
        return 0;

    f->conn_id      = PACKET_data(pkt);
    f->conn_id_len  = len;

    if (!PACKET_forward(pkt, len))
        return 0;

    if (!PACKET_copy_bytes(pkt, (unsigned char *)f->stateless_reset_token,
                           sizeof(f->stateless_reset_token)))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_retire_conn_id(PACKET *pkt,
                                               uint64_t *seq_num)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_RETIRE_CONN_ID)
            || !PACKET_get_quic_vlint(pkt, seq_num))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_path_challenge(PACKET *pkt,
                                               uint64_t *data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PATH_CHALLENGE)
            || !PACKET_get_net_8(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_path_response(PACKET *pkt,
                                              uint64_t *data)
{
    if (!expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PATH_RESPONSE)
            || !PACKET_get_net_8(pkt, data))
        return 0;

    return 1;
}

int ossl_quic_wire_decode_frame_conn_close(PACKET *pkt,
                                           OSSL_QUIC_FRAME_CONN_CLOSE *f)
{
    uint64_t frame_type, reason_len;

    if (!expect_frame_header_mask(pkt, OSSL_QUIC_FRAME_TYPE_CONN_CLOSE_TRANSPORT,
                                  1, &frame_type)
            || !PACKET_get_quic_vlint(pkt, &f->error_code))
        return 0;

    f->is_app = ((frame_type & 1) != 0);

    if (!f->is_app) {
        if (!PACKET_get_quic_vlint(pkt, &f->frame_type))
            return 0;
    } else {
        f->frame_type = 0;
    }

    if (!PACKET_get_quic_vlint(pkt, &reason_len)
            || reason_len > SIZE_MAX)
        return 0;

    if (!PACKET_get_bytes(pkt, (const unsigned char **)&f->reason, reason_len))
        return 0;

    f->reason_len = reason_len;
    return 1;
}

size_t ossl_quic_wire_decode_frame_padding(PACKET *pkt)
{
    const unsigned char *start = PACKET_data(pkt), *end = PACKET_end(pkt),
                        *p = start;

    for (; p < end; ++p)
        if (*p != 0)
            break;

    if (!PACKET_forward(pkt, p - start))
        return 0;

    return p - start;
}

int ossl_quic_wire_decode_frame_ping(PACKET *pkt)
{
    return expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_PING);
}

int ossl_quic_wire_decode_frame_handshake_done(PACKET *pkt)
{
    return expect_frame_header(pkt, OSSL_QUIC_FRAME_TYPE_HANDSHAKE_DONE);
}

int ossl_quic_wire_peek_transport_param(PACKET *pkt, uint64_t *id)
{
    return PACKET_peek_quic_vlint(pkt, id);
}

const uint8_t *ossl_quic_wire_decode_transport_param_bytes(PACKET *pkt,
                                                           uint64_t *id,
                                                           size_t *len)
{
    uint64_t len_;
    const uint8_t *b = NULL;

    if (!PACKET_get_quic_vlint(pkt, id)
            || !PACKET_get_quic_vlint(pkt, &len_))
        return NULL;

    if (len_ > SIZE_MAX
            || !PACKET_get_bytes(pkt, (const unsigned char **)&b, (size_t)len_))
        return NULL;

    *len = (size_t)len_;
    return b;
}

int ossl_quic_wire_decode_transport_param_int(PACKET *pkt,
                                              uint64_t *id,
                                              uint64_t *value)
{
    PACKET sub;

    sub.curr = ossl_quic_wire_decode_transport_param_bytes(pkt,
                                                           id, &sub.remaining);
    if (sub.curr == NULL)
        return 0;

    if (!PACKET_get_quic_vlint(&sub, value))
        return 0;

   return 1;
}
