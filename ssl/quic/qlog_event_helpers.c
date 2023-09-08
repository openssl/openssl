/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/qlog_event_helpers.h"
#include "internal/common.h"
#include "internal/quic_channel.h"
#include "internal/quic_error.h"

void ossl_qlog_event_connectivity_connection_started(QLOG *qlog,
                                                     const QUIC_CONN_ID *init_dcid)
{
#ifndef OPENSSL_NO_QLOG
    QLOG_EVENT_BEGIN(qlog, connectivity, connection_started)
        QLOG_STR("protocol", "quic");
        QLOG_CID("dst_cid", init_dcid);
    QLOG_EVENT_END()
#endif
}

#ifndef OPENSSL_NO_QLOG
static const char *map_state_to_qlog(uint32_t state,
                                     int handshake_complete,
                                     int handshake_confirmed)
{
    switch (state) {
    default:
    case QUIC_CHANNEL_STATE_IDLE:
        return NULL;

    case QUIC_CHANNEL_STATE_ACTIVE:
        if (handshake_confirmed)
            return "handshake_confirmed";
        else if (handshake_complete)
            return "handshake_complete";
        else
            return "attempted";

    case QUIC_CHANNEL_STATE_TERMINATING_CLOSING:
        return "closing";

    case QUIC_CHANNEL_STATE_TERMINATING_DRAINING:
        return "draining";

    case QUIC_CHANNEL_STATE_TERMINATED:
        return "closed";
    }
}
#endif

void ossl_qlog_event_connectivity_connection_state_updated(QLOG *qlog,
                                                           uint32_t old_state,
                                                           uint32_t new_state,
                                                           int handshake_complete,
                                                           int handshake_confirmed)
{
#ifndef OPENSSL_NO_QLOG
    const char *state_s;

    QLOG_EVENT_BEGIN(qlog, connectivity, connection_state_updated)
        state_s = map_state_to_qlog(new_state,
                                    handshake_complete,
                                    handshake_confirmed);

        if (state_s != NULL)
            QLOG_STR("state", state_s);
    QLOG_EVENT_END()
#endif
}

#ifndef OPENSSL_NO_QLOG
static const char *quic_err_to_qlog(uint64_t error_code)
{
    switch (error_code) {
        case QUIC_ERR_INTERNAL_ERROR:
            return "internal_error";
        case QUIC_ERR_CONNECTION_REFUSED:
            return "connection_refused";
        case QUIC_ERR_FLOW_CONTROL_ERROR:
            return "flow_control_error";
        case QUIC_ERR_STREAM_LIMIT_ERROR:
            return "stream_limit_error";
        case QUIC_ERR_STREAM_STATE_ERROR:
            return "stream_state_error";
        case QUIC_ERR_FINAL_SIZE_ERROR:
            return "final_size_error";
        case QUIC_ERR_FRAME_ENCODING_ERROR:
            return "frame_encoding_error";
        case QUIC_ERR_TRANSPORT_PARAMETER_ERROR:
            return "transport_parameter_error";
        case QUIC_ERR_CONNECTION_ID_LIMIT_ERROR:
            return "connection_id_limit_error";
        case QUIC_ERR_PROTOCOL_VIOLATION:
            return "protocol_violation";
        case QUIC_ERR_INVALID_TOKEN:
            return "invalid_token";
        case QUIC_ERR_APPLICATION_ERROR:
            return "application_error";
        case QUIC_ERR_CRYPTO_BUFFER_EXCEEDED:
            return "crypto_buffer_exceeded";
        case QUIC_ERR_KEY_UPDATE_ERROR:
            return "key_update_error";
        case QUIC_ERR_AEAD_LIMIT_REACHED:
            return "aead_limit_reached";
        case QUIC_ERR_NO_VIABLE_PATH:
            return "no_viable_path";
        default:
            return NULL;
    }
}
#endif

void ossl_qlog_event_connectivity_connection_closed(QLOG *qlog,
                                                    const QUIC_TERMINATE_CAUSE *tcause)
{
#ifndef OPENSSL_NO_QLOG
    QLOG_EVENT_BEGIN(qlog, connectivity, connection_closed)
        QLOG_STR("owner", tcause->remote ? "remote" : "local");
        if (tcause->app) {
            QLOG_U64("application_code", tcause->error_code);
        } else {
            const char *m = quic_err_to_qlog(tcause->error_code);
            char ce[32];

            if (tcause->error_code >= QUIC_ERR_CRYPTO_ERR_BEGIN
                && tcause->error_code <= QUIC_ERR_CRYPTO_ERR_END) {
                snprintf(ce, sizeof(ce), "crypto_error_0x%03llx",
                         (unsigned long long)tcause->error_code);
                m = ce;
            }
            /* TODO(QLOG): Consider adding ERR information in the output. */

            if (m != NULL)
                QLOG_STR("connection_code", m);
            else
                QLOG_U64("connection_code", tcause->error_code);
        }

        QLOG_STR_LEN("reason", tcause->reason, tcause->reason_len);
    QLOG_EVENT_END()
#endif
}
