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
