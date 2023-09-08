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
