/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QLOG_EVENT_HELPERS_H
# define OSSL_QLOG_EVENT_HELPERS_H

# include <openssl/ssl.h>
# include "internal/qlog.h"
# include "internal/quic_types.h"
# include "internal/quic_channel.h"

/* connectivity:connection_started */
void ossl_qlog_event_connectivity_connection_started(QLOG *qlog,
                                                     const QUIC_CONN_ID *init_dcid);

/* connectivity:connection_state_updated */
void ossl_qlog_event_connectivity_connection_state_updated(QLOG *qlog,
                                                           uint32_t old_state,
                                                           uint32_t new_state,
                                                           int handshake_complete,
                                                           int handshake_confirmed);

/* connectivity:connection_closed */
void ossl_qlog_event_connectivity_connection_closed(QLOG *qlog,
                                                    const QUIC_TERMINATE_CAUSE *tcause);

#endif
