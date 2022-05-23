/*
* Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
*
* Licensed under the Apache License 2.0 (the "License").  You may not use
* this file except in compliance with the License.  You can obtain a copy
* in the file LICENSE in the source distribution or at
* https://www.openssl.org/source/license.html
*/

#ifndef OSSL_INTERNAL_QUIC_PARAM_H
# define OSSL_INTERNAL_QUIC_PARAM_H
# pragma once

# define QUIC_TRANSPORT_PARAM_ORIGINAL_DESTINATIION_CONNECTION_ID        0x00
# define QUIC_TRANSPORT_PARAM_MAX_IDLE_TIMEOUT                           0x01
# define QUIC_TRANSPORT_PARAM_STATELESS_RESET_TOKEN                      0x02
# define QUIC_TRANSPORT_PARAM_MAX_UDP_PAYLOAD_SIZE                       0x03
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_DATA                           0x04
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL         0x05
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE        0x06
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAM_DATA_UNI                0x07
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_BIDI                   0x08
# define QUIC_TRANSPORT_PARAM_INITIAL_MAX_STREAMS_UNI                    0x09
# define QUIC_TRANSPORT_PARAM_ACK_DELAY_EXPONENT                         0x0A
# define QUIC_TRANSPORT_PARAM_MAX_ACK_DELAY                              0x0B
# define QUIC_TRANSPORT_PARAM_DISABLE_ACTIVE_MIGRATION                   0x0C
# define QUIC_TRANSPORT_PARAM_PREFERRED_ADDRESS                          0x0D
# define QUIC_TRANSPORT_PARAM_ACTIVE_CONNECTION_ID_LIMIT                 0x0E
# define QUIC_TRANSPORT_PARAM_INITIAL_SOURCE_CONNECTION_ID               0x0F
# define QUIC_TRANSPORT_PARAM_RETRY_SOURCE_CONNECTION_ID                 0x10

#endif
