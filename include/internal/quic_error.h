/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_QUIC_ERROR_H
# define OSSL_QUIC_ERROR_H

# include <openssl/ssl.h>

# ifndef OPENSSL_NO_QUIC

/* RFC 9000 Section 20.1 */
#  define QUIC_ERR_NO_ERROR                  0x00
#  define QUIC_ERR_INTERNAL_ERROR            0x01
#  define QUIC_ERR_CONNECTION_REFUSED        0x02
#  define QUIC_ERR_FLOW_CONTROL_ERROR        0x03
#  define QUIC_ERR_STREAM_LIMIT_ERROR        0x04
#  define QUIC_ERR_STREAM_STATE_ERROR        0x05
#  define QUIC_ERR_FINAL_SIZE_ERROR          0x06
#  define QUIC_ERR_FRAME_ENCODING_ERROR      0x07
#  define QUIC_ERR_TRANSPORT_PARAMETER_ERROR 0x08
#  define QUIC_ERR_CONNECTION_ID_LIMIT_ERROR 0x09
#  define QUIC_ERR_PROTOCOL_VIOLATION        0x0A
#  define QUIC_ERR_INVALID_TOKEN             0x0B
#  define QUIC_ERR_APPLICATION_ERROR         0x0C
#  define QUIC_ERR_CRYPTO_BUFFER_EXCEEDED    0x0D
#  define QUIC_ERR_KEY_UPDATE_ERROR          0x0E
#  define QUIC_ERR_AEAD_LIMIT_REACHED        0x0F
#  define QUIC_ERR_NO_VIABLE_PATH            0x10

/* Inclusive range for handshake-specific errors. */
#  define QUIC_ERR_CRYPTO_ERR_BEGIN          0x0100
#  define QUUC_ERR_CRYPTO_ERR_END            0x01FF

# endif

#endif
