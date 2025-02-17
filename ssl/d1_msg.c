/*
 * Copyright 2005-2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssl_local.h"

int dtls1_write_app_data_bytes(SSL *s, uint8_t type, const void *buf_,
                               size_t len, size_t *written)
{
    int i;
    SSL_CONNECTION *sc = SSL_CONNECTION_FROM_SSL_ONLY(s);

    if (sc == NULL)
        return -1;

    if (SSL_in_init(s) && !ossl_statem_get_in_handshake(sc)) {
        i = sc->handshake_func(s);
        if (i < 0)
            return i;
        if (i == 0) {
            ERR_raise(ERR_LIB_SSL, SSL_R_SSL_HANDSHAKE_FAILURE);
            return -1;
        }
    }

    if (len > SSL3_RT_MAX_PLAIN_LENGTH) {
        ERR_raise(ERR_LIB_SSL, SSL_R_DTLS_MESSAGE_TOO_BIG);
        return -1;
    }

    return dtls1_write_bytes(sc, type, buf_, len, written);
}
