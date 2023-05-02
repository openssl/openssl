/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bio.h>
#include "../ssl_local.h"

int ossl_quic_trace(int write_p, int version, int content_type,
                    const void *buf, size_t msglen, SSL *ssl, void *arg)
{
    BIO *bio = arg;

    switch (content_type) {
    case SSL3_RT_QUIC_DATAGRAM:
        BIO_puts(bio, write_p ? "Sent" : "Received");
        /*
         * Unfortunately there is no way of receiving auxilliary information
         * about the datagram through the msg_callback API such as the peer
         * address
         */
        BIO_printf(bio, " Datagram\n  Length: %zu\n", msglen);
        break;

    default:
        /* Unrecognised content_type. We defer to SSL_trace */
        return 0;
    }

    return 1;
}
