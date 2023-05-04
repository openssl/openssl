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
#include "internal/quic_wire_pkt.h"

static const char *packet_type(int type)
{
    switch (type) {
    case QUIC_PKT_TYPE_INITIAL:
        return "Initial";

    case QUIC_PKT_TYPE_0RTT:
        return "0RTT";

    case QUIC_PKT_TYPE_HANDSHAKE:
        return "Handshake";

    case QUIC_PKT_TYPE_RETRY:
        return "Retry";

    case QUIC_PKT_TYPE_1RTT:
        return "1RTT";

    case QUIC_PKT_TYPE_VERSION_NEG:
        return "VersionNeg";

    default:
        return "Unknown";
    }
}

static const char *conn_id(QUIC_CONN_ID *id, char *buf, size_t buflen)
{
    size_t i;
    char *obuf = buf;

    if (id->id_len == 0)
        return "<zero length id>";

    if ((((size_t)id->id_len * 2) + 2) > buflen - 1)
        return "<id too long>"; /* Should never happen */

    buf[0] = '0';
    buf[1]= 'x';
    buf += 2;
    buflen -= 2;

    for (i = 0; i < id->id_len; i++, buflen -= 2, buf += 2)
        BIO_snprintf(buf, buflen, "%02x", id->id[i]);

    return obuf;
}

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

    case SSL3_RT_QUIC_PACKET:
        {
            PACKET pkt;
            QUIC_PKT_HDR hdr;
            /*
             * Max Conn id is 20 bytes (40 hex digits) plus "0x" bytes plus NUL
             * terminator
             */
            char tmpbuf[43];
            size_t i;

            if (!PACKET_buf_init(&pkt, buf, msglen))
                return 0;
            /* Decode the packet header */
            /*
             * TODO(QUIC): We need to query the short connection id len here,
             *             e.g. via some API SSL_get_short_conn_id_len()
             */
            if (ossl_quic_wire_decode_pkt_hdr(&pkt, 0, 0, &hdr, NULL) != 1)
                return 0;

            BIO_puts(bio, write_p ? "Sent" : "Received");
            BIO_puts(bio, " Packet\n");
            BIO_printf(bio, "  Packet Type: %s\n", packet_type(hdr.type));
            if (hdr.type != QUIC_PKT_TYPE_1RTT)
                BIO_printf(bio, "  Version: 0x%08x\n", hdr.version);
            BIO_printf(bio, "  Destination Conn Id: %s\n",
                       conn_id(&hdr.dst_conn_id, tmpbuf, sizeof(tmpbuf)));
            if (hdr.type != QUIC_PKT_TYPE_1RTT)
                BIO_printf(bio, "  Source Conn Id: %s\n",
                           conn_id(&hdr.src_conn_id, tmpbuf, sizeof(tmpbuf)));
            BIO_printf(bio, "  Payload length: %zu\n", hdr.len);
            if (hdr.type == QUIC_PKT_TYPE_INITIAL) {
                BIO_puts(bio, "  Token: ");
                if (hdr.token_len == 0) {
                    BIO_puts(bio, "<zerlo length token>");
                } else {
                    for (i = 0; i < hdr.token_len; i++)
                        BIO_printf(bio, "%02x", hdr.token[i]);
                }
                BIO_puts(bio, "\n");
            }
            if (hdr.type != QUIC_PKT_TYPE_VERSION_NEG
                    && hdr.type != QUIC_PKT_TYPE_RETRY) {
                BIO_puts(bio, "  Packet Number: 0x");
                /* Will always be at least 1 byte */
                for (i = 0; i < hdr.pn_len; i++)
                    BIO_printf(bio, "%02x", hdr.pn[i]);
                BIO_puts(bio, "\n");
            }
            break;
        }


    default:
        /* Unrecognised content_type. We defer to SSL_trace */
        return 0;
    }

    return 1;
}
