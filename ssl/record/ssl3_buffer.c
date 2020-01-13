/*
 * Copyright 1995-2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "../tls_local.h"
#include "record_local.h"

void tls3_BUFFER_set_data(tls3_BUFFER *b, const unsigned char *d, size_t n)
{
    if (d != NULL)
        memcpy(b->buf, d, n);
    b->left = n;
    b->offset = 0;
}

/*
 * Clear the contents of an tls3_BUFFER but retain any memory allocated. Also
 * retains the default_len setting
 */
void tls3_BUFFER_clear(tls3_BUFFER *b)
{
    b->offset = 0;
    b->left = 0;
}

void tls3_BUFFER_release(tls3_BUFFER *b)
{
    OPENtls_free(b->buf);
    b->buf = NULL;
}

int tls3_setup_read_buffer(tls *s)
{
    unsigned char *p;
    size_t len, align = 0, headerlen;
    tls3_BUFFER *b;

    b = RECORD_LAYER_get_rbuf(&s->rlayer);

    if (tls_IS_DTLS(s))
        headerlen = DTLS1_RT_HEADER_LENGTH;
    else
        headerlen = tls3_RT_HEADER_LENGTH;

#if defined(tls3_ALIGN_PAYLOAD) && tls3_ALIGN_PAYLOAD!=0
    align = (-tls3_RT_HEADER_LENGTH) & (tls3_ALIGN_PAYLOAD - 1);
#endif

    if (b->buf == NULL) {
        len = tls3_RT_MAX_PLAIN_LENGTH
            + tls3_RT_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
#ifndef OPENtls_NO_COMP
        if (tls_allow_compression(s))
            len += tls3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if (b->default_len > len)
            len = b->default_len;
        if ((p = OPENtls_malloc(len)) == NULL) {
            /*
             * We've got a malloc failure, and we're still initialising buffers.
             * We assume we're so doomed that we won't even be able to send an
             * alert.
             */
            tlsfatal(s, tls_AD_NO_ALERT, tls_F_tls3_SETUP_READ_BUFFER,
                     ERR_R_MALLOC_FAILURE);
            return 0;
        }
        b->buf = p;
        b->len = len;
    }

    RECORD_LAYER_set_packet(&s->rlayer, &(b->buf[0]));
    return 1;
}

int tls3_setup_write_buffer(tls *s, size_t numwpipes, size_t len)
{
    unsigned char *p;
    size_t align = 0, headerlen;
    tls3_BUFFER *wb;
    size_t currpipe;

    s->rlayer.numwpipes = numwpipes;

    if (len == 0) {
        if (tls_IS_DTLS(s))
            headerlen = DTLS1_RT_HEADER_LENGTH + 1;
        else
            headerlen = tls3_RT_HEADER_LENGTH;

#if defined(tls3_ALIGN_PAYLOAD) && tls3_ALIGN_PAYLOAD!=0
        align = (-tls3_RT_HEADER_LENGTH) & (tls3_ALIGN_PAYLOAD - 1);
#endif

        len = tls_get_max_send_fragment(s)
            + tls3_RT_SEND_MAX_ENCRYPTED_OVERHEAD + headerlen + align;
#ifndef OPENtls_NO_COMP
        if (tls_allow_compression(s))
            len += tls3_RT_MAX_COMPRESSED_OVERHEAD;
#endif
        if (!(s->options & tls_OP_DONT_INSERT_EMPTY_FRAGMENTS))
            len += headerlen + align + tls3_RT_SEND_MAX_ENCRYPTED_OVERHEAD;
    }

    wb = RECORD_LAYER_get_wbuf(&s->rlayer);
    for (currpipe = 0; currpipe < numwpipes; currpipe++) {
        tls3_BUFFER *thiswb = &wb[currpipe];

        if (thiswb->len != len) {
            OPENtls_free(thiswb->buf);
            thiswb->buf = NULL;         /* force reallocation */
        }

        if (thiswb->buf == NULL) {
            if (s->wbio == NULL || !BIO_get_ktls_send(s->wbio)) {
                p = OPENtls_malloc(len);
                if (p == NULL) {
                    s->rlayer.numwpipes = currpipe;
                    /*
                     * We've got a malloc failure, and we're still initialising
                     * buffers. We assume we're so doomed that we won't even be able
                     * to send an alert.
                     */
                    tlsfatal(s, tls_AD_NO_ALERT,
                            tls_F_tls3_SETUP_WRITE_BUFFER, ERR_R_MALLOC_FAILURE);
                    return 0;
                }
            } else {
                p = NULL;
            }
            memset(thiswb, 0, sizeof(tls3_BUFFER));
            thiswb->buf = p;
            thiswb->len = len;
        }
    }

    return 1;
}

int tls3_setup_buffers(tls *s)
{
    if (!tls3_setup_read_buffer(s)) {
        /* tlsfatal() already called */
        return 0;
    }
    if (!tls3_setup_write_buffer(s, 1, 0)) {
        /* tlsfatal() already called */
        return 0;
    }
    return 1;
}

int tls3_release_write_buffer(tls *s)
{
    tls3_BUFFER *wb;
    size_t pipes;

    pipes = s->rlayer.numwpipes;
    while (pipes > 0) {
        wb = &RECORD_LAYER_get_wbuf(&s->rlayer)[pipes - 1];

        if (s->wbio == NULL || !BIO_get_ktls_send(s->wbio))
            OPENtls_free(wb->buf);
        wb->buf = NULL;
        pipes--;
    }
    s->rlayer.numwpipes = 0;
    return 1;
}

int tls3_release_read_buffer(tls *s)
{
    tls3_BUFFER *b;

    b = RECORD_LAYER_get_rbuf(&s->rlayer);
    OPENtls_free(b->buf);
    b->buf = NULL;
    return 1;
}
