/*
 * Copyright 2015-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "packet_locl.h"

/*
 * Allocate bytes in the WPACKET_BUF for the output. This reserves the bytes
 * and count them as "written", but doesn't actually do the writing.
 */
static unsigned char *WPACKET_BUF_allocate(WPACKET_BUF *wbuf, size_t len)
{
    unsigned char *ret = wbuf->curr;

    if (SIZE_MAX - wbuf->written < len)
        return 0;

    if (wbuf->maxsize > 0 && wbuf->written + len > wbuf->maxsize)
        return 0;

    if (wbuf->buf->length - wbuf->written < len) {
        size_t newlen;

        if (wbuf->buf->length > SIZE_MAX / 2)
            newlen = SIZE_MAX;
        else
            newlen = wbuf->buf->length * 2;
        if (BUF_MEM_grow(wbuf->buf, newlen) == 0)
            return NULL;
    }
    wbuf->written += len;
    wbuf->curr += len;

    return ret;
}

/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
{
    WPACKET_BUF *wbuf;
    /* Sanity check */
    if (buf == NULL)
        return 0;

    wbuf = OPENSSL_zalloc(sizeof(WPACKET_BUF));
    if (wbuf == NULL) {
        pkt->isclosed = 1;
        return 0;
    }

    wbuf->buf = buf;
    wbuf->curr = (unsigned char *)buf->data;
    wbuf->written = 0;
    wbuf->maxsize = 0;

    pkt->parent = NULL;
    pkt->wbuf = wbuf;
    pkt->pwritten = lenbytes;
    pkt->lenbytes = lenbytes;
    pkt->haschild = 0;
    pkt->isclosed = 0;

    if (lenbytes == 0) {
        pkt->packet_len = NULL;
        return 1;
    }

    pkt->packet_len = WPACKET_BUF_allocate(wbuf, lenbytes);
    if (pkt->packet_len == NULL) {
        OPENSSL_free(wbuf);
        pkt->wbuf = NULL;
        pkt->isclosed = 1;
        return 0;
    }

    return 1;
}

/*
 * Same as WPACKET_init_len except there is no preallocation of the WPACKET
 * length.
 */
int WPACKET_init(WPACKET *pkt, BUF_MEM *buf)
{
    return WPACKET_init_len(pkt, buf, 0);
}

/*
 * Set the WPACKET length, and the location for where we should write that
 * length. Normally this will be at the start of the WPACKET, and therefore
 * the WPACKET would have been initialised via WPACKET_init_len(). However there
 * is the possibility that the length needs to be written to some other location
 * other than the start of the WPACKET. In that case init via WPACKET_init() and
 * then set the location for the length using this function.
 */
int WPACKET_set_packet_len(WPACKET *pkt, unsigned char *packet_len,
                           size_t lenbytes)
{
    /* We only allow this to be set once */
    if (pkt->isclosed || pkt->packet_len != NULL)
        return 0;

    pkt->lenbytes = lenbytes;
    pkt->packet_len = packet_len;

    return 1;
}

int WPACKET_set_flags(WPACKET *pkt, unsigned int flags)
{
    pkt->flags = flags;

    return 1;
}

/*
 * Closes the WPACKET and marks it as invalid for future writes. It also writes
 * out the length of the packet to the required location (normally the start
 * of the WPACKET) if appropriate. A WPACKET cannot be closed if it has an
 * active sub-packet.
 */
int WPACKET_close(WPACKET *pkt)
{
    size_t packlen;

    if (pkt->isclosed || pkt->haschild)
        return 0;

    packlen = pkt->wbuf->written - pkt->pwritten;
    if (packlen == 0 && pkt->flags & OPENSSL_WPACKET_FLAGS_NON_ZERO_LENGTH)
        return 0;

    if (packlen == 0
            && pkt->flags & OPENSSL_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) {
        /* Deallocate any bytes allocated for the length of the WPACKET */
        if ((pkt->wbuf->curr - pkt->lenbytes) == pkt->packet_len) {
            pkt->wbuf->written -= pkt->lenbytes;
            pkt->wbuf->curr -= pkt->lenbytes;
        }

        /* Don't write out the packet length */
        pkt->packet_len = NULL;
    }

    /* Write out the WPACKET length if needed */
    if (pkt->packet_len != NULL) {
        size_t lenbytes;

        lenbytes = pkt->lenbytes;

        for (; lenbytes > 0; lenbytes--) {
            pkt->packet_len[lenbytes - 1] = (unsigned char)(packlen & 0xff);
            packlen >>= 8;
        }
        if (packlen > 0) {
            /*
             * We've extended beyond the max allowed for the number of len bytes
             */
            return 0;
        }
    }

    if (pkt->parent != NULL) {
        if (pkt->parent->haschild != 1) {
            /* Should not happen! */
            return 0;
        }
        pkt->parent->haschild = 0;
        pkt->parent = NULL;
    }

    pkt->isclosed = 1;

    return 1;
}

/*
 * Initialise a new sub-packet (|subpkt|), based on a parent (|pkt|).
 * Additionally |lenbytes| of data is preallocated at the start of the
 * sub-packet to store its length once we know it.
 */
int WPACKET_get_sub_packet_len(WPACKET *pkt, WPACKET *subpkt, size_t lenbytes)
{
    if (pkt->isclosed || pkt->haschild || subpkt == NULL)
        return 0;

    subpkt->parent = pkt;
    subpkt->wbuf = pkt->wbuf;
    subpkt->pwritten = pkt->wbuf->written + lenbytes;
    subpkt->lenbytes = lenbytes;
    subpkt->haschild = 0;
    subpkt->isclosed = 0;

    if (lenbytes == 0) {
        subpkt->packet_len = NULL;
        pkt->haschild = 1;
        return 1;
    }

    subpkt->packet_len = WPACKET_BUF_allocate(pkt->wbuf, lenbytes);
    if (subpkt->packet_len == NULL) {
        subpkt->isclosed = 1;
        return 0;
    }

    pkt->haschild = 1;

    return 1;
}

/*
 * Same as WPACKET_get_sub_packet_len() except no bytes are pre-allocated for
 * the sub-packet length.
 */
int WPACKET_get_sub_packet(WPACKET *pkt, WPACKET *subpkt)
{
    return WPACKET_get_sub_packet_len(pkt, subpkt, 0);
}

/*
 * Allocate some bytes in the WPACKET for writing. That number of bytes is
 * marked as having been written, and a pointer to their location is stored in
 * |*allocbytes|.
 */
int WPACKET_allocate_bytes(WPACKET *pkt, size_t bytes,
                           unsigned char **allocbytes)
{
    unsigned char *data;

    if (pkt->isclosed || pkt->haschild || bytes == 0)
        return 0;

    data = WPACKET_BUF_allocate(pkt->wbuf, bytes);
    if (data == NULL)
        return 0;

    *allocbytes = data;

    return 1;
}

/*
 * Write the value stored in |val| into the WPACKET. The value will consome
 * |bytes| amount of storage. An error will occur if |val| cannot be accommdated
 * in |bytes| storage, e.g. attempting to write the value 256 into 1 byte will
 * fail.
 */
int WPACKET_put_bytes(WPACKET *pkt, unsigned int val, size_t bytes)
{
    unsigned char *data;

    if (bytes > sizeof(unsigned int)
            || !WPACKET_allocate_bytes(pkt, bytes, &data))
        return 0;

    data += bytes - 1;
    for (; bytes > 0; bytes--) {
        *data = (unsigned char)(val & 0xff);
        data--;
        val >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (val > 0)
        return 0;

    return 1;
}

/*
 * Set a maximum size that we will not allow the WPACKET to grow beyond. If not
 * set then there is no maximum.
 */
int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)
{
    pkt->wbuf->maxsize = maxsize;

    return 1;
}

/*
 * Copy |len| bytes of data from |*src| into the WPACKET.
 */
int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    memcpy(dest, src, len);

    return 1;
}

/*
 * Return the total number of bytes written so far to the underlying buffer.
 * This might includes bytes written by a parent WPACKET.
 */
int WPACKET_get_total_written(WPACKET *pkt, size_t *written)
{
    if (pkt->isclosed || written == NULL)
        return 0;

    *written = pkt->wbuf->curr - (unsigned char *)pkt->wbuf->buf->data;

    return 1;
}

/*
 * Returns the length of this WPACKET so far. This excludes any bytes allocated
 * for the length itself.
 */
int WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    if (pkt->isclosed || len == NULL)
        return 0;

    *len = pkt->wbuf->written - pkt->pwritten;

    return 1;
}
