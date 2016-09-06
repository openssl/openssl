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
 * Allocate bytes in the WPACKET for the output. This reserves the bytes
 * and count them as "written", but doesn't actually do the writing.
 */
int WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (pkt->subs == NULL || len == 0)
        return 0;

    if (SIZE_MAX - pkt->written < len)
        return 0;

    if (pkt->maxsize > 0 && pkt->written + len > pkt->maxsize)
        return 0;

    if (pkt->buf->length - pkt->written < len) {
        size_t newlen;

        if (pkt->buf->length > SIZE_MAX / 2)
            newlen = SIZE_MAX;
        else
            newlen = pkt->buf->length * 2;
        if (BUF_MEM_grow(pkt->buf, newlen) == 0)
            return 0;
    }
    pkt->written += len;
    *allocbytes = pkt->curr;
    pkt->curr += len;

    return 1;
}

/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
{
    /* Sanity check */
    if (buf == NULL)
        return 0;

    pkt->buf = buf;
    pkt->curr = (unsigned char *)buf->data;
    pkt->written = 0;
    pkt->maxsize = 0;

    pkt->subs = OPENSSL_zalloc(sizeof(*pkt->subs));
    if (pkt->subs == NULL)
        return 0;

    if (lenbytes == 0)
        return 1;

    pkt->subs->pwritten = lenbytes;
    pkt->subs->lenbytes = lenbytes;

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &(pkt->subs->packet_len))) {
        OPENSSL_free(pkt->subs);
        pkt->subs = NULL;
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
    if (pkt->subs == NULL)
        return 0;

    pkt->subs->lenbytes = lenbytes;
    pkt->subs->packet_len = packet_len;

    return 1;
}

int WPACKET_set_flags(WPACKET *pkt, unsigned int flags)
{
    if (pkt->subs == NULL)
        return 0;

    pkt->subs->flags = flags;

    return 1;
}


/*
 * Internal helper function used by WPACKET_close() and WPACKET_finish() to
 * close a sub-packet and write out its length if necessary.
 */
static int wpacket_intern_close(WPACKET *pkt)
{
    size_t packlen;
    WPACKET_SUB *sub = pkt->subs;

    packlen = pkt->written - sub->pwritten;
    if (packlen == 0
            && sub->flags & OPENSSL_WPACKET_FLAGS_NON_ZERO_LENGTH)
        return 0;

    if (packlen == 0
            && sub->flags & OPENSSL_WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) {
        /* Deallocate any bytes allocated for the length of the WPACKET */
        if ((pkt->curr - sub->lenbytes) == sub->packet_len) {
            pkt->written -= sub->lenbytes;
            pkt->curr -= sub->lenbytes;
        }

        /* Don't write out the packet length */
        sub->packet_len = NULL;
    }

    /* Write out the WPACKET length if needed */
    if (sub->packet_len != NULL) {
        size_t lenbytes;

        lenbytes = sub->lenbytes;

        for (; lenbytes > 0; lenbytes--) {
            sub->packet_len[lenbytes - 1]
                = (unsigned char)(packlen & 0xff);
            packlen >>= 8;
        }
        if (packlen > 0) {
            /*
             * We've extended beyond the max allowed for the number of len bytes
             */
            return 0;
        }
    }

    pkt->subs = sub->parent;
    OPENSSL_free(sub);

    return 1;
}

/*
 * Closes the most recent sub-packet. It also writes out the length of the
 * packet to the required location (normally the start of the WPACKET) if
 * appropriate. The top level WPACKET should be closed using WPACKET_finish()
 * instead of this function.
 */
int WPACKET_close(WPACKET *pkt)
{
    if (pkt->subs == NULL || pkt->subs->parent == NULL)
        return 0;

    return wpacket_intern_close(pkt);
}

/*
 * The same as WPACKET_close() but only for the top most WPACKET. Additionally
 * frees memory resources for this WPACKET.
 */
int WPACKET_finish(WPACKET *pkt)
{
    int ret;

    if (pkt->subs == NULL || pkt->subs->parent != NULL)
        return 0;

    ret = wpacket_intern_close(pkt);

    /* We free up memory no matter whether |ret| is zero or not */
    OPENSSL_free(pkt->subs);
    pkt->subs = NULL;
    return ret;
}

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the start of the sub-packet to store its length once we know it.
 */
int WPACKET_start_sub_packet_len(WPACKET *pkt, size_t lenbytes)
{
    WPACKET_SUB *sub;

    if (pkt->subs == NULL)
        return 0;

    sub = OPENSSL_zalloc(sizeof(*sub));
    if (sub == NULL)
        return 0;

    sub->parent = pkt->subs;
    pkt->subs = sub;
    sub->pwritten = pkt->written + lenbytes;
    sub->lenbytes = lenbytes;

    if (lenbytes == 0) {
        sub->packet_len = NULL;
        return 1;
    }

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &sub->packet_len)) {
        return 0;
    }

    return 1;
}

/*
 * Same as WPACKET_get_sub_packet_len() except no bytes are pre-allocated for
 * the sub-packet length.
 */
int WPACKET_start_sub_packet(WPACKET *pkt)
{
    return WPACKET_start_sub_packet_len(pkt, 0);
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
    pkt->maxsize = maxsize;

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
    if (pkt->subs == NULL || written == NULL)
        return 0;

    *written = pkt->written;

    return 1;
}

/*
 * Returns the length of the last sub-packet. This excludes any bytes allocated
 * for the length itself.
 */
int WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    if (pkt->subs == NULL || len == NULL)
        return 0;

    *len = pkt->written - pkt->subs->pwritten;

    return 1;
}
