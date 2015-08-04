/* ssl/packet_locl.h */
/*
 * Written by Matt Caswell for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 2015 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */

#ifndef HEADER_PACKET_LOCL_H
# define HEADER_PACKET_LOCL_H

# include <string.h>
# include <openssl/bn.h>
# include <openssl/buffer.h>
# include "e_os.h"

# ifdef __cplusplus
extern "C" {
# endif

typedef struct {
    /* Pointer to the start of the buffer data */
    unsigned char *start;

    /* Pointer to the first byte after the end of the buffer data */
    unsigned char *end;

    /* Pointer to where we are currently reading from */
    unsigned char *curr;
} PACKET;

/*
 * Returns 1 if there are exactly |len| bytes left to be read from |pkt|
 * and 0 otherwise
 */
__owur static inline size_t PACKET_remaining(PACKET *pkt)
{
    return (size_t)(pkt->end - pkt->curr);
}

/*
 * Initialise a PACKET with |len| bytes held in |buf|. This does not make a
 * copy of the data so |buf| must be present for the whole time that the PACKET
 * is being used.
 */
static inline int PACKET_buf_init(PACKET *pkt, unsigned char *buf, size_t len)
{
    pkt->start = pkt->curr = buf;
    pkt->end = pkt->start + len;

    /* Sanity checks */
    if (pkt->start > pkt->end
            || pkt->curr < pkt->start
            || pkt->curr > pkt->end
            || len != (size_t)(pkt->end - pkt->start)) {
        return 0;
    }

    return 1;
}

/*
 * Peek ahead and initialize |subpkt| with the next |len| bytes read from |pkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static inline int PACKET_peek_sub_packet(PACKET *pkt, PACKET *subpkt,
                                               size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    PACKET_buf_init(subpkt, pkt->curr, len);

    return 1;
}

/*
 * Initialize |subpkt| with the next |len| bytes read from |pkt|. Data is not
 * copied: the |subpkt| packet will share its underlying buffer with the
 * original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static inline int PACKET_get_sub_packet(PACKET *pkt, PACKET *subpkt,
                                               size_t len)
{
    if (!PACKET_peek_sub_packet(pkt, subpkt, len))
        return 0;

    pkt->curr += len;

    return 1;
}

/* Peek ahead at 2 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static inline int PACKET_peek_net_2(PACKET *pkt, unsigned int *data)
{
    if (PACKET_remaining(pkt) < 2)
        return 0;

    *data  = ((unsigned int)(*pkt->curr)) <<  8;
    *data |= *(pkt->curr + 1);

    return 1;
}

/* Equivalent of n2s */
/* Get 2 bytes in network order from |pkt| and store the value in |*data| */
__owur static inline int PACKET_get_net_2(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_net_2(pkt, data))
        return 0;

    pkt->curr += 2;

    return 1;
}

/* Peek ahead at 3 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static inline int PACKET_peek_net_3(PACKET *pkt, unsigned long *data)
{
    if (PACKET_remaining(pkt) < 3)
        return 0;

    *data  = ((unsigned long)(*pkt->curr)) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 1))) <<  8;
    *data |= *(pkt->curr + 2);

    return 1;
}

/* Equivalent of n2l3 */
/* Get 3 bytes in network order from |pkt| and store the value in |*data| */
__owur static inline int PACKET_get_net_3(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_3(pkt, data))
        return 0;

    pkt->curr += 3;

    return 1;
}

/* Peek ahead at 4 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static inline int PACKET_peek_net_4(PACKET *pkt, unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data  = ((unsigned long)(*pkt->curr)) << 24;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 2))) <<  8;
    *data |= *(pkt->curr+3);

    return 1;
}

/* Equivalent of n2l */
/* Get 4 bytes in network order from |pkt| and store the value in |*data| */
__owur static inline int PACKET_get_net_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_4(pkt, data))
        return 0;

    pkt->curr += 4;

    return 1;
}

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
__owur static inline int PACKET_peek_1(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_remaining(pkt))
        return 0;

    *data = *pkt->curr;

    return 1;
}

/* Get 1 byte from |pkt| and store the value in |*data| */
__owur static inline int PACKET_get_1(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_1(pkt, data))
        return 0;

    pkt->curr++;

    return 1;
}

/*
 * Peek ahead at 4 bytes in reverse network order from |pkt| and store the value
 * in |*data|
 */
__owur static inline int PACKET_peek_4(PACKET *pkt, unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data  = *pkt->curr;
    *data |= ((unsigned long)(*(pkt->curr + 1))) <<  8;
    *data |= ((unsigned long)(*(pkt->curr + 2))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 3))) << 24;

    return 1;
}

/* Equivalent of c2l */
/*
 * Get 4 bytes in reverse network order from |pkt| and store the value in
 * |*data|
 */
__owur static inline int PACKET_get_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_4(pkt, data))
        return 0;

    pkt->curr += 4;

    return 1;
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
__owur static inline int PACKET_peek_bytes(PACKET *pkt, unsigned char **data,
                                          size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    *data = pkt->curr;

    return 1;
}

/*
 * Read |len| bytes from the |pkt| and store a pointer to them in |*data|. This
 * just points at the underlying buffer that |pkt| is using. The caller should
 * not free this data directly (it will be freed when the underlying buffer gets
 * freed
 */
__owur static inline int PACKET_get_bytes(PACKET *pkt, unsigned char **data,
                                          size_t len)
{
    if (!PACKET_peek_bytes(pkt, data, len))
        return 0;

    pkt->curr += len;

    return 1;
}

/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
__owur static inline int PACKET_peek_copy_bytes(PACKET *pkt,
                                                unsigned char *data, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    memcpy(data, pkt->curr, len);

    return 1;
}

/* Read |len| bytes from |pkt| and copy them to |data| */
__owur static inline int PACKET_copy_bytes(PACKET *pkt, unsigned char *data,
                                          size_t len)
{
    if (!PACKET_peek_copy_bytes(pkt, data, len))
        return 0;

    pkt->curr += len;

    return 1;
}

/* Move the current reading position back |len| bytes */
__owur static inline int PACKET_back(PACKET *pkt, size_t len)
{
    if (len > (size_t)(pkt->curr - pkt->start))
        return 0;

    pkt->curr -= len;

    return 1;
}

/* Move the current reading position forward |len| bytes */
__owur static inline int PACKET_forward(PACKET *pkt, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    pkt->curr += len;

    return 1;
}

/* Store a bookmark for the current reading position in |*bm| */
__owur static inline int PACKET_get_bookmark(PACKET *pkt, size_t *bm)
{
    *bm = pkt->curr - pkt->start;

    return 1;
}

/* Set the current reading position to the bookmark |bm| */
__owur static inline int PACKET_goto_bookmark(PACKET *pkt, size_t bm)
{
    if (bm > (size_t)(pkt->end - pkt->start))
        return 0;

    pkt->curr = pkt->start + bm;

    return 1;
}

/*
 * Stores the total length of the packet we have in the underlying buffer in
 * |*len|
 */
__owur static inline int PACKET_length(PACKET *pkt, size_t *len)
{
    *len = pkt->end - pkt->start;

    return 1;
}

# ifdef __cplusplus
}
# endif

#endif /* HEADER_PACKET_LOCL_H */

