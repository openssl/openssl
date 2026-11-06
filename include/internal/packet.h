/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PACKET_H
#define OSSL_INTERNAL_PACKET_H
#pragma once

#include <string.h>
#include <stdint.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>
#include <openssl/err.h>
#include "internal/cryptlib.h"
#include "internal/packet.h"
#include "internal/numbers.h"
#include "internal/common.h"
#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
#include "internal/quic_vlint.h"
#endif

#define DEFAULT_BUF_SIZE 256

typedef struct {
    /* Pointer to where we are currently reading from */
    const unsigned char *curr;
    /* Pointer to the start of the message */
    const unsigned char *msgstart;
    /* Number of bytes remaining */
    size_t remaining;
} PACKET;

/* Writable packets */

#define WPACKET_INLINE_SUBS 6
/* Flags */

/* Default */
#define WPACKET_FLAGS_NONE 0

/* Error on WPACKET_close() if no data written to the WPACKET */
#define WPACKET_FLAGS_NON_ZERO_LENGTH 1

/*
 * Abandon all changes on WPACKET_close() if no data written to the WPACKET,
 * i.e. this does not write out a zero packet length
 */
#define WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH 2

/* QUIC variable-length integer length prefix */
#define WPACKET_FLAGS_QUIC_VLINT 4

#define WPACKET_FLAGS_SUB_INLINE 8
typedef struct wpacket_sub WPACKET_SUB;
struct wpacket_sub {
    /* The parent WPACKET_SUB if we have one or NULL otherwise */
    WPACKET_SUB *parent;

    /*
     * Offset into the buffer where the length of this WPACKET goes. We use an
     * offset in case the buffer grows and gets reallocated.
     */
    size_t packet_len;

    /* Number of bytes in the packet_len or 0 if we don't write the length */
    size_t lenbytes;

    /* Number of bytes written to the buf prior to this packet starting */
    size_t pwritten;

    /* Flags for this sub-packet */
    unsigned int flags;
};

typedef struct wpacket_st WPACKET;
struct wpacket_st {
    /* The buffer where we store the output data */
    BUF_MEM *buf;

    /* Fixed sized buffer which can be used as an alternative to buf */
    unsigned char *staticbuf;

    /*
     * Offset into the buffer where we are currently writing. We use an offset
     * in case the buffer grows and gets reallocated.
     */
    size_t curr;

    /* Number of bytes written so far */
    size_t written;

    /* Maximum number of bytes we will allow to be written to this WPACKET */
    size_t maxsize;

    /* Our sub-packets (always at least one if not finished) */
    WPACKET_SUB *subs;

    WPACKET_SUB inline_subs[WPACKET_INLINE_SUBS];
    unsigned int nsubs;

    /* Writing from the end first? */
    unsigned int endfirst : 1;
};

static ossl_inline int wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose);
#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
static ossl_inline int put_quic_value(unsigned char *data, size_t value, size_t len);
#endif

/* Internal unchecked shorthand; don't use outside this file. */
static ossl_inline void packet_forward(PACKET *pkt, size_t len)
{
    pkt->curr += len;
    pkt->remaining -= len;
}

/*
 * Returns the number of bytes remaining to be read in the PACKET
 */
static ossl_inline size_t PACKET_remaining(const PACKET *pkt)
{
    return pkt->remaining;
}

/*
 * Returns a pointer to the first byte after the packet data.
 * Useful for integrating with non-PACKET parsing code.
 * Specifically, we use PACKET_end() to verify that a d2i_... call
 * has consumed the entire packet contents.
 */
static ossl_inline const unsigned char *PACKET_end(const PACKET *pkt)
{
    return pkt->curr + pkt->remaining;
}

/*
 * Returns a pointer to the very start of the buffer. If this is a sub packet
 * this will be the start of the buffer for the top of the PACKET tree.
 */
static ossl_inline const unsigned char *PACKET_msg_start(const PACKET *pkt)
{
    return pkt->msgstart;
}

/*
 * Returns a pointer to the PACKET's current position.
 * For use in non-PACKETized APIs.
 */
static ossl_inline const unsigned char *PACKET_data(const PACKET *pkt)
{
    return pkt->curr;
}

/*
 * Initialise a PACKET with |len| bytes held in |buf|. This does not make a
 * copy of the data so |buf| must be present for the whole time that the PACKET
 * is being used.
 */
__owur static ossl_inline int PACKET_buf_init(PACKET *pkt,
    const unsigned char *buf,
    size_t len)
{
    /* Sanity check for negative values. */
    if (len > (size_t)(SIZE_MAX / 2))
        return 0;

    pkt->curr = pkt->msgstart = buf;
    pkt->remaining = len;
    return 1;
}

/* Initialize a PACKET to hold zero bytes. */
static ossl_inline void PACKET_null_init(PACKET *pkt)
{
    pkt->curr = pkt->msgstart = NULL;
    pkt->remaining = 0;
}

/*
 * Returns 1 if the packet has length |num| and its contents equal the |num|
 * bytes read from |ptr|. Returns 0 otherwise (lengths or contents not equal).
 * If lengths are equal, performs the comparison in constant time.
 */
__owur static ossl_inline int PACKET_equal(const PACKET *pkt, const void *ptr,
    size_t num)
{
    if (PACKET_remaining(pkt) != num)
        return 0;
    return CRYPTO_memcmp(pkt->curr, ptr, num) == 0;
}

/*
 * Peek ahead and initialize |subpkt| with the next |len| bytes read from |pkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static ossl_inline int PACKET_peek_sub_packet(const PACKET *pkt,
    PACKET *subpkt, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    if (!PACKET_buf_init(subpkt, pkt->curr, len))
        return 0;

    subpkt->msgstart = pkt->msgstart;
    return 1;
}

/*
 * Initialize |subpkt| with the next |len| bytes read from |pkt|. Data is not
 * copied: the |subpkt| packet will share its underlying buffer with the
 * original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 */
__owur static ossl_inline int PACKET_get_sub_packet(PACKET *pkt,
    PACKET *subpkt, size_t len)
{
    if (!PACKET_peek_sub_packet(pkt, subpkt, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Peek ahead at 2 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_2(const PACKET *pkt,
    unsigned int *data)
{
    if (PACKET_remaining(pkt) < 2)
        return 0;

    *data = ((unsigned int)(*pkt->curr)) << 8;
    *data |= *(pkt->curr + 1);

    return 1;
}

/* Equivalent of n2s */
/* Get 2 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_2(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_net_2(pkt, data))
        return 0;

    packet_forward(pkt, 2);

    return 1;
}

/* Same as PACKET_get_net_2() but for a size_t */
__owur static ossl_inline int PACKET_get_net_2_len(PACKET *pkt, size_t *data)
{
    unsigned int i;
    int ret = PACKET_get_net_2(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 3 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_3(const PACKET *pkt,
    unsigned long *data)
{
    if (PACKET_remaining(pkt) < 3)
        return 0;

    *data = ((unsigned long)(*pkt->curr)) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 8;
    *data |= *(pkt->curr + 2);

    return 1;
}

/* Equivalent of n2l3 */
/* Get 3 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_3(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_3(pkt, data))
        return 0;

    packet_forward(pkt, 3);

    return 1;
}

/* Same as PACKET_get_net_3() but for a size_t */
__owur static ossl_inline int PACKET_get_net_3_len(PACKET *pkt, size_t *data)
{
    unsigned long i;
    int ret = PACKET_get_net_3(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 4 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_4(const PACKET *pkt,
    unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data = ((unsigned long)(*pkt->curr)) << 24;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 2))) << 8;
    *data |= *(pkt->curr + 3);

    return 1;
}

/*
 * Peek ahead at 6 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_6(const PACKET *pkt,
    uint64_t *data)
{
    if (PACKET_remaining(pkt) < 6)
        return 0;

    *data = ((uint64_t)(*(pkt->curr))) << 40;
    *data |= ((uint64_t)(*(pkt->curr + 1))) << 32;
    *data |= ((uint64_t)(*(pkt->curr + 2))) << 24;
    *data |= ((uint64_t)(*(pkt->curr + 3))) << 16;
    *data |= ((uint64_t)(*(pkt->curr + 4))) << 8;
    *data |= *(pkt->curr + 5);

    return 1;
}

/* Get 6 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_6(PACKET *pkt, uint64_t *data)
{
    if (!PACKET_peek_net_6(pkt, data))
        return 0;

    packet_forward(pkt, 6);

    return 1;
}

/*
 * Peek ahead at 8 bytes in network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_peek_net_8(const PACKET *pkt,
    uint64_t *data)
{
    if (PACKET_remaining(pkt) < 8)
        return 0;

    *data = ((uint64_t)(*pkt->curr)) << 56;
    *data |= ((uint64_t)(*(pkt->curr + 1))) << 48;
    *data |= ((uint64_t)(*(pkt->curr + 2))) << 40;
    *data |= ((uint64_t)(*(pkt->curr + 3))) << 32;
    *data |= ((uint64_t)(*(pkt->curr + 4))) << 24;
    *data |= ((uint64_t)(*(pkt->curr + 5))) << 16;
    *data |= ((uint64_t)(*(pkt->curr + 6))) << 8;
    *data |= *(pkt->curr + 7);

    return 1;
}

/* Equivalent of n2l */
/* Get 4 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_net_4(pkt, data))
        return 0;

    packet_forward(pkt, 4);

    return 1;
}

/* Same as PACKET_get_net_4() but for a size_t */
__owur static ossl_inline int PACKET_get_net_4_len(PACKET *pkt, size_t *data)
{
    unsigned long i;
    int ret = PACKET_get_net_4(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/**
 * @brief Get 4 bytes in network order from |pkt| and store the value in |*data|
 * Similar to PACKET_get_net_4() except the data is uint32_t
 *
 * @param pkt Contains a buffer to read from
 * @param data The object to write the data to.
 * @returns 1 on success, or 0 otherwise.
 */
static ossl_unused ossl_inline int PACKET_get_net_4_len_u32(PACKET *pkt, uint32_t *data)
{
    size_t i = 0;
    int ret = PACKET_get_net_4_len(pkt, &i);

    if (ret)
        *data = (uint32_t)i;
    return ret;
}

/* Get 8 bytes in network order from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_net_8(PACKET *pkt, uint64_t *data)
{
    if (!PACKET_peek_net_8(pkt, data))
        return 0;

    packet_forward(pkt, 8);

    return 1;
}

/* Peek ahead at 1 byte from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_peek_1(const PACKET *pkt,
    unsigned int *data)
{
    if (!PACKET_remaining(pkt))
        return 0;

    *data = *pkt->curr;

    return 1;
}

/* Get 1 byte from |pkt| and store the value in |*data| */
__owur static ossl_inline int PACKET_get_1(PACKET *pkt, unsigned int *data)
{
    if (!PACKET_peek_1(pkt, data))
        return 0;

    packet_forward(pkt, 1);

    return 1;
}

/* Same as PACKET_get_1() but for a size_t */
__owur static ossl_inline int PACKET_get_1_len(PACKET *pkt, size_t *data)
{
    unsigned int i;
    int ret = PACKET_get_1(pkt, &i);

    if (ret)
        *data = (size_t)i;

    return ret;
}

/*
 * Peek ahead at 4 bytes in reverse network order from |pkt| and store the value
 * in |*data|
 */
__owur static ossl_inline int PACKET_peek_4(const PACKET *pkt,
    unsigned long *data)
{
    if (PACKET_remaining(pkt) < 4)
        return 0;

    *data = *pkt->curr;
    *data |= ((unsigned long)(*(pkt->curr + 1))) << 8;
    *data |= ((unsigned long)(*(pkt->curr + 2))) << 16;
    *data |= ((unsigned long)(*(pkt->curr + 3))) << 24;

    return 1;
}

/* Equivalent of c2l */
/*
 * Get 4 bytes in reverse network order from |pkt| and store the value in
 * |*data|
 */
__owur static ossl_inline int PACKET_get_4(PACKET *pkt, unsigned long *data)
{
    if (!PACKET_peek_4(pkt, data))
        return 0;

    packet_forward(pkt, 4);

    return 1;
}

/*
 * Peek ahead at |len| bytes from the |pkt| and store a pointer to them in
 * |*data|. This just points at the underlying buffer that |pkt| is using. The
 * caller should not free this data directly (it will be freed when the
 * underlying buffer gets freed
 */
__owur static ossl_inline int PACKET_peek_bytes(const PACKET *pkt,
    const unsigned char **data,
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
__owur static ossl_inline int PACKET_get_bytes(PACKET *pkt,
    const unsigned char **data,
    size_t len)
{
    if (!PACKET_peek_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/* Peek ahead at |len| bytes from |pkt| and copy them to |data| */
__owur static ossl_inline int PACKET_peek_copy_bytes(const PACKET *pkt,
    unsigned char *data,
    size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    memcpy(data, pkt->curr, len);

    return 1;
}

/*
 * Read |len| bytes from |pkt| and copy them to |data|.
 * The caller is responsible for ensuring that |data| can hold |len| bytes.
 */
__owur static ossl_inline int PACKET_copy_bytes(PACKET *pkt,
    unsigned char *data, size_t len)
{
    if (!PACKET_peek_copy_bytes(pkt, data, len))
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Copy packet data to |dest|, and set |len| to the number of copied bytes.
 * If the packet has more than |dest_len| bytes, nothing is copied.
 * Returns 1 if the packet data fits in |dest_len| bytes, 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing
 * done with a given PACKET).
 */
__owur static ossl_inline int PACKET_copy_all(const PACKET *pkt,
    unsigned char *dest,
    size_t dest_len, size_t *len)
{
    if (PACKET_remaining(pkt) > dest_len) {
        *len = 0;
        return 0;
    }
    *len = pkt->remaining;
    memcpy(dest, pkt->curr, pkt->remaining);
    return 1;
}

/*
 * Copy |pkt| bytes to a newly allocated buffer and store a pointer to the
 * result in |*data|, and the length in |len|.
 * If |*data| is not NULL, the old data is OPENSSL_free'd.
 * If the packet is empty, or malloc fails, |*data| will be set to NULL.
 * Returns 1 if the malloc succeeds and 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing
 * done with a given PACKET).
 */
__owur static ossl_inline int PACKET_memdup(const PACKET *pkt,
    unsigned char **data, size_t *len)
{
    size_t length;

    OPENSSL_free(*data);
    *data = NULL;
    *len = 0;

    length = PACKET_remaining(pkt);

    if (length == 0)
        return 1;

    *data = OPENSSL_memdup(pkt->curr, length);
    if (*data == NULL)
        return 0;

    *len = length;
    return 1;
}

/*
 * Read a C string from |pkt| and copy to a newly allocated, NUL-terminated
 * buffer. Store a pointer to the result in |*data|.
 * If |*data| is not NULL, the old data is OPENSSL_free'd.
 * If the data in |pkt| does not contain a NUL-byte, the entire data is
 * copied and NUL-terminated.
 * Returns 1 if the malloc succeeds and 0 otherwise.
 * Does not forward PACKET position (because it is typically the last thing done
 * with a given PACKET).
 */
__owur static ossl_inline int PACKET_strndup(const PACKET *pkt, char **data)
{
    OPENSSL_free(*data);

    /* This will succeed on an empty packet, unless pkt->curr == NULL. */
    *data = OPENSSL_strndup((const char *)pkt->curr, PACKET_remaining(pkt));
    return (*data != NULL);
}

/* Returns 1 if |pkt| contains at least one 0-byte, 0 otherwise. */
static ossl_inline int PACKET_contains_zero_byte(const PACKET *pkt)
{
    return memchr(pkt->curr, 0, pkt->remaining) != NULL;
}

/* Move the current reading position forward |len| bytes */
__owur static ossl_inline int PACKET_forward(PACKET *pkt, size_t len)
{
    if (PACKET_remaining(pkt) < len)
        return 0;

    packet_forward(pkt, len);

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a one-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_1(PACKET *pkt,
    PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_1(&tmp, &length) || !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = length;

    return 1;
}

/*
 * Like PACKET_get_length_prefixed_1, but additionally, fails when there are
 * leftover bytes in |pkt|.
 */
__owur static ossl_inline int PACKET_as_length_prefixed_1(PACKET *pkt,
    PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_1(&tmp, &length) || !PACKET_get_bytes(&tmp, &data, (size_t)length) || PACKET_remaining(&tmp) != 0) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = length;

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a two-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_2(PACKET *pkt,
    PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;

    if (!PACKET_get_net_2(&tmp, &length) || !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = length;

    return 1;
}

/*
 * Like PACKET_get_length_prefixed_2, but additionally, fails when there are
 * leftover bytes in |pkt|.
 */
__owur static ossl_inline int PACKET_as_length_prefixed_2(PACKET *pkt,
    PACKET *subpkt)
{
    unsigned int length;
    const unsigned char *data;
    PACKET tmp = *pkt;

    if (!PACKET_get_net_2(&tmp, &length) || !PACKET_get_bytes(&tmp, &data, (size_t)length) || PACKET_remaining(&tmp) != 0) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = length;

    return 1;
}

/*
 * Reads a variable-length vector prefixed with a three-byte length, and stores
 * the contents in |subpkt|. |pkt| can equal |subpkt|.
 * Data is not copied: the |subpkt| packet will share its underlying buffer with
 * the original |pkt|, so data wrapped by |pkt| must outlive the |subpkt|.
 * Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_length_prefixed_3(PACKET *pkt,
    PACKET *subpkt)
{
    unsigned long length;
    const unsigned char *data;
    PACKET tmp = *pkt;
    if (!PACKET_get_net_3(&tmp, &length) || !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = length;

    return 1;
}

#define WPACKET_start_sub_packet_u24_at_offset(pkt, offset) \
    WPACKET_start_sub_packet_at_offset_len__((pkt), 3, (offset))

/*
 * Convenience macros for calling WPACKET_start_sub_packet_len with different
 * lengths
 */
#define WPACKET_start_sub_packet_u8(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 1)
#define WPACKET_start_sub_packet_u16(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 2)
#define WPACKET_start_sub_packet_u24(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 3)
#define WPACKET_start_sub_packet_u32(pkt) \
    WPACKET_start_sub_packet_len__((pkt), 4)

/*
 * Convenience macros for calling WPACKET_sub_allocate_bytes with different
 * lengths
 */
#define WPACKET_sub_allocate_bytes_u8(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_allocate_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_allocate_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_allocate_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_allocate_bytes__((pkt), (len), (bytes), 4)

static ossl_inline int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes);

/*
 * Convenience macros for  WPACKET_sub_reserve_bytes with different lengths
 */
#define WPACKET_sub_reserve_bytes_u8(pkt, len, bytes) \
    WPACKET_reserve_bytes__((pkt), (len), (bytes), 1)
#define WPACKET_sub_reserve_bytes_u16(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 2)
#define WPACKET_sub_reserve_bytes_u24(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 3)
#define WPACKET_sub_reserve_bytes_u32(pkt, len, bytes) \
    WPACKET_sub_reserve_bytes__((pkt), (len), (bytes), 4)

/*
 * Convenience macros for calling WPACKET_put_bytes with different
 * lengths
 */
#define WPACKET_put_bytes_u8(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 1)
#define WPACKET_put_bytes_u16(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 2)
#define WPACKET_put_bytes_u24(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 3)
#define WPACKET_put_bytes_u32(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 4)
#define WPACKET_put_bytes_u48(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 6)
#define WPACKET_put_bytes_u64(pkt, val) \
    WPACKET_put_bytes__((pkt), (val), 8)

/* Convenience macros for calling WPACKET_sub_memcpy with different lengths */
#define WPACKET_sub_memcpy_u8(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 1)
#define WPACKET_sub_memcpy_u16(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 2)
#define WPACKET_sub_memcpy_u24(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 3)
#define WPACKET_sub_memcpy_u32(pkt, src, len) \
    WPACKET_sub_memcpy__((pkt), (src), (len), 4)

/*
 * Allocate bytes in the WPACKET for the output. This reserves the bytes
 * and counts them as "written", but doesn't actually do the writing. A pointer
 * to the allocated bytes is stored in |*allocbytes|. |allocbytes| may be NULL.
 * WARNING: the allocated bytes must be filled in immediately, without further
 * WPACKET_* calls. If not then the underlying buffer may be realloc'd and
 * change its location.
 */
static ossl_inline int WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (!WPACKET_reserve_bytes(pkt, len, allocbytes))
        return 0;

    pkt->written += len;
    pkt->curr += len;
    return 1;
}

/* Store the |value| of length |len| at location |data| */
static ossl_inline int put_value(unsigned char *data, uint64_t value, size_t len)
{
    if (data == NULL)
        return 1;

    for (data += len - 1; len > 0; len--) {
        *data = (unsigned char)(value & 0xff);
        data--;
        value >>= 8;
    }

    /* Check whether we could fit the value in the assigned number of bytes */
    if (value > 0)
        return 0;

    return 1;
}

static ossl_inline int WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t size)
{
    unsigned char *data;

    /* Internal API, so should not fail */
    if (!ossl_assert(size <= sizeof(uint64_t))
        || !WPACKET_allocate_bytes(pkt, size, &data)
        || !put_value(data, val, size))
        return 0;

    return 1;
}

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

static ossl_inline WPACKET_SUB *wpacket_sub_new(WPACKET *pkt)
{
    WPACKET_SUB *sub;
    uint32_t idx;

    if (pkt->nsubs != 0) {
#if __has_builtin(__builtin_ffs)
        idx = __builtin_ffs(pkt->nsubs) - 1;
#else
        int snsubs = pkt->nsubs;
        static const int MultiplyDeBruijnBitPosition[32] = {
            0, 1, 28, 2, 29, 14, 24, 3, 30, 22, 20, 15, 25, 17, 4, 8,
            31, 27, 13, 23, 21, 19, 16, 7, 26, 12, 18, 6, 11, 5, 10, 9
        };

        /*
         * (x & -x) isolates the lowest set bit (LSB)
         * Multiplying hashes that bit uniquely into the upper 5 bits
         */
        idx = MultiplyDeBruijnBitPosition[((uint32_t)((snsubs & -snsubs) * 0x077CB531U)) >> 27];
#endif
        pkt->nsubs &= (~(1 << idx));
        sub = &pkt->inline_subs[idx];
        memset(sub, 0, sizeof(*sub));
        sub->flags = WPACKET_FLAGS_SUB_INLINE;
    } else {
        sub = OPENSSL_zalloc(sizeof(*sub));
        if (sub == NULL)
            return NULL;
    }
    return sub;
}

static ossl_inline void wpacket_sub_free(WPACKET *pkt, WPACKET_SUB *sub)
{
    if (sub == NULL)
        return;
    if (sub->flags & WPACKET_FLAGS_SUB_INLINE) {
        uintptr_t idx = ((uintptr_t)sub - (uintptr_t)pkt->inline_subs) / sizeof(WPACKET_SUB);

        pkt->nsubs |= (1 << idx);
        return;
    }
    OPENSSL_free(sub);
}

/*
 * Closes the most recent sub-packet. It also writes out the length of the
 * packet to the required location (normally the start of the WPACKET) if
 * appropriate. The top level WPACKET should be closed using WPACKET_finish()
 * instead of this function.
 */
static ossl_inline int WPACKET_close(WPACKET *pkt)
{
    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent == NULL)
        return 0;

    return wpacket_intern_close(pkt, pkt->subs, 1);
}

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the current position in |pkt| to store the sub-packets length once we know
 * it. The sub-packet start is set at |offset| from current position in |pkt|
 * Don't call this directly. Use the convenience macros below instead.
 */
static ossl_inline int WPACKET_start_sub_packet_at_offset_len__(WPACKET *pkt, size_t lenbytes,
    size_t offset)
{
    WPACKET_SUB *sub;
    unsigned char *lenchars;

    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    /* We don't support lenbytes greater than 0 when doing endfirst writing */
    if (lenbytes > 0 && pkt->endfirst)
        return 0;

    if ((sub = wpacket_sub_new(pkt)) == NULL)
        return 0;

    sub->parent = pkt->subs;
    pkt->subs = sub;
    sub->pwritten = pkt->written + lenbytes + offset;
    sub->lenbytes = lenbytes;

    if (lenbytes == 0) {
        sub->packet_len = 0;
        return 1;
    }

    sub->packet_len = pkt->written;

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)
        || (offset > 0 && !WPACKET_allocate_bytes(pkt, offset, &lenchars)))
        return 0;

    return 1;
}

/*
 * Initialise a new sub-packet. Additionally |lenbytes| of data is preallocated
 * at the start of the sub-packet to store its length once we know it. Don't
 * call this directly. Use the convenience macros below instead.
 */
static ossl_inline int WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes)
{
    return WPACKET_start_sub_packet_at_offset_len__(pkt, lenbytes, 0);
}

/*
 * The same as WPACKET_allocate_bytes() except additionally a new sub-packet is
 * started for the allocated bytes, and then closed immediately afterwards. The
 * number of length bytes for the sub-packet is in |lenbytes|. Don't call this
 * directly. Use the convenience macros below instead.
 */
static ossl_inline int WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    if (!WPACKET_start_sub_packet_len__(pkt, lenbytes)
        || !WPACKET_allocate_bytes(pkt, len, allocbytes)
        || !WPACKET_close(pkt))
        return 0;

    return 1;
}

#define GETBUF(p) (((p)->staticbuf != NULL)         \
        ? (p)->staticbuf                            \
        : ((p)->buf != NULL                         \
                  ? (unsigned char *)(p)->buf->data \
                  : NULL))

static ossl_inline unsigned char *WPACKET_get_curr(WPACKET *pkt)
{
    unsigned char *buf = GETBUF(pkt);

    if (buf == NULL)
        return NULL;

    if (pkt->endfirst)
        return buf + pkt->maxsize - pkt->curr;

    return buf + pkt->curr;
}

/*
 * The same as WPACKET_allocate_bytes() except the reserved bytes are not
 * actually counted as written. Typically this will be for when we don't know
 * how big arbitrary data is going to be up front, but we do know what the
 * maximum size will be. If this function is used, then it should be immediately
 * followed by a WPACKET_allocate_bytes() call before any other WPACKET
 * functions are called (unless the write to the allocated bytes is abandoned).
 *
 * For example: If we are generating a signature, then the size of that
 * signature may not be known in advance. We can use WPACKET_reserve_bytes() to
 * handle this:
 *
 *  if (!WPACKET_sub_reserve_bytes_u16(&pkt, EVP_PKEY_get_size(pkey), &sigbytes1)
 *          || EVP_SignFinal(md_ctx, sigbytes1, &siglen, pkey) <= 0
 *          || !WPACKET_sub_allocate_bytes_u16(&pkt, siglen, &sigbytes2)
 *          || sigbytes1 != sigbytes2)
 *      goto err;
 */
static ossl_inline int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != 0))
        return 0;

    if (pkt->maxsize - pkt->written < len)
        return 0;

    if (pkt->buf != NULL && (pkt->buf->length - pkt->written < len)) {
        size_t newlen;
        size_t reflen;

        reflen = (len > pkt->buf->length) ? len : pkt->buf->length;

        if (reflen > SIZE_MAX / 2) {
            newlen = SIZE_MAX;
        } else {
            newlen = reflen * 2;
            if (newlen < DEFAULT_BUF_SIZE)
                newlen = DEFAULT_BUF_SIZE;
        }
        if (BUF_MEM_grow(pkt->buf, newlen) == 0)
            return 0;
    }
    if (allocbytes != NULL) {
        *allocbytes = WPACKET_get_curr(pkt);
        if (pkt->endfirst && *allocbytes != NULL)
            *allocbytes -= len;
    }

    return 1;
}

static ossl_inline int WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    if (pkt->endfirst && lenbytes > 0)
        return 0;

    if (!WPACKET_reserve_bytes(pkt, lenbytes + len, allocbytes))
        return 0;

    if (*allocbytes != NULL)
        *allocbytes += lenbytes;

    return 1;
}

static ossl_inline size_t maxmaxsize(size_t lenbytes)
{
    if (lenbytes >= sizeof(size_t) || lenbytes == 0)
        return SIZE_MAX;

    return ((size_t)1 << (lenbytes * 8)) - 1 + lenbytes;
}

static ossl_inline int wpacket_intern_init_len(WPACKET *pkt, size_t lenbytes)
{
    unsigned char *lenchars;

    pkt->curr = 0;
    pkt->written = 0;
    pkt->nsubs = (1 << WPACKET_INLINE_SUBS) - 1;

    if ((pkt->subs = wpacket_sub_new(pkt)) == NULL)
        return 0;

    if (lenbytes == 0)
        return 1;

    pkt->subs->pwritten = lenbytes;
    pkt->subs->lenbytes = lenbytes;

    if (!WPACKET_allocate_bytes(pkt, lenbytes, &lenchars)) {
        wpacket_sub_free(pkt, pkt->subs);
        pkt->subs = NULL;
        return 0;
    }
    pkt->subs->packet_len = 0;

    return 1;
}

/*
 * Same as WPACKET_init_len except we do not use a growable BUF_MEM structure.
 * A fixed buffer of memory |buf| of size |len| is used instead. A failure will
 * occur if you attempt to write beyond the end of the buffer
 */
static ossl_inline int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
    size_t lenbytes)
{
    size_t max = maxmaxsize(lenbytes);

    pkt->subs = NULL;
    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = (max < len) ? max : len;
    pkt->endfirst = 0;

    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    return wpacket_intern_init_len(pkt, lenbytes);
}

/*
 * Same as WPACKET_init_static_len except lenbytes is always 0, and we set the
 * WPACKET to write to the end of the buffer moving towards the start and use
 * DER length encoding for sub-packets.
 */
static ossl_inline int WPACKET_init_der(WPACKET *pkt, unsigned char *buf, size_t len)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = len;
    pkt->endfirst = 1;

    return wpacket_intern_init_len(pkt, 0);
}

/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
static ossl_inline int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL))
        return 0;

    pkt->staticbuf = NULL;
    pkt->buf = buf;
    pkt->maxsize = maxmaxsize(lenbytes);
    pkt->endfirst = 0;

    return wpacket_intern_init_len(pkt, lenbytes);
}

static ossl_inline int WPACKET_init(WPACKET *pkt, BUF_MEM *buf)
{
    return WPACKET_init_len(pkt, buf, 0);
}

/*
 * Same as WPACKET_init_len except there is no underlying buffer. No data is
 * ever actually written. We just keep track of how much data would have been
 * written if a buffer was there.
 */
static ossl_inline int WPACKET_init_null(WPACKET *pkt, size_t lenbytes)
{
    pkt->staticbuf = NULL;
    pkt->buf = NULL;
    pkt->maxsize = maxmaxsize(lenbytes);
    pkt->endfirst = 0;

    return wpacket_intern_init_len(pkt, 0);
}

/*
 * Same as WPACKET_init_null except we set the WPACKET to assume DER length
 * encoding for sub-packets.
 */
static ossl_inline int WPACKET_init_null_der(WPACKET *pkt)
{
    pkt->staticbuf = NULL;
    pkt->buf = NULL;
    pkt->maxsize = SIZE_MAX;
    pkt->endfirst = 1;

    return wpacket_intern_init_len(pkt, 0);
}

/*
 * Set the flags to be applied to the current sub-packet
 */
static ossl_inline int WPACKET_set_flags(WPACKET *pkt, unsigned int flags)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    /*
     * Preserve the inline flag to prevent freeing
     */
    pkt->subs->flags = (pkt->subs->flags & WPACKET_FLAGS_SUB_INLINE) | flags;

    return 1;
}

/*
 * Internal helper function used by WPACKET_close(), WPACKET_finish() and
 * WPACKET_fill_lengths() to close a sub-packet and write out its length if
 * necessary. If |doclose| is 0 then it goes through the motions of closing
 * (i.e. it fills in all the lengths), but doesn't actually close anything.
 */
static ossl_inline int wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose)
{
    size_t packlen = pkt->written - sub->pwritten;

    if (packlen == 0
        && (sub->flags & WPACKET_FLAGS_NON_ZERO_LENGTH) != 0)
        return 0;

    if (packlen == 0
        && sub->flags & WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH) {
        /* We can't handle this case. Return an error */
        if (!doclose)
            return 0;

        /* Deallocate any bytes allocated for the length of the WPACKET */
        if ((pkt->curr - sub->lenbytes) == sub->packet_len) {
            pkt->written -= sub->lenbytes;
            pkt->curr -= sub->lenbytes;
        }

        /* Don't write out the packet length */
        sub->packet_len = 0;
        sub->lenbytes = 0;
    }

    /* Write out the WPACKET length if needed */
    if (sub->lenbytes > 0) {
        unsigned char *buf = GETBUF(pkt);

        if (buf != NULL) {
#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
            if ((sub->flags & WPACKET_FLAGS_QUIC_VLINT) == 0) {
                if (!put_value(&buf[sub->packet_len], packlen, sub->lenbytes))
                    return 0;
            } else {
                if (!put_quic_value(&buf[sub->packet_len], packlen, sub->lenbytes))
                    return 0;
            }
#else
            if (!put_value(&buf[sub->packet_len], packlen, sub->lenbytes))
                return 0;
#endif
        }
    } else if (pkt->endfirst && sub->parent != NULL
        && (packlen != 0
            || (sub->flags
                   & WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH)
                == 0)) {
        size_t tmplen = packlen;
        size_t numlenbytes = 1;

        while ((tmplen = tmplen >> 8) > 0)
            numlenbytes++;
        if (!WPACKET_put_bytes__(pkt, packlen, numlenbytes))
            return 0;
        if (packlen > 0x7f) {
            numlenbytes |= 0x80;
            if (!WPACKET_put_bytes_u8(pkt, numlenbytes))
                return 0;
        }
    }

    if (doclose) {
        pkt->subs = sub->parent;
        wpacket_sub_free(pkt, sub);
    }

    return 1;
}

/*
 * Iterate through all the sub-packets and write out their lengths as if they
 * were being closed. The lengths will be overwritten with the final lengths
 * when the sub-packets are eventually closed (which may be different if more
 * data is added to the WPACKET). This function fails if a sub-packet is of 0
 * length and WPACKET_FLAGS_ABANDON_ON_ZERO_LENGTH is set.
 */
static ossl_inline int WPACKET_fill_lengths(WPACKET *pkt)
{
    WPACKET_SUB *sub;

    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    for (sub = pkt->subs; sub != NULL; sub = sub->parent) {
        if (!wpacket_intern_close(pkt, sub, 0))
            return 0;
    }

    return 1;
}

/*
 * The same as WPACKET_close() but only for the top most WPACKET. Additionally
 * frees memory resources for this WPACKET.
 */
static ossl_inline int WPACKET_finish(WPACKET *pkt)
{
    int ret;

    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent != NULL)
        return 0;

    ret = wpacket_intern_close(pkt, pkt->subs, 1);
    if (ret) {
        wpacket_sub_free(pkt, pkt->subs);
        pkt->subs = NULL;
    }

    return ret;
}

/*
 * Same as WPACKET_start_sub_packet_len__() except no bytes are pre-allocated
 * for the sub-packet length.
 */
static ossl_inline int WPACKET_start_sub_packet(WPACKET *pkt)
{
    return WPACKET_start_sub_packet_len__(pkt, 0);
}

static ossl_inline int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)
{
    WPACKET_SUB *sub;
    size_t lenbytes;

    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL))
        return 0;

    /* Find the WPACKET_SUB for the top level */
    for (sub = pkt->subs; sub->parent != NULL; sub = sub->parent)
        continue;

    lenbytes = sub->lenbytes;
    if (lenbytes == 0)
        lenbytes = sizeof(pkt->maxsize);

    if (maxmaxsize(lenbytes) < maxsize || maxsize < pkt->written)
        return 0;

    pkt->maxsize = maxsize;

    return 1;
}

static ossl_inline int WPACKET_memset(WPACKET *pkt, int ch, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    if (dest != NULL)
        memset(dest, ch, len);

    return 1;
}

static ossl_inline int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes(pkt, len, &dest))
        return 0;

    if (dest != NULL)
        memcpy(dest, src, len);

    return 1;
}

static ossl_inline int WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len,
    size_t lenbytes)
{
    if (!WPACKET_start_sub_packet_len__(pkt, lenbytes)
        || !WPACKET_memcpy(pkt, src, len)
        || !WPACKET_close(pkt))
        return 0;

    return 1;
}

static ossl_inline int WPACKET_get_total_written(WPACKET *pkt, size_t *written)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(written != NULL))
        return 0;

    *written = pkt->written;

    return 1;
}

static ossl_inline int WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != NULL))
        return 0;

    *len = pkt->written - pkt->subs->pwritten;

    return 1;
}

static ossl_inline int WPACKET_is_null_buf(WPACKET *pkt)
{
    return pkt->buf == NULL && pkt->staticbuf == NULL;
}

static ossl_inline void WPACKET_cleanup(WPACKET *pkt)
{
    WPACKET_SUB *sub, *parent;

    for (sub = pkt->subs; sub != NULL; sub = parent) {
        parent = sub->parent;
        wpacket_sub_free(pkt, sub);
    }
    pkt->subs = NULL;
}

#ifndef OPENSSL_NO_QUIC
/*
 * Decodes a QUIC variable-length integer in |pkt| and stores the result in
 * |data|.
 */
__owur static ossl_inline int PACKET_get_quic_vlint(PACKET *pkt,
    uint64_t *data)
{
    size_t enclen;

    if (PACKET_remaining(pkt) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*pkt->curr);

    if (PACKET_remaining(pkt) < enclen)
        return 0;

    *data = ossl_quic_vlint_decode_unchecked(pkt->curr);
    packet_forward(pkt, enclen);
    return 1;
}

/*
 * Decodes a QUIC variable-length integer in |pkt| and stores the result in
 * |data|. Unlike PACKET_get_quic_vlint, this does not advance the current
 * position. If was_minimal is non-NULL, *was_minimal is set to 1 if the integer
 * was encoded using the minimal possible number of bytes and 0 otherwise.
 */
__owur static ossl_inline int PACKET_peek_quic_vlint_ex(PACKET *pkt,
    uint64_t *data,
    int *was_minimal)
{
    size_t enclen;

    if (PACKET_remaining(pkt) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*pkt->curr);

    if (PACKET_remaining(pkt) < enclen)
        return 0;

    *data = ossl_quic_vlint_decode_unchecked(pkt->curr);

    if (was_minimal != NULL)
        *was_minimal = (enclen == ossl_quic_vlint_encode_len(*data));

    return 1;
}

__owur static ossl_inline int PACKET_peek_quic_vlint(PACKET *pkt,
    uint64_t *data)
{
    return PACKET_peek_quic_vlint_ex(pkt, data, NULL);
}

/*
 * Skips over a QUIC variable-length integer in |pkt| without decoding it.
 */
__owur static ossl_inline int PACKET_skip_quic_vlint(PACKET *pkt)
{
    size_t enclen;

    if (PACKET_remaining(pkt) < 1)
        return 0;

    enclen = ossl_quic_vlint_decode_len(*pkt->curr);

    if (PACKET_remaining(pkt) < enclen)
        return 0;

    packet_forward(pkt, enclen);
    return 1;
}

/*
 * Reads a variable-length vector prefixed with a QUIC variable-length integer
 * denoting the length, and stores the contents in |subpkt|. |pkt| can equal
 * |subpkt|. Data is not copied: the |subpkt| packet will share its underlying
 * buffer with the original |pkt|, so data wrapped by |pkt| must outlive the
 * |subpkt|. Upon failure, the original |pkt| and |subpkt| are not modified.
 */
__owur static ossl_inline int PACKET_get_quic_length_prefixed(PACKET *pkt,
    PACKET *subpkt)
{
    uint64_t length;
    const unsigned char *data;
    PACKET tmp = *pkt;

    if (!PACKET_get_quic_vlint(&tmp, &length) || length > SIZE_MAX || !PACKET_get_bytes(&tmp, &data, (size_t)length)) {
        return 0;
    }

    *pkt = tmp;
    subpkt->curr = data;
    subpkt->msgstart = pkt->msgstart;
    subpkt->remaining = (size_t)length;

    return 1;
}

static ossl_inline int put_quic_value(unsigned char *data, size_t value, size_t len)
{
    if (data == NULL)
        return 1;

    /* Value too large for field. */
    if (ossl_quic_vlint_encode_len(value) > len)
        return 0;

    ossl_quic_vlint_encode_n(data, value, (int)len);
    return 1;
}

/*
 * Starts a QUIC sub-packet headed by a QUIC variable-length integer. max_len
 * specifies the upper bound for the sub-packet size at the time the sub-packet
 * is closed, which determines the encoding size for the variable-length
 * integer header. max_len can be a precise figure or a worst-case bound
 * if a precise figure is not available.
 */
static __owur ossl_inline int WPACKET_start_quic_sub_packet_bound(WPACKET *pkt, size_t max_len)
{
    size_t enclen = ossl_quic_vlint_encode_len(max_len);

    if (enclen == 0)
        return 0;

    if (WPACKET_start_sub_packet_len__(pkt, enclen) == 0)
        return 0;

    pkt->subs->flags |= WPACKET_FLAGS_QUIC_VLINT;
    return 1;
}

/*
 * Starts a QUIC sub-packet headed by a QUIC variable-length integer. A 4-byte
 * representation is used.
 */
static __owur ossl_inline int WPACKET_start_quic_sub_packet(WPACKET *pkt)
{
    /*
     * Assume no (sub)packet will exceed 4GiB, thus the 8-byte encoding need not
     * be used.
     */
    return WPACKET_start_quic_sub_packet_bound(pkt, OSSL_QUIC_VLINT_4B_MIN);
}

/*
 * Allocates a QUIC sub-packet with exactly len bytes of payload, headed by a
 * QUIC variable-length integer. The pointer to the payload buffer is output and
 * must be filled by the caller. This function assures optimal selection of
 * variable-length integer encoding length.
 */
static __owur ossl_inline int WPACKET_quic_sub_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (!WPACKET_start_quic_sub_packet_bound(pkt, len)
        || !WPACKET_allocate_bytes(pkt, len, allocbytes)
        || !WPACKET_close(pkt))
        return 0;

    return 1;
}

/*
 * Write a QUIC variable-length integer to the packet.
 */
static __owur ossl_inline int WPACKET_quic_write_vlint(WPACKET *pkt, uint64_t v)
{
    unsigned char *b = NULL;
    size_t enclen = ossl_quic_vlint_encode_len(v);

    if (enclen == 0)
        return 0;

    if (WPACKET_allocate_bytes(pkt, enclen, &b) == 0)
        return 0;

    ossl_quic_vlint_encode(b, v);
    return 1;
}
#endif
#endif
