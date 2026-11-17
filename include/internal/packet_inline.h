/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_INTERNAL_PACKET_INLINE_H
#define OSSL_INTERNAL_PACKET_INLINE_H

#include <string.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/e_os2.h>

#include "internal/numbers.h"
#include "internal/common.h"
#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
#include "internal/quic_vlint.h"
#endif

#define DEFAULT_BUF_SIZE 256

/* Writable packets */

#define WPACKET_INLINE_SUBS 6
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

#define GETBUF(p) (((p)->staticbuf != NULL)         \
        ? (p)->staticbuf                            \
        : ((p)->buf != NULL                         \
                  ? (unsigned char *)(p)->buf->data \
                  : NULL))

static ossl_inline ossl_unused size_t maxmaxsize(size_t lenbytes)
{
    if (lenbytes >= sizeof(size_t) || lenbytes == 0)
        return SIZE_MAX;

    return ((size_t)1 << (lenbytes * 8)) - 1 + lenbytes;
}

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

static ossl_inline ossl_unused WPACKET_SUB *wpacket_sub_new(WPACKET *pkt)
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

static ossl_inline ossl_unused void wpacket_sub_free(WPACKET *pkt, WPACKET_SUB *sub)
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

static ossl_inline ossl_unused unsigned char *WPACKET_get_curr_int(WPACKET *pkt)
{
    unsigned char *buf = GETBUF(pkt);

    if (buf == NULL)
        return NULL;

    if (pkt->endfirst)
        return buf + pkt->maxsize - pkt->curr;

    return buf + pkt->curr;
}

static ossl_inline ossl_unused int WPACKET_reserve_bytes_int(WPACKET *pkt, size_t len, unsigned char **allocbytes)
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
        *allocbytes = WPACKET_get_curr_int(pkt);
        if (pkt->endfirst && *allocbytes != NULL)
            *allocbytes -= len;
    }

    return 1;
}

static ossl_inline ossl_unused int WPACKET_allocate_bytes_int(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    if (!WPACKET_reserve_bytes_int(pkt, len, allocbytes))
        return 0;

    pkt->written += len;
    pkt->curr += len;
    return 1;
}

static ossl_inline ossl_unused int wpacket_intern_init_len(WPACKET *pkt, size_t lenbytes)
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

    if (!WPACKET_allocate_bytes_int(pkt, lenbytes, &lenchars)) {
        wpacket_sub_free(pkt, pkt->subs);
        pkt->subs = NULL;
        return 0;
    }
    pkt->subs->packet_len = 0;

    return 1;
}

/*
 * Initialise a WPACKET with the buffer in |buf|. The buffer must exist
 * for the whole time that the WPACKET is being used. Additionally |lenbytes| of
 * data is preallocated at the start of the buffer to store the length of the
 * WPACKET once we know it.
 */
static ossl_inline ossl_unused int WPACKET_init_len_int(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
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

static ossl_inline ossl_unused int WPACKET_init_int(WPACKET *pkt, BUF_MEM *buf)
{
    return WPACKET_init_len_int(pkt, buf, 0);
}

static ossl_inline ossl_unused int WPACKET_init_null_der_int(WPACKET *pkt)
{
    pkt->staticbuf = NULL;
    pkt->buf = NULL;
    pkt->maxsize = SIZE_MAX;
    pkt->endfirst = 1;

    return wpacket_intern_init_len(pkt, 0);
}

static ossl_inline ossl_unused int WPACKET_init_null_int(WPACKET *pkt, size_t lenbytes)
{
    pkt->staticbuf = NULL;
    pkt->buf = NULL;
    pkt->maxsize = maxmaxsize(lenbytes);
    pkt->endfirst = 0;

    return wpacket_intern_init_len(pkt, 0);
}

static ossl_inline ossl_unused int WPACKET_init_der_int(WPACKET *pkt, unsigned char *buf, size_t len)
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

static ossl_inline ossl_unused int WPACKET_init_static_len_int(WPACKET *pkt, unsigned char *buf, size_t len,
    size_t lenbytes)
{
    size_t max = maxmaxsize(lenbytes);

    pkt->staticbuf = buf;
    pkt->buf = NULL;
    pkt->maxsize = (max < len) ? max : len;
    pkt->endfirst = 0;
    pkt->subs = NULL;

    /* Internal API, so should not fail */
    if (!ossl_assert(buf != NULL && len > 0))
        return 0;

    return wpacket_intern_init_len(pkt, lenbytes);
}

static ossl_inline ossl_unused int WPACKET_memset_int(WPACKET *pkt, int ch, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes_int(pkt, len, &dest))
        return 0;

    if (dest != NULL)
        memset(dest, ch, len);

    return 1;
}

static ossl_inline ossl_unused int WPACKET_sub_reserve_bytes___int(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    if (pkt->endfirst && lenbytes > 0)
        return 0;

    if (!WPACKET_reserve_bytes_int(pkt, lenbytes + len, allocbytes))
        return 0;

    if (*allocbytes != NULL)
        *allocbytes += lenbytes;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_start_sub_packet_at_offset_len___int(WPACKET *pkt, size_t lenbytes,
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

    if (!WPACKET_allocate_bytes_int(pkt, lenbytes, &lenchars)
        || (offset > 0 && !WPACKET_allocate_bytes_int(pkt, offset, &lenchars)))
        return 0;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_start_sub_packet_len___int(WPACKET *pkt, size_t lenbytes)
{
    return WPACKET_start_sub_packet_at_offset_len___int(pkt, lenbytes, 0);
}

static ossl_inline ossl_unused int WPACKET_start_sub_packet_int(WPACKET *pkt)
{
    return WPACKET_start_sub_packet_len___int(pkt, 0);
}

#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
static ossl_inline ossl_unused int put_quic_value(unsigned char *data, size_t value, size_t len)
{
    if (data == NULL)
        return 1;

    /* Value too large for field. */
    if (ossl_quic_vlint_encode_len(value) > len)
        return 0;

    ossl_quic_vlint_encode_n(data, value, (int)len);
    return 1;
}
#endif

/* Store the |value| of length |len| at location |data| */
static ossl_inline ossl_unused int put_value(unsigned char *data, uint64_t value, size_t len)
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

static ossl_inline ossl_unused int WPACKET_put_bytes___int(WPACKET *pkt, uint64_t val, size_t size)
{
    unsigned char *data;

    /* Internal API, so should not fail */
    if (!ossl_assert(size <= sizeof(uint64_t))
        || !WPACKET_allocate_bytes_int(pkt, size, &data)
        || !put_value(data, val, size))
        return 0;

    return 1;
}

/*
 * Internal helper function used by WPACKET_close(), WPACKET_finish() and
 * WPACKET_fill_lengths() to close a sub-packet and write out its length if
 * necessary. If |doclose| is 0 then it goes through the motions of closing
 * (i.e. it fills in all the lengths), but doesn't actually close anything.
 */
static ossl_inline ossl_unused int wpacket_intern_close(WPACKET *pkt, WPACKET_SUB *sub, int doclose)
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
        if (!WPACKET_put_bytes___int(pkt, packlen, numlenbytes))
            return 0;
        if (packlen > 0x7f) {
            numlenbytes |= 0x80;
            /* WPACKET_put_bytes_u8 */
            if (!WPACKET_put_bytes___int(pkt, numlenbytes, 1))
                return 0;
        }
    }

    if (doclose) {
        pkt->subs = sub->parent;
        wpacket_sub_free(pkt, sub);
    }

    return 1;
}

static ossl_inline ossl_unused int WPACKET_fill_lengths_int(WPACKET *pkt)
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

static ossl_inline ossl_unused int WPACKET_finish_int(WPACKET *pkt)
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

static ossl_inline ossl_unused int WPACKET_close_int(WPACKET *pkt)
{
    /*
     * Internal API, so should not fail - but we do negative testing of this
     * so no assert (otherwise the tests fail)
     */
    if (pkt->subs == NULL || pkt->subs->parent == NULL)
        return 0;

    return wpacket_intern_close(pkt, pkt->subs, 1);
}

static ossl_inline ossl_unused int WPACKET_memcpy_int(WPACKET *pkt, const void *src, size_t len)
{
    unsigned char *dest;

    if (len == 0)
        return 1;

    if (!WPACKET_allocate_bytes_int(pkt, len, &dest))
        return 0;

    if (dest != NULL)
        memcpy(dest, src, len);

    return 1;
}

static ossl_inline ossl_unused int WPACKET_sub_allocate_bytes___int(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    if (!WPACKET_start_sub_packet_len___int(pkt, lenbytes)
        || !WPACKET_allocate_bytes_int(pkt, len, allocbytes)
        || !WPACKET_close_int(pkt))
        return 0;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_sub_memcpy___int(WPACKET *pkt, const void *src, size_t len,
    size_t lenbytes)
{
    if (!WPACKET_start_sub_packet_len___int(pkt, lenbytes)
        || !WPACKET_memcpy_int(pkt, src, len)
        || !WPACKET_close_int(pkt))
        return 0;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_is_null_buf_int(WPACKET *pkt)
{
    return pkt->buf == NULL && pkt->staticbuf == NULL;
}

static ossl_inline ossl_unused int WPACKET_get_length_int(WPACKET *pkt, size_t *len)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(pkt->subs != NULL && len != NULL))
        return 0;

    *len = pkt->written - pkt->subs->pwritten;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_set_flags_int(WPACKET *pkt, unsigned int flags)
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

static ossl_inline ossl_unused int WPACKET_get_total_written_int(WPACKET *pkt, size_t *written)
{
    /* Internal API, so should not fail */
    if (!ossl_assert(written != NULL))
        return 0;

    *written = pkt->written;

    return 1;
}

static ossl_inline ossl_unused int WPACKET_set_max_size_int(WPACKET *pkt, size_t maxsize)
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

static ossl_inline ossl_unused void WPACKET_cleanup_int(WPACKET *pkt)
{
    WPACKET_SUB *sub, *parent;

    for (sub = pkt->subs; sub != NULL; sub = parent) {
        parent = sub->parent;
        wpacket_sub_free(pkt, sub);
    }
    pkt->subs = NULL;
}

#endif /* OSSL_INTERNAL_PACKET_INLINE_H */
