/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/cryptlib.h"
#include <stdint.h>
#include "internal/packet.h"
#include "internal/packet_inline.h"
#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE
#include "internal/packet_quic.h"
#endif
#include <openssl/err.h>

#ifdef OPENSSL_SMALL_FOOTPRINT
int WPACKET_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    return WPACKET_allocate_bytes_int(pkt, len, allocbytes);
}

int WPACKET_sub_allocate_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    return WPACKET_sub_allocate_bytes___int(pkt, len, allocbytes, lenbytes);
}

int WPACKET_reserve_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
{
    return WPACKET_reserve_bytes_int(pkt, len, allocbytes);
}

int WPACKET_sub_reserve_bytes__(WPACKET *pkt, size_t len,
    unsigned char **allocbytes, size_t lenbytes)
{
    return WPACKET_sub_reserve_bytes___int(pkt, len, allocbytes, lenbytes);
}

int WPACKET_init_static_len(WPACKET *pkt, unsigned char *buf, size_t len,
    size_t lenbytes)
{
    return WPACKET_init_static_len_int(pkt, buf, len, lenbytes);
}

int WPACKET_init_der(WPACKET *pkt, unsigned char *buf, size_t len)
{
    return WPACKET_init_der_int(pkt, buf, len);
}

int WPACKET_init_len(WPACKET *pkt, BUF_MEM *buf, size_t lenbytes)
{
    return WPACKET_init_len_int(pkt, buf, lenbytes);
}

int WPACKET_init(WPACKET *pkt, BUF_MEM *buf)
{
    return WPACKET_init_int(pkt, buf);
}

int WPACKET_init_null(WPACKET *pkt, size_t lenbytes)
{
    return WPACKET_init_null_int(pkt, lenbytes);
}

int WPACKET_init_null_der(WPACKET *pkt)
{
    return WPACKET_init_null_der_int(pkt);
}

int WPACKET_set_flags(WPACKET *pkt, unsigned int flags)
{
    return WPACKET_set_flags_int(pkt, flags);
}

int WPACKET_fill_lengths(WPACKET *pkt)
{
    return WPACKET_fill_lengths_int(pkt);
}

int WPACKET_close(WPACKET *pkt)
{
    return WPACKET_close_int(pkt);
}

int WPACKET_finish(WPACKET *pkt)
{
    return WPACKET_finish_int(pkt);
}

int WPACKET_start_sub_packet_len__(WPACKET *pkt, size_t lenbytes)
{
    return WPACKET_start_sub_packet_len___int(pkt, lenbytes);
}

int WPACKET_start_sub_packet_at_offset_len__(WPACKET *pkt, size_t lenbytes,
    size_t offset)
{
    return WPACKET_start_sub_packet_at_offset_len___int(pkt, lenbytes, offset);
}

int WPACKET_start_sub_packet(WPACKET *pkt)
{
    return WPACKET_start_sub_packet_int(pkt);
}

int WPACKET_put_bytes__(WPACKET *pkt, uint64_t val, size_t size)
{
    return WPACKET_put_bytes___int(pkt, val, size);
}

int WPACKET_set_max_size(WPACKET *pkt, size_t maxsize)
{
    return WPACKET_set_max_size_int(pkt, maxsize);
}

int WPACKET_memset(WPACKET *pkt, int ch, size_t len)
{
    return WPACKET_memset_int(pkt, ch, len);
}

int WPACKET_memcpy(WPACKET *pkt, const void *src, size_t len)
{
    return WPACKET_memcpy_int(pkt, src, len);
}

int WPACKET_sub_memcpy__(WPACKET *pkt, const void *src, size_t len,
    size_t lenbytes)
{
    return WPACKET_sub_memcpy___int(pkt, src, len, lenbytes);
}

int WPACKET_get_total_written(WPACKET *pkt, size_t *written)
{
    return WPACKET_get_total_written_int(pkt, written);
}

int WPACKET_get_length(WPACKET *pkt, size_t *len)
{
    return WPACKET_get_length_int(pkt, len);
}

unsigned char *WPACKET_get_curr(WPACKET *pkt)
{
    return WPACKET_get_curr_int(pkt);
}

int WPACKET_is_null_buf(WPACKET *pkt)
{
    return WPACKET_is_null_buf_int(pkt);
}

void WPACKET_cleanup(WPACKET *pkt)
{
    WPACKET_cleanup_int(pkt);
}

#endif

#if !defined OPENSSL_NO_QUIC && !defined FIPS_MODULE

int WPACKET_start_quic_sub_packet_bound(WPACKET *pkt, size_t max_len)
{
    size_t enclen = ossl_quic_vlint_encode_len(max_len);

    if (enclen == 0)
        return 0;

    if (WPACKET_start_sub_packet_len__(pkt, enclen) == 0)
        return 0;

    pkt->subs->flags |= WPACKET_FLAGS_QUIC_VLINT;
    return 1;
}

int WPACKET_start_quic_sub_packet(WPACKET *pkt)
{
    /*
     * Assume no (sub)packet will exceed 4GiB, thus the 8-byte encoding need not
     * be used.
     */
    return WPACKET_start_quic_sub_packet_bound(pkt, OSSL_QUIC_VLINT_4B_MIN);
}

int WPACKET_quic_sub_allocate_bytes(WPACKET *pkt, size_t len, unsigned char **allocbytes)
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
int WPACKET_quic_write_vlint(WPACKET *pkt, uint64_t v)
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
