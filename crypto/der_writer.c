/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>
#include "internal/cryptlib.h"
#include "internal/der.h"
#include "crypto/bn.h"

static int int_start_context(WPACKET *pkt, int tag)
{
    if (tag < 0)
        return 1;
    if (!ossl_assert(tag <= 30))
        return 0;
    return WPACKET_start_sub_packet(pkt);
}

static int int_end_context(WPACKET *pkt, int tag)
{
    if (tag < 0)
        return 1;
    if (!ossl_assert(tag <= 30))
        return 0;
    return WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_C_CONTEXT | tag);
}

int DER_w_precompiled(WPACKET *pkt, int tag,
                      const unsigned char *precompiled, size_t precompiled_n)
{
    return int_start_context(pkt, tag)
        && WPACKET_memcpy(pkt, precompiled, precompiled_n)
        && int_end_context(pkt, tag);
}

int DER_w_boolean(WPACKET *pkt, int tag, int b)
{
    return int_start_context(pkt, tag)
        && WPACKET_start_sub_packet(pkt)
        && (!b || WPACKET_put_bytes_u8(pkt, 0xFF))
        && !WPACKET_close(pkt)
        && !WPACKET_put_bytes_u8(pkt, DER_P_BOOLEAN)
        && int_end_context(pkt, tag);
}

static int int_der_w_integer(WPACKET *pkt, int tag,
                             int (*put_bytes)(WPACKET *pkt, const void *v,
                                              unsigned int *top_byte),
                             const void *v)
{
    unsigned int top_byte = 0;

    return int_start_context(pkt, tag)
        && WPACKET_start_sub_packet(pkt)
        && put_bytes(pkt, v, &top_byte)
        && ((top_byte & 0x80) == 0 || WPACKET_put_bytes_u8(pkt, 0))
        && WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_P_INTEGER)
        && int_end_context(pkt, tag);
}

static int int_put_bytes_ulong(WPACKET *pkt, const void *v,
                               unsigned int *top_byte)
{
    const unsigned long *value = v;
    unsigned long tmp = *value;
    size_t n = 0;

    while (tmp != 0) {
        n++;
        *top_byte = (tmp & 0xFF);
        tmp >>= 8;
    }
    if (n == 0)
        n = 1;

    return WPACKET_put_bytes__(pkt, *value, n);
}

/* For integers, we only support unsigned values for now */
int DER_w_ulong(WPACKET *pkt, int tag, unsigned long v)
{
    return int_der_w_integer(pkt, tag, int_put_bytes_ulong, &v);
}

static int int_put_bytes_bn(WPACKET *pkt, const void *v,
                            unsigned int *top_byte)
{
    unsigned char *p = NULL;
    size_t n = BN_num_bytes(v);

    /* The BIGNUM limbs are in LE order */
    *top_byte =
        ((bn_get_words(v) [(n - 1) / BN_BYTES]) >> (8 * ((n - 1) % BN_BYTES)))
        & 0xFF;

    if (!WPACKET_allocate_bytes(pkt, n, &p))
        return 0;
    if (p != NULL)
        BN_bn2bin(v, p);
    return 1;
}

int DER_w_bn(WPACKET *pkt, int tag, const BIGNUM *v)
{
    if (v == NULL || BN_is_negative(v))
        return 0;
    if (BN_is_zero(v))
        return DER_w_ulong(pkt, tag, 0);

    return int_der_w_integer(pkt, tag, int_put_bytes_bn, v);
}

int DER_w_null(WPACKET *pkt, int tag)
{
    return int_start_context(pkt, tag)
        && WPACKET_start_sub_packet(pkt)
        && WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_P_NULL)
        && int_end_context(pkt, tag);
}

/* Constructed things need a start and an end */
int DER_w_begin_sequence(WPACKET *pkt, int tag)
{
    return int_start_context(pkt, tag)
        && WPACKET_start_sub_packet(pkt);
}

int DER_w_end_sequence(WPACKET *pkt, int tag)
{
    return WPACKET_close(pkt)
        && WPACKET_put_bytes_u8(pkt, DER_F_CONSTRUCTED | DER_P_SEQUENCE)
        && int_end_context(pkt, tag);
}
