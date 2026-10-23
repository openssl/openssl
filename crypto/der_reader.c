/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <limits.h>
#include "internal/cryptlib.h"
#include "internal/der.h"

/*
 * Read a DER length from |pkt|.  Indefinite length is rejected, as are
 * lengths that need more octets than a size_t can hold.  Non-minimal
 * encodings are accepted, in line with the leniency documented in
 * internal/der.h.
 */
static int int_der_r_length(PACKET *pkt, size_t *len)
{
    unsigned int b = 0;

    if (!PACKET_get_1(pkt, &b))
        return 0;
    if ((b & 0x80) == 0) {
        *len = b;
        return 1;
    }

    b &= 0x7F;
    if (b == 0 || b > sizeof(*len))
        return 0;

    *len = 0;
    while (b-- > 0) {
        unsigned int c = 0;

        if (!PACKET_get_1(pkt, &c))
            return 0;
        *len = (*len << 8) | c;
    }
    return 1;
}

int ossl_DER_r_element(PACKET *pkt, unsigned int *identifier,
    PACKET *contents)
{
    unsigned int id = 0;
    size_t len = 0;
    PACKET content;

    if (!PACKET_get_1(pkt, &id)
        /* The high-tag-number form is unsupported */
        || (id & 0x1F) == 0x1F
        || !int_der_r_length(pkt, &len)
        || !PACKET_get_sub_packet(pkt, &content, len))
        return 0;

    *identifier = id;
    if (contents != NULL)
        *contents = content;
    return 1;
}

int ossl_DER_r_peek_element(const PACKET *pkt, unsigned int *identifier,
    PACKET *contents)
{
    PACKET tmp = *pkt;

    return ossl_DER_r_element(&tmp, identifier, contents);
}

/* Read one element with the expected |universal| identifier octet */
static int int_der_r_universal(PACKET *pkt, unsigned int universal,
    PACKET *contents)
{
    unsigned int id = 0;

    return ossl_DER_r_element(pkt, &id, contents)
        && id == universal;
}

/*
 * Read the element identified by |tag|, using the same conventions as the
 * writers: with DER_NO_CONTEXT, the element with the universal identifier
 * |universal| is read bare; with a context tag number, a constructed
 * context specific element is expected, wrapping exactly the element with
 * the universal identifier |universal|.
 */
static int int_der_r_contextual(PACKET *pkt, int tag, unsigned int universal,
    PACKET *contents)
{
    PACKET wrapper;

    if (tag < 0)
        return int_der_r_universal(pkt, universal, contents);
    if (!ossl_assert(tag <= 30))
        return 0;
    return int_der_r_universal(pkt, DER_C_CONTEXT | DER_F_CONSTRUCTED | tag,
               &wrapper)
        && int_der_r_universal(&wrapper, universal, contents)
        && PACKET_remaining(&wrapper) == 0;
}

int ossl_DER_r_precompiled(PACKET *pkt, int tag,
    const unsigned char *precompiled,
    size_t precompiled_n)
{
    PACKET wrapper;
    PACKET skipped;

    if (tag < 0) {
        if (PACKET_remaining(pkt) < precompiled_n
            || memcmp(PACKET_data(pkt), precompiled, precompiled_n) != 0)
            return 0;
        return PACKET_get_sub_packet(pkt, &skipped, precompiled_n);
    }
    if (!ossl_assert(tag <= 30))
        return 0;
    return int_der_r_universal(pkt, DER_C_CONTEXT | DER_F_CONSTRUCTED | tag,
               &wrapper)
        && PACKET_equal(&wrapper, precompiled, precompiled_n);
}

int ossl_DER_r_boolean(PACKET *pkt, int tag, int *b)
{
    PACKET contents;
    unsigned int v = 0;

    if (!int_der_r_contextual(pkt, tag, DER_P_BOOLEAN, &contents)
        || !PACKET_get_1(&contents, &v)
        || PACKET_remaining(&contents) != 0)
        return 0;
    *b = (v != 0);
    return 1;
}

static int int_der_r_uint32_contents(const PACKET *contents, uint32_t *v)
{
    const unsigned char *p = PACKET_data(contents);
    size_t len = PACKET_remaining(contents);
    uint32_t value = 0;
    size_t i = 0;

    /*
     * We only support non-negative integers that fit in uint32_t,
     * like the writer.  With an optional sign padding octet, that's
     * at most 5 octets.
     */
    if (len == 0 || len > 5)
        return 0;
    if ((*p & 0x80) != 0)
        return 0;
    if (*p == 0x00) {
        /* Skip the sign padding octet */
        p++;
        len--;
    }
    if (len > 4)
        return 0;
    for (i = 0; i < len; i++)
        value = (value << 8) | p[i];
    *v = value;
    return 1;
}

int ossl_DER_r_uint32(PACKET *pkt, int tag, uint32_t *v)
{
    PACKET contents;

    return int_der_r_contextual(pkt, tag, DER_P_INTEGER, &contents)
        && int_der_r_uint32_contents(&contents, v);
}

int ossl_DER_r_bn(PACKET *pkt, int tag, BIGNUM **v)
{
    PACKET contents;
    const unsigned char *p = NULL;
    size_t len = 0;
    BIGNUM *bn = NULL;

    if (!int_der_r_contextual(pkt, tag, DER_P_INTEGER, &contents))
        return 0;

    p = PACKET_data(&contents);
    len = PACKET_remaining(&contents);
    /* We only support non-negative integers, like the writer */
    if (len == 0 || len > (size_t)INT_MAX || (*p & 0x80) != 0)
        return 0;
    if (*p == 0x00) {
        /* Skip the sign padding octet */
        p++;
        len--;
    }
    bn = (len == 0) ? BN_new() : BN_bin2bn(p, (int)len, NULL);
    if (bn == NULL)
        return 0;
    *v = bn;
    return 1;
}

int ossl_DER_r_null(PACKET *pkt, int tag)
{
    PACKET contents;

    return int_der_r_contextual(pkt, tag, DER_P_NULL, &contents)
        && PACKET_remaining(&contents) == 0;
}

int ossl_DER_r_octet_string(PACKET *pkt, int tag, PACKET *contents)
{
    return int_der_r_contextual(pkt, tag, DER_P_OCTET_STRING, contents);
}

int ossl_DER_r_begin_sequence(PACKET *pkt, int tag, PACKET *contents)
{
    return int_der_r_contextual(pkt, tag,
        DER_F_CONSTRUCTED | DER_P_SEQUENCE, contents);
}
