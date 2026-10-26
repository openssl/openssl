/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/crypto.h>

#include "internal/bytestring.h"

void CBS_init(CBS *cbs, const uint8_t *data, size_t len)
{
    cbs->data = data;
    cbs->initial_len = len;
    cbs->len = len;
}

void CBS_dup(const CBS *cbs, CBS *out)
{
    *out = *cbs;
}

const uint8_t *CBS_data(const CBS *cbs)
{
    return cbs->data;
}

size_t CBS_len(const CBS *cbs)
{
    return cbs->len;
}

size_t CBS_offset(const CBS *cbs)
{
    return cbs->initial_len - cbs->len;
}

static int cbs_get(CBS *cbs, const uint8_t **p, size_t n)
{
    if (cbs->len < n)
        return 0;

    *p = cbs->data;
    cbs->data += n;
    cbs->len -= n;
    return 1;
}

static int cbs_get_u(CBS *cbs, uint64_t *out, size_t width)
{
    const uint8_t *p;
    uint64_t v = 0;
    size_t i;

    if (!cbs_get(cbs, &p, width))
        return 0;
    for (i = 0; i < width; i++)
        v = (v << 8) | p[i];
    *out = v;
    return 1;
}

int CBS_skip(CBS *cbs, size_t len)
{
    const uint8_t *p;

    return cbs_get(cbs, &p, len);
}

int CBS_stow(const CBS *cbs, uint8_t **out_ptr, size_t *out_len)
{
    OPENSSL_free(*out_ptr);
    *out_ptr = NULL;
    *out_len = 0;

    if (cbs->len == 0)
        return 1;
    if ((*out_ptr = OPENSSL_memdup(cbs->data, cbs->len)) == NULL)
        return 0;
    *out_len = cbs->len;
    return 1;
}

int CBS_mem_equal(const CBS *cbs, const uint8_t *data, size_t len)
{
    if (cbs->len != len)
        return 0;

    return CRYPTO_memcmp(cbs->data, data, len) == 0;
}

int CBS_contains_zero_byte(const CBS *cbs)
{
    return cbs->len != 0 && memchr(cbs->data, 0, cbs->len) != NULL;
}

int CBS_get_u8(CBS *cbs, uint8_t *out)
{
    const uint8_t *p;

    if (!cbs_get(cbs, &p, 1))
        return 0;
    *out = p[0];
    return 1;
}

int CBS_get_u16(CBS *cbs, uint16_t *out)
{
    uint64_t v;

    if (!cbs_get_u(cbs, &v, 2))
        return 0;
    *out = (uint16_t)v;
    return 1;
}

int CBS_get_u24(CBS *cbs, uint32_t *out)
{
    uint64_t v;

    if (!cbs_get_u(cbs, &v, 3))
        return 0;
    *out = (uint32_t)v;
    return 1;
}

int CBS_get_u32(CBS *cbs, uint32_t *out)
{
    uint64_t v;

    if (!cbs_get_u(cbs, &v, 4))
        return 0;
    *out = (uint32_t)v;
    return 1;
}

int CBS_get_u48(CBS *cbs, uint64_t *out)
{
    return cbs_get_u(cbs, out, 6);
}

int CBS_get_u64(CBS *cbs, uint64_t *out)
{
    return cbs_get_u(cbs, out, 8);
}

int CBS_peek_u8(const CBS *cbs, uint8_t *out)
{
    if (cbs->len == 0)
        return 0;
    *out = cbs->data[0];
    return 1;
}

int CBS_get_bytes(CBS *cbs, CBS *out, size_t len)
{
    const uint8_t *p;

    if (!cbs_get(cbs, &p, len))
        return 0;
    CBS_init(out, p, len);
    return 1;
}

static int cbs_get_length_prefixed(CBS *cbs, CBS *out, size_t width)
{
    CBS tmp = *cbs;
    uint64_t len;

    if (!cbs_get_u(&tmp, &len, width)
        || !CBS_get_bytes(&tmp, out, (size_t)len))
        return 0;
    *cbs = tmp;
    return 1;
}

int CBS_get_u8_length_prefixed(CBS *cbs, CBS *out)
{
    return cbs_get_length_prefixed(cbs, out, 1);
}

int CBS_get_u16_length_prefixed(CBS *cbs, CBS *out)
{
    return cbs_get_length_prefixed(cbs, out, 2);
}

int CBS_get_u24_length_prefixed(CBS *cbs, CBS *out)
{
    return cbs_get_length_prefixed(cbs, out, 3);
}

int CBS_get_any_asn1_element(CBS *cbs, CBS *out, unsigned int *out_tag,
    size_t *out_header_len)
{
    CBS header = *cbs;
    CBS element;
    uint8_t tag, length_byte;
    uint64_t len;
    size_t header_len, num_bytes;

    if (!CBS_get_u8(&header, &tag) || !CBS_get_u8(&header, &length_byte))
        return 0;
    if ((tag & 0x1f) == 0x1f)
        return 0;

    if ((length_byte & 0x80) == 0) {
        len = length_byte;
        header_len = 2;
    } else {
        num_bytes = length_byte & 0x7f;
        if (num_bytes == 0 || num_bytes > 4)
            return 0;
        if (!cbs_get_u(&header, &len, num_bytes))
            return 0;
        if (len < 0x80)
            return 0;
        if ((len >> ((num_bytes - 1) * 8)) == 0)
            return 0;
        header_len = 2 + num_bytes;
    }
    if (len > SIZE_MAX - header_len)
        return 0;
    if (!CBS_get_bytes(cbs, &element, header_len + (size_t)len))
        return 0;

    if (out != NULL)
        *out = element;
    if (out_tag != NULL)
        *out_tag = tag;
    if (out_header_len != NULL)
        *out_header_len = header_len;
    return 1;
}

static int cbs_get_asn1(CBS *cbs, CBS *out, unsigned int tag, int skip_header)
{
    CBS tmp = *cbs;
    CBS element;
    unsigned int actual_tag;
    size_t header_len;

    if (!CBS_get_any_asn1_element(&tmp, &element, &actual_tag, &header_len)
        || actual_tag != tag)
        return 0;
    if (skip_header && !CBS_skip(&element, header_len))
        return 0;

    *cbs = tmp;
    if (out != NULL)
        *out = element;
    return 1;
}

int CBS_get_asn1(CBS *cbs, CBS *out, unsigned int tag)
{
    return cbs_get_asn1(cbs, out, tag, 1);
}

int CBS_get_asn1_element(CBS *cbs, CBS *out, unsigned int tag)
{
    return cbs_get_asn1(cbs, out, tag, 0);
}

int CBS_peek_asn1_tag(const CBS *cbs, unsigned int tag)
{
    if (cbs->len == 0 || (tag & 0x1f) == 0x1f)
        return 0;

    return cbs->data[0] == tag;
}

int CBS_get_optional_asn1(CBS *cbs, CBS *out, int *out_present,
    unsigned int tag)
{
    if (!CBS_peek_asn1_tag(cbs, tag)) {
        *out_present = 0;
        return 1;
    }
    if (!CBS_get_asn1(cbs, out, tag))
        return 0;
    *out_present = 1;
    return 1;
}

int CBS_get_asn1_uint64(CBS *cbs, uint64_t *out)
{
    CBS tmp = *cbs;
    CBS contents;
    const uint8_t *data;
    uint64_t v = 0;
    size_t i, len;

    if (!CBS_get_asn1(&tmp, &contents, CBS_ASN1_INTEGER))
        return 0;
    data = CBS_data(&contents);
    len = CBS_len(&contents);
    if (len == 0)
        return 0;
    if ((data[0] & 0x80) != 0)
        return 0;
    if (data[0] == 0 && len > 1 && (data[1] & 0x80) == 0)
        return 0;
    for (i = 0; i < len; i++) {
        if ((v >> 56) != 0)
            return 0;
        v = (v << 8) | data[i];
    }

    *cbs = tmp;
    *out = v;
    return 1;
}
