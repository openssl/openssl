/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include "internal/bytestring.h"
#include "internal/nelem.h"
#include "testutil.h"

static int test_cbs_skip(void)
{
    static const uint8_t data[] = { 1, 2, 3 };
    CBS cbs;
    uint8_t v;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_skip(&cbs, 1))
        || !TEST_true(CBS_get_u8(&cbs, &v))
        || !TEST_uint_eq(v, 2)
        || !TEST_false(CBS_skip(&cbs, 2))
        || !TEST_size_t_eq(CBS_len(&cbs), 1)
        || !TEST_true(CBS_skip(&cbs, 1))
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    return 1;
}

static int test_cbs_get_u(void)
{
    static const uint8_t data[] = {
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
        20, 21, 22, 23, 24
    };
    CBS cbs;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;
    uint64_t u64;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_get_u8(&cbs, &u8))
        || !TEST_uint_eq(u8, 1)
        || !TEST_true(CBS_get_u16(&cbs, &u16))
        || !TEST_uint_eq(u16, 0x0203)
        || !TEST_true(CBS_get_u24(&cbs, &u32))
        || !TEST_uint_eq(u32, 0x040506)
        || !TEST_true(CBS_get_u32(&cbs, &u32))
        || !TEST_uint_eq(u32, 0x0708090a)
        || !TEST_true(CBS_get_u64(&cbs, &u64))
        || !TEST_uint64_t_eq(u64, UINT64_C(0x0b0c0d0e0f101112))
        || !TEST_false(CBS_get_u64(&cbs, &u64))
        || !TEST_size_t_eq(CBS_len(&cbs), 6)
        || !TEST_true(CBS_get_u48(&cbs, &u64))
        || !TEST_uint64_t_eq(u64, UINT64_C(0x131415161718))
        || !TEST_false(CBS_get_u48(&cbs, &u64))
        || !TEST_false(CBS_get_u24(&cbs, &u32))
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    return 1;
}

static int test_cbs_peek_u8(void)
{
    static const uint8_t data[] = { 0x42 };
    CBS cbs;
    uint8_t v;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_peek_u8(&cbs, &v))
        || !TEST_uint_eq(v, 0x42)
        || !TEST_size_t_eq(CBS_len(&cbs), 1)
        || !TEST_true(CBS_skip(&cbs, 1))
        || !TEST_false(CBS_peek_u8(&cbs, &v)))
        return 0;

    return 1;
}

static int test_cbs_get_prefixed(void)
{
    static const uint8_t data[] = {
        1, 2, 0, 2, 3, 4, 0, 0, 3, 3, 2, 1
    };
    CBS cbs, prefixed;
    uint8_t u8;
    uint16_t u16;
    uint32_t u32;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_get_u8_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&prefixed), 1)
        || !TEST_true(CBS_get_u8(&prefixed, &u8))
        || !TEST_uint_eq(u8, 2)
        || !TEST_true(CBS_get_u16_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&prefixed), 2)
        || !TEST_true(CBS_get_u16(&prefixed, &u16))
        || !TEST_uint_eq(u16, 0x0304)
        || !TEST_true(CBS_get_u24_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&prefixed), 3)
        || !TEST_true(CBS_get_u24(&prefixed, &u32))
        || !TEST_uint_eq(u32, 0x030201)
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    return 1;
}

static int test_cbs_get_prefixed_bad(void)
{
    static const uint8_t short8[] = { 2, 1 };
    static const uint8_t short16[] = { 0, 2, 1 };
    static const uint8_t short24[] = { 0, 0, 2, 1 };
    CBS cbs, prefixed;

    CBS_init(&cbs, short8, sizeof(short8));
    if (!TEST_false(CBS_get_u8_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&cbs), sizeof(short8)))
        return 0;
    CBS_init(&cbs, short16, sizeof(short16));
    if (!TEST_false(CBS_get_u16_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&cbs), sizeof(short16)))
        return 0;
    CBS_init(&cbs, short24, sizeof(short24));
    if (!TEST_false(CBS_get_u24_length_prefixed(&cbs, &prefixed))
        || !TEST_size_t_eq(CBS_len(&cbs), sizeof(short24)))
        return 0;

    return 1;
}

static int test_cbs_offset_dup(void)
{
    static const uint8_t data[] = { 1, 2, 3, 4 };
    CBS cbs, copy;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_size_t_eq(CBS_offset(&cbs), 0)
        || !TEST_true(CBS_skip(&cbs, 1))
        || !TEST_size_t_eq(CBS_offset(&cbs), 1))
        return 0;
    CBS_dup(&cbs, &copy);
    if (!TEST_ptr_eq(CBS_data(&copy), data + 1)
        || !TEST_size_t_eq(CBS_len(&copy), 3)
        || !TEST_size_t_eq(CBS_offset(&copy), 1)
        || !TEST_true(CBS_skip(&copy, 3))
        || !TEST_size_t_eq(CBS_offset(&copy), 4)
        || !TEST_size_t_eq(CBS_len(&cbs), 3))
        return 0;

    return 1;
}

static int test_cbs_mem_equal_zero_byte(void)
{
    static const uint8_t data[] = { 'a', 'b', 0, 'c' };
    CBS cbs;

    CBS_init(&cbs, data, 2);
    if (!TEST_true(CBS_mem_equal(&cbs, (const uint8_t *)"ab", 2))
        || !TEST_false(CBS_mem_equal(&cbs, (const uint8_t *)"ac", 2))
        || !TEST_false(CBS_mem_equal(&cbs, (const uint8_t *)"abc", 3))
        || !TEST_false(CBS_contains_zero_byte(&cbs)))
        return 0;
    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_contains_zero_byte(&cbs)))
        return 0;
    CBS_init(&cbs, NULL, 0);
    if (!TEST_true(CBS_mem_equal(&cbs, NULL, 0))
        || !TEST_false(CBS_contains_zero_byte(&cbs)))
        return 0;

    return 1;
}

static int test_cbs_stow(void)
{
    static const uint8_t data[] = { 1, 2, 3 };
    CBS cbs;
    uint8_t *ptr = NULL;
    size_t len = 0;
    int ret = 0;

    CBS_init(&cbs, data, sizeof(data));
    if (!TEST_true(CBS_stow(&cbs, &ptr, &len))
        || !TEST_mem_eq(ptr, len, data, sizeof(data))
        || !TEST_ptr_ne(ptr, data))
        goto err;
    if (!TEST_true(CBS_skip(&cbs, 1))
        || !TEST_true(CBS_stow(&cbs, &ptr, &len))
        || !TEST_mem_eq(ptr, len, data + 1, sizeof(data) - 1))
        goto err;
    CBS_init(&cbs, NULL, 0);
    if (!TEST_true(CBS_stow(&cbs, &ptr, &len))
        || !TEST_ptr_null(ptr)
        || !TEST_size_t_eq(len, 0))
        goto err;

    ret = 1;
err:
    OPENSSL_free(ptr);
    return ret;
}

static int test_cbs_get_asn1(void)
{
    static const uint8_t seq[] = { 0x30, 2, 1, 2 };
    static const uint8_t truncated[] = { 0x30, 3, 1, 2 };
    static const uint8_t indefinite[] = { 0x30, 0x80 };
    static const uint8_t long_form_short[] = { 0x30, 0x81, 1, 1 };
    static const uint8_t non_minimal[4 + 0x80] = { 0x30, 0x82, 0, 0x80 };
    static const uint8_t five_byte_len[] = { 0x30, 0x85, 0, 0, 0, 0, 1, 0 };
    static const uint8_t high_tag[] = { 0x1f, 0x81, 0x00, 0 };
    CBS cbs, contents;

    CBS_init(&cbs, seq, sizeof(seq));
    if (!TEST_false(CBS_peek_asn1_tag(&cbs, CBS_ASN1_BOOLEAN))
        || !TEST_true(CBS_peek_asn1_tag(&cbs, CBS_ASN1_SEQUENCE))
        || !TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SET))
        || !TEST_size_t_eq(CBS_len(&cbs), sizeof(seq))
        || !TEST_true(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE))
        || !TEST_mem_eq(CBS_data(&contents), CBS_len(&contents),
            "\x01\x02", 2)
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    CBS_init(&cbs, seq, sizeof(seq));
    if (!TEST_true(CBS_get_asn1_element(&cbs, &contents, CBS_ASN1_SEQUENCE))
        || !TEST_mem_eq(CBS_data(&contents), CBS_len(&contents),
            seq, sizeof(seq)))
        return 0;

    CBS_init(&cbs, truncated, sizeof(truncated));
    if (!TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE)))
        return 0;
    CBS_init(&cbs, indefinite, sizeof(indefinite));
    if (!TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE)))
        return 0;
    CBS_init(&cbs, long_form_short, sizeof(long_form_short));
    if (!TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE)))
        return 0;
    CBS_init(&cbs, non_minimal, sizeof(non_minimal));
    if (!TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE)))
        return 0;
    CBS_init(&cbs, five_byte_len, sizeof(five_byte_len));
    if (!TEST_false(CBS_get_asn1(&cbs, &contents, CBS_ASN1_SEQUENCE)))
        return 0;
    CBS_init(&cbs, high_tag, sizeof(high_tag));
    if (!TEST_false(CBS_get_any_asn1_element(&cbs, NULL, NULL, NULL))
        || !TEST_false(CBS_peek_asn1_tag(&cbs, 0x1f)))
        return 0;

    CBS_init(&cbs, NULL, 0);
    if (!TEST_false(CBS_peek_asn1_tag(&cbs, CBS_ASN1_SEQUENCE))
        || !TEST_false(CBS_get_any_asn1_element(&cbs, NULL, NULL, NULL)))
        return 0;

    return 1;
}

static int test_cbs_get_any_asn1_element(void)
{
    static uint8_t long_form[4 + 0x100] = { 0x04, 0x82, 0x01, 0x00 };
    static const uint8_t ctx[] = { 0xa1, 3, 0x04, 1, 1 };
    CBS cbs, element;
    unsigned int tag;
    size_t header_len;

    CBS_init(&cbs, long_form, sizeof(long_form));
    if (!TEST_true(CBS_get_any_asn1_element(&cbs, &element, &tag,
            &header_len))
        || !TEST_uint_eq(tag, CBS_ASN1_OCTETSTRING)
        || !TEST_size_t_eq(header_len, 4)
        || !TEST_size_t_eq(CBS_len(&element), sizeof(long_form))
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    CBS_init(&cbs, ctx, sizeof(ctx));
    if (!TEST_true(CBS_get_any_asn1_element(&cbs, &element, &tag,
            &header_len))
        || !TEST_uint_eq(tag,
            CBS_ASN1_CONTEXT_SPECIFIC | CBS_ASN1_CONSTRUCTED | 1)
        || !TEST_size_t_eq(header_len, 2)
        || !TEST_size_t_eq(CBS_len(&element), sizeof(ctx)))
        return 0;

    return 1;
}

static int test_cbs_get_optional_asn1(void)
{
    static const uint8_t ctx[] = { 0xa1, 3, 0x04, 1, 1 };
    static const uint8_t ctx_truncated[] = { 0xa1, 3, 0x04, 1 };
    CBS cbs, contents;
    int present;

    CBS_init(&cbs, NULL, 0);
    if (!TEST_true(CBS_get_optional_asn1(&cbs, &contents, &present, 0xa0))
        || !TEST_false(present))
        return 0;

    CBS_init(&cbs, ctx, sizeof(ctx));
    if (!TEST_true(CBS_get_optional_asn1(&cbs, &contents, &present, 0xa0))
        || !TEST_false(present)
        || !TEST_size_t_eq(CBS_len(&cbs), sizeof(ctx))
        || !TEST_true(CBS_get_optional_asn1(&cbs, &contents, &present, 0xa1))
        || !TEST_true(present)
        || !TEST_mem_eq(CBS_data(&contents), CBS_len(&contents),
            "\x04\x01\x01", 3)
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    CBS_init(&cbs, ctx_truncated, sizeof(ctx_truncated));
    if (!TEST_false(CBS_get_optional_asn1(&cbs, &contents, &present, 0xa1)))
        return 0;

    return 1;
}

static const struct {
    uint64_t value;
    const char *der;
    size_t der_len;
} asn1_uint64_valid[] = {
    { 0, "\x02\x01\x00", 3 },
    { 1, "\x02\x01\x01", 3 },
    { 127, "\x02\x01\x7f", 3 },
    { 128, "\x02\x02\x00\x80", 4 },
    { 0xdeadbeef, "\x02\x05\x00\xde\xad\xbe\xef", 7 },
    { UINT64_C(0x0102030405060708),
        "\x02\x08\x01\x02\x03\x04\x05\x06\x07\x08", 10 },
    { UINT64_C(0xffffffffffffffff),
        "\x02\x09\x00\xff\xff\xff\xff\xff\xff\xff\xff", 11 }
};

static const struct {
    const char *der;
    size_t der_len;
} asn1_uint64_invalid[] = {
    { "\x03\x01\x00", 3 },
    { "\x02\x00", 2 },
    { "\x02\x01\x80", 3 },
    { "\x02\x09\x01\x00\x00\x00\x00\x00\x00\x00\x00", 11 },
    { "\x02\x02\x00\x01", 4 }
};

static int test_cbs_asn1_uint64_valid(int idx)
{
    CBS cbs;
    uint64_t value;

    CBS_init(&cbs, (const uint8_t *)asn1_uint64_valid[idx].der,
        asn1_uint64_valid[idx].der_len);
    if (!TEST_true(CBS_get_asn1_uint64(&cbs, &value))
        || !TEST_uint64_t_eq(value, asn1_uint64_valid[idx].value)
        || !TEST_size_t_eq(CBS_len(&cbs), 0))
        return 0;

    return 1;
}

static int test_cbs_asn1_uint64_invalid(int idx)
{
    CBS cbs;
    uint64_t value;

    CBS_init(&cbs, (const uint8_t *)asn1_uint64_invalid[idx].der,
        asn1_uint64_invalid[idx].der_len);
    if (!TEST_false(CBS_get_asn1_uint64(&cbs, &value))
        || !TEST_size_t_eq(CBS_len(&cbs), asn1_uint64_invalid[idx].der_len))
        return 0;

    return 1;
}

int setup_tests(void)
{
    ADD_TEST(test_cbs_skip);
    ADD_TEST(test_cbs_get_u);
    ADD_TEST(test_cbs_peek_u8);
    ADD_TEST(test_cbs_get_prefixed);
    ADD_TEST(test_cbs_get_prefixed_bad);
    ADD_TEST(test_cbs_offset_dup);
    ADD_TEST(test_cbs_mem_equal_zero_byte);
    ADD_TEST(test_cbs_stow);
    ADD_TEST(test_cbs_get_asn1);
    ADD_TEST(test_cbs_get_any_asn1_element);
    ADD_TEST(test_cbs_get_optional_asn1);
    ADD_ALL_TESTS(test_cbs_asn1_uint64_valid, OSSL_NELEM(asn1_uint64_valid));
    ADD_ALL_TESTS(test_cbs_asn1_uint64_invalid, OSSL_NELEM(asn1_uint64_invalid));
    return 1;
}
