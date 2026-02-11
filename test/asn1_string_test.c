/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* ASN1_STRING tests */

#include <stdio.h>

#include <openssl/asn1.h>
#include "testutil.h"

struct abs_get_length_test {
    const char *descr;
    int valid;
    const unsigned char der[20];
    int der_len;
    size_t length;
    int unused_bits;
};

static const struct abs_get_length_test abs_get_length_tests[] = {
    {
        .descr = "zero bits",
        .valid = 1,
        .der = {
            0x03,
            0x01,
            0x00,
        },
        .der_len = 3,
        .length = 0,
        .unused_bits = 0,
    },
    {
        .descr = "zero bits one unused",
        .valid = 0,
        .der = {
            0x03,
            0x01,
            0x01,
        },
        .der_len = 3,
    },
    {
        .descr = "single zero bit",
        .valid = 1,
        .der = {
            0x03,
            0x02,
            0x07,
            0x00,
        },
        .der_len = 4,
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "single one bit",
        .valid = 1,
        .der = {
            0x03,
            0x02,
            0x07,
            0x80,
        },
        .der_len = 4,
        .length = 1,
        .unused_bits = 7,
    },
    {
        /* XXX - the library pretends this is 03 02 07 80 */
        .descr = "invalid: single one bit, seventh bit set",
        .valid = 1,
        .der = {
            0x03,
            0x02,
            0x07,
            0xc0,
        },
        .der_len = 4,
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "x.690, primitive encoding in example 8.6.4.2",
        .valid = 1,
        .der = {
            0x03,
            0x07,
            0x04,
            0x0A,
            0x3b,
            0x5F,
            0x29,
            0x1c,
            0xd0,
        },
        .der_len = 9,
        .length = 6,
        .unused_bits = 4,
    },
    {
        /*
         * XXX - the library thinks it "decodes" this but gets it
         * quite wrong. Looks like it uses the unused bits of the
         * first component, and the unused bits octet 04 of the
         * second component somehow becomes part of the value.
         */
        .descr = "x.690, constructed encoding in example 8.6.4.2",
        .valid = 1,
        .der = {
            0x23,
            0x80,
            0x03,
            0x03,
            0x00,
            0x0A,
            0x3b,
            0x03,
            0x05,
            0x04,
            0x5F,
            0x29,
            0x1c,
            0xd0,
            0x00,
            0x00,
        },
        .der_len = 16,
        .length = 7, /* XXX - should be 6. */
        .unused_bits = 0, /* XXX - should be 4. */
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv4 address 10.5.0.4",
        .valid = 1,
        .der = {
            0x03,
            0x05,
            0x00,
            0x0a,
            0x05,
            0x00,
            0x04,
        },
        .der_len = 7,
        .length = 4,
        .unused_bits = 0,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv4 prefix 10.5.0/23",
        .valid = 1,
        .der = {
            0x03,
            0x04,
            0x01,
            0x0a,
            0x05,
            0x00,
        },
        .der_len = 6,
        .length = 3,
        .unused_bits = 1,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::1",
        .valid = 1,
        .der = {
            0x03,
            0x11,
            0x00,
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
        },
        .der_len = 19,
        .length = 16,
        .unused_bits = 0,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv6 prefix 2001:0:200/39",
        .valid = 1,
        .der = {
            0x03,
            0x06,
            0x01,
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
        },
        .der_len = 8,
        .length = 5,
        .unused_bits = 1,
    },
};

static int
abs_get_length_test(const struct abs_get_length_test *tbl, int idx)
{
    const struct abs_get_length_test *test = &tbl[idx];
    ASN1_BIT_STRING *abs = NULL;
    const unsigned char *p;
    int unused_bits, ret;
    size_t length;
    int success = 0;

    p = test->der;
    if (!TEST_ptr(abs = d2i_ASN1_BIT_STRING(NULL, &p, test->der_len))) {
        TEST_info("%s, (idx=%d) - d2i_ASN1_BIT_STRING faled", __func__, idx);
        goto err;
    }

    ret = ASN1_BIT_STRING_get_length(abs, &length, &unused_bits);
    if (!TEST_int_eq(test->valid, ret)) {
        TEST_info("%s (idx=%d): %s ASN1_BIT_STRING_get_length want %d, got %d\n",
            __func__, idx, test->descr, test->valid, ret);
        goto err;
    }
    if (!test->valid)
        goto done;

    if (!TEST_size_t_eq(length, test->length)
        || !TEST_int_eq(unused_bits, test->unused_bits)) {
        TEST_info("%s: (idx=%d) %s: want (%zu, %d), got (%zu, %d)\n", __func__,
            idx, test->descr, test->length, test->unused_bits, length,
            unused_bits);
        goto err;
    }

done:
    success = 1;

err:
    ASN1_STRING_free(abs);

    return success;
}

static int
asn1_bit_string_get_length_test(int idx)
{
    return abs_get_length_test(abs_get_length_tests, idx);
}

struct abs_set1_test {
    const char *descr;
    int valid;
    const uint8_t data[20];
    size_t length;
    int unused_bits;
    const unsigned char der[20];
    int der_len;
};

static const struct abs_set1_test abs_set1_tests[] = {
    {
        .descr = "length too large",
        .valid = 0,
        .length = (size_t)INT_MAX + 1,
    },
    {
        .descr = "negative unused bits",
        .valid = 0,
        .unused_bits = -1,
    },
    {
        .descr = "8 unused bits",
        .valid = 0,
        .unused_bits = 8,
    },
    {
        .descr = "empty with unused bits",
        .valid = 0,
        .data = {
            0x00,
        },
        .length = 0,
        .unused_bits = 1,
    },
    {
        .descr = "empty",
        .valid = 1,
        .data = {
            0x00,
        },
        .length = 0,
        .unused_bits = 0,
        .der = {
            0x03,
            0x01,
            0x00,
        },
        .der_len = 3,
    },
    {
        .descr = "single zero bit",
        .valid = 1,
        .data = {
            0x00,
        },
        .length = 1,
        .unused_bits = 7,
        .der = {
            0x03,
            0x02,
            0x07,
            0x00,
        },
        .der_len = 4,
    },
    {
        .descr = "single zero bit, with non-zero unused bit 6",
        .valid = 0,
        .data = {
            0x40,
        },
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "single zero bit, with non-zero unused bit 0",
        .valid = 0,
        .data = {
            0x01,
        },
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "single one bit",
        .valid = 1,
        .data = {
            0x80,
        },
        .length = 1,
        .unused_bits = 7,
        .der = {
            0x03,
            0x02,
            0x07,
            0x80,
        },
        .der_len = 4,
    },
    {
        .descr = "single one bit, with non-zero unused-bit 6",
        .valid = 0,
        .data = {
            0xc0,
        },
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "single one bit, with non-zero unused-bit 0",
        .valid = 0,
        .data = {
            0x81,
        },
        .length = 1,
        .unused_bits = 7,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv4 address 10.5.0.4",
        .valid = 1,
        .data = {
            0x0a,
            0x05,
            0x00,
            0x04,
        },
        .length = 4,
        .unused_bits = 0,
        .der = {
            0x03,
            0x05,
            0x00,
            0x0a,
            0x05,
            0x00,
            0x04,
        },
        .der_len = 7,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv4 address 10.5.0/23",
        .valid = 1,
        .data = {
            0x0a,
            0x05,
            0x00,
        },
        .length = 3,
        .unused_bits = 1,
        .der = {
            0x03,
            0x04,
            0x01,
            0x0a,
            0x05,
            0x00,
        },
        .der_len = 6,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv4 address 10.5.0/23, unused bit",
        .valid = 0,
        .data = {
            0x0a,
            0x05,
            0x01,
        },
        .length = 3,
        .unused_bits = 1,
    },
    {
        .descr = "RFC 3779, IPv4 address 10.5.0/17",
        .valid = 1,
        .data = {
            0x0a,
            0x05,
            0x00,
        },
        .length = 3,
        .unused_bits = 7,
        .der = {
            0x03,
            0x04,
            0x07,
            0x0a,
            0x05,
            0x00,
        },
        .der_len = 6,
    },
    {
        .descr = "RFC 3779, IPv4 address 10.5.0/18, unused bit set",
        .valid = 0,
        .data = {
            0x0a,
            0x05,
            0x20,
        },
        .length = 3,
        .unused_bits = 6,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::1",
        .valid = 1,
        .data = {
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
        },
        .length = 16,
        .unused_bits = 0,
        .der = {
            0x03,
            0x11,
            0x00,
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
        },
        .der_len = 19,
    },
    {
        .descr = "RFC 3779, IPv6 address 2001:0:200:3::/127",
        .valid = 1,
        .data = {
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        },
        .length = 16,
        .unused_bits = 1,
        .der = {
            0x03,
            0x11,
            0x01,
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
        },
        .der_len = 19,
    },
    {
        .descr = "RFC 3779, IPv6 address 2001:0:200:3::/127, unused bit",
        .valid = 0,
        .data = {
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
            0x00,
            0x03,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x01,
        },
        .length = 16,
        .unused_bits = 1,
    },
    {
        .descr = "RFC 3779, 2.1.1, IPv6 address 2001:0:200:3::/39",
        .valid = 1,
        .data = {
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
        },
        .length = 5,
        .unused_bits = 1,
        .der = {
            0x03,
            0x06,
            0x01,
            0x20,
            0x01,
            0x00,
            0x00,
            0x02,
        },
        .der_len = 8,
    },
};

static int
abs_set1_test(const struct abs_set1_test *tbl, int idx)
{
    const struct abs_set1_test *test = &tbl[idx];
    ASN1_BIT_STRING *abs = NULL;
    unsigned char *der = NULL;
    int ret, der_len = 0;
    int success = 0;

    if (!TEST_ptr(abs = ASN1_BIT_STRING_new())) {
        TEST_info("%s: (idx = %d) %s ASN1_BIT_STRING_new()", __func__, idx, test->descr);
        goto err;
    }

    ret = ASN1_BIT_STRING_set1(abs, test->data, test->length, test->unused_bits);
    if (!TEST_int_eq(ret, test->valid)) {
        TEST_info("%s: (idx = %d) %s ASN1_BIT_STRING_set1(): want %d, got %d",
            __func__, idx, test->descr, test->valid, ret);
        goto err;
    }

    if (!test->valid)
        goto done;

    der = NULL;
    if (!TEST_int_eq((der_len = i2d_ASN1_BIT_STRING(abs, &der)), test->der_len)) {
        TEST_info("%s: (idx=%d), %s i2d_ASN1_BIT_STRING(): want %d, got %d",
            __func__, idx, test->descr, test->der_len, der_len);
        if (der_len < 0)
            der_len = 0;
        goto err;
    }

    if (!TEST_mem_eq(der, der_len, test->der, test->der_len)) {
        TEST_info("%s: (idx = %d)  %s DER mismatch", __func__, idx, test->descr);
        goto err;
    }

done:
    success = 1;

err:
    ASN1_BIT_STRING_free(abs);
    OPENSSL_clear_free(der, der_len);

    return success;
}

static int
asn1_bit_string_set1_test(int idx)
{
    return abs_set1_test(abs_set1_tests, idx);
}

int setup_tests(void)
{
    ADD_ALL_TESTS(asn1_bit_string_get_length_test, OSSL_NELEM(abs_get_length_tests));
    ADD_ALL_TESTS(asn1_bit_string_set1_test, OSSL_NELEM(abs_set1_tests));
    return 1;
}
