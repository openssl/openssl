/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/asn1t.h>
#include "test_main.h"
#include "testutil.h"

typedef struct {
    long test_long;
    long test_zlong;
} ASN1_ENCODE_TEST;

ASN1_SEQUENCE(ASN1_ENCODE_TEST) = {
    ASN1_SIMPLE(ASN1_ENCODE_TEST, test_long, LONG),
    ASN1_SIMPLE(ASN1_ENCODE_TEST, test_zlong, ZLONG)
} static_ASN1_SEQUENCE_END(ASN1_ENCODE_TEST)

IMPLEMENT_STATIC_ASN1_ENCODE_FUNCTIONS(ASN1_ENCODE_TEST)

typedef struct {
    unsigned char *prefix;
    size_t prefix_len;
    unsigned char *suffix;
    size_t suffix_len;
} ASN1_ENCODINGS;

unsigned char test_long_prefix[] = { 0x02 };
unsigned char test_long_suffix[] = { 0x02, 0x01, 0x01 };
unsigned char test_zlong_prefix[] = { 0x02, 0x01, 0x00, 0x02 };

#define FIELD_TEST_LONG     0
#define FIELD_TEST_ZLONG    1

ASN1_ENCODINGS encodings[] = {
    {
        test_long_prefix,
        sizeof(test_long_prefix),
        test_long_suffix,
        sizeof(test_long_suffix)
    },
    {
        test_zlong_prefix,
        sizeof(test_zlong_prefix),
        NULL,
        0
    }
};

/* Do a decode and check the expected value */
static int do_decode_long(size_t field, long testval, int checkval,
                          unsigned char *data, size_t datalen)
{
    ASN1_ENCODE_TEST *enctst = NULL;
    const unsigned char *start, *datain;
    int ret = 0;

    start = datain = data;
    enctst = d2i_ASN1_ENCODE_TEST(NULL, &datain, datalen);
    if (enctst == NULL)
        goto err;

    if (start + datalen != datain)
        goto err;

    if (checkval) {
        if (field == FIELD_TEST_LONG) {
            if (testval != enctst->test_long)
                goto err;
        } else {
            if (testval != enctst->test_zlong)
                goto err;
        }
    }

    ret = 1;
 err:
    /* If we expected to fail and we did, then clear error queue */
    if (!ret && !checkval)
        ERR_clear_error();
    M_ASN1_free_of(enctst, ASN1_ENCODE_TEST);
    return ret;
}

/* Do an encode/decode round trip */
static int do_enc_dec_long(size_t field, long testval)
{
    ASN1_ENCODE_TEST enctstin;
    int len;
    unsigned char *data = NULL;

    memset(&enctstin, 0, sizeof(enctstin));
    if (field == FIELD_TEST_LONG) {
        enctstin.test_long = testval;
        enctstin.test_zlong = 1;
    } else {
        enctstin.test_zlong = testval;
    }

    len = i2d_ASN1_ENCODE_TEST(&enctstin, &data);
    if (len < 0)
        return 0;

    return do_decode_long(field, testval, 1, data, len);
}

/* Attempt to decode a custom encoding of the test structure */
static int do_decode_long_custom(size_t field, long testval, int checkval,
                                 unsigned char *data, size_t datalen)
{
    size_t lenbytes, fulllen;
    size_t totlen = encodings[field].prefix_len + datalen
                    + encodings[field].suffix_len;
    unsigned char *encoding, *p = NULL;
    int ret;

    /* lenbytes doesn't include the initial "short form" length byte */
    if (totlen > 255)
        lenbytes = 2;
    else if (totlen > 127)
        lenbytes = 1;
    else
        lenbytes = 0;

    /* We have 2 bytes for the sequence tag, and the first length byte */
    fulllen = 2 + lenbytes + totlen;
    encoding = p = OPENSSL_malloc(fulllen);
    if (encoding == NULL)
        return 0;

    /* Sequence tag */
    *p++ = 0x30;
    if (lenbytes == 0) {
        *p++ = totlen;
    } else {
        *p++ = lenbytes;
        if (lenbytes == 2) {
            *p++ = 0x80 | (totlen >> 8);
            totlen &= 0xff;
            *p++ = totlen;
        } else {
            *p++ = 0x80 | totlen;
        }
    }

    memcpy(p, encodings[field].prefix, encodings[field].prefix_len);
    p += encodings[field].prefix_len;
    memcpy(p, data, datalen);
    p += datalen;
    if (encodings[field].suffix != NULL) {
        memcpy(p, encodings[field].suffix, encodings[field].suffix_len);
        p += encodings[field].suffix_len;
    }

    if ((size_t)(p - encoding) != fulllen) {
        OPENSSL_free(encoding);
        return 0;
    }

    ret = do_decode_long(field, testval, checkval, encoding, fulllen);
    OPENSSL_free(encoding);

    return ret;
}


static int test_long_intern(size_t field)
{
    unsigned char longzero[] = {
        0x01, 0x00
    };
    unsigned char longundef[] = {
        0x04, 0x7f, 0xff, 0xff, 0xff
    };
#ifdef SIXTY_FOUR_BIT_LONG
    unsigned char toolong[] = {
        0x09, 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    unsigned char toolong2[] = {
        0x09, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    unsigned char longenc[] = {
        0x08, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    unsigned char longencpad[] = {
        0x09, 0x00, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
    };
    unsigned char longencneg[] = {
        0x08, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    unsigned char longencnegpad[] = {
        0x09, 0xff, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    const long maxval = LONG_MAX;
#else
    /* 32-bit long */
    unsigned char toolong[] = {
        0x05, 0x01, 0xff, 0xff, 0xff, 0xff
    };
    unsigned char toolong2[] = {
        0x05, 0x00, 0x80, 0x00, 0x00, 0x00
    };
    /* We make the last byte 0xfe to avoid a clash with ASN1_LONG_UNDEF */
    unsigned char longenc[] = {
        0x04, 0x7f, 0xff, 0xff, 0xfe
    };
    unsigned char longencpad[] = {
        0x05, 0x00, 0x7f, 0xff, 0xff, 0xfe
    };
    unsigned char longencneg[] = {
        0x04, 0x80, 0x00, 0x00, 0x00
    };
    unsigned char longencnegpad[] = {
        0x05, 0xff, 0x80, 0x00, 0x00, 0x00
    };
    /* Avoid a clash with ASN1_LONG_UNDEF */
    const long maxval = LONG_MAX - 1;
#endif

    /*
     * The value 0 is undefined for ZLONG. For LONG the undefined value is
     * ASN1_LONG_UNDEF
     */
    if (!do_enc_dec_long(field, maxval)
            || !do_enc_dec_long(field, LONG_MIN)
            || !do_enc_dec_long(field, 1)
            || (field == FIELD_TEST_LONG && !do_enc_dec_long(field, 0))
            || !do_enc_dec_long(field, -1)
            || (field == FIELD_TEST_ZLONG
                && !do_enc_dec_long(field, ASN1_LONG_UNDEF))) {
        printf("Failed encode/decode round trip of LONG\n");
        return 0;
    }

    if (!do_decode_long_custom(field, maxval, 1, longenc, sizeof(longenc))
            || !do_decode_long_custom(field, maxval, 1, longencpad,
                                      sizeof(longencpad))
            || !do_decode_long_custom(field, LONG_MIN, 1, longencneg,
                                      sizeof(longencneg))
            || !do_decode_long_custom(field, LONG_MIN, 1, longencnegpad,
                                      sizeof(longencnegpad))
            || (field == FIELD_TEST_LONG
                && !do_decode_long_custom(field, 0, 1, longzero,
                                          sizeof(longzero)))
            || (field == FIELD_TEST_ZLONG
                && !do_decode_long_custom(field, ASN1_LONG_UNDEF, 1, longundef,
                                          sizeof(longundef)))) {
        printf("Failed custom decode of LONG\n");
        return 0;
    }

    /* These are expected to fail */
    if (field == FIELD_TEST_LONG) {
        if (do_enc_dec_long(field, ASN1_LONG_UNDEF)
                || do_decode_long_custom(field, 0, 0, longundef,
                                         sizeof(longundef))) {
        printf("Unexpected success with undefined LONG types\n");
        return 0;
        }
    } else {
        if (do_enc_dec_long(field, 0)
                || do_decode_long_custom(field, 0, 0, longzero,
                                         sizeof(longzero))) {
        printf("Unexpected success with undefined ZLONG types\n");
        return 0;
        }
    }
    ERR_clear_error();

    if (do_decode_long_custom(field, 0, 0, toolong, sizeof(toolong))
            || do_decode_long_custom(field, 0, 0, toolong2, sizeof(toolong2))) {
        printf("Unexpected success custom decode of LONG\n");
        return 0;
    }
    return 1;
}

static int test_long(void)
{
    return test_long_intern(FIELD_TEST_LONG);
}

static int test_zlong(void)
{
    return test_long_intern(FIELD_TEST_ZLONG);
}

void register_tests(void)
{
    ADD_TEST(test_long);
    ADD_TEST(test_zlong);
}
