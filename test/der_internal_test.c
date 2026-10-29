/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the DER reader (and its symmetry with the writer) */

#include <string.h>

#include <openssl/bn.h>
#include "internal/der.h"
#include "internal/nelem.h"
#include "testutil.h"

/*
 * Round-trip helper: write one element with |writer| into a fresh DER
 * buffer.  |der| / |derlen| receive the location of the produced DER
 * within |buf|.
 */
static int write_der(unsigned char *buf, size_t buflen,
    unsigned char **der, size_t *derlen,
    int (*writer)(WPACKET *pkt))
{
    WPACKET wpkt;
    int ret = 0;

    if (!WPACKET_init_der(&wpkt, buf, buflen))
        return 0;
    if (writer(&wpkt)
        && WPACKET_finish(&wpkt)
        && WPACKET_get_total_written(&wpkt, derlen)
        && (*der = WPACKET_get_curr(&wpkt)) != NULL)
        ret = 1;
    WPACKET_cleanup(&wpkt);
    return ret;
}

static uint32_t cur_uint32;
static int wr_uint32(WPACKET *pkt)
{
    return ossl_DER_w_uint32(pkt, -1, (uint32_t)cur_uint32);
}

static int cur_bool;
static int wr_boolean(WPACKET *pkt)
{
    return ossl_DER_w_boolean(pkt, -1, cur_bool);
}

static int wr_null(WPACKET *pkt)
{
    return ossl_DER_w_null(pkt, -1);
}

static BIGNUM *cur_bn = NULL;
static int wr_bn(WPACKET *pkt)
{
    return ossl_DER_w_bn(pkt, -1, cur_bn);
}

static int test_roundtrip_uint32(void)
{
    static const unsigned int cases[] = {
        0, 1, 127, 128, 255, 256, 65535, 0xFFFFFFFFU
    };
    unsigned char buf[64];
    size_t i = 0;
    int testresult = 0;

    for (i = 0; i < OSSL_NELEM(cases); i++) {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        uint32_t v = 0;

        cur_uint32 = cases[i];
        if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_uint32))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
            || !TEST_uint_eq((unsigned int)v, cases[i])
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }
    testresult = 1;
end:
    return testresult;
}

static int test_roundtrip_uint32_context(void)
{
    unsigned char buf[64];
    int testresult = 0;

    /* Written with a context tag, read back with the same tag */
    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        uint32_t v = 0;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_uint32(&wpkt, 2, 42))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        /* The expected encoding is [2] { INTEGER 42 }, i.e. A2 03 02 01 2A */
        if (!TEST_size_t_eq(derlen, 5)
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_uint32(&pkt, 2, &v))
            || !TEST_uint_eq((unsigned int)v, 42)
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* Written bare, must not be accepted when a context tag is expected */
    {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        uint32_t v = 0;

        cur_uint32 = 42;
        if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_uint32))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_false(ossl_DER_r_uint32(&pkt, 2, &v)))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

static int test_roundtrip_boolean(void)
{
    static const int cases[] = { 0, 1 };
    unsigned char buf[64];
    size_t i = 0;
    int testresult = 0;

    for (i = 0; i < OSSL_NELEM(cases); i++) {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        int b = -1;

        cur_bool = cases[i];
        if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_boolean))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_boolean(&pkt, DER_NO_CONTEXT, &b))
            || !TEST_int_eq(b, cases[i])
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* context tagged */
    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        int b = 0;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_boolean(&wpkt, 1, 1))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        if (!TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_boolean(&pkt, 1, &b))
            || !TEST_true(b)
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

static int test_roundtrip_null(void)
{
    unsigned char buf[16];
    unsigned char *der = NULL;
    size_t derlen = 0;
    PACKET pkt;
    int testresult = 0;

    if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_null))
        || !TEST_size_t_eq(derlen, 2)
        || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
        || !TEST_true(ossl_DER_r_null(&pkt, DER_NO_CONTEXT))
        || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
        goto end;

    testresult = 1;
end:
    return testresult;
}

static int test_roundtrip_octet_string(void)
{
    static const unsigned char content[] = { 0xDE, 0xAD, 0xBE, 0xEF };
    unsigned char buf[64];
    int testresult = 0;

    /* bare */
    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt, contents;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_octet_string(&wpkt, -1,
                content, sizeof(content)))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        if (!TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_octet_string(&pkt, DER_NO_CONTEXT,
                &contents))
            || !TEST_mem_eq(PACKET_data(&contents), PACKET_remaining(&contents),
                content, sizeof(content))
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* context tagged */
    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt, contents;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_octet_string(&wpkt, 1,
                content, sizeof(content)))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        if (!TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_octet_string(&pkt, 1, &contents))
            || !TEST_mem_eq(PACKET_data(&contents), PACKET_remaining(&contents),
                content, sizeof(content))
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

static int test_roundtrip_bn(void)
{
    static const char *const cases[] = {
        "0", "1", "4294967295", "4294967296",
        "1208925819614629174706176" /* 2^80 */
    };
    unsigned char buf[64];
    size_t i = 0;
    int testresult = 0;

    for (i = 0; i < OSSL_NELEM(cases); i++) {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        BIGNUM *v = NULL;

        cur_bn = NULL;
        if (!TEST_true(BN_dec2bn(&cur_bn, cases[i]))
            || !TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_bn))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_bn(&pkt, DER_NO_CONTEXT, &v))
            || !TEST_BN_eq(v, cur_bn)
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0)) {
            BN_free(cur_bn);
            goto end;
        }
        BN_free(cur_bn);
        BN_free(v);
    }
    testresult = 1;
end:
    return testresult;
}

/*
 * SEQUENCE { [0] SEQUENCE { INTEGER 42 } }, written and read with nested
 * begin_sequence calls.
 */
static int test_roundtrip_sequence(void)
{
    unsigned char buf[64];
    int testresult = 0;

    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt, outer, inner;
        uint32_t v = 0;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_begin_sequence(&wpkt, -1))
            || !TEST_true(ossl_DER_w_begin_sequence(&wpkt, 0))
            || !TEST_true(ossl_DER_w_uint32(&wpkt, -1, 42))
            || !TEST_true(ossl_DER_w_end_sequence(&wpkt, 0))
            || !TEST_true(ossl_DER_w_end_sequence(&wpkt, -1))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        if (!TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_begin_sequence(&pkt, DER_NO_CONTEXT,
                &outer))
            || !TEST_true(ossl_DER_r_begin_sequence(&outer, 0, &inner))
            || !TEST_true(ossl_DER_r_uint32(&inner, DER_NO_CONTEXT, &v))
            || !TEST_uint_eq((unsigned int)v, 42)
            || !TEST_size_t_eq(PACKET_remaining(&inner), 0)
            || !TEST_size_t_eq(PACKET_remaining(&outer), 0)
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

/* A "precompiled" OID-ish blob, read bare and wrapped in a context tag */
static const unsigned char oidish[] = { 0x06, 0x03, 0x2A, 0x03, 0x04 };

static int wr_precompiled(WPACKET *pkt)
{
    return ossl_DER_w_precompiled(pkt, -1, oidish, sizeof(oidish));
}

static int test_roundtrip_precompiled(void)
{
    unsigned char buf[64];
    int testresult = 0;

    /* bare */
    {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;

        if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen,
                wr_precompiled))
            || !TEST_size_t_eq(derlen, sizeof(oidish))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_precompiled(&pkt, DER_NO_CONTEXT,
                oidish, sizeof(oidish)))
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* context tagged */
    {
        WPACKET wpkt;
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;

        if (!TEST_true(WPACKET_init_der(&wpkt, buf, sizeof(buf)))
            || !TEST_true(ossl_DER_w_precompiled(&wpkt, 3,
                oidish, sizeof(oidish)))
            || !TEST_true(WPACKET_finish(&wpkt))
            || !TEST_true(WPACKET_get_total_written(&wpkt, &derlen))
            || !TEST_ptr(der = WPACKET_get_curr(&wpkt)))
            goto end;
        WPACKET_cleanup(&wpkt);

        if (!TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_true(ossl_DER_r_precompiled(&pkt, 3,
                oidish, sizeof(oidish)))
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* mismatch must fail */
    {
        static const unsigned char other_oidish[] = {
            0x06, 0x03, 0x2A, 0x03, 0x05
        };
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;

        if (!TEST_true(write_der(buf, sizeof(buf), &der, &derlen,
                wr_precompiled))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_false(ossl_DER_r_precompiled(&pkt, DER_NO_CONTEXT,
                other_oidish, sizeof(other_oidish))))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

/*
 * A fixed RSASSA-PSS-params encoding (RFC 8017, A.2.3), with
 * hashAlgorithm = sha256, maskGenAlgorithm = mgf1SHA256 and
 * saltLength = 32, exercising the reader the way an RSA-PSS
 * implementation would.
 */
static const unsigned char sha256_aid[] = {
    0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
    0x01, 0x05, 0x00
};
static const unsigned char mgf1sha256_aid[] = {
    0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
    0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
    0x02, 0x01, 0x05, 0x00
};
static const unsigned char pss_params[] = {
    0x30, 0x34,
    0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
    0x04, 0x02, 0x01, 0x05, 0x00,
    0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
    0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
    0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
    0xa2, 0x03, 0x02, 0x01, 0x20
};

static int test_pss_params_vector(void)
{
    PACKET pkt, seq;
    unsigned int id = 0;
    uint32_t saltlen = 0;
    int got_hash = 0, got_mgf = 0, got_saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params, sizeof(pss_params)))
        || !TEST_true(ossl_DER_r_begin_sequence(&pkt, DER_NO_CONTEXT, &seq)))
        goto end;

    while (PACKET_remaining(&seq) > 0) {
        if (!TEST_true(ossl_DER_r_peek_element(&seq, &id, NULL)))
            goto end;
        switch (id) {
        case DER_C_CONTEXT | DER_F_CONSTRUCTED | 0:
            if (!TEST_true(ossl_DER_r_precompiled(&seq, 0,
                    sha256_aid, sizeof(sha256_aid))))
                goto end;
            got_hash = 1;
            break;
        case DER_C_CONTEXT | DER_F_CONSTRUCTED | 1:
            if (!TEST_true(ossl_DER_r_precompiled(&seq, 1,
                    mgf1sha256_aid, sizeof(mgf1sha256_aid))))
                goto end;
            got_mgf = 1;
            break;
        case DER_C_CONTEXT | DER_F_CONSTRUCTED | 2:
            if (!TEST_true(ossl_DER_r_uint32(&seq, 2, &saltlen)))
                goto end;
            got_saltlen = 1;
            break;
        default:
            TEST_error("unexpected element 0x%02x", id);
            goto end;
        }
    }

    if (!TEST_true(got_hash)
        || !TEST_true(got_mgf)
        || !TEST_true(got_saltlen)
        || !TEST_uint_eq((unsigned int)saltlen, 32)
        || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/*
 * Malformed input must be rejected, with a couple of leniency exceptions
 * documented in internal/der.h.
 */
static int test_malformed(void)
{
    /* Indefinite length is not DER */
    static const unsigned char indefinite[] = { 0x30, 0x80, 0x00, 0x00 };
    /* High-tag-number form is unsupported */
    static const unsigned char hightag[] = { 0x9F, 0x20, 0x00 };
    /* Truncated: SEQUENCE claims 5 contents octets, has 3 */
    static const unsigned char truncated[] = { 0x30, 0x05, 0x02, 0x01, 0x20 };
    /* Truncated length: long form claims 2 length octets, has 1 */
    static const unsigned char trunclen[] = { 0x30, 0x82, 0x01 };
    /* Negative INTEGER */
    static const unsigned char negative[] = { 0x02, 0x01, 0x80 };
    /* INTEGER that doesn't fit in uint32_t */
    static const unsigned char oversized[] = {
        0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /* BOOLEAN with two contents octets */
    static const unsigned char bool2[] = { 0x01, 0x02, 0xFF, 0xFF };
    /* NULL with contents */
    static const unsigned char nullcontent[] = { 0x05, 0x01, 0x00 };
    /* Context wrapper [2] containing INTEGER 32 and a trailing NULL */
    static const unsigned char contextgarbage[] = {
        0xA2, 0x05, 0x02, 0x01, 0x20, 0x05, 0x00
    };
    /* OCTET STRING read as INTEGER */
    static const unsigned char wrongtag[] = { 0x04, 0x01, 0x00 };

    /* Lenient: non-minimal long form length is accepted */
    static const unsigned char longlen[] = {
        0x30, 0x81, 0x03, 0x02, 0x01, 0x20
    };
    /* Lenient: 5-octet INTEGER with sign padding is accepted */
    static const unsigned char padded[] = {
        0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    };

    PACKET pkt, contents;
    unsigned int id = 0;
    uint32_t v = 0;
    int b = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, indefinite, sizeof(indefinite)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, hightag, sizeof(hightag)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, truncated, sizeof(truncated)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, trunclen, sizeof(trunclen)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, negative, sizeof(negative)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, oversized, sizeof(oversized)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, bool2, sizeof(bool2)))
        || !TEST_false(ossl_DER_r_boolean(&pkt, DER_NO_CONTEXT, &b)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, nullcontent, sizeof(nullcontent)))
        || !TEST_false(ossl_DER_r_null(&pkt, DER_NO_CONTEXT)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, contextgarbage,
            sizeof(contextgarbage)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, 2, &v)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, wrongtag, sizeof(wrongtag)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v)))
        goto end;

    /* Lenient cases must be accepted */
    if (!TEST_true(PACKET_buf_init(&pkt, longlen, sizeof(longlen)))
        || !TEST_true(ossl_DER_r_begin_sequence(&pkt, DER_NO_CONTEXT,
            &contents))
        || !TEST_size_t_eq(PACKET_remaining(&contents), 3))
        goto end;
    v = 0;
    if (!TEST_true(PACKET_buf_init(&pkt, padded, sizeof(padded)))
        || !TEST_true(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !TEST_uint_eq((unsigned int)v, 0xFFFFFFFFU))
        goto end;

    testresult = 1;
end:
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_roundtrip_uint32);
    ADD_TEST(test_roundtrip_uint32_context);
    ADD_TEST(test_roundtrip_boolean);
    ADD_TEST(test_roundtrip_null);
    ADD_TEST(test_roundtrip_octet_string);
    ADD_TEST(test_roundtrip_bn);
    ADD_TEST(test_roundtrip_sequence);
    ADD_TEST(test_roundtrip_precompiled);
    ADD_TEST(test_pss_params_vector);
    ADD_TEST(test_malformed);
    return 1;
}
