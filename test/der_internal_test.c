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

/* Check that a failed read left |pkt| untouched */
static int packet_unchanged(const PACKET *pkt,
    const unsigned char *data, size_t len)
{
    return TEST_ptr_eq(PACKET_data(pkt), data)
        && TEST_size_t_eq(PACKET_remaining(pkt), len);
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
            || !TEST_false(ossl_DER_r_uint32(&pkt, 2, &v))
            || !packet_unchanged(&pkt, der, derlen))
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
                sizeof(content), &contents))
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
            || !TEST_true(ossl_DER_r_octet_string(&pkt, 1,
                sizeof(content), &contents))
            || !TEST_mem_eq(PACKET_data(&contents), PACKET_remaining(&contents),
                content, sizeof(content))
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
            goto end;
    }

    /* limit exceeded: the contents are 4 octets, the limit is 3 */
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
            || !TEST_false(ossl_DER_r_octet_string(&pkt, DER_NO_CONTEXT,
                sizeof(content) - 1, &contents))
            || !packet_unchanged(&pkt, der, derlen))
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
            || !TEST_true(ossl_DER_r_bn(&pkt, DER_NO_CONTEXT,
                sizeof(buf), &v))
            || !TEST_BN_eq(v, cur_bn)
            || !TEST_size_t_eq(PACKET_remaining(&pkt), 0)) {
            BN_free(cur_bn);
            goto end;
        }
        BN_free(cur_bn);
        BN_free(v);
    }

    /* limit exceeded: 2^80 has 11 contents octets, the limit is 10 */
    {
        unsigned char *der = NULL;
        size_t derlen = 0;
        PACKET pkt;
        BIGNUM *v = NULL;

        cur_bn = NULL;
        if (!TEST_true(BN_dec2bn(&cur_bn, "1208925819614629174706176"))
            || !TEST_true(write_der(buf, sizeof(buf), &der, &derlen, wr_bn))
            || !TEST_true(PACKET_buf_init(&pkt, der, derlen))
            || !TEST_false(ossl_DER_r_bn(&pkt, DER_NO_CONTEXT, 10, &v))
            || !packet_unchanged(&pkt, der, derlen)) {
            BN_free(cur_bn);
            goto end;
        }
        BN_free(cur_bn);
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
                other_oidish, sizeof(other_oidish)))
            || !packet_unchanged(&pkt, der, derlen))
            goto end;
    }

    testresult = 1;
end:
    return testresult;
}

/*
 * A fixed RSASSA-PSS-params encoding (RFC 8017, A.2.3), with
 * hashAlgorithm = sha256, maskGenAlgorithm = mgf1SHA256 and
 * saltLength = 32, with trailerField defaulted and omitted, exercising
 * the reader the way an RSA-PSS implementation would.
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

/*
 * Parse an RSASSA-PSS-params SEQUENCE, the way an RSA-PSS
 * implementation would: consume the context tagged fields in declaration
 * order, applying defaults for absent fields.
 */
static int parse_pss_params(PACKET *pkt, uint32_t *saltlen)
{
    PACKET seq;
    uint32_t salt = 20;
    uint32_t trailer = 1;
    unsigned int min_tag = 0;
    int ret = 0;

    if (!ossl_DER_r_begin_sequence(pkt, DER_NO_CONTEXT, &seq))
        return 0;

    while (PACKET_remaining(&seq) > 0) {
        unsigned int id = 0;
        unsigned int tag = 0;

        if (!ossl_DER_r_peek_element(&seq, &id, NULL))
            goto end;
        tag = id & 0x1F;
        /* Only constructed [0]-[3], in declaration order */
        if (id != (DER_C_CONTEXT | DER_F_CONSTRUCTED | tag)
            || tag > 3
            || tag < min_tag)
            goto end;
        min_tag = tag + 1;

        switch (tag) {
        case 0:
            if (!ossl_DER_r_precompiled(&seq, 0,
                    sha256_aid, sizeof(sha256_aid)))
                goto end;
            break;
        case 1:
            if (!ossl_DER_r_precompiled(&seq, 1,
                    mgf1sha256_aid, sizeof(mgf1sha256_aid)))
                goto end;
            break;
        case 2:
            if (!ossl_DER_r_uint32(&seq, 2, &salt))
                goto end;
            break;
        case 3:
            if (!ossl_DER_r_uint32(&seq, 3, &trailer))
                goto end;
            break;
        }
    }

    if (trailer != 1)
        goto end;

    *saltlen = salt;
    ret = 1;
end:
    return ret;
}

static int test_pss_params_vector(void)
{
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params, sizeof(pss_params)))
        || !TEST_true(parse_pss_params(&pkt, &saltlen))
        || !TEST_uint_eq((unsigned int)saltlen, 32)
        || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/* All fields may be absent; defaults apply */
static int test_pss_params_defaults(void)
{
    static const unsigned char pss_params_defaults[] = { 0x30, 0x00 };
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params_defaults,
            sizeof(pss_params_defaults)))
        || !TEST_true(parse_pss_params(&pkt, &saltlen))
        || !TEST_uint_eq((unsigned int)saltlen, 20)
        || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
        goto end;

    testresult = 1;
end:
    return testresult;
}

static int test_pss_params_sparse(void)
{
    /* Fields may be skipped, but present fields stay ordered */
    static const unsigned char pss_params_sparse[] = {
        0x30, 0x0a,
        0xa2, 0x03, 0x02, 0x01, 0x20,
        0xa3, 0x03, 0x02, 0x01, 0x01
    };
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params_sparse,
            sizeof(pss_params_sparse)))
        || !TEST_true(parse_pss_params(&pkt, &saltlen))
        || !TEST_uint_eq((unsigned int)saltlen, 32)
        || !TEST_size_t_eq(PACKET_remaining(&pkt), 0))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/* A repeated field must be rejected, not silently consumed */
static int test_pss_params_duplicates(void)
{
    /* pss_params with the saltLength field [2] repeated */
    static const unsigned char pss_params_dup[] = {
        0x30, 0x39,
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
        0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48,
        0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa2, 0x03, 0x02, 0x01, 0x20,
        0xa2, 0x03, 0x02, 0x01, 0x20
    };
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params_dup,
            sizeof(pss_params_dup)))
        || !TEST_false(parse_pss_params(&pkt, &saltlen)))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/* Out-of-order fields must be rejected */
static int test_pss_params_out_of_order(void)
{
    /* pss_params with the saltLength field [2] first */
    static const unsigned char pss_params_reordered[] = {
        0x30, 0x34,
        0xa2, 0x03, 0x02, 0x01, 0x20,
        0xa0, 0x0f, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
        0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00,
        0xa1, 0x1c, 0x30, 0x1a, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
        0xf7, 0x0d, 0x01, 0x01, 0x08, 0x30, 0x0d, 0x06, 0x09, 0x60,
        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00
    };
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params_reordered,
            sizeof(pss_params_reordered)))
        || !TEST_false(parse_pss_params(&pkt, &saltlen)))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/* trailerField only has one valid value */
static int test_pss_params_bad_trailer(void)
{
    static const unsigned char pss_params_bad_trailer[] = {
        0x30, 0x05,
        0xa3, 0x03, 0x02, 0x01, 0x02
    };
    PACKET pkt;
    uint32_t saltlen = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, pss_params_bad_trailer,
            sizeof(pss_params_bad_trailer)))
        || !TEST_false(parse_pss_params(&pkt, &saltlen)))
        goto end;

    testresult = 1;
end:
    return testresult;
}

/*
 * Malformed or non-DER input must be rejected, per the strictness
 * documented in internal/der.h.  Every rejection must also leave the
 * PACKET unchanged, per the atomicity guarantee documented there.
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
    /* Non-minimal length: long form used for a short form length */
    static const unsigned char longlen[] = {
        0x30, 0x81, 0x03, 0x02, 0x01, 0x20
    };
    /* Non-minimal length: superfluous leading zero length octet */
    static const unsigned char longlen0[] = { 0x30, 0x82, 0x00, 0x80 };
    /* Negative INTEGER */
    static const unsigned char negative[] = { 0x02, 0x01, 0x80 };
    /* INTEGER with unnecessary sign padding octet */
    static const unsigned char overpadded[] = { 0x02, 0x02, 0x00, 0x7F };
    /* INTEGER with two sign padding octets */
    static const unsigned char doublepadded[] = {
        0x02, 0x03, 0x00, 0x00, 0x80
    };
    /* INTEGER that doesn't fit in uint32_t */
    static const unsigned char oversized[] = {
        0x02, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    /* BOOLEAN with two contents octets */
    static const unsigned char bool2[] = { 0x01, 0x02, 0xFF, 0xFF };
    /* BOOLEAN TRUE encoded other than 0xFF is BER, not DER */
    static const unsigned char boolber[] = { 0x01, 0x01, 0x7F };
    /* NULL with contents */
    static const unsigned char nullcontent[] = { 0x05, 0x01, 0x00 };
    /* Context wrapper [2] containing INTEGER 32 and a trailing NULL */
    static const unsigned char contextgarbage[] = {
        0xA2, 0x05, 0x02, 0x01, 0x20, 0x05, 0x00
    };
    /* OCTET STRING read as INTEGER */
    static const unsigned char wrongtag[] = { 0x04, 0x01, 0x00 };

    /* 5-octet INTEGER with necessary sign padding is valid DER */
    static const unsigned char padded[] = {
        0x02, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF
    };

    PACKET pkt, contents;
    unsigned int id = 0;
    uint32_t v = 0;
    BIGNUM *bn = NULL;
    int b = 0;
    int testresult = 0;

    if (!TEST_true(PACKET_buf_init(&pkt, indefinite, sizeof(indefinite)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents))
        || !packet_unchanged(&pkt, indefinite, sizeof(indefinite)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, hightag, sizeof(hightag)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents))
        || !packet_unchanged(&pkt, hightag, sizeof(hightag)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, truncated, sizeof(truncated)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents))
        || !packet_unchanged(&pkt, truncated, sizeof(truncated)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, trunclen, sizeof(trunclen)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents))
        || !packet_unchanged(&pkt, trunclen, sizeof(trunclen)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, longlen, sizeof(longlen)))
        || !TEST_false(ossl_DER_r_begin_sequence(&pkt, DER_NO_CONTEXT,
            &contents))
        || !packet_unchanged(&pkt, longlen, sizeof(longlen)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, longlen0, sizeof(longlen0)))
        || !TEST_false(ossl_DER_r_element(&pkt, &id, &contents))
        || !packet_unchanged(&pkt, longlen0, sizeof(longlen0)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, negative, sizeof(negative)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !packet_unchanged(&pkt, negative, sizeof(negative)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, overpadded, sizeof(overpadded)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !packet_unchanged(&pkt, overpadded, sizeof(overpadded)))
        goto end;
    /* Same INTEGER padding rejection through the BIGNUM reader */
    if (!TEST_true(PACKET_buf_init(&pkt, overpadded, sizeof(overpadded)))
        || !TEST_false(ossl_DER_r_bn(&pkt, DER_NO_CONTEXT, 5, &bn))
        || !packet_unchanged(&pkt, overpadded, sizeof(overpadded)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, doublepadded,
            sizeof(doublepadded)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !packet_unchanged(&pkt, doublepadded, sizeof(doublepadded)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, oversized, sizeof(oversized)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !packet_unchanged(&pkt, oversized, sizeof(oversized)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, bool2, sizeof(bool2)))
        || !TEST_false(ossl_DER_r_boolean(&pkt, DER_NO_CONTEXT, &b))
        || !packet_unchanged(&pkt, bool2, sizeof(bool2)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, boolber, sizeof(boolber)))
        || !TEST_false(ossl_DER_r_boolean(&pkt, DER_NO_CONTEXT, &b))
        || !packet_unchanged(&pkt, boolber, sizeof(boolber)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, nullcontent, sizeof(nullcontent)))
        || !TEST_false(ossl_DER_r_null(&pkt, DER_NO_CONTEXT))
        || !packet_unchanged(&pkt, nullcontent, sizeof(nullcontent)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, contextgarbage,
            sizeof(contextgarbage)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, 2, &v))
        || !packet_unchanged(&pkt, contextgarbage, sizeof(contextgarbage)))
        goto end;
    if (!TEST_true(PACKET_buf_init(&pkt, wrongtag, sizeof(wrongtag)))
        || !TEST_false(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !packet_unchanged(&pkt, wrongtag, sizeof(wrongtag)))
        goto end;

    /* Valid strict DER must be accepted */
    v = 0;
    if (!TEST_true(PACKET_buf_init(&pkt, padded, sizeof(padded)))
        || !TEST_true(ossl_DER_r_uint32(&pkt, DER_NO_CONTEXT, &v))
        || !TEST_uint_eq((unsigned int)v, 0xFFFFFFFFU))
        goto end;

    testresult = 1;
end:
    BN_free(bn);
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
    ADD_TEST(test_pss_params_defaults);
    ADD_TEST(test_pss_params_sparse);
    ADD_TEST(test_pss_params_duplicates);
    ADD_TEST(test_pss_params_out_of_order);
    ADD_TEST(test_pss_params_bad_trailer);
    ADD_TEST(test_malformed);
    return 1;
}
