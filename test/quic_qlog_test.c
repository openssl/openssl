/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/qlog.h"
#include "testutil.h"

static const char expected[] =
    "\x1e{\"qlog_version\":\"0.3\",\"qlog_format\":\"JSON-SEQ\",\"title\":"
    "\"test title\",\"description\":\"test description\",\"trace\":{"
    "\"common_fields\":{\"time_format\":\"delta\",\"protocol_type\":"
    "[\"QUIC\"],\"group_id\":\"test group ID\",\"system_info\":{"
    "\"process_id\":123}},\"vantage_point\":{\"type\":\"client\","
    "\"name\":\"OpenSSL/x.y.z\"}}}\n"

    "\x1e{\"name\":\"transport:packet_sent\",\"data\":{\"field1\":\"foo\","
    "\"field2\":\"bar\",\"field3\":42,\"field4\":\"1152921504606846976\","
    "\"field5\":\"18446744073709551615\",\"field6\":false,\"field7\":true,"
    "\"field8\":\"01af\",\"field9\":\"55\",\"subgroup\":{\"field10\":\"baz\"},"
    "\"array\":[\"a\",\"b\"]},\"time\":170653117000}\n"

    "\x1e{\"name\":\"transport:packet_sent\",\"data\":{\"field1\":\"bar\"},"
    "\"time\":1000}\n"
    ;

static const unsigned char bin_buf[] = {
    0x01, 0xaf
};

static OSSL_TIME last_time;

static OSSL_TIME now(void *arg)
{
    OSSL_TIME t = last_time;

    last_time = ossl_time_add(t, ossl_ms2time(1000));
    return t;
}

static int test_qlog(void)
{
    int testresult = 0;
    QLOG_TRACE_INFO qti = {0};
    QLOG *qlog;
    BIO *bio;
    char *buf = NULL;
    size_t buf_len = 0;

    last_time = ossl_time_from_time_t(170653117);

    qti.odcid.id_len        = 1;
    qti.odcid.id[0]         = 0x55;
    qti.title               = "test title";
    qti.description         = "test description";
    qti.group_id            = "test group ID";
    qti.override_process_id = 123;
    qti.now_cb              = now;
    qti.override_impl_name  = "OpenSSL/x.y.z";

    if (!TEST_ptr(qlog = ossl_qlog_new(&qti)))
        goto err;

    if (!TEST_true(ossl_qlog_set_event_type_enabled(qlog, QLOG_EVENT_TYPE_transport_packet_sent, 1)))
        goto err;

    if (!TEST_ptr(bio = BIO_new(BIO_s_mem())))
        goto err;

    if (!TEST_true(ossl_qlog_set_sink_bio(qlog, bio)))
        goto err;

    QLOG_EVENT_BEGIN(qlog, transport, packet_sent)
        QLOG_STR("field1", "foo");
        QLOG_STR_LEN("field2", "bar", 3);
        QLOG_I64("field3", 42);
        QLOG_I64("field4", 1ULL << 60);
        QLOG_U64("field5", UINT64_MAX);
        QLOG_BOOL("field6", 0);
        QLOG_BOOL("field7", 1);
        QLOG_BIN("field8", bin_buf, sizeof(bin_buf));
        QLOG_CID("field9", &qti.odcid);
        QLOG_BEGIN("subgroup")
            QLOG_STR("field10", "baz");
        QLOG_END()
        QLOG_BEGIN_ARRAY("array")
            QLOG_STR(NULL, "a");
            QLOG_STR(NULL, "b");
        QLOG_END_ARRAY()
    QLOG_EVENT_END()

    /* not enabled */
    QLOG_EVENT_BEGIN(qlog, transport, packet_received)
        QLOG_STR("field1", "foo");
    QLOG_EVENT_END()

    /* test delta time calculation */
    QLOG_EVENT_BEGIN(qlog, transport, packet_sent)
        QLOG_STR("field1", "bar");
    QLOG_EVENT_END()

    if (!TEST_true(ossl_qlog_flush(qlog)))
        goto err;

    buf_len = BIO_get_mem_data(bio, &buf);
    if (!TEST_size_t_gt(buf_len, 0))
        goto err;

    if (!TEST_mem_eq(buf, buf_len, expected, sizeof(expected) - 1))
        goto err;

    testresult = 1;
err:
    ossl_qlog_free(qlog);
    return testresult;
}

struct filter_spec {
    const char *filter;
    int         expect_ok;
    uint32_t    expect_event_type;
    int         expect_event_enable;
};

static const struct filter_spec filters[] = {
    { "*", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { "-*", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "+*", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { "* *", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 1 },
    { "-* +*", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 1 },
    { "-* +* -*", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 0 },
    { "  *", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { " ", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { "transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 0 },
    { "* -transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 1 },
    { "* -transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "unknown:event", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "unknown:event +transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { "unknown:event transport:*", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 1 },
    { "unknown:event +transport:* -transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_received, 1 },
    { "unknown:event transport:* -transport:packet_sent", 1,
      QLOG_EVENT_TYPE_transport_packet_sent, 0 },
    { "* -transport:*", 1,
      QLOG_EVENT_TYPE_connectivity_connection_started, 1 },
    { "* -transport:*", 1,
      QLOG_EVENT_TYPE_transport_parameters_set, 0 },
    { "&", 0 },
    { "event_name_without_category", 0 },
    { "event_name_with_@badchar:foo", 0 },
    { "event_name_with_badchar:f@oo", 0 },
    { "category:", 0 },
    { ":name", 0 },
    { ":", 0 },
    { "**", 0 },
    { "foo:bar*", 0 },
    { "foo:*bar", 0 },
    { "foo*:bar", 0 },
    { "*foo:bar", 0 },
};

static int test_qlog_filter(int idx)
{
    int testresult = 0;
    QLOG_TRACE_INFO qti = {0};
    QLOG *qlog;

    qti.odcid.id_len        = 1;
    qti.odcid.id[0]         = 0x55;

    if (!TEST_ptr(qlog = ossl_qlog_new(&qti)))
        goto err;

    if (!TEST_int_eq(ossl_qlog_set_filter(qlog, filters[idx].filter),
                     filters[idx].expect_ok))
        goto err;

    if (filters[idx].expect_event_type != QLOG_EVENT_TYPE_NONE)
        if (!TEST_int_eq(ossl_qlog_enabled(qlog, filters[idx].expect_event_type),
                         filters[idx].expect_event_enable))
            goto err;

    testresult = 1;
err:
    ossl_qlog_free(qlog);
    return testresult;
}

int setup_tests(void)
{
    ADD_TEST(test_qlog);
    ADD_ALL_TESTS(test_qlog_filter, OSSL_NELEM(filters));
    return 1;
}
