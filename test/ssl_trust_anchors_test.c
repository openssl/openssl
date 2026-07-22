/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for trust_anchors extension handling */

#include <string.h>

#include <openssl/ssl.h>

#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "testutil.h"

/*
 * RequestedTrustAnchorList test vectors: the extension_data of a ClientHello
 * trust_anchors extension.  When valid, the stored list is the vector minus
 * its two-byte outer length.
 */
static const struct {
    const uint8_t *data;
    size_t data_len;
    int ok;
} parse_tests[] = {
    /* One ID, 32473.1. */
    { (const uint8_t *)"\x00\x05\x04\x81\xfd\x59\x01", 7, 1 },
    /* Two IDs, 32473.1 and a two-byte ID. */
    { (const uint8_t *)"\x00\x08\x04\x81\xfd\x59\x01\x02\xaa\xbb", 10, 1 },
    /* An empty list is permitted. */
    { (const uint8_t *)"\x00\x00", 2, 1 },
    /* A zero-length ID is not. */
    { (const uint8_t *)"\x00\x01\x00", 3, 0 },
    /* The list must fill its length. */
    { (const uint8_t *)"\x00\x05\x04\x81\xfd\x59", 6, 0 },
    /* An ID truncated by the list. */
    { (const uint8_t *)"\x00\x04\x04\x81\xfd\x59", 6, 0 },
    /* Trailing data after the list. */
    { (const uint8_t *)"\x00\x00\xaa", 3, 0 },
};

static SSL_CTX *server_ctx = NULL;

static int test_parse_trust_anchors(int idx)
{
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    PACKET pkt;
    int ret = 0;

    if (!TEST_ptr(ssl = SSL_new(server_ctx))
        || !TEST_ptr(s = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(PACKET_buf_init(&pkt, parse_tests[idx].data,
            parse_tests[idx].data_len)))
        goto err;

    if (parse_tests[idx].ok) {
        if (!TEST_true(tls_parse_ctos_trust_anchors(s, &pkt,
                SSL_EXT_CLIENT_HELLO, NULL, 0))
            || !TEST_true(s->ext.peer_sent_trust_anchors))
            goto err;
        if (parse_tests[idx].data_len == 2) {
            /* An empty list is stored as no allocation at all. */
            if (!TEST_size_t_eq(s->ext.peer_requested_trust_anchors_len, 0)
                || !TEST_ptr_null(s->ext.peer_requested_trust_anchors))
                goto err;
        } else if (!TEST_mem_eq(s->ext.peer_requested_trust_anchors,
                       s->ext.peer_requested_trust_anchors_len,
                       parse_tests[idx].data + 2, parse_tests[idx].data_len - 2)) {
            goto err;
        }
    } else {
        if (!TEST_false(tls_parse_ctos_trust_anchors(s, &pkt,
                SSL_EXT_CLIENT_HELLO, NULL, 0))
            || !TEST_false(s->ext.peer_sent_trust_anchors))
            goto err;
        ERR_clear_error();
    }

    ret = 1;
err:
    SSL_free(ssl);
    return ret;
}

/*
 * SSL_clear() forgets what the peer sent in trust_anchors: the flag and list
 * from a parsed ClientHello extension.
 */
static int test_clear_peer_trust_anchors(void)
{
    static const uint8_t list[] = { 0x00, 0x04, 0x03, 0x81, 0xfd, 0x59 };
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    PACKET pkt;
    int ret = 0;

    if (!TEST_ptr(ssl = SSL_new(server_ctx))
        || !TEST_ptr(s = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(PACKET_buf_init(&pkt, list, sizeof(list)))
        || !TEST_true(tls_parse_ctos_trust_anchors(s, &pkt,
            SSL_EXT_CLIENT_HELLO, NULL, 0))
        || !TEST_true(s->ext.peer_sent_trust_anchors)
        || !TEST_ptr(s->ext.peer_requested_trust_anchors))
        goto err;

    if (!TEST_true(SSL_clear(ssl))
        || !TEST_false(s->ext.peer_sent_trust_anchors)
        || !TEST_ptr_null(s->ext.peer_requested_trust_anchors)
        || !TEST_size_t_eq(s->ext.peer_requested_trust_anchors_len, 0))
        goto err;

    ret = 1;
err:
    SSL_free(ssl);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(server_ctx = SSL_CTX_new(TLS_server_method())))
        return 0;
    ADD_ALL_TESTS(test_parse_trust_anchors, OSSL_NELEM(parse_tests));
    ADD_TEST(test_clear_peer_trust_anchors);
    return 1;
}

void cleanup_tests(void)
{
    SSL_CTX_free(server_ctx);
}
