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

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
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
    /* A 32-byte ID is the longest. */
    { (const uint8_t *)"\x00\x21\x20"
                       "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                       "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                       "\x01\x01\x01\x01",
        35, 1 },
    /* One byte longer is rejected. */
    { (const uint8_t *)"\x00\x22\x21"
                       "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                       "\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01\x01"
                       "\x01\x01\x01\x01\x01",
        36, 0 },
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
 * from a parsed ClientHello extension, and the available list a server sent.
 */
static int test_clear_peer_trust_anchors(void)
{
    static const uint8_t list[] = { 0x00, 0x04, 0x03, 0x81, 0xfd, 0x59 };
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    PACKET pkt;
    const uint8_t *ids;
    size_t ids_len;
    int ret = 0;

    if (!TEST_ptr(ssl = SSL_new(server_ctx))
        || !TEST_ptr(s = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(PACKET_buf_init(&pkt, list, sizeof(list)))
        || !TEST_true(tls_parse_ctos_trust_anchors(s, &pkt,
            SSL_EXT_CLIENT_HELLO, NULL, 0))
        || !TEST_true(s->ext.peer_sent_trust_anchors)
        || !TEST_ptr(s->ext.peer_requested_trust_anchors))
        goto err;
    /* What a server's EncryptedExtensions would have left behind. */
    s->ext.peer_available_trust_anchors = OPENSSL_memdup(list + 2,
        sizeof(list) - 2);
    if (!TEST_ptr(s->ext.peer_available_trust_anchors))
        goto err;
    s->ext.peer_available_trust_anchors_len = sizeof(list) - 2;

    if (!TEST_true(SSL_clear(ssl))
        || !TEST_false(s->ext.peer_sent_trust_anchors)
        || !TEST_ptr_null(s->ext.peer_requested_trust_anchors)
        || !TEST_size_t_eq(s->ext.peer_requested_trust_anchors_len, 0))
        goto err;
    SSL_get0_peer_available_trust_anchors(ssl, &ids, &ids_len);
    if (!TEST_ptr_null(ids) || !TEST_size_t_eq(ids_len, 0))
        goto err;

    ret = 1;
err:
    SSL_free(ssl);
    return ret;
}

/* 32473.{123-456}.{789-}, the example of section 5.3.1. */
#define EXAMPLE_PATTERN "\x81\xfd\x59\x81\xfd\x59\x7b\x83\x48\x86\x15\x80"
/* 32473.{2^64+1 - 2^64+3}. */
#define LARGE_PATTERN                                                  \
    "\x81\xfd\x59\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x01" \
    "\x82\x80\x80\x80\x80\x80\x80\x80\x80\x03"
/* 32473.1.2.1.{3-}: CA 32473.1's landmark groups for log 1, landmark 3 on. */
#define LANDMARK_PATTERN \
    "\x81\xfd\x59\x81\xfd\x59\x01\x01\x02\x02\x01\x01\x03\x80"

/*
 * Trust anchor ID pattern test vectors: those of section 5.3.1 and Appendix A
 * of https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/,
 * then a landmark group pattern.
 */
static const struct {
    const char *pattern;
    size_t pattern_len;
    const char *id;
    size_t id_len;
    int contains;
} pattern_tests[] = {
    /* 32473.123.789 */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x7b\x86\x15", 6, 1 },
    /* 32473.300.900 */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x82\x2c\x87\x04", 7, 1 },
    /* 32473.456.99999 */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x83\x48\x86\x8d\x1f", 8, 1 },
    /* 32473.456.(2^64-1) */
    { EXAMPLE_PATTERN, 12,
        "\x81\xfd\x59\x83\x48\x81\xff\xff\xff\xff\xff\xff\xff\xff\x7f", 15, 1 },
    /* 32473.456.(2^64) */
    { EXAMPLE_PATTERN, 12,
        "\x81\xfd\x59\x83\x48\x82\x80\x80\x80\x80\x80\x80\x80\x80\x00", 15, 1 },
    /* 32473.123, too few components */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x7b", 4, 0 },
    /* 32473.123.789.0, too many components */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x7b\x86\x15\x00", 7, 0 },
    /* 32474.123.789, first component out of range */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x5a\x7b\x86\x15", 6, 0 },
    /* 32473.500.789, second component out of range */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x83\x74\x86\x15", 7, 0 },
    /* 32473.123.700, third component out of range */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x7b\x85\x3c", 6, 0 },
    /* invalid ID, not minimally encoded */
    { EXAMPLE_PATTERN, 12, "\x80\x81\xfd\x59\x7b\x86\x15", 7, 0 },
    /* invalid ID, component truncated */
    { EXAMPLE_PATTERN, 12, "\x81\xfd\x59\x7b\x86\x95", 6, 0 },
    /* 32473.(2^64+1) */
    { LARGE_PATTERN, 26,
        "\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x01", 13, 1 },
    /* 32473.(2^64+2) */
    { LARGE_PATTERN, 26,
        "\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x02", 13, 1 },
    /* 32473.(2^64+3) */
    { LARGE_PATTERN, 26,
        "\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x03", 13, 1 },
    /* 32473.2 */
    { LARGE_PATTERN, 26, "\x81\xfd\x59\x02", 4, 0 },
    /* 32473.(2^64) */
    { LARGE_PATTERN, 26,
        "\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x00", 13, 0 },
    /* 32473.(2^64+4) */
    { LARGE_PATTERN, 26,
        "\x81\xfd\x59\x82\x80\x80\x80\x80\x80\x80\x80\x80\x04", 13, 0 },
    /* invalid pattern, odd number of values */
    { "\x81\xfd\x59", 3, "\x81\xfd\x59", 3, 0 },
    /* invalid pattern, truncated min */
    { "\x81\xfd", 2, "\x81\xfd\x59", 3, 0 },
    /* invalid pattern, truncated max */
    { "\x81\xfd\x59\x81\xff\xff", 6, "\x81\xfd\x59", 3, 0 },
    /* invalid pattern, min of infinity */
    { "\x80\x42", 2, "\x00", 1, 0 },
    /* 32473.1.2.1.3 */
    { LANDMARK_PATTERN, 14, "\x81\xfd\x59\x01\x02\x01\x03", 7, 1 },
    /* 32473.1.2.1.200 */
    { LANDMARK_PATTERN, 14, "\x81\xfd\x59\x01\x02\x01\x81\x48", 8, 1 },
    /* 32473.1.2.1.2, below the landmark */
    { LANDMARK_PATTERN, 14, "\x81\xfd\x59\x01\x02\x01\x02", 7, 0 },
    /* 32473.1.2.2.3, another log */
    { LANDMARK_PATTERN, 14, "\x81\xfd\x59\x01\x02\x02\x03", 7, 0 },
    /* an empty pattern contains no ID */
    { "", 0, "\x01", 1, 0 },
};

static int test_pattern_contains(int idx)
{
    return TEST_int_eq(ossl_ssl_trust_anchor_pattern_contains(
                           (const uint8_t *)pattern_tests[idx].pattern,
                           pattern_tests[idx].pattern_len,
                           (const uint8_t *)pattern_tests[idx].id,
                           pattern_tests[idx].id_len),
        pattern_tests[idx].contains);
}

/* 32473.1.2.{0-}.{0-}: every MTC landmark group of CA 32473.1. */
#define STANDALONE_PATTERN \
    "\x81\xfd\x59\x81\xfd\x59\x01\x01\x02\x02\x00\x80\x00\x80"

/*
 * Requested-list vectors for credential matching.  The credential under test
 * has trust anchor ID 32473.1 and the group pattern STANDALONE_PATTERN.
 */
static const struct {
    const uint8_t *ids;
    size_t ids_len;
    int matches;
} match_tests[] = {
    /* 32473.1 requested: an exact trust anchor ID match. */
    { (const uint8_t *)"\x04\x81\xfd\x59\x01", 5, 1 },
    /* An unrelated ID. */
    { (const uint8_t *)"\x02\xaa\xbb", 3, 0 },
    /* 32473.1.2.1.3, log 1 to landmark 3: matched by the group pattern. */
    { (const uint8_t *)"\x07\x81\xfd\x59\x01\x02\x01\x03", 8, 1 },
    /* The matching ID need not be first. */
    { (const uint8_t *)"\x02\xaa\xbb\x07\x81\xfd\x59\x01\x02\x01\x03", 11, 1 },
    /* A multi-byte landmark number, 32473.1.2.1.200. */
    { (const uint8_t *)"\x08\x81\xfd\x59\x01\x02\x01\x81\x48", 9, 1 },
    /* A multi-byte log number, 32473.1.2.200.3. */
    { (const uint8_t *)"\x08\x81\xfd\x59\x01\x02\x81\x48\x03", 9, 1 },
    /* An individual landmark ID, 32473.1.1.1.3. */
    { (const uint8_t *)"\x07\x81\xfd\x59\x01\x01\x01\x03", 8, 0 },
    /* Too few components: 32473.1.2.1. */
    { (const uint8_t *)"\x06\x81\xfd\x59\x01\x02\x01", 7, 0 },
    /* Too many: 32473.1.2.1.3.4. */
    { (const uint8_t *)"\x08\x81\xfd\x59\x01\x02\x01\x03\x04", 9, 0 },
    /* A non-minimally-encoded component is rejected. */
    { (const uint8_t *)"\x08\x81\xfd\x59\x01\x02\x01\x80\x03", 9, 0 },
    /* An unterminated final component is rejected. */
    { (const uint8_t *)"\x07\x81\xfd\x59\x01\x02\x01\x81", 8, 0 },
    /* An empty request matches nothing. */
    { (const uint8_t *)"", 0, 0 },
};

static int test_credential_matches(int idx)
{
    static const uint8_t tai_id[] = { 0x81, 0xfd, 0x59, 0x01 };
    SSL_CREDENTIAL *cred = NULL, *bare = NULL;
    int ret = 0;

    if (!TEST_ptr(cred = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509))
        || !TEST_true(ossl_ssl_credential_set1_trust_anchor_id(cred, tai_id,
            sizeof(tai_id)))
        || !TEST_true(ossl_ssl_credential_add1_trust_anchor_group(cred,
            (const uint8_t *)STANDALONE_PATTERN,
            sizeof(STANDALONE_PATTERN) - 1)))
        goto err;

    if (!TEST_int_eq(ossl_ssl_credential_matches_request(cred,
                         match_tests[idx].ids, match_tests[idx].ids_len),
            match_tests[idx].matches))
        goto err;

    /* A credential with no trust anchor ID and no groups matches nothing. */
    if (!TEST_ptr(bare = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509))
        || !TEST_false(ossl_ssl_credential_matches_request(bare,
            match_tests[idx].ids, match_tests[idx].ids_len)))
        goto err;

    ret = 1;
err:
    SSL_CREDENTIAL_free(cred);
    SSL_CREDENTIAL_free(bare);
    return ret;
}

/* A one-entry RequestedTrustAnchorList: the ID 32473.1. */
static const uint8_t req_good[] = { 0x04, 0x81, 0xfd, 0x59, 0x01 };

/* The client's requested-trust-anchors list is validated and stored. */
static int test_requested_ta_setter(void)
{
    static const uint8_t bad_trunc[] = { 0x04, 0x81, 0xfd }; /* claims 4 */
    static const uint8_t bad_zero[] = { 0x00 }; /* empty ID */
    static const uint8_t bad_long[] = { 0x21, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
        0x01, 0x01, 0x01, 0x01 }; /* 33-byte ID */
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_client_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(ssl)))
        goto err;

    if (!TEST_true(SSL_set1_requested_trust_anchors(ssl, req_good,
            sizeof(req_good)))
        || !TEST_true(sc->ext.requested_trust_anchors_set)
        || !TEST_mem_eq(sc->ext.requested_trust_anchors,
            sc->ext.requested_trust_anchors_len, req_good, sizeof(req_good)))
        goto err;

    /* Malformed lists are rejected. */
    if (!TEST_false(SSL_set1_requested_trust_anchors(ssl, bad_trunc,
            sizeof(bad_trunc)))
        || !TEST_false(SSL_set1_requested_trust_anchors(ssl, bad_zero,
            sizeof(bad_zero)))
        || !TEST_false(SSL_set1_requested_trust_anchors(ssl, bad_long,
            sizeof(bad_long))))
        goto err;
    ERR_clear_error();

    /* An empty list is accepted and marks the list as set. */
    if (!TEST_true(SSL_set1_requested_trust_anchors(ssl, NULL, 0))
        || !TEST_true(sc->ext.requested_trust_anchors_set)
        || !TEST_size_t_eq(sc->ext.requested_trust_anchors_len, 0)
        || !TEST_ptr_null(sc->ext.requested_trust_anchors))
        goto err;

    /* The CTX-level setter stores on the context. */
    if (!TEST_true(SSL_CTX_set1_requested_trust_anchors(ctx, req_good,
            sizeof(req_good)))
        || !TEST_true(ctx->ext.requested_trust_anchors_set))
        goto err;

    ret = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return ret;
}

/*
 * An explicitly set list is advertised verbatim in the ClientHello, while a
 * client with nothing configured and no MTC CAs sends no extension.
 */
static int test_requested_ta_construct(void)
{
    static const uint8_t expect[] = { 0xca, 0x34, 0x00, 0x07, 0x00, 0x05, 0x04,
        0x81, 0xfd, 0x59, 0x01 };
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL, *plain = NULL;
    SSL_CONNECTION *sc, *psc;
    WPACKET pkt;
    uint8_t buf[64];
    size_t written = 0;
    int have_pkt = 0, ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_client_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(SSL_set1_requested_trust_anchors(ssl, req_good,
            sizeof(req_good)))
        || !TEST_true(WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)))
        goto err;
    have_pkt = 1;

    if (!TEST_int_eq(tls_construct_ctos_trust_anchors(sc, &pkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_SENT)
        || !TEST_true(WPACKET_get_total_written(&pkt, &written))
        || !TEST_mem_eq(buf, written, expect, sizeof(expect)))
        goto err;

    /* A connection with nothing configured and no MTC CAs sends nothing. */
    if (!TEST_ptr(plain = SSL_new(ctx))
        || !TEST_ptr(psc = SSL_CONNECTION_FROM_SSL(plain))
        || !TEST_int_eq(tls_construct_ctos_trust_anchors(psc, &pkt,
                            SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_NOT_SENT))
        goto err;

    ret = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    SSL_free(ssl);
    SSL_free(plain);
    SSL_CTX_free(ctx);
    return ret;
}

/*
 * The default advertisement for a trusted MTC CA with landmark state is its
 * landmark group ID (section 8.2.1 of the Merkle Tree Certificates draft), not
 * its bare CA ID: with log 1 current to landmark 3, the client sends
 * 32473.1.2.1.3.
 */
static int test_default_ta_construct_landmarks(void)
{
    /* 32473.1 as TrustAnchorID relative-OID bytes. */
    static const uint8_t mtc_ca_id[] = { 0x81, 0xfd, 0x59, 0x01 };
    static const uint8_t hash[32] = { 0x5a };
    /* The extension: one ID, the group 32473.1.2.1.3. */
    static const uint8_t expect[] = { 0xca, 0x34, 0x00, 0x0a, 0x00, 0x08, 0x07,
        0x81, 0xfd, 0x59, 0x01, 0x02, 0x01, 0x03 };
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    EVP_PKEY *ca_key = NULL;
    OSSL_MTC_CA *ca = NULL;
    BIO *bio = NULL;
    WPACKET pkt;
    uint8_t buf[64];
    size_t written = 0;
    int have_pkt = 0, ret = 0;

#if defined(OPENSSL_NO_ML_DSA)
    return TEST_skip("ML-DSA is disabled");
#endif /* defined(OPENSSL_NO_ML_DSA) */

    if (!TEST_ptr(ca_key = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44"))
        || !TEST_ptr(ca = OSSL_MTC_CA_new(mtc_ca_id, sizeof(mtc_ca_id),
                         EVP_sha256(), 0, ca_key)))
        goto err;

    /* Log 1 current to landmark 3, with the landmark-3 subtree [7,8) vetted. */
    if (!TEST_ptr(bio = BIO_new_mem_buf("3\n8 100\n6 100\n3 50\n", -1))
        || !TEST_true(OSSL_MTC_CA_load_landmarks(ca, 1, bio, INT64_MIN))
        || !TEST_true(OSSL_MTC_CA_add_subtree_hash(ca, 1, 7, 8, hash,
            sizeof(hash))))
        goto err;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_client_method()))
        || !TEST_true(X509_STORE_trust_mtc_ca(SSL_CTX_get_cert_store(ctx), ca))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(ssl))
        || !TEST_true(WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)))
        goto err;
    have_pkt = 1;

    if (!TEST_int_eq(tls_construct_ctos_trust_anchors(sc, &pkt,
                         SSL_EXT_CLIENT_HELLO, NULL, 0),
            EXT_RETURN_SENT)
        || !TEST_true(WPACKET_get_total_written(&pkt, &written))
        || !TEST_mem_eq(buf, written, expect, sizeof(expect)))
        goto err;

    ret = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    OSSL_MTC_CA_free(ca); /* the store borrows the CA; we own it */
    EVP_PKEY_free(ca_key);
    BIO_free(bio);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(server_ctx = SSL_CTX_new(TLS_server_method())))
        return 0;
    ADD_ALL_TESTS(test_parse_trust_anchors, OSSL_NELEM(parse_tests));
    ADD_TEST(test_clear_peer_trust_anchors);
    ADD_ALL_TESTS(test_pattern_contains, OSSL_NELEM(pattern_tests));
    ADD_ALL_TESTS(test_credential_matches, OSSL_NELEM(match_tests));
    ADD_TEST(test_requested_ta_setter);
    ADD_TEST(test_requested_ta_construct);
    ADD_TEST(test_default_ta_construct_landmarks);
    return 1;
}

void cleanup_tests(void)
{
    SSL_CTX_free(server_ctx);
}
