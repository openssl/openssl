/*
 * Copyright 2015-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/mtc.h>
#include <openssl/ssl.h>
#include <openssl/x509_vfy.h>
#include <openssl/err.h>
#include <time.h>

#include "internal/packet.h"

#include "testutil.h"

#define CLIENT_VERSION_LEN 2

#define TOTAL_NUM_TESTS 1

/*
 * Test that explicitly setting ticket data results in it appearing in the
 * ClientHello for a negotiated SSL/TLS version
 */
#define TEST_SET_SESSION_TICK_DATA_VER_NEG 0

static int test_client_hello(int currtest)
{
    SSL_CTX *ctx;
    SSL *con = NULL;
    BIO *rbio;
    BIO *wbio;
    long len;
    unsigned char *data;
    PACKET pkt, pkt2, pkt3;
    char *dummytick = "Hello World!";
    unsigned int type = 0;
    int testresult = 0;
    BIO *sessbio = NULL;
    SSL_SESSION *sess = NULL;

    memset(&pkt, 0, sizeof(pkt));
    memset(&pkt2, 0, sizeof(pkt2));
    memset(&pkt3, 0, sizeof(pkt3));

    /*
     * For each test set up an SSL_CTX and SSL and see what ClientHello gets
     * produced when we try to connect
     */
    ctx = SSL_CTX_new(TLS_method());
    if (!TEST_ptr(ctx))
        goto end;
    if (!TEST_true(SSL_CTX_set_max_proto_version(ctx, 0)))
        goto end;

    switch (currtest) {
    case TEST_SET_SESSION_TICK_DATA_VER_NEG:
#if !defined(OPENSSL_NO_TLS1_3) && defined(OPENSSL_NO_TLS1_2)
        /* TLSv1.3 is enabled and TLSv1.2 is disabled so can't do this test */
        SSL_CTX_free(ctx);
        return 1;
#else
        /* Testing for session tickets <= TLS1.2; not relevant for 1.3 */
        if (!TEST_true(SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION)))
            goto end;
#endif
        break;

    default:
        goto end;
    }

    con = SSL_new(ctx);
    if (!TEST_ptr(con))
        goto end;

    rbio = BIO_new(BIO_s_mem());
    wbio = BIO_new(BIO_s_mem());
    if (!TEST_ptr(rbio) || !TEST_ptr(wbio)) {
        BIO_free(rbio);
        BIO_free(wbio);
        goto end;
    }

    SSL_set_bio(con, rbio, wbio);
    SSL_set_connect_state(con);

    if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
        if (!TEST_true(SSL_set_session_ticket_ext(con, dummytick,
                (int)strlen(dummytick))))
            goto end;
    }

    if (!TEST_int_le(SSL_connect(con), 0)) {
        /* This shouldn't succeed because we don't have a server! */
        goto end;
    }

    if (!TEST_long_ge(len = BIO_get_mem_data(wbio, (char **)&data), 0)
        || !TEST_true(PACKET_buf_init(&pkt, data, len))
        /* Skip the record header */
        || !PACKET_forward(&pkt, SSL3_RT_HEADER_LENGTH))
        goto end;

    /* Skip the handshake message header */
    if (!TEST_true(PACKET_forward(&pkt, SSL3_HM_HEADER_LENGTH))
        /* Skip client version and random */
        || !TEST_true(PACKET_forward(&pkt, CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE))
        /* Skip session id */
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        /* Skip ciphers */
        || !TEST_true(PACKET_get_length_prefixed_2(&pkt, &pkt2))
        /* Skip compression */
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        /* Extensions len */
        || !TEST_true(PACKET_as_length_prefixed_2(&pkt, &pkt2)))
        goto end;

    /* Loop through all extensions */
    while (PACKET_remaining(&pkt2)) {

        if (!TEST_true(PACKET_get_net_2(&pkt2, &type))
            || !TEST_true(PACKET_get_length_prefixed_2(&pkt2, &pkt3)))
            goto end;

        if (type == TLSEXT_TYPE_session_ticket) {
            if (currtest == TEST_SET_SESSION_TICK_DATA_VER_NEG) {
                if (TEST_true(PACKET_equal(&pkt3, dummytick,
                        strlen(dummytick)))) {
                    /* Ticket data is as we expected */
                    testresult = 1;
                }
                goto end;
            }
        }
    }

end:
    SSL_free(con);
    SSL_CTX_free(ctx);
    SSL_SESSION_free(sess);
    BIO_free(sessbio);

    return testresult;
}

/*
 * Test that the client sends the trust_anchors extension (section 5 of
 * https://datatracker.ietf.org/doc/draft-ietf-tls-trust-anchor-ids-05/)
 * carrying the identifiers of the configured Merkle Tree Certificate CAs, and
 * only when such CAs are configured.  |with_ca| selects the two cases.
 */
static int test_client_hello_trust_anchors(int with_ca)
{
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
    return TEST_skip("trust_anchors needs TLS 1.3 and EC or DH");
#else
    /* The CA ID 32473.1, as TrustAnchorID relative-OID bytes. */
    static const unsigned char trust_anchor_ca_id[] = { 0x81, 0xfd, 0x59,
        0x01 };
    SSL_CTX *ctx = NULL;
    SSL *con = NULL;
    BIO *rbio = NULL, *wbio = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_MTC_CA *ca = NULL;
    long len;
    unsigned char *data;
    PACKET pkt, pkt2, pkt3, tas, id;
    unsigned int type = 0;
    int found = 0, testresult = 0;

    memset(&pkt, 0, sizeof(pkt));
    memset(&pkt2, 0, sizeof(pkt2));
    memset(&pkt3, 0, sizeof(pkt3));
    memset(&tas, 0, sizeof(tas));
    memset(&id, 0, sizeof(id));

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_method()))
        || !TEST_true(SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)))
        goto end;

    if (with_ca) {
        /*
         * Any cosigner key works here: the send path only reads the CA id.
         * ML-DSA-44 is the cosigner role in the draft; skip if unavailable.
         */
        pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-44");
        if (pkey == NULL) {
            testresult = TEST_skip("ML-DSA-44 unavailable");
            goto end;
        }
        ca = OSSL_MTC_CA_new(trust_anchor_ca_id, sizeof(trust_anchor_ca_id),
            EVP_sha256(), 0, pkey);
        if (!TEST_ptr(ca)
            || !TEST_true(X509_STORE_trust_mtc_ca(SSL_CTX_get_cert_store(ctx),
                ca)))
            goto end;
    }

    if (!TEST_ptr(con = SSL_new(ctx)))
        goto end;
    if (!TEST_ptr(rbio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(wbio = BIO_new(BIO_s_mem()))) {
        BIO_free(rbio);
        BIO_free(wbio);
        goto end;
    }
    SSL_set_bio(con, rbio, wbio);
    SSL_set_connect_state(con);

    /* No server present, so this fails after writing the ClientHello. */
    if (!TEST_int_le(SSL_connect(con), 0))
        goto end;

    if (!TEST_long_ge(len = BIO_get_mem_data(wbio, (char **)&data), 0)
        || !TEST_true(PACKET_buf_init(&pkt, data, len))
        /* Skip the record header */
        || !PACKET_forward(&pkt, SSL3_RT_HEADER_LENGTH)
        /* Skip the handshake message header */
        || !TEST_true(PACKET_forward(&pkt, SSL3_HM_HEADER_LENGTH))
        /* Skip client version and random */
        || !TEST_true(PACKET_forward(&pkt, CLIENT_VERSION_LEN + SSL3_RANDOM_SIZE))
        /* Skip session id, ciphers, compression */
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        || !TEST_true(PACKET_get_length_prefixed_2(&pkt, &pkt2))
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &pkt2))
        /* Extensions */
        || !TEST_true(PACKET_as_length_prefixed_2(&pkt, &pkt2)))
        goto end;

    while (PACKET_remaining(&pkt2)) {
        if (!TEST_true(PACKET_get_net_2(&pkt2, &type))
            || !TEST_true(PACKET_get_length_prefixed_2(&pkt2, &pkt3)))
            goto end;
        if (type != TLSEXT_TYPE_trust_anchors)
            continue;

        found = 1;
        /*
         * extension_data is a RequestedTrustAnchorList: a u16-length list of
         * u8-length-prefixed TrustAnchorIDs.  Expect exactly our one CA id.
         */
        if (!TEST_true(PACKET_get_length_prefixed_2(&pkt3, &tas))
            || !TEST_true(PACKET_get_length_prefixed_1(&tas, &id))
            || !TEST_true(PACKET_equal(&id, trust_anchor_ca_id,
                sizeof(trust_anchor_ca_id)))
            || !TEST_size_t_eq(PACKET_remaining(&tas), 0)
            || !TEST_size_t_eq(PACKET_remaining(&pkt3), 0))
            goto end;
    }

    testresult = with_ca ? TEST_true(found) : TEST_false(found);

end:
    SSL_free(con);
    SSL_CTX_free(ctx); /* frees the store, which only borrowed the CA */
    OSSL_MTC_CA_free(ca);
    EVP_PKEY_free(pkey);
    return testresult;
#endif /* defined(OPENSSL_NO_TLS1_3) || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH)) */
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    ADD_ALL_TESTS(test_client_hello, TOTAL_NUM_TESTS);
    ADD_ALL_TESTS(test_client_hello_trust_anchors, 2);
    return 1;
}
