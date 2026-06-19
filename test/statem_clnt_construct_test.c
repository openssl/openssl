/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Direct tests for tls_construct_client_hello(): prime a client SSL_CONNECTION
 * enough to call the construct function without a full handshake, then check
 * the result structurally and by round-tripping it through the server parser.
 * OOM branches are covered with mfail tests.
 */

#include <openssl/ssl.h>
#ifndef OPENSSL_NO_ECH
#include <openssl/ech.h>
#include <openssl/hpke.h>
#endif

#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/statem/statem_local.h"
#include "testutil.h"

/*
 * TLS 1.3 needs a key-share group, so it is unusable when both EC and DH are
 * disabled even though the protocol itself is compiled in (e.g. no-bulk).
 */
#if defined(OPENSSL_NO_TLS1_3) \
    || (defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH))
#define OSSL_NO_USABLE_TLS1_3
#endif

/* ECH needs a curve (EC/ECX) for its default suite and usable TLS 1.3. */
#if defined(OPENSSL_NO_ECH) || defined(OPENSSL_NO_EC) \
    || defined(OPENSSL_NO_ECX) || defined(OSSL_NO_USABLE_TLS1_3)
#define OSSL_NO_USABLE_ECH
#endif

/*
 * Helpers down to prime_ssl() are generic and reusable by tests for any
 * statem_clnt construct function; the ClientHello-specific code follows.
 */

/* Connection configuration shared by the construct tests. */
typedef struct {
    int is_dtls;
    int min_ver; /* 0 for library default */
    int max_ver; /* 0 for library default */
    int clear_midbox; /* clear SSL_OP_ENABLE_MIDDLEBOX_COMPAT */
} CH_CONFIG;

static const SSL_METHOD *client_method(const CH_CONFIG *cfg)
{
    return cfg->is_dtls ? DTLS_client_method() : TLS_client_method();
}

/* Handshake message header length (msg precedes the ClientHello body). */
static size_t hdr_len(const CH_CONFIG *cfg)
{
    return cfg->is_dtls ? DTLS1_HM_HEADER_LENGTH : SSL3_HM_HEADER_LENGTH;
}

static const SSL_METHOD *server_method(const CH_CONFIG *cfg)
{
    return cfg->is_dtls ? DTLS_server_method() : TLS_server_method();
}

static SSL_CTX *new_ctx(const CH_CONFIG *cfg, const SSL_METHOD *meth)
{
    SSL_CTX *ctx = SSL_CTX_new(meth);

    if (ctx == NULL)
        return NULL;
    if ((cfg->min_ver != 0
            && !SSL_CTX_set_min_proto_version(ctx, cfg->min_ver))
        || (cfg->max_ver != 0
            && !SSL_CTX_set_max_proto_version(ctx, cfg->max_ver))) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}

/*
 * Set up the init_buf and handshake state the write state machine would have
 * established before calling a construct function.  For the client a WPACKET
 * with the handshake header is emitted into init_buf.  initbuf_len of 0 means
 * full size; a small value exercises WPACKET failures.
 */
static int prime_ssl(SSL *ssl, int is_client, size_t initbuf_len, WPACKET *pkt)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!TEST_ptr(s))
        return 0;

    if (is_client)
        SSL_set_connect_state(ssl);
    else
        SSL_set_accept_state(ssl);

    if (initbuf_len == 0)
        initbuf_len = SSL3_RT_MAX_PLAIN_LENGTH;

    if (!TEST_ptr(s->init_buf = BUF_MEM_new())
        || !TEST_true(BUF_MEM_grow(s->init_buf, initbuf_len)))
        return 0;

    if (!TEST_true(tls_setup_handshake(s)))
        return 0;

    if (pkt != NULL
        && (!TEST_true(WPACKET_init(pkt, s->init_buf))
            || !TEST_true(ssl_set_handshake_header(s, pkt,
                SSL3_MT_CLIENT_HELLO))))
        return 0;

    return 1;
}

/*
 * ===========================================================================
 * tls_construct_client_hello
 * ===========================================================================
 */

/* Finalize the constructed message and return its bytes (header + body). */
static int finish_ch(SSL *ssl, WPACKET *pkt, unsigned char **msg,
    size_t *msglen)
{
    SSL_CONNECTION *s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!TEST_true(ssl_close_construct_packet(s, pkt, SSL3_MT_CLIENT_HELLO))
        || !TEST_true(WPACKET_get_total_written(pkt, msglen))
        || !TEST_true(WPACKET_finish(pkt)))
        return 0;

    *msg = (unsigned char *)s->init_buf->data;
    return 1;
}

/* Recover the session_id length, the main branching difference in construct. */
static int get_ch_sessid_len(const CH_CONFIG *cfg, const unsigned char *msg,
    size_t msglen, size_t *sidlen)
{
    PACKET pkt = { 0 }, sessid = { 0 }, cookie = { 0 };
    PACKET ciphers = { 0 }, comp = { 0 };
    unsigned int legacy_version;
    size_t hl = hdr_len(cfg);

    if (!TEST_size_t_gt(msglen, hl)
        || !TEST_true(PACKET_buf_init(&pkt, msg + hl, msglen - hl)))
        return 0;

    if (!TEST_true(PACKET_get_net_2(&pkt, &legacy_version))
        || !TEST_true(PACKET_forward(&pkt, SSL3_RANDOM_SIZE))
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &sessid)))
        return 0;

    if (cfg->is_dtls
        && !TEST_true(PACKET_get_length_prefixed_1(&pkt, &cookie)))
        return 0;

    /* Sanity: cipher list non-empty, compression present and contains NULL. */
    if (!TEST_true(PACKET_get_length_prefixed_2(&pkt, &ciphers))
        || !TEST_size_t_gt(PACKET_remaining(&ciphers), 0)
        || !TEST_true(PACKET_get_length_prefixed_1(&pkt, &comp))
        || !TEST_size_t_gt(PACKET_remaining(&comp), 0))
        return 0;

    *sidlen = PACKET_remaining(&sessid);
    return 1;
}

/* Run the produced ClientHello body through the server-side parser. */
static int roundtrip_process_ch(const CH_CONFIG *cfg, const unsigned char *msg,
    size_t msglen)
{
    SSL_CTX *sctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    PACKET pkt;
    int ret = 0;

    if (!TEST_ptr(sctx = new_ctx(cfg, server_method(cfg)))
        || !TEST_ptr(ssl = SSL_new(sctx)))
        goto err;

    if (!prime_ssl(ssl, 0, 0, NULL))
        goto err;
    s = SSL_CONNECTION_FROM_SSL(ssl);

    if (!TEST_true(PACKET_buf_init(&pkt, msg + hdr_len(cfg),
            msglen - hdr_len(cfg))))
        goto err;

    if (!TEST_int_eq(tls_process_client_hello(s, &pkt),
            MSG_PROCESS_CONTINUE_PROCESSING))
        goto err;

    ret = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(sctx);
    return ret;
}

/*
 * Construct a ClientHello, assert its session_id length and optionally
 * round-trip it. prep injects extra state just before construct;
 * expect_random asserts the produced client random (to check reuse).
 * Both may be NULL.
 */
static int do_construct_ch(const CH_CONFIG *cfg,
    int (*prep)(SSL_CONNECTION *s), size_t expect_sidlen, int roundtrip,
    const unsigned char *expect_random)
{
    SSL_CTX *cctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    WPACKET pkt;
    unsigned char *msg = NULL;
    size_t msglen = 0, sidlen = 0;
    int ret = 0;

    if (!TEST_ptr(cctx = new_ctx(cfg, client_method(cfg)))
        || !TEST_ptr(ssl = SSL_new(cctx)))
        goto err;
    if (cfg->clear_midbox)
        SSL_clear_options(ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    if (!prime_ssl(ssl, 1, 0, &pkt))
        goto err;
    s = SSL_CONNECTION_FROM_SSL(ssl);

    if (prep != NULL && !prep(s)) {
        WPACKET_cleanup(&pkt);
        goto err;
    }

    if (!TEST_int_eq(tls_construct_client_hello(s, &pkt), CON_FUNC_SUCCESS)) {
        WPACKET_cleanup(&pkt);
        goto err;
    }
    if (!finish_ch(ssl, &pkt, &msg, &msglen))
        goto err;

    if (!get_ch_sessid_len(cfg, msg, msglen, &sidlen)
        || !TEST_size_t_eq(sidlen, expect_sidlen))
        goto err;

    /* The client random follows the 2-byte legacy_version in the body. */
    if (expect_random != NULL
        && !TEST_mem_eq(msg + hdr_len(cfg) + 2, SSL3_RANDOM_SIZE,
            expect_random, SSL3_RANDOM_SIZE))
        goto err;

    if (roundtrip && !roundtrip_process_ch(cfg, msg, msglen))
        goto err;

    ret = 1;
err:
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    return ret;
}

/* Expect tls_construct_client_hello() to fail (CON_FUNC_ERROR). */
static int do_construct_ch_expect_fail(const CH_CONFIG *cfg,
    int (*prep)(SSL_CONNECTION *s),
    size_t initbuf_len, int empty_ciphers)
{
    SSL_CTX *cctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    WPACKET pkt;
    int have_pkt = 0;
    int ret = 0;

    if (!TEST_ptr(cctx = new_ctx(cfg, client_method(cfg)))
        || !TEST_ptr(ssl = SSL_new(cctx)))
        goto err;

    if (empty_ciphers) {
        /* Leave no usable cipher: aNULL is disabled at default sec level. */
        int r1 = SSL_set_ciphersuites(ssl, "");
        int r2 = SSL_set_cipher_list(ssl, "aNULL");

        (void)r1;
        (void)r2;
    }

    if (!prime_ssl(ssl, 1, initbuf_len, &pkt))
        goto err;
    have_pkt = 1;
    s = SSL_CONNECTION_FROM_SSL(ssl);

    if (prep != NULL && !prep(s))
        goto err;

    if (!TEST_int_eq(tls_construct_client_hello(s, &pkt), CON_FUNC_ERROR))
        goto err;

    ret = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    return ret;
}

/* TLS 1.2 happy-path / session tests */

#ifndef OPENSSL_NO_TLS1_2
static int test_construct_ch_tls12(void)
{
    CH_CONFIG cfg = { 0, TLS1_2_VERSION, TLS1_2_VERSION, 0 };

    /* Fresh (non-resumable) TLS 1.2 session: empty session id. */
    return do_construct_ch(&cfg, NULL, 0, 1, NULL);
}

/* Resumable non-TLS1.3 session: construct reuses its session id. */
static int prep_resume(SSL_CONNECTION *s)
{
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);
    SSL_SESSION *sess = SSL_SESSION_new();
    int ret = 0;

    if (!TEST_ptr(sess))
        goto err;
    sess->ssl_version = TLS1_2_VERSION;
    sess->session_id_length = sizeof(sess->session_id);
    memset(sess->session_id, 0x5A, sess->session_id_length);
    sess->cipher = sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), 0);
    if (!TEST_ptr(sess->cipher) || !TEST_true(SSL_set_session(ssl, sess)))
        goto err;
    ret = 1;
err:
    SSL_SESSION_free(sess);
    return ret;
}

static int test_construct_ch_resume(void)
{
    CH_CONFIG cfg = { 0, TLS1_2_VERSION, TLS1_2_VERSION, 0 };

    /* Resumed session: the pre-loaded 32-byte session id is sent. */
    return do_construct_ch(&cfg, prep_resume, SSL_MAX_SSL_SESSION_ID_LENGTH, 1,
        NULL);
}
#endif /* OPENSSL_NO_TLS1_2 */

/* TLS 1.3 happy-path / HRR tests */

#ifndef OSSL_NO_USABLE_TLS1_3
static int test_construct_ch_tls13(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 0 };

    /* Middlebox compat is on by default: a random 32-byte session id. */
    return do_construct_ch(&cfg, NULL, SSL_MAX_SSL_SESSION_ID_LENGTH, 1, NULL);
}

static int test_construct_ch_tls13_no_middlebox(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 1 };

    /* No middlebox compat: empty session id. */
    return do_construct_ch(&cfg, NULL, 0, 1, NULL);
}

static int prep_hrr(SSL_CONNECTION *s)
{
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);
    SSL_SESSION *sess = SSL_SESSION_new();
    int ret = 0;

    /* Under HRR construct skips ssl_get_new_session(), so a session must
     * already exist (created for the first ClientHello). */
    if (!TEST_ptr(sess))
        goto err;
    sess->ssl_version = TLS1_3_VERSION;
    sess->cipher = sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), 0);
    if (!TEST_ptr(sess->cipher) || !TEST_true(SSL_set_session(ssl, sess)))
        goto err;
    s->hello_retry_request = SSL_HRR_COMPLETE;
    ret = 1;
err:
    SSL_SESSION_free(sess);
    return ret;
}

static int test_construct_ch_hrr(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 0 };

    /* TLS 1.3 + middlebox compat still emits a 32-byte session id under HRR. */
    return do_construct_ch(&cfg, prep_hrr, SSL_MAX_SSL_SESSION_ID_LENGTH, 1,
        NULL);
}
#endif /* OSSL_NO_USABLE_TLS1_3 */

/* DTLS happy-path / cookie / random-reuse tests */

#ifndef OPENSSL_NO_DTLS
static int test_construct_ch_dtls(void)
{
    CH_CONFIG cfg = { 1, 0, 0, 0 };

    /* DTLS uses a different server parser path; skip the roundtrip. */
    return do_construct_ch(&cfg, NULL, 0, 0, NULL);
}

static int prep_dtls_cookie(SSL_CONNECTION *s)
{
    /* A HelloVerifyRequest cookie is echoed in the ClientHello. */
    static const unsigned char cookie[16] = {
        0xc0, 0x01, 0xc0, 0x02, 0xc0, 0x03, 0xc0, 0x04,
        0xc0, 0x05, 0xc0, 0x06, 0xc0, 0x07, 0xc0, 0x08
    };

    memcpy(s->d1->cookie, cookie, sizeof(cookie));
    s->d1->cookie_len = sizeof(cookie);
    return 1;
}

static int test_construct_ch_dtls_cookie(void)
{
    CH_CONFIG cfg = { 1, 0, 0, 0 };

    return do_construct_ch(&cfg, prep_dtls_cookie, 0, 0, NULL);
}

/* A recognizable, all-non-zero client random to detect reuse. */
static const unsigned char reused_random[SSL3_RANDOM_SIZE] = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
    0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
    0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf
};

static int prep_dtls_client_random(SSL_CONNECTION *s)
{
    /* DTLS reuses an already-set client random (HelloVerifyRequest reply). */
    memcpy(s->s3.client_random, reused_random, sizeof(reused_random));
    return 1;
}

static int test_construct_ch_dtls_client_random(void)
{
    CH_CONFIG cfg = { 1, 0, 0, 0 };

    return do_construct_ch(&cfg, prep_dtls_client_random, 0, 0, reused_random);
}
#endif /* OPENSSL_NO_DTLS */

/* Deterministic error-branch tests */

static int test_construct_ch_small_buf(void)
{
    /* Default version: the overflow is version-independent. */
    CH_CONFIG cfg = { 0, 0, 0, 0 };
    SSL_CTX *cctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    WPACKET pkt;
    /*
     * Fixed, non-growable buffer that overflows part-way through the body (a
     * BUF_MEM-backed WPACKET would just grow), hitting a WPACKET write failure.
     */
    unsigned char buf[40];
    int have_pkt = 0;
    int ret = 0;

    if (!TEST_ptr(cctx = new_ctx(&cfg, client_method(&cfg)))
        || !TEST_ptr(ssl = SSL_new(cctx)))
        goto err;
    SSL_set_connect_state(ssl);
    s = SSL_CONNECTION_FROM_SSL(ssl);
    if (!TEST_ptr(s)
        || !TEST_ptr(s->init_buf = BUF_MEM_new())
        || !TEST_true(BUF_MEM_grow(s->init_buf, SSL3_RT_MAX_PLAIN_LENGTH))
        || !TEST_true(tls_setup_handshake(s)))
        goto err;

    if (!TEST_true(WPACKET_init_static_len(&pkt, buf, sizeof(buf), 0)))
        goto err;
    have_pkt = 1;
    if (!TEST_true(ssl_set_handshake_header(s, &pkt, SSL3_MT_CLIENT_HELLO)))
        goto err;

    if (!TEST_int_eq(tls_construct_client_hello(s, &pkt), CON_FUNC_ERROR))
        goto err;

    ret = 1;
err:
    if (have_pkt)
        WPACKET_cleanup(&pkt);
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    return ret;
}

static int test_construct_ch_no_ciphers(void)
{
    CH_CONFIG cfg = { 0, 0, 0, 0 };

    return do_construct_ch_expect_fail(&cfg, NULL, 0, 1);
}

/* Allocation-failure (mfail) tests */

/* Compiled when any mfail caller below (TLS 1.2, TLS 1.3 or ECH) is. */
#if !defined(OSSL_NO_USABLE_TLS1_3) || !defined(OPENSSL_NO_TLS1_2)
static int mfail_construct_ch_common(const CH_CONFIG *cfg,
    int (*prep)(SSL_CONNECTION *s))
{
    SSL_CTX *cctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *s;
    WPACKET pkt;
    int ok = 0;
    int ret = 0;

    if (!TEST_ptr(cctx = new_ctx(cfg, client_method(cfg)))
        || !TEST_ptr(ssl = SSL_new(cctx)))
        goto err;
    if (cfg->clear_midbox)
        SSL_clear_options(ssl, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

    if (!prime_ssl(ssl, 1, 0, &pkt))
        goto err;
    s = SSL_CONNECTION_FROM_SSL(ssl);

    if (prep != NULL && !prep(s)) {
        WPACKET_cleanup(&pkt);
        goto err;
    }

    MFAIL_start();
    ok = (tls_construct_client_hello(s, &pkt) == CON_FUNC_SUCCESS);
    MFAIL_end();

    WPACKET_cleanup(&pkt);

    /* 1 on clean success, 0 on an injected allocation failure. */
    ret = ok ? 1 : 0;
err:
    SSL_free(ssl);
    SSL_CTX_free(cctx);
    return ret;
}
#endif

#if !defined(OSSL_NO_USABLE_TLS1_3) && !defined(OPENSSL_NO_CACHED_FETCH)
static int mfail_construct_ch_tls13(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 0 };

    return mfail_construct_ch_common(&cfg, NULL);
}
#endif

#ifndef OPENSSL_NO_TLS1_2
static int mfail_construct_ch_tls12(void)
{
    CH_CONFIG cfg = { 0, TLS1_2_VERSION, TLS1_2_VERSION, 0 };

    return mfail_construct_ch_common(&cfg, NULL);
}
#endif

#ifndef OSSL_NO_USABLE_ECH
/* ECH path tests */

/* Attach an ECH config so construct takes the ECH wrapper path. */
static int prep_ech(SSL_CONNECTION *s)
{
    SSL *ssl = SSL_CONNECTION_GET_SSL(s);
    OSSL_ECHSTORE *es = NULL;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    int ret = 0;

    if (!TEST_ptr(es = OSSL_ECHSTORE_new(NULL, NULL))
        || !TEST_true(OSSL_ECHSTORE_new_config(es, OSSL_ECH_CURRENT_VERSION, 0,
            "example.com", suite))
        || !TEST_true(SSL_set1_echstore(ssl, es)))
        goto err;
    ret = 1;
err:
    OSSL_ECHSTORE_free(es);
    return ret;
}

/*
 * ECH happy path: the server reuses the client's store, which holds the private
 * key needed to decrypt the inner ClientHello, so the round-trip can succeed.
 */
static int test_construct_ch_ech(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 0 };
    SSL_CTX *cctx = NULL, *sctx = NULL;
    SSL *cssl = NULL, *sssl = NULL;
    SSL_CONNECTION *cs, *ss;
    OSSL_ECHSTORE *es = NULL;
    OSSL_HPKE_SUITE suite = OSSL_HPKE_SUITE_DEFAULT;
    WPACKET pkt;
    PACKET rpkt;
    unsigned char *msg = NULL;
    size_t msglen = 0, sidlen = 0;
    int ret = 0;

    if (!TEST_ptr(es = OSSL_ECHSTORE_new(NULL, NULL))
        || !TEST_true(OSSL_ECHSTORE_new_config(es, OSSL_ECH_CURRENT_VERSION, 0,
            "example.com", suite)))
        goto err;

    /* Client: construct the outer ClientHello with ECH. */
    if (!TEST_ptr(cctx = new_ctx(&cfg, client_method(&cfg)))
        || !TEST_ptr(cssl = SSL_new(cctx))
        || !TEST_true(SSL_set1_echstore(cssl, es))
        || !prime_ssl(cssl, 1, 0, &pkt))
        goto err;
    cs = SSL_CONNECTION_FROM_SSL(cssl);
    if (!TEST_int_eq(tls_construct_client_hello(cs, &pkt), CON_FUNC_SUCCESS)) {
        WPACKET_cleanup(&pkt);
        goto err;
    }
    if (!finish_ch(cssl, &pkt, &msg, &msglen)
        || !get_ch_sessid_len(&cfg, msg, msglen, &sidlen)
        || !TEST_size_t_eq(sidlen, SSL_MAX_SSL_SESSION_ID_LENGTH))
        goto err;

    /* Server: decrypt and process the outer using the same store. */
    if (!TEST_ptr(sctx = new_ctx(&cfg, server_method(&cfg)))
        || !TEST_ptr(sssl = SSL_new(sctx))
        || !TEST_true(SSL_set1_echstore(sssl, es))
        || !prime_ssl(sssl, 0, 0, NULL))
        goto err;
    ss = SSL_CONNECTION_FROM_SSL(sssl);
    if (!TEST_true(PACKET_buf_init(&rpkt, msg + hdr_len(&cfg),
            msglen - hdr_len(&cfg)))
        || !TEST_int_eq(tls_process_client_hello(ss, &rpkt),
            MSG_PROCESS_CONTINUE_PROCESSING))
        goto err;

    ret = 1;
err:
    OSSL_ECHSTORE_free(es);
    SSL_free(cssl);
    SSL_free(sssl);
    SSL_CTX_free(cctx);
    SSL_CTX_free(sctx);
    return ret;
}

#ifndef OPENSSL_NO_TLS1_2
static int test_construct_ch_ech_tls12(void)
{
    CH_CONFIG cfg = { 0, TLS1_2_VERSION, TLS1_2_VERSION, 0 };

    /* ECH requires TLS 1.3: the inner construct fails the version check. */
    return do_construct_ch_expect_fail(&cfg, prep_ech, 0, 0);
}
#endif /* OPENSSL_NO_TLS1_2 */

#ifndef OPENSSL_NO_CACHED_FETCH
static int mfail_construct_ch_ech(void)
{
    CH_CONFIG cfg = { 0, TLS1_3_VERSION, TLS1_3_VERSION, 0 };

    return mfail_construct_ch_common(&cfg, prep_ech);
}
#endif /* OPENSSL_NO_CACHED_FETCH */
#endif /* OSSL_NO_USABLE_ECH */

int setup_tests(void)
{
    ADD_TEST(test_construct_ch_small_buf);
    ADD_TEST(test_construct_ch_no_ciphers);

#ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_construct_ch_tls12);
    ADD_TEST(test_construct_ch_resume);
    ADD_MFAIL_TEST(mfail_construct_ch_tls12);
#endif

#ifndef OSSL_NO_USABLE_TLS1_3
    ADD_TEST(test_construct_ch_tls13);
    ADD_TEST(test_construct_ch_tls13_no_middlebox);
    ADD_TEST(test_construct_ch_hrr);
#ifndef OPENSSL_NO_CACHED_FETCH
    /*
     * The non-cached mfail run takes too long and does not test too much extra
     * so better to skip it.
     */
#if defined(OPENSSL_NO_ECX)
    /*
     * Without ECX the key_share falls back to EC keygen, which makes a
     * best-effort param-cache allocation whose failure does not propagate;
     * only crash/leak checking is meaningful then.
     *
     * No caching also needs no check.
     */
    ADD_MFAIL_NO_CHECK_TEST(mfail_construct_ch_tls13);
#else
    ADD_MFAIL_TEST(mfail_construct_ch_tls13);
#endif /* OPENSSL_NO_ECX */
#endif /* OPENSSL_NO_CACHED_FETCH */
#endif /* OSSL_NO_USABLE_TLS1_3 */

#ifndef OPENSSL_NO_DTLS
    ADD_TEST(test_construct_ch_dtls);
    ADD_TEST(test_construct_ch_dtls_cookie);
    ADD_TEST(test_construct_ch_dtls_client_random);
#endif

#ifndef OSSL_NO_USABLE_ECH
    ADD_TEST(test_construct_ch_ech);
#ifndef OPENSSL_NO_TLS1_2
    ADD_TEST(test_construct_ch_ech_tls12);
#endif
#ifndef OPENSSL_NO_CACHED_FETCH
    ADD_MFAIL_TEST(mfail_construct_ch_ech);
#endif /* OPENSSL_NO_CACHED_FETCH */
#endif /* OSSL_NO_USABLE_ECH */
    return 1;
}
