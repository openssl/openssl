/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* DTLS CCS early-arrival tests */

#include <openssl/aes.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "helpers/ssltestlib.h"
#include "testutil.h"

static char *cert = NULL;
static char *privkey = NULL;

static unsigned int infinite_timer_cb(SSL *s, unsigned int timer_us)
{
    (void)s;

    if (timer_us == 0)
        return 999999999;
    return timer_us;
}

static int verify_accept_cb(int ok, X509_STORE_CTX *ctx)
{
    (void)ok;
    (void)ctx;

    return 1;
}

static int tick_key_renew_cb(SSL *s, unsigned char key_name[16],
    unsigned char iv[EVP_MAX_IV_LENGTH],
    EVP_CIPHER_CTX *ctx, EVP_MAC_CTX *hctx,
    int enc)
{
    const unsigned char tick_aes_key[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    unsigned char tick_hmac_key[16] = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };
    OSSL_PARAM params[2];
    EVP_CIPHER *aes128cbc = EVP_CIPHER_fetch(NULL, "AES-128-CBC", NULL);
    int ret;

    (void)s;

    if (aes128cbc == NULL)
        return -1;

    memset(key_name, 0, 16);
    memset(iv, 0, AES_BLOCK_SIZE);
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
        "SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CipherInit_ex(ctx, aes128cbc, NULL, tick_aes_key, iv, enc)
        || !EVP_MAC_init(hctx, tick_hmac_key, sizeof(tick_hmac_key), params))
        ret = -1;
    else
        ret = enc ? 1 : 2;

    EVP_CIPHER_free(aes128cbc);
    return ret;
}

static int verify_data_transfer(SSL *writer, SSL *reader)
{
    const char msg[] = "CCS reorder test";
    char buf[sizeof(msg)];

    if (!TEST_int_eq(SSL_write(writer, msg, sizeof(msg)), (int)sizeof(msg))
        || !TEST_int_eq(SSL_read(reader, buf, sizeof(buf)), (int)sizeof(msg))
        || !TEST_mem_eq(buf, sizeof(msg), msg, sizeof(msg)))
        return 0;
    return 1;
}

/* Move CCS just before the handshake message given by before_hs_msg. */
static int reorder_ccs(BIO *bio, int before_hs_msg)
{
    int target_pkt = -1, target_rec = -1;
    int ccs_pkt = -1, ccs_rec = -1;
    int p;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec)))
        return 0;

    if (target_rec > 0
        && !TEST_true(mempacket_split_packet_at(bio, target_pkt, target_rec)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC, -1,
            &ccs_pkt, &ccs_rec)))
        return 0;

    if (ccs_rec > 0
        && !TEST_true(mempacket_split_packet_at(bio, ccs_pkt, ccs_rec)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC, -1,
            &ccs_pkt, &ccs_rec))
        || !TEST_int_eq(ccs_rec, 0))
        return 0;

    if (!TEST_true(mempacket_split_packet_at(bio, ccs_pkt, 1)))
        return 0;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec))
        || !TEST_int_eq(target_rec, 0))
        return 0;

    if (ccs_pkt == target_pkt)
        return 0;

    if (ccs_pkt > target_pkt) {
        if (!TEST_true(mempacket_move_packet(bio, target_pkt, ccs_pkt)))
            return 0;
    } else {
        for (p = ccs_pkt; p + 1 < target_pkt; p++) {
            if (!TEST_true(mempacket_move_packet(bio, p, p + 1)))
                return 0;
        }
    }

    /* CCS packet should be at position target_pkt - 1 */
    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_CHANGE_CIPHER_SPEC,
            -1, &ccs_pkt, &ccs_rec))
        || !TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            before_hs_msg,
            &target_pkt, &target_rec))
        || !TEST_int_eq(ccs_pkt + 1, target_pkt)
        || !TEST_int_eq(ccs_rec, 0)
        || !TEST_int_eq(target_rec, 0))
        return 0;

    return 1;
}

static const struct {
    int mtls;
    int reorder_before;
    int max_version;
} full_hs_tests[] = {
#ifndef OPENSSL_NO_DTLS1_2
    /* DTLS 1.2: [CKE][CCS][Fin] -> [CCS][CKE][Fin] */
    { 0, SSL3_MT_CLIENT_KEY_EXCHANGE, DTLS1_2_VERSION },
    /* DTLS 1.2 mTLS: [Cert][CKE][CV][CCS][Fin] -> [CCS][Cert]... */
    { 1, SSL3_MT_CERTIFICATE, DTLS1_2_VERSION },
    /* DTLS 1.2 mTLS: [Cert][CKE][CV][CCS][Fin] -> [Cert][CKE][CCS][CV]... */
    { 1, SSL3_MT_CERTIFICATE_VERIFY, DTLS1_2_VERSION },
#endif
#ifndef OPENSSL_NO_DTLS1
    /* DTLS 1.0: [CKE][CCS][Fin] -> [CCS][CKE][Fin] */
    { 0, SSL3_MT_CLIENT_KEY_EXCHANGE, DTLS1_VERSION },
    /* DTLS 1.0 mTLS: [Cert][CKE][CV][CCS][Fin] -> [CCS][Cert]... */
    { 1, SSL3_MT_CERTIFICATE, DTLS1_VERSION },
    /* DTLS 1.0 mTLS: [Cert][CKE][CV][CCS][Fin] -> [Cert][CKE][CCS][CV]... */
    { 1, SSL3_MT_CERTIFICATE_VERIFY, DTLS1_VERSION },
#endif
};

/* Full handshake, Flight 3 (C->S): early CCS in the client flight. */
static int test_dtls_ccs_full_hs(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    X509 *peer = NULL;
    int testresult = 0, ret;
    int mtls = full_hs_tests[idx].mtls;
    int reorder_before = full_hs_tests[idx].reorder_before;
    int max_ver = full_hs_tests[idx].max_version;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            max_ver, max_ver,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (max_ver == DTLS1_VERSION) {
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_security_level(cctx, 0);
    }

    if (mtls) {
        SSL_CTX_set_verify(sctx,
            SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
            verify_accept_cb);

        if (!TEST_true(SSL_CTX_use_certificate_file(cctx, cert,
                SSL_FILETYPE_PEM))
            || !TEST_true(SSL_CTX_use_PrivateKey_file(cctx, privkey,
                SSL_FILETYPE_PEM)))
            goto end;
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, reorder_before)))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    if (mtls) {
        peer = SSL_get1_peer_certificate(sssl);
        if (!TEST_ptr(peer))
            goto end;
    }

    if (!TEST_true(verify_data_transfer(sssl, cssl)))
        goto end;

    testresult = 1;
end:
    X509_free(peer);
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static const int nst_versions[] = {
#ifndef OPENSSL_NO_DTLS1_2
    DTLS1_2_VERSION,
#endif
#ifndef OPENSSL_NO_DTLS1
    DTLS1_VERSION,
#endif
};

/* Flight 4 (S->C): [NST][CCS][Finished] -> [CCS][NST][Finished] */
static int test_dtls_ccs_before_nst(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0, ret;
    int max_ver = nst_versions[idx];

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            max_ver, max_ver,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (max_ver == DTLS1_VERSION) {
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_security_level(cctx, 0);
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_NEWSESSION_TICKET)))
        goto end;

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    if (!TEST_true(verify_data_transfer(cssl, sssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

static const struct {
    int use_ticket;
    int reorder_before;
    int max_version;
} resume_tests[] = {
#ifndef OPENSSL_NO_DTLS1_2
    /* DTLS 1.2 Session ID: [SH][CCS][Fin] -> [CCS][SH][Fin] */
    { 0, SSL3_MT_SERVER_HELLO, DTLS1_2_VERSION },
    /* DTLS 1.2 Ticket renewal: [NST][CCS][Fin] -> [CCS][NST][Fin] */
    { 1, SSL3_MT_NEWSESSION_TICKET, DTLS1_2_VERSION },
#endif
#ifndef OPENSSL_NO_DTLS1
    /* DTLS 1.0 Session ID: [SH][CCS][Fin] -> [CCS][SH][Fin] */
    { 0, SSL3_MT_SERVER_HELLO, DTLS1_VERSION },
    /* DTLS 1.0 Ticket renewal: [NST][CCS][Fin] -> [CCS][NST][Fin] */
    { 1, SSL3_MT_NEWSESSION_TICKET, DTLS1_VERSION },
#endif
};

/* Resumption, Flight 2 (S->C): early CCS in the server flight. */
static int test_dtls_ccs_resume(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    SSL_SESSION *sess = NULL;
    BIO *bio;
    int testresult = 0, ret;
    int use_ticket = resume_tests[idx].use_ticket;
    int reorder_before = resume_tests[idx].reorder_before;
    int max_ver = resume_tests[idx].max_version;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            max_ver, max_ver,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (max_ver == DTLS1_VERSION) {
        SSL_CTX_set_security_level(sctx, 0);
        SSL_CTX_set_security_level(cctx, 0);
    }

    if (use_ticket) {
        if (!TEST_true(SSL_CTX_set_tlsext_ticket_key_evp_cb(sctx,
                tick_key_renew_cb)))
            goto end;
    } else {
        SSL_CTX_set_options(sctx, SSL_OP_NO_TICKET);
    }

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(sssl, cssl, SSL_ERROR_NONE)))
        goto end;

    sess = SSL_get1_session(cssl);
    if (!TEST_ptr(sess))
        goto end;

    shutdown_ssl_connection(sssl, cssl);
    sssl = cssl = NULL;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_true(SSL_set_session(cssl, sess)))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    bio = SSL_get_wbio(sssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, reorder_before)))
        goto end;

    ret = SSL_connect(cssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_connect: ret=%d err=%d state=%s",
            ret, SSL_get_error(cssl, ret),
            SSL_state_string_long(cssl));
        goto end;
    }

    ret = SSL_accept(sssl);
    if (!TEST_int_gt(ret, 0)) {
        TEST_info("SSL_accept: ret=%d err=%d state=%s",
            ret, SSL_get_error(sssl, ret),
            SSL_state_string_long(sssl));
        goto end;
    }

    if (!TEST_true(SSL_session_reused(cssl)))
        goto end;

    if (!TEST_true(verify_data_transfer(cssl, sssl)))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_SESSION_free(sess);
    return testresult;
}

static int test_dtls_data_after_ccs(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *sssl = NULL, *cssl = NULL;
    BIO *bio;
    int testresult = 0, ret;
    int target_pkt, target_rec;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_2_VERSION, DTLS1_2_VERSION,
            &sctx, &cctx, cert, privkey)))
        return 0;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &sssl, &cssl, NULL, NULL)))
        goto end;

    DTLS_set_timer_cb(sssl, infinite_timer_cb);
    DTLS_set_timer_cb(cssl, infinite_timer_cb);

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    if (!TEST_int_le(SSL_accept(sssl), 0))
        goto end;

    if (!TEST_int_le(SSL_connect(cssl), 0))
        goto end;

    bio = SSL_get_wbio(cssl);
    if (!TEST_ptr(bio)
        || !TEST_true(reorder_ccs(bio, SSL3_MT_CLIENT_KEY_EXCHANGE)))
        goto end;

    if (!TEST_true(mempacket_find_record(bio, SSL3_RT_HANDSHAKE,
            SSL3_MT_CLIENT_KEY_EXCHANGE,
            &target_pkt, &target_rec)))
        goto end;
    if (!TEST_true(mempacket_append_to_record(bio, target_pkt, target_rec,
            (unsigned char *)"test data", 9)))
        goto end;

    ret = SSL_accept(sssl);
    if (!TEST_int_le(ret, 0))
        goto end;
    if (!TEST_int_eq(SSL_get_error(sssl, ret), SSL_ERROR_SSL))
        goto end;
    if (!TEST_int_eq(ERR_GET_REASON(ERR_get_error()), SSL_R_UNEXPECTED_MESSAGE))
        goto end;

    testresult = 1;
end:
    SSL_free(sssl);
    SSL_free(cssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_dtls_ccs_full_hs, OSSL_NELEM(full_hs_tests));
    ADD_ALL_TESTS(test_dtls_ccs_before_nst, OSSL_NELEM(nst_versions));
    ADD_ALL_TESTS(test_dtls_ccs_resume, OSSL_NELEM(resume_tests));
    ADD_TEST(test_dtls_data_after_ccs);

    return 1;
}

void cleanup_tests(void)
{
    bio_s_mempacket_test_free();
}
