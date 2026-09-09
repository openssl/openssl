/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "../ssl/record/methods/recmethod_local.h"
#include "../ssl/ssl_local.h"
#include "internal/nelem.h"
#include "internal/ssl_unwrap.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"
#include <openssl/evp.h>
#include <openssl/ssl.h>

static char *cert = NULL;
static char *privkey = NULL;

static const char *cipher_names[] = {
    "aes-128-ecb",
    "aes-256-ecb",
#if !defined(OPENSSL_NO_CHACHA)
    "chacha20",
#endif
};

static int test_dtls_crypt_sequence_number(int idx)
{
    /*
     * Test all possiblie Encryption Algorithms for dtls_crypt_sequence_number function
     * aes-128-ecb, "aes-256-ecb" and "chacha20"
     */
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    unsigned char key[32] = { 0 };
    unsigned char iv[16] = { 0 };
    unsigned char initial_seq[2] = { 0, 0 };
    unsigned char zero_seq[2] = { 0, 0 };
    unsigned char rec_data[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    cipher = EVP_CIPHER_fetch(NULL, cipher_names[idx], NULL);
    if (!TEST_ptr(cipher))
        goto err;

    ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is no longer zero */
    if (!TEST_mem_ne(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    if (!TEST_int_eq(dtls_crypt_sequence_number(ctx, initial_seq, sizeof(initial_seq), rec_data), 1))
        goto err;

    /* Verify Sequence Number is back to zero */
    if (!TEST_mem_eq(initial_seq, sizeof(initial_seq), zero_seq, sizeof(zero_seq)))
        goto err;

    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return 1;
err:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (cipher != NULL)
        EVP_CIPHER_free(cipher);
    return 0;
}

/* rfc9147 section 4.2.2 sequence number reconstruction vectors. */
typedef struct seq_num_test_st {
    /* Zero also represents the initial empty replay window. */
    uint64_t max_seq_num;
    uint64_t truncated;
    size_t seqlen;
    uint64_t seq_num;
} SEQ_NUM_TEST;

static const SEQ_NUM_TEST seq_num_tests[] = {
    /* Empty window and first-period lower-bound cases. */
    { 0, 0, 1, 0 },
    { 0, 1, 1, 1 },
    { 0, 0x7f, 1, 0x7f },
    { 0, 0x80, 1, 0x80 },
    { 0, 0x81, 1, 0x81 },
    { 0, 0xff, 1, 0xff },
    { 0, 0, 2, 0 },
    { 0, 1, 2, 1 },
    { 0, 0x7fff, 2, 0x7fff },
    { 0, 0x8000, 2, 0x8000 },
    { 0, 0x8001, 2, 0x8001 },
    { 0, 0x8002, 2, 0x8002 },
    { 0, 40000, 2, 40000 },
    { 0, 0xffff, 2, 0xffff },

    /* Ordinary forward progression */
    { 5, 6, 2, 6 },
    { 5, 6, 1, 6 },
    { 200, 201, 2, 201 },
    { 0x1234, 0x1235, 2, 0x1235 },

    /* 8- and 16-bit wraps */
    { 0xfe, 0xff, 1, 0xff },
    { 0xff, 0x00, 1, 0x100 },
    { 0x100, 0x01, 1, 0x101 },
    { 0x1fe, 0xff, 1, 0x1ff },
    { 0x1ff, 0x00, 1, 0x200 },
    { 0xfffe, 0xffff, 2, 0xffff },
    { 0xffff, 0x0000, 2, 0x10000 },
    { 0x10000, 0x0001, 2, 0x10001 },
    { 0x1fffe, 0xffff, 2, 0x1ffff },
    { 0x1ffff, 0x0000, 2, 0x20000 },
    { 0x20000, 0x0001, 2, 0x20001 },

    /* Reordered records */
    { 0x100, 0xff, 2, 0xff },
    { 0x100, 0xfe, 2, 0xfe },
    { 0x10010, 0x000f, 2, 0x1000f },
    { 300, 40, 1, 296 },

    /* Half-period ties select the forward candidate in either phase. */
    { 199, 72, 1, 328 }, /* candidate 72, 128 behind: pick 328 */
    { 299, 172, 1, 428 }, /* candidate 428, 128 ahead: keep it */
    { 0x180ff, 0x0100, 2, 0x20100 }, /* candidate 0x10100: pick 0x20100 */
    { 0x100ff, 0x8100, 2, 0x18100 }, /* candidate 0x18100: keep it */

    /* Top-of-uint64_t fallback and overflow boundaries */
    { UINT64_MAX, 0, 2, UINT64_MAX & ~UINT64_C(0xffff) },
    { UINT64_MAX, 0xffff, 2, UINT64_MAX },
    { UINT64_MAX, 0xffc0, 2, (UINT64_MAX & ~UINT64_C(0xffff)) | 0xffc0 },
    { UINT64_MAX, 5, 1, (UINT64_MAX & ~UINT64_C(0xff)) | 5 },
    { UINT64_MAX - 1, 0, 2, UINT64_MAX & ~UINT64_C(0xffff) },
    { UINT64_MAX - 0x10000, 0, 2, UINT64_MAX - 0xffff },
    { UINT64_MAX - 0x10000, 1, 2, UINT64_MAX - 0xffff + 1 },
    { UINT64_MAX - 0x10000, 0x8000, 2,
        (UINT64_MAX - 0xffff) | 0x8000 },
};

static int test_seq_num_reconstruction(int idx)
{
    const SEQ_NUM_TEST *t = &seq_num_tests[idx];
    uint64_t seq_num = 0;

    seq_num = dtls13_reconstruct_seq_num(t->max_seq_num, t->truncated,
        t->seqlen);

    if (!TEST_uint64_t_eq(seq_num, t->seq_num))
        return 0;

    /* The reconstructed value must retain the wire bits used in the AAD. */
    return TEST_uint64_t_eq(seq_num & DTLS13_UNI_HDR_SEQ_MASK(t->seqlen),
        t->truncated);
}

#ifndef OPENSSL_NO_DTLS1_3
/*
 * Test that dtls1_increment_epoch() enforces the RFC 9147 Section 8 limit
 * on the write (sending) epoch for DTLS 1.3: "sending implementations MUST
 * NOT allow the epoch to exceed 2^48-1". This is stricter than the 2^64-1
 * wrap-around ceiling in Section 6.1, and applies only to the write side
 * and only for DTLS 1.3 -- DTLS 1.2 keeps its existing UINT16_MAX limit.
 *
 * There's no way to actually drive 2^48 real KeyUpdates in a test, so this
 * drives one real DTLS 1.3 handshake to get a genuinely-typed connection
 * (SSL_CONNECTION_IS_DTLS13() depends on the negotiated method, not
 * anything that can be poked directly), then writes w_conn_epoch directly
 * to one below the limit before calling the real increment function at and
 * past the boundary.
 */
static int test_dtls13_increment_epoch_max(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *sc = NULL;
    int testresult = 0;

    if (!TEST_true(create_ssl_ctx_pair(NULL, DTLS_server_method(),
            DTLS_client_method(),
            DTLS1_3_VERSION, DTLS1_3_VERSION,
            &sctx, &cctx, cert, privkey)))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE)))
        goto end;

    if (!TEST_int_eq(SSL_version(serverssl), DTLS1_3_VERSION))
        goto end;

    if (!TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(serverssl)))
        goto end;

    if (!TEST_true(SSL_CONNECTION_IS_DTLS13(sc)))
        goto end;

    /* One below the Section 8 limit: incrementing must still succeed. */
    sc->rlayer.d->w_conn_epoch = DTLS1_3_MAX_EPOCH - 1;
    if (!TEST_true(dtls1_increment_epoch(sc, SSL3_CC_WRITE)))
        goto end;
    if (!TEST_uint64_t_eq(sc->rlayer.d->w_conn_epoch, DTLS1_3_MAX_EPOCH))
        goto end;

    /* Already at the limit: incrementing further must be rejected. */
    if (!TEST_false(dtls1_increment_epoch(sc, SSL3_CC_WRITE)))
        goto end;
    if (!TEST_uint64_t_eq(sc->rlayer.d->w_conn_epoch, DTLS1_3_MAX_EPOCH))
        goto end;

    testresult = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    return testresult;
}
#endif /* OPENSSL_NO_DTLS1_3 */

int setup_tests(void)
{
    if (!TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1)))
        return 0;

    ADD_ALL_TESTS(test_dtls_crypt_sequence_number, OSSL_NELEM(cipher_names));
    ADD_ALL_TESTS(test_seq_num_reconstruction, OSSL_NELEM(seq_num_tests));
#ifndef OPENSSL_NO_DTLS1_3
    ADD_TEST(test_dtls13_increment_epoch_max);
#endif
    return 1;
}
