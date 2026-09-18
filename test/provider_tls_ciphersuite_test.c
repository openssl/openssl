/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include <string.h>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/provider.h>
#include <openssl/ssl.h>
#include "internal/ktls.h"
#include "internal/ssl_unwrap.h"
#include "../ssl/ssl_local.h"
#include "../ssl/record/methods/recmethod_local.h"
#include "helpers/ssltestlib.h"
#include "testutil.h"

#include "helpers/tls_provider.h"

typedef struct {
    const char *mode;
    int expect_success;
    int expected_count;
} CIPHERSUITE_TEST;

static const CIPHERSUITE_TEST ciphersuite_tests[] = {
    { "unsupported", 1, 0 },
    { "empty", 1, 0 },
    { "capability-error", 1, 0 },
    { "valid", 1, 1 },
    { "valid-composed", 1, 1 },
    { "valid-unknown-param", 1, 1 },
    { "valid-two", 1, 2 },
    { "non-private-codepoint", 1, 1 },
    { "bang-name", 1, 1 },
    { "tilde-name", 1, 1 },
    { "unterminated-name", 1, 1 },
    { "unterminated-max-name", 0, 0 },
    { "unterminated-algorithm-names", 1, 1 },
    { "max-name", 1, 1 },
    { "max-aead-name", 1, 0 },
    { "max-digest-name", 1, 0 },
    { "unavailable-aead", 1, 0 },
    { "unavailable-digest", 1, 0 },
    { "bad-name", 0, 0 },
    { "builtin-name", 0, 0 },
    { "builtin-name-lower", 0, 0 },
    { "legacy-name", 0, 0 },
    { "legacy-name-lower", 0, 0 },
    { "legacy-stdname", 0, 0 },
    { "legacy-stdname-lower", 0, 0 },
    { "space-name", 0, 0 },
    { "delete-name", 0, 0 },
    { "nonascii-name", 0, 0 },
    { "embedded-nul-name", 0, 0 },
    { "overlong-name", 0, 0 },
    { "null-name-data", 0, 0 },
    { "zero-name-size", 0, 0 },
    { "oversized-name-size", 0, 0 },
    { "null-codepoint-data", 0, 0 },
    { "zero-codepoint-size", 0, 0 },
    { "oversized-codepoint-size", 0, 0 },
    { "wrong-type-codepoint", 0, 0 },
    { "null-secbits-data", 0, 0 },
    { "zero-secbits-size", 0, 0 },
    { "oversized-secbits-size", 0, 0 },
    { "wrong-type-secbits", 0, 0 },
    { "null-taglen-data", 0, 0 },
    { "zero-taglen-size", 0, 0 },
    { "oversized-taglen-size", 0, 0 },
    { "wrong-type-taglen", 0, 0 },
    { "overlong-aead-name", 0, 0 },
    { "overlong-digest-name", 0, 0 },
    { "zero-codepoint", 0, 0 },
    { "grease-codepoint", 0, 0 },
    { "builtin-codepoint", 0, 0 },
    { "non-aead", 0, 0 },
    { "ccm", 0, 0 },
    { "oversized-key", 0, 0 },
    { "bad-digest", 0, 0 },
    { "oversized-digest", 0, 0 },
    { "oversized-digest-sha384", 0, 0 },
    { "bad-tag-length", 0, 0 },
    { "low-security", 0, 0 },
    { "excess-security", 0, 0 },
    { "missing-param", 0, 0 },
    { "wrong-type", 0, 0 },
    { "duplicate-descriptor", 0, 0 },
    { "duplicate-codepoint", 0, 0 },
    { "duplicate-name", 0, 0 },
    { "valid-then-invalid", 0, 0 },
    { "valid-then-abort", 1, 0 },
    { "too-many", 0, 0 }
};

static OSSL_LIB_CTX *libctx;
static OSSL_PROVIDER *defprov, *tlsprov;
static char *cert, *privkey;

#define TLS_TEST_SHA256_NAME "TLS_TEST_PROVIDER_AES_128_GCM_SHA256"
#define TLS_TEST_SHA384_NAME "TLS_TEST_PROVIDER_AES_256_GCM_SHA384"
#define TLS_TEST_COMPOSED_NAME "TLS_TEST_COMPOSED_AES_128_GCM_SHA256"
#define TLS_TEST_AEAD128_NAME "TLS-TEST-AES-128-GCM"
#define TLS_TEST_OVERSIZED_AEAD_NAME "TLS-TEST-AEAD-65"
#define TLS_TEST_MANY_COUNT 128

static int corrupt_records;
static BIO_METHOD *corrupt_filter_method;

static int corrupt_filter_read(BIO *bio, char *out, int outl)
{
    int ret = BIO_read(BIO_next(bio), out, outl);

    BIO_clear_retry_flags(bio);
    BIO_copy_next_retry(bio);
    return ret;
}

static int corrupt_filter_write(BIO *bio, const char *in, int inl)
{
    BIO *next = BIO_next(bio);
    unsigned char *copy = NULL;
    int ret;

    if (!corrupt_records || inl <= 0) {
        ret = BIO_write(next, in, inl);
    } else {
        copy = OPENSSL_memdup(in, (size_t)inl);
        if (copy == NULL)
            return 0;
        copy[inl - 1] ^= 1;
        ret = BIO_write(next, copy, inl);
        OPENSSL_free(copy);
    }
    BIO_clear_retry_flags(bio);
    BIO_copy_next_retry(bio);
    return ret;
}

static long corrupt_filter_ctrl(BIO *bio, int cmd, long num, void *ptr)
{
    BIO *next = BIO_next(bio);

    return next == NULL ? 0 : BIO_ctrl(next, cmd, num, ptr);
}

static int corrupt_filter_new(BIO *bio)
{
    BIO_set_init(bio, 1);
    return 1;
}

static int corrupt_filter_free(BIO *bio)
{
    BIO_set_init(bio, 0);
    return 1;
}

static const BIO_METHOD *corrupt_filter(void)
{
    if (corrupt_filter_method == NULL) {
        corrupt_filter_method = BIO_meth_new(BIO_TYPE_FILTER,
            "TLS record corruption filter");
        if (corrupt_filter_method == NULL
            || !BIO_meth_set_read(corrupt_filter_method, corrupt_filter_read)
            || !BIO_meth_set_write(corrupt_filter_method,
                corrupt_filter_write)
            || !BIO_meth_set_ctrl(corrupt_filter_method, corrupt_filter_ctrl)
            || !BIO_meth_set_create(corrupt_filter_method, corrupt_filter_new)
            || !BIO_meth_set_destroy(corrupt_filter_method,
                corrupt_filter_free))
            return NULL;
    }
    return corrupt_filter_method;
}

static int test_provider_aead_kat(void)
{
    static const unsigned char key[16] = { 0 };
    static const unsigned char iv[12] = { 0 };
    static const unsigned char plaintext[16] = { 0 };
    static const unsigned char ciphertext[16] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
    };
    static const unsigned char expected_tag[16] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
    };
    EVP_CIPHER *cipher = NULL;
    EVP_MD *digest = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char out[sizeof(plaintext) + EVP_GCM_TLS_TAG_LEN];
    unsigned char tag[sizeof(expected_tag)];
    int len, finlen, ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, TLS_TEST_AEAD128_NAME,
                      "provider=tls-provider"))
        || !TEST_ptr_eq(EVP_CIPHER_get0_provider(cipher), tlsprov)
        || !TEST_str_eq(OSSL_PROVIDER_get0_name(
                            EVP_CIPHER_get0_provider(cipher)),
            "tls-provider")
        || !TEST_true((EVP_CIPHER_get_flags(cipher)
                          & EVP_CIPH_FLAG_AEAD_CIPHER)
            != 0)
        || !TEST_int_eq(EVP_CIPHER_get_mode(cipher), EVP_CIPH_GCM_MODE)
        || !TEST_int_eq(EVP_CIPHER_get_block_size(cipher), 1)
        || !TEST_int_eq(EVP_CIPHER_get_key_length(cipher), 16)
        || !TEST_int_eq(EVP_CIPHER_get_iv_length(cipher), 12)
        || !TEST_ptr(digest = EVP_MD_fetch(libctx, "TLS-TEST-SHA2-256",
                         "provider=tls-provider"))
        || !TEST_ptr_eq(EVP_MD_get0_provider(digest), tlsprov)
        || !TEST_true(EVP_MD_is_a(digest, OSSL_DIGEST_NAME_SHA2_256))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx, out, &len, plaintext,
            sizeof(plaintext)))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, out + len, &finlen))
        || !TEST_int_eq(len + finlen, (int)sizeof(ciphertext))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
            sizeof(tag), tag))
        || !TEST_mem_eq(out, sizeof(ciphertext), ciphertext,
            sizeof(ciphertext))
        || !TEST_mem_eq(tag, sizeof(tag), expected_tag,
            sizeof(expected_tag)))
        goto end;

    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
        || !TEST_true(EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
            sizeof(tag), tag))
        || !TEST_true(EVP_DecryptUpdate(ctx, out, &len, ciphertext,
            sizeof(ciphertext)))
        || !TEST_true(EVP_DecryptFinal_ex(ctx, out + len, &finlen))
        || !TEST_mem_eq(out, sizeof(plaintext), plaintext,
            sizeof(plaintext)))
        goto end;

    tag[0] ^= 1;
    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
        || !TEST_true(EVP_DecryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
            sizeof(tag), tag))
        || !TEST_true(EVP_DecryptUpdate(ctx, out, &len, ciphertext,
            sizeof(ciphertext)))
        || !TEST_int_le(EVP_DecryptFinal_ex(ctx, out + len, &finlen), 0))
        goto end;

    memcpy(out, plaintext, sizeof(plaintext));
    if (!TEST_true(EVP_CIPHER_CTX_reset(ctx))
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx, out, &len, out,
            sizeof(plaintext)))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, out + len, &finlen))
        || !TEST_mem_eq(out, sizeof(ciphertext), ciphertext,
            sizeof(ciphertext)))
        goto end;

    ret = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_MD_free(digest);
    EVP_CIPHER_free(cipher);
    ERR_clear_error();
    return ret;
}

static int test_oversized_aead_fixture(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(libctx,
                      TLS_TEST_OVERSIZED_AEAD_NAME, "provider=tls-provider"))
        || !TEST_int_eq(EVP_CIPHER_get_key_length(cipher),
            EVP_MAX_KEY_LENGTH + 1)
        || !TEST_int_eq(EVP_CIPHER_get_block_size(cipher), 1)
        || !TEST_int_eq(EVP_CIPHER_get_iv_length(cipher), 12)
        || !TEST_true((EVP_CIPHER_get_flags(cipher)
                          & EVP_CIPH_FLAG_AEAD_CIPHER)
            != 0)
        || !TEST_int_eq(EVP_CIPHER_get_mode(cipher), EVP_CIPH_GCM_MODE)
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, NULL))
        || !TEST_int_eq(EVP_CIPHER_CTX_get_tag_length(ctx),
            EVP_GCM_TLS_TAG_LEN))
        goto end;

    ret = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

static void count_server_hellos_cb(int write_p, int version, int content_type,
    const void *buf, size_t len, SSL *ssl, void *arg)
{
    int *count = arg;
    const unsigned char *msg = buf;

    if (!write_p && content_type == SSL3_RT_HANDSHAKE && len > 0
        && msg[0] == SSL3_MT_SERVER_HELLO)
        (*count)++;
}

#if !defined(OPENSSL_NO_TLS1_2)
static int expect_no_shared_cipher(SSL *serverssl, SSL *clientssl)
{
    unsigned long error;

    ERR_clear_error();
    if (!TEST_false(create_ssl_connection(serverssl, clientssl, SSL_ERROR_SSL)))
        return 0;
    do {
        error = ERR_get_error();
        if (error == 0) {
            TEST_error("no shared cipher error not found");
            return 0;
        }
    } while (ERR_GET_LIB(error) != ERR_LIB_SSL
        || ERR_GET_REASON(error) != SSL_R_NO_SHARED_CIPHER);
    return 1;
}
#endif /* !defined(OPENSSL_NO_TLS1_2) */

typedef struct {
    SSL_CTX *first;
    SSL_CTX *second;
    int set_ciphersuites;
    int set_cipher_list;
    int keep_contexts;
    int calls;
} SNI_SWITCH_DATA;

static int sni_switch_cb(SSL *ssl, int *alert, void *arg)
{
    SNI_SWITCH_DATA *data = arg;

    data->calls++;
    if (SSL_set_SSL_CTX(ssl, data->first) == NULL
        || (data->set_ciphersuites
            && !SSL_set_ciphersuites(ssl, TLS_TEST_SHA256_NAME))
        || (data->set_cipher_list
            && !SSL_set_cipher_list(ssl, "DEFAULT"))
        || (data->second != NULL
            && SSL_set_SSL_CTX(ssl, data->second) == NULL)) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }

    if (!data->keep_contexts) {
        SSL_CTX_free(data->first);
        data->first = NULL;
        if (data->second != NULL) {
            SSL_CTX_free(data->second);
            data->second = NULL;
        }
    }
    return SSL_TLSEXT_ERR_OK;
}

static int check_valid_suite(const SSL_CIPHER *suite, int index,
    int check_default_id)
{
    unsigned int codepoint = check_default_id
        ? 0xffa0U + (unsigned int)index
        : 0xfea0U;

    if (!TEST_ptr(suite)
        || !TEST_int_eq(suite->origin, SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_uint_eq(suite->id,
            SSL3_CK_CIPHERSUITE_FLAG | codepoint)
        || !TEST_int_eq(suite->min_tls, TLS1_3_VERSION)
        || !TEST_int_eq(suite->max_tls, TLS1_3_VERSION)
        || !TEST_int_eq(suite->min_dtls, 0)
        || !TEST_int_eq(suite->max_dtls, 0)
        || !TEST_true((suite->algo_strength & SSL_NOT_DEFAULT) != 0)
        || !TEST_int_eq(suite->strength_bits, 128)
        || !TEST_uint_eq(suite->alg_bits, 128)
        || !TEST_ptr(suite->provider_cipher)
        || !TEST_ptr(suite->provider_digest))
        return 0;

    return 1;
}

#if !defined(OPENSSL_NO_DTLS)
static int cipher_stack_has_provider_suite(
    const STACK_OF(SSL_CIPHER) *ciphers)
{
    int i;

    for (i = 0; i < sk_SSL_CIPHER_num(ciphers); i++) {
        if (sk_SSL_CIPHER_value(ciphers, i)->origin
            == SSL_CIPHER_ORIGIN_PROVIDER)
            return 1;
    }
    return 0;
}
#endif /* !defined(OPENSSL_NO_DTLS) */

static int test_ciphersuite_mode(int idx)
{
    const CIPHERSUITE_TEST *test = &ciphersuite_tests[idx];
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *ctx = NULL;
    int i, ret = 0;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-mode", test->mode, "?provider=tls-provider")))
        goto end;
    ctx = SSL_CTX_new_ex(localctx, NULL, TLS_method());
    if (test->expect_success) {
        if (!TEST_ptr(ctx)
            || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites),
                test->expected_count)
            || !TEST_ulong_eq(ERR_peek_error(), 0))
            goto end;
        for (i = 0; i < test->expected_count; i++) {
            if (!check_valid_suite(
                    sk_SSL_CIPHER_value(ctx->provider_ciphersuites, i), i,
                    strcmp(test->mode, "non-private-codepoint") != 0))
                goto end;
        }
        for (i = 0; i < sk_SSL_CIPHER_num(ctx->tls13_ciphersuites); i++) {
            if (!TEST_int_ne(sk_SSL_CIPHER_value(ctx->tls13_ciphersuites, i)->origin,
                    SSL_CIPHER_ORIGIN_PROVIDER))
                goto end;
        }
    } else {
        if (!TEST_ptr_null(ctx) || !TEST_ulong_ne(ERR_peek_error(), 0))
            goto end;
    }

    ret = 1;
end:
    ERR_clear_error();
    SSL_CTX_free(ctx);
    tls_provider_libctx_free(localctx, localdef, localtls);
    return ret;
}

static int test_property_query_exclusion(void)
{
    SSL_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, "provider=default",
                      TLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites), 0)
        || !TEST_false(SSL_CTX_set_ciphersuites(ctx,
            TLS_TEST_SHA256_NAME)))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_registry_indexes(void)
{
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *ctx = NULL;
    const SSL_CIPHER *by_id, *by_name;
    char name[64], description[256];
    uint32_t id;
    int i, ret = 0;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-many", "valid-many", "?provider=tls-provider"))
        || !TEST_ptr(ctx = SSL_CTX_new_ex(localctx, NULL, TLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites),
            TLS_TEST_MANY_COUNT)
        || !TEST_int_eq(sk_SSL_CIPHER_num(
                            ctx->provider_ciphersuites_by_name),
            TLS_TEST_MANY_COUNT)
        || !TEST_true(sk_SSL_CIPHER_is_sorted(ctx->provider_ciphersuites))
        || !TEST_true(sk_SSL_CIPHER_is_sorted(
            ctx->provider_ciphersuites_by_name)))
        goto end;

    for (i = 0; i < TLS_TEST_MANY_COUNT; i++) {
        id = SSL3_CK_CIPHERSUITE_FLAG | (0xff00U + (unsigned int)i);
        snprintf(name, sizeof(name), "TLS_TEST_PROVIDER_INDEX_%03d",
            TLS_TEST_MANY_COUNT - 1 - i);
        by_id = ossl_ssl_get0_provider_cipher_by_id(ctx, id);
        by_name = ossl_ssl_get0_provider_cipher_by_name(ctx, name);
        if (!TEST_ptr(by_id)
            || !TEST_ptr_eq(by_name, by_id)
            || !TEST_uint_eq(by_id->id, id))
            goto end;
    }

    if (!TEST_ptr_eq(ossl_ssl_get0_provider_cipher_by_name(
                         ctx, "tls_test_provider_index_064"),
            ossl_ssl_get0_provider_cipher_by_id(ctx,
                SSL3_CK_CIPHERSUITE_FLAG
                    | (0xff00U + TLS_TEST_MANY_COUNT - 1U - 64U)))
        || !TEST_ptr_null(ossl_ssl_get0_provider_cipher_by_id(ctx,
            SSL3_CK_CIPHERSUITE_FLAG | 0xff80U))
        || !TEST_ptr_null(ossl_ssl_get0_provider_cipher_by_name(ctx,
            "TLS_TEST_PROVIDER_INDEX_MISSING"))
        || !TEST_ulong_eq(ERR_peek_error(), 0))
        goto end;

    by_id = ossl_ssl_get0_provider_cipher_by_id(
        ctx, SSL3_CK_CIPHERSUITE_FLAG | 0xff00U);
    if (!TEST_ptr(by_id)
        || !TEST_ptr_null(SSL_CIPHER_standard_name(by_id))
        || !TEST_int_eq(SSL_CIPHER_get_digest_nid(by_id), NID_undef)
        || !TEST_true(SSL_CIPHER_is_aead(by_id))
        || !TEST_ptr(SSL_CIPHER_get_handshake_digest(by_id))
        || !TEST_ptr(SSL_CIPHER_description(
            by_id, description, sizeof(description))))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(ctx);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

static int test_provider_peer_list_deduplication(void)
{
    static const unsigned char suites[] = {
        0xff, 0xa0, 0xff, 0xa0, 0xff, 0xa0,
        0x13, 0x01, 0x13, 0x01
    };
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *ciphers = NULL, *scsvs = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_true(SSL_bytes_to_cipher_list(ssl, suites, sizeof(suites),
            0, &ciphers, &scsvs))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ciphers), 3)
        || !TEST_int_eq(sk_SSL_CIPHER_value(ciphers, 0)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_int_eq(sk_SSL_CIPHER_value(ciphers, 1)->origin,
            SSL_CIPHER_ORIGIN_STATIC)
        || !TEST_ptr_eq(sk_SSL_CIPHER_value(ciphers, 1),
            sk_SSL_CIPHER_value(ciphers, 2)))
        goto end;

    ret = 1;
end:
    sk_SSL_CIPHER_free(ciphers);
    sk_SSL_CIPHER_free(scsvs);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_composition(void)
{
    static const unsigned char message[] = "provider composition";
    unsigned char received[sizeof(message)];
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *suite;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-composed", "valid-composed", "provider=default"))
        || !TEST_true(create_ssl_ctx_pair(localctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_int_eq(sk_SSL_CIPHER_num(sctx->provider_ciphersuites), 1)
        || !TEST_ptr(suite = sk_SSL_CIPHER_value(
                         sctx->provider_ciphersuites, 0))
        || !TEST_ptr_eq(EVP_CIPHER_get0_provider(suite->provider_cipher),
            localdef)
        || !TEST_ptr_eq(EVP_MD_get0_provider(suite->provider_digest),
            localdef)
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx,
            TLS_TEST_COMPOSED_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx,
            TLS_TEST_COMPOSED_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(message))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message))
        || !TEST_true(SSL_write_ex(serverssl, message, sizeof(message),
            &written))
        || !TEST_true(SSL_read_ex(clientssl, received, sizeof(received),
            &readbytes))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message))
        || !TEST_true(SSL_key_update(clientssl, SSL_KEY_UPDATE_REQUESTED))
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message))
        || !TEST_true(SSL_write_ex(serverssl, message, sizeof(message),
            &written))
        || !TEST_true(SSL_read_ex(clientssl, received, sizeof(received),
            &readbytes))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

static int test_provider_discovery_mfail(void)
{
    SSL_CTX *ctx;
    int ret = 0;

    MFAIL_start();
    ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method());
    MFAIL_end();

    if (ctx != NULL
        && sk_SSL_CIPHER_num(ctx->provider_ciphersuites) == 2)
        ret = 1;
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int cipher_stacks_equal(const STACK_OF(SSL_CIPHER) *actual,
    const STACK_OF(SSL_CIPHER) *expected)
{
    int i;

    if (!TEST_int_eq(sk_SSL_CIPHER_num(actual), sk_SSL_CIPHER_num(expected)))
        return 0;
    for (i = 0; i < sk_SSL_CIPHER_num(expected); i++)
        if (!TEST_ptr_eq(sk_SSL_CIPHER_value(actual, i),
                sk_SSL_CIPHER_value(expected, i)))
            return 0;
    return 1;
}

static int test_ciphersuite_setter_null(int idx)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *ctx_ciphers, *ssl_ciphers;
    int result, ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(ssl = SSL_new(ctx)))
        goto end;
    ctx_ciphers = SSL_CTX_get_ciphers(ctx);
    ssl_ciphers = SSL_get_ciphers(ssl);
    ERR_clear_error();
    if (idx < 2)
        result = SSL_CTX_set_ciphersuites(idx == 0 ? NULL : ctx,
            idx == 0 ? TLS_TEST_SHA256_NAME : NULL);
    else
        result = SSL_set_ciphersuites(idx == 2 ? NULL : ssl,
            idx == 2 ? TLS_TEST_SHA256_NAME : NULL);
    if (!TEST_false(result)
        || !TEST_int_eq(ERR_GET_LIB(ERR_peek_last_error()), ERR_LIB_SSL)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            ERR_R_PASSED_NULL_PARAMETER)
        || !TEST_ptr_eq(SSL_CTX_get_ciphers(ctx), ctx_ciphers)
        || !TEST_ptr_eq(SSL_get_ciphers(ssl), ssl_ciphers))
        goto end;
    ret = 1;
end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_ssl_ciphersuites_mfail(int idx)
{
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    STACK_OF(SSL_CIPHER) **stacks[3], *old[3], *saved[3] = { NULL };
    STACK_OF(SSL_CIPHER) *context_list = NULL, *context_by_id = NULL;
    STACK_OF(SSL_CIPHER) *active, *by_id;
    const SSL_CIPHER *cipher;
    int i, j, pos, set_ok, role = idx % 3, ret = -1;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method())))
        goto end;

    /* An empty combined list forces the first insertion to allocate. */
    if (idx >= 3) {
        if (!TEST_true(SSL_CTX_set_ciphersuites(ctx, ""))
            || !TEST_int_eq(SSL_CTX_set_cipher_list(ctx, ""),
                ctx->method->num_ciphers() == 0)
            || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->cipher_list), 0)
            || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->cipher_list_by_id), 0))
            goto end;
        ERR_clear_error();
    }
    if (!TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl)))
        goto end;

    /* Cover an owned SSL list, an inherited SSL list, and the context. */
    if (role == 0
        && !TEST_true(SSL_set_ciphersuites(ssl,
            idx >= 3 ? "" : "TLS_AES_128_GCM_SHA256")))
        goto end;

    stacks[0] = role == 2 ? &ctx->tls13_ciphersuites : &sc->tls13_ciphersuites;
    stacks[1] = role == 2 ? &ctx->cipher_list : &sc->cipher_list;
    stacks[2] = role == 2 ? &ctx->cipher_list_by_id : &sc->cipher_list_by_id;
    for (i = 0; i < 3; i++) {
        old[i] = *stacks[i];
        if (old[i] != NULL && !TEST_ptr(saved[i] = sk_SSL_CIPHER_dup(old[i])))
            goto end;
    }
    if (!TEST_ptr(context_list = sk_SSL_CIPHER_dup(ctx->cipher_list))
        || !TEST_ptr(context_by_id = sk_SSL_CIPHER_dup(ctx->cipher_list_by_id)))
        goto end;

    MFAIL_start();
    set_ok = role == 2
        ? SSL_CTX_set_ciphersuites(ctx, TLS_TEST_SHA384_NAME ":" TLS_TEST_SHA256_NAME)
        : SSL_set_ciphersuites(ssl, TLS_TEST_SHA384_NAME ":" TLS_TEST_SHA256_NAME);
    MFAIL_end();

    if (set_ok) {
        active = *stacks[1];
        by_id = *stacks[2];
        if (!TEST_int_eq(sk_SSL_CIPHER_num(*stacks[0]), 2)
            || !TEST_int_ge(sk_SSL_CIPHER_num(active), 2)
            || !TEST_int_eq(sk_SSL_CIPHER_num(active), sk_SSL_CIPHER_num(by_id))
            || !TEST_str_eq(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(active, 0)),
                TLS_TEST_SHA384_NAME)
            || !TEST_str_eq(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(active, 1)),
                TLS_TEST_SHA256_NAME))
            goto end;
        for (i = 0; i < 2; i++)
            if (!TEST_ptr_eq(sk_SSL_CIPHER_value(active, i),
                    sk_SSL_CIPHER_value(*stacks[0], i)))
                goto end;
        for (i = 0; i < sk_SSL_CIPHER_num(active); i++) {
            cipher = sk_SSL_CIPHER_value(active, i);
            pos = sk_SSL_CIPHER_find(by_id, cipher);
            if (!TEST_int_ge(pos, 0)
                || !TEST_ptr_eq(sk_SSL_CIPHER_value(by_id, pos), cipher))
                goto end;
        }
        /* Updating TLS 1.3 must preserve every legacy entry and its order. */
        j = 2;
        for (i = 0; i < sk_SSL_CIPHER_num(context_list); i++) {
            cipher = sk_SSL_CIPHER_value(context_list, i);
            if (cipher->min_tls != TLS1_3_VERSION
                && !TEST_ptr_eq(sk_SSL_CIPHER_value(active, j++), cipher))
                goto end;
        }
        if (!TEST_int_eq(sk_SSL_CIPHER_num(active), j))
            goto end;
    } else {
        for (i = 0; i < 3; i++)
            if (!TEST_ptr_eq(*stacks[i], old[i])
                || !cipher_stacks_equal(*stacks[i], saved[i]))
                goto end;
    }
    if (role != 2
        && (!cipher_stacks_equal(ctx->cipher_list, context_list)
            || !cipher_stacks_equal(ctx->cipher_list_by_id, context_by_id)))
        goto end;

    ret = 1;
end:
    for (i = 0; i < 3; i++)
        sk_SSL_CIPHER_free(saved[i]);
    sk_SSL_CIPHER_free(context_list);
    sk_SSL_CIPHER_free(context_by_id);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_hrr(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *cipher;
    int server_hellos = 0, ret = 0;

#if defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH)
    return TEST_skip("EC and DH are disabled");
#endif /* defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH) */

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
#if !defined(OPENSSL_NO_EC)
        /* Group lists from tls13groupselection_test. */
        || !TEST_true(SSL_CTX_set1_groups_list(cctx,
            "secp521r1:secp384r1:prime256v1"))
        || !TEST_true(SSL_CTX_set1_groups_list(sctx,
            "prime256v1:secp384r1"))
#else
        || !TEST_true(SSL_CTX_set1_groups_list(cctx,
            "ffdhe2048:ffdhe3072"))
        || !TEST_true(SSL_CTX_set1_groups_list(sctx, "ffdhe3072"))
#endif /* !defined(OPENSSL_NO_EC) */
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_set_msg_callback_arg(clientssl, &server_hellos);
    SSL_set_msg_callback(clientssl, count_server_hellos_cb);
    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_int_eq(server_hellos, 2)
        || !TEST_ptr(cipher = SSL_get_current_cipher(clientssl))
        || !TEST_int_eq(cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

/*
 * idx 0: the callback sets per-SSL ciphersuites and cipher list and
 *        switches twice.
 * idx 1: HRR; the selected context enables the provider suite at context
 *        level and nothing is set on the SSL.
 * idx 2: the callback sets per-SSL ciphersuites and switches twice.
 * idx 3: the selected context does not enable the provider suite. TLS 1.3
 *        selects the suite before the callback; the saved selection persists.
 * The callback releases the contexts it switched to; the SSL keeps them alive.
 */
static int test_sni_context_switch(int idx)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL_CTX *selected_ctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *expected = NULL, *negotiated;
    SNI_SWITCH_DATA data = { 0 };
    int ret = 0;

#if defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH)
    if (idx == 1)
        return TEST_skip("EC and DH are disabled");
#endif /* defined(OPENSSL_NO_EC) && defined(OPENSSL_NO_DH) */

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(expected = ossl_ssl_get0_provider_cipher_by_id(sctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xffa0U)))
        goto end;

    if (idx == 0 || idx == 2) {
        const char *target_suites = idx == 2
            ? "TLS_AES_256_GCM_SHA384"
            : TLS_TEST_SHA256_NAME;

        data.set_ciphersuites = 1;
        data.set_cipher_list = idx == 0;
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.first, NULL,
                cert, privkey))
            || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.second, NULL,
                cert, privkey))
            || !TEST_true(SSL_CTX_set_ciphersuites(
                data.first, target_suites))
            || !TEST_true(SSL_CTX_set_ciphersuites(
                data.second, target_suites)))
            goto end;
    } else if (idx == 1) {
        data.keep_contexts = 1;
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.first, NULL,
                cert, privkey))
            || !TEST_true(SSL_CTX_set_ciphersuites(data.first,
                TLS_TEST_SHA256_NAME)))
            goto end;
        /* Trigger HRR after the context switch. */
#if !defined(OPENSSL_NO_EC)
        if (!TEST_true(SSL_CTX_set1_groups_list(cctx,
                "secp521r1:secp384r1:prime256v1"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx,
                "prime256v1:secp384r1")))
            goto end;
#else
        if (!TEST_true(SSL_CTX_set1_groups_list(cctx, "ffdhe2048:ffdhe3072"))
            || !TEST_true(SSL_CTX_set1_groups_list(sctx, "ffdhe3072")))
            goto end;
#endif /* !defined(OPENSSL_NO_EC) */
    } else {
        if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
                TLS1_3_VERSION, TLS1_3_VERSION, &data.first, NULL,
                cert, privkey))
            || !TEST_true(SSL_CTX_set_ciphersuites(
                data.first, "TLS_AES_256_GCM_SHA384")))
            goto end;
    }
    selected_ctx = data.first;

    if (!TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx,
            sni_switch_cb))
        || !TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, &data))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_tlsext_host_name(clientssl,
            "provider.example")))
        goto end;

    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_int_eq(data.calls, idx == 1 ? 2 : 1)
        || !TEST_ptr(negotiated = SSL_get_current_cipher(serverssl))
        || !TEST_ptr_eq(negotiated, expected))
        goto end;
    if ((idx == 1 || idx == 3)
        && !TEST_ptr_eq(SSL_get_SSL_CTX(serverssl), selected_ctx))
        goto end;
    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(data.first);
    SSL_CTX_free(data.second);
    ERR_clear_error();
    return ret;
}

static const SSL_CIPHER *find_provider_cipher(STACK_OF(SSL_CIPHER) *sk)
{
    int i;

    for (i = 0; i < sk_SSL_CIPHER_num(sk); i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(sk, i);

        if (cipher->origin == SSL_CIPHER_ORIGIN_PROVIDER)
            return cipher;
    }
    return NULL;
}

/*
 * An SSL without its own cipher list follows the list of its current
 * SSL_CTX across SSL_set_SSL_CTX(); a list set on the SSL persists and holds
 * canonical descriptors.
 */
static int test_switched_context_supported_ciphers(void)
{
    SSL_CTX *initial = NULL, *alternate = NULL;
    SSL *ssl = NULL;
    STACK_OF(SSL_CIPHER) *supported = NULL, *borrowed;
    const SSL_CIPHER *canonical, *listed;
    int ret = 0;

    if (!TEST_ptr(initial = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(initial,
            TLS_TEST_SHA256_NAME))
        || !TEST_ptr(canonical = ossl_ssl_get0_provider_cipher_by_name(initial,
                         TLS_TEST_SHA256_NAME))
        || !TEST_ptr(ssl = SSL_new(initial))
        || !TEST_ptr(alternate = SSL_CTX_new_ex(libctx, "provider=default",
                         TLS_method())))
        goto end;

    /* Without a per-SSL list the SSL borrows the list of its context. */
    if (!TEST_ptr(borrowed = SSL_get_ciphers(ssl))
        || !TEST_ptr_eq(borrowed, SSL_CTX_get_ciphers(initial))
        || !TEST_ptr_eq(find_provider_cipher(borrowed), canonical))
        goto end;

    /* After a switch the SSL follows the list of the new context. */
    if (!TEST_ptr(SSL_set_SSL_CTX(ssl, alternate))
        || !TEST_ptr_eq(SSL_get_ciphers(ssl), SSL_CTX_get_ciphers(alternate))
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(ssl))
        || !TEST_ptr_null(find_provider_cipher(supported)))
        goto end;
    sk_SSL_CIPHER_free(supported);
    supported = NULL;

    /*
     * Switching back restores the original view. The borrowed stack stayed
     * valid because session_ctx keeps the initial context alive.
     */
    SSL_CTX_free(alternate);
    alternate = NULL;
    if (!TEST_ptr(SSL_set_SSL_CTX(ssl, NULL))
        || !TEST_ptr_eq(SSL_get_ciphers(ssl), borrowed)
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(ssl))
        || !TEST_ptr(listed = find_provider_cipher(supported))
        || !TEST_ptr_eq(listed, canonical)
        || !TEST_str_eq(SSL_CIPHER_get_name(listed), TLS_TEST_SHA256_NAME))
        goto end;
    sk_SSL_CIPHER_free(supported);
    supported = NULL;

    /* A list set on the SSL persists across a switch and is canonical. */
    if (!TEST_ptr(alternate = SSL_CTX_new_ex(libctx, "provider=default",
                      TLS_method()))
        || !TEST_true(SSL_set_ciphersuites(ssl, TLS_TEST_SHA256_NAME))
        || !TEST_ptr_ne(SSL_get_ciphers(ssl), borrowed)
        || !TEST_ptr(SSL_set_SSL_CTX(ssl, alternate))
        || !TEST_ptr_ne(SSL_get_ciphers(ssl), SSL_CTX_get_ciphers(alternate))
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(ssl))
        || !TEST_ptr_eq(find_provider_cipher(supported), canonical))
        goto end;

    ret = 1;
end:
    sk_SSL_CIPHER_free(supported);
    SSL_free(ssl);
    SSL_CTX_free(initial);
    SSL_CTX_free(alternate);
    ERR_clear_error();
    return ret;
}

/* The legacy setter and SSL_dup retain saved TLS 1.3 entries for both origins. */
static int test_context_switch_saved_tls13_list(int idx)
{
    const char *saved_name = idx == 0 ? "TLS_AES_128_GCM_SHA256"
                                      : TLS_TEST_SHA256_NAME;
    const char *target_name = idx == 0 ? "TLS_AES_256_GCM_SHA384"
                                       : TLS_TEST_SHA384_NAME;
    SSL_CTX *initial = NULL, *alternate = NULL;
    SSL *ssl = NULL, *duplicate = NULL;
    SSL_CONNECTION *sc;
    STACK_OF(SSL_CIPHER) *supported = NULL;
    int ret = 0;

    if (!TEST_ptr(initial = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(alternate = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_true(SSL_CTX_set_ciphersuites(initial, saved_name))
        || !TEST_true(SSL_CTX_set_ciphersuites(alternate, target_name))
        || !TEST_ptr(ssl = SSL_new(initial))
        || !TEST_ptr(SSL_set_SSL_CTX(ssl, alternate))
        || !TEST_ptr_eq(SSL_get_ciphers(ssl), SSL_CTX_get_ciphers(alternate))
        || !TEST_true(SSL_set_cipher_list(ssl, "DEFAULT"))
        || !TEST_str_eq(SSL_CIPHER_get_name(
                            sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), 0)),
            saved_name)
        || !TEST_ptr(duplicate = SSL_dup(ssl))
        || !TEST_ptr_ne(duplicate, ssl)
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(duplicate))
        || !TEST_int_eq(sk_SSL_CIPHER_num(sc->tls13_ciphersuites), 1)
        || !TEST_str_eq(SSL_CIPHER_get_name(
                            sk_SSL_CIPHER_value(sc->tls13_ciphersuites, 0)),
            saved_name)
        || !TEST_true(SSL_set_ciphersuites(ssl, target_name))
        || !TEST_str_eq(SSL_CIPHER_get_name(
                            sk_SSL_CIPHER_value(SSL_get_ciphers(ssl), 0)),
            target_name)
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(duplicate))
        || !TEST_str_eq(SSL_CIPHER_get_name(
                            sk_SSL_CIPHER_value(supported, 0)),
            saved_name))
        goto end;

    ret = 1;
end:
    sk_SSL_CIPHER_free(supported);
    SSL_free(duplicate);
    SSL_free(ssl);
    SSL_CTX_free(initial);
    SSL_CTX_free(alternate);
    ERR_clear_error();
    return ret;
}

#if !defined(OPENSSL_NO_TLS1_2)
static int sni_policy_cb(SSL *ssl, int *alert, void *arg)
{
    if (SSL_set_SSL_CTX(ssl, arg) == NULL) {
        *alert = SSL_AD_INTERNAL_ERROR;
        return SSL_TLSEXT_ERR_ALERT_FATAL;
    }
    return SSL_TLSEXT_ERR_OK;
}
#endif /* !defined(OPENSSL_NO_TLS1_2) */

/*
 * The cipher list of an SSL_CTX selected by the servername callback applies
 * to a TLS 1.2 handshake when nothing is set on the SSL, without any provider
 * suite involved.
 * idx 0: the selected context permits the client's only cipher.
 * idx 1: the selected context does not; the handshake must fail.
 */
static int test_sni_switch_cipher_list_policy(int idx)
{
#if defined(OPENSSL_NO_TLS1_2)
    return TEST_skip("TLS 1.2 is disabled");
#else
    SSL_CTX *sctx = NULL, *cctx = NULL, *target = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *negotiated;
    const char *policy = idx == 0 ? "ALL:@SECLEVEL=0"
                                  : "AES256-SHA:@SECLEVEL=0";
    int ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_2_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_cipher_list(sctx, "ALL:@SECLEVEL=0"))
        || !TEST_true(SSL_CTX_set_cipher_list(cctx,
            "AES128-SHA:@SECLEVEL=0"))
        || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(), NULL,
            TLS1_2_VERSION, TLS1_2_VERSION, &target, NULL, cert, privkey))
        || !TEST_true(SSL_CTX_set_cipher_list(target, policy))
        || !TEST_true(SSL_CTX_set_tlsext_servername_callback(sctx,
            sni_policy_cb))
        || !TEST_true(SSL_CTX_set_tlsext_servername_arg(sctx, target))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_tlsext_host_name(clientssl, "policy.example")))
        goto end;

    if (idx == 0) {
        if (!TEST_true(create_ssl_connection(serverssl, clientssl,
                SSL_ERROR_NONE))
            || !TEST_ptr_eq(SSL_get_SSL_CTX(serverssl), target)
            || !TEST_ptr_eq(SSL_get_ciphers(serverssl),
                SSL_CTX_get_ciphers(target))
            || !TEST_ptr(negotiated = SSL_get_current_cipher(serverssl))
            || !TEST_str_eq(SSL_CIPHER_get_name(negotiated), "AES128-SHA"))
            goto end;
    } else {
        if (!TEST_true(expect_no_shared_cipher(serverssl, clientssl))
            || !TEST_ptr_eq(SSL_get_SSL_CTX(serverssl), target)
            || !TEST_ptr_eq(SSL_get_ciphers(serverssl),
                SSL_CTX_get_ciphers(target)))
            goto end;
    }

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(target);
    ERR_clear_error();
    return ret;
#endif /* defined(OPENSSL_NO_TLS1_2) */
}

static int test_post_handshake_context_switch(void)
{
    static const unsigned char message[] = "post-handshake context switch";
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL, *alternate = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME)))
        goto end;
    if (!TEST_ptr(alternate = SSL_CTX_new_ex(libctx, "provider=default",
                      TLS_client_method())))
        goto end;

    if (!TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr_eq(SSL_set_SSL_CTX(clientssl, alternate), alternate)
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    SSL_CTX_free(alternate);
    ERR_clear_error();
    return ret;
}

/* Also runs with no-cached-fetch, where equal EVP methods have distinct pointers. */
static int test_provider_descriptor_equivalence(void)
{
    SSL_CTX *ctx = NULL, *other = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *canonical, *equivalent, *different;
    SSL_CIPHER probe;
    int i, ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(other = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl))
        || !TEST_ptr(canonical = ossl_ssl_get0_provider_cipher_by_name(ctx,
                         TLS_TEST_SHA384_NAME))
        || !TEST_ptr(equivalent = ossl_ssl_get0_provider_cipher_by_name(other,
                         TLS_TEST_SHA384_NAME))
        || !TEST_ptr(different = ossl_ssl_get0_provider_cipher_by_name(other,
                         TLS_TEST_SHA256_NAME))
        || !TEST_ptr_ne(canonical, equivalent)
        || !TEST_ptr_eq(ossl_ssl_get0_cipher_canon(sc, equivalent), canonical))
        goto end;

    for (i = 0; i < 5; i++) {
        /* Borrow the fields for comparison; the probe owns no references. */
        probe = *equivalent;
        if (i == 0)
            probe.id ^= 1U;
        else if (i == 1)
            probe.name = "TLS_TEST_DIFFERENT_NAME";
        else if (i == 2)
            probe.strength_bits = 128;
        else if (i == 3)
            probe.provider_cipher = different->provider_cipher;
        else
            probe.provider_digest = different->provider_digest;
        if (!TEST_ptr_null(ossl_ssl_get0_cipher_canon(sc, &probe)))
            goto end;
    }

    ret = 1;
end:
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    SSL_CTX_free(other);
    ERR_clear_error();
    return ret;
}

static int test_ssl_dup_canonicalisation(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *original = NULL, *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *canonical, *negotiated;
    int idx, ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(canonical = ossl_ssl_get0_provider_cipher_by_id(sctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xffa0U))
        || !TEST_ptr(original = SSL_new(sctx))
        || !TEST_true(SSL_set_ciphersuites(original, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(serverssl = SSL_dup(original))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(serverssl))
        || !TEST_int_ge(idx = ossl_ssl_cipher_stack_find(sc->tls13_ciphersuites,
                            canonical),
            0)
        || !TEST_ptr_eq(sk_SSL_CIPHER_value(sc->tls13_ciphersuites, idx),
            canonical)
        || !TEST_true(create_ssl_objects(NULL, cctx, &serverssl, &clientssl,
            NULL, NULL)))
        goto end;

    SSL_free(original);
    original = NULL;
    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_ptr(negotiated = SSL_get_current_cipher(serverssl))
        || !TEST_ptr_eq(negotiated, canonical))
        goto end;

    ret = 1;
end:
    SSL_free(original);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_ssl_dup_rejects_foreign_ciphersuite(void)
{
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *initial = NULL, *foreign = NULL;
    SSL *ssl = NULL, *dup = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *foreign_suite;
    int ret = 0;

    if (!TEST_ptr(initial = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(ssl = SSL_new(initial))
        || !TEST_true(SSL_set_ciphersuites(ssl, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL_ONLY(ssl)))
        goto end;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-conflicting", "valid-conflicting", "?provider=tls-provider"))
        || !TEST_ptr(foreign = SSL_CTX_new_ex(localctx, NULL, TLS_method()))
        || !TEST_ptr(foreign_suite = ossl_ssl_get0_provider_cipher_by_name(foreign,
                         TLS_TEST_SHA256_NAME))
        || !TEST_ptr(sk_SSL_CIPHER_set(sc->tls13_ciphersuites, 0,
            foreign_suite))
        || !TEST_ptr_null(dup = SSL_dup(ssl)))
        goto end;

    ret = 1;
end:
    SSL_free(dup);
    SSL_free(ssl);
    SSL_CTX_free(initial);
    SSL_CTX_free(foreign);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

static int test_one_sided_offer(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    int ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx,
            "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_false(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_tls12_exclusion(void)
{
#if defined(OPENSSL_NO_TLS1_2)
    return TEST_skip("TLS 1.2 is disabled");
#else
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    const SSL_CIPHER *cipher;
    int ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_2_VERSION, TLS1_2_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(cipher = SSL_get_current_cipher(clientssl))
        || !TEST_int_ne(cipher->origin, SSL_CIPHER_ORIGIN_PROVIDER))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
#endif /* defined(OPENSSL_NO_TLS1_2) */
}

static int test_quic_exclusion(void)
{
#if !defined(OPENSSL_NO_QUIC)
    static const unsigned char wire_id[] = { 0xff, 0xa0 };
    SSL_CTX *ctx = NULL, *tlsctx = NULL;
    SSL *quic = NULL, *external = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *suite;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL,
                      OSSL_QUIC_client_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites), 0)
        || !TEST_false(SSL_CTX_set_ciphersuites(ctx, TLS_TEST_SHA256_NAME))
        || !TEST_ptr(quic = SSL_new(ctx))
        || !TEST_ptr_null(SSL_CIPHER_find(quic, wire_id))
        || !TEST_ptr(tlsctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(external = SSL_new(tlsctx))
        || !TEST_ptr(suite = ossl_ssl_get0_provider_cipher_by_id(tlsctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xffa0U))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(external)))
        goto end;
    sc->s3.flags |= TLS1_FLAGS_QUIC;
    sc->s3.tmp.min_ver = sc->s3.tmp.max_ver = TLS1_3_VERSION;
    if (!TEST_ptr_null(SSL_CIPHER_find(external, wire_id))
        || !TEST_true(ssl_cipher_disabled(sc, suite,
            SSL_SECOP_CIPHER_SUPPORTED)))
        goto end;

    ret = 1;
end:
    SSL_free(external);
    SSL_free(quic);
    SSL_CTX_free(tlsctx);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
#else
    return TEST_skip("QUIC is disabled");
#endif /* !defined(OPENSSL_NO_QUIC) */
}

static int test_dtls_exclusion(void)
{
#if !defined(OPENSSL_NO_DTLS)
    static const unsigned char wire_id[] = { 0xff, 0xa0 };
    STACK_OF(SSL_CIPHER) *supported = NULL;
    SSL_CTX *ctx = NULL, *tlsctx = NULL;
    SSL *ssl = NULL;
    SSL_CONNECTION *sc;
    const SSL_CIPHER *suite;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new_ex(libctx, NULL, DTLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(ctx->provider_ciphersuites), 0)
        || !TEST_false(cipher_stack_has_provider_suite(
            SSL_CTX_get_ciphers(ctx)))
        || !TEST_false(SSL_CTX_set_ciphersuites(ctx,
            TLS_TEST_SHA256_NAME))
        || !TEST_ptr(ssl = SSL_new(ctx))
        || !TEST_ptr(supported = SSL_get1_supported_ciphers(ssl))
        || !TEST_false(cipher_stack_has_provider_suite(supported))
        || !TEST_ptr_null(SSL_CIPHER_find(ssl, wire_id))
        || !TEST_ptr(tlsctx = SSL_CTX_new_ex(libctx, NULL, TLS_method()))
        || !TEST_ptr(suite = ossl_ssl_get0_provider_cipher_by_id(tlsctx,
                         SSL3_CK_CIPHERSUITE_FLAG | 0xffa0U))
        || !TEST_ptr(sc = SSL_CONNECTION_FROM_SSL(ssl)))
        goto end;
    SSL_SESSION_free(sc->session);
    sc->session = SSL_SESSION_new();
    sc->s3.tmp.new_cipher = suite;
    if (!TEST_ptr(sc->session) || !TEST_false(tls13_setup_key_block(sc)))
        goto end;

    ret = 1;
end:
    sk_SSL_CIPHER_free(supported);
    SSL_free(ssl);
    SSL_CTX_free(tlsctx);
    SSL_CTX_free(ctx);
    ERR_clear_error();
    return ret;
#else
    return TEST_skip("DTLS is disabled");
#endif /* !defined(OPENSSL_NO_DTLS) */
}

static int test_provider_record_tamper(void)
{
    static const unsigned char message[] = "provider record tamper";
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    BIO *filter = NULL;
    size_t written = 0, readbytes = 0;
    unsigned long error;
    int ret = 0;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_ptr(filter = BIO_new(corrupt_filter()))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, filter))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE)))
        goto end;
    filter = NULL;

    corrupt_records = 1;
    if (!TEST_true(SSL_write_ex(clientssl, message, sizeof(message), &written))
        || !TEST_size_t_eq(written, sizeof(message)))
        goto end;
    ERR_clear_error();
    if (!TEST_false(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes)))
        goto end;
    do {
        error = ERR_get_error();
        if (error == 0) {
            TEST_error("bad record MAC error not found");
            goto end;
        }
    } while (ERR_GET_REASON(error)
        != SSL_R_DECRYPTION_FAILED_OR_BAD_RECORD_MAC);
    ret = 1;

end:
    corrupt_records = 0;
    BIO_free(filter);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

static int test_provider_large_fragmented_record(void)
{
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    unsigned char *message = NULL, *received = NULL;
    size_t written = 0, readbytes = 0, total = 0, i;
    int ret = 0;

    message = OPENSSL_malloc(SSL3_RT_MAX_PLAIN_LENGTH);
    received = OPENSSL_malloc(SSL3_RT_MAX_PLAIN_LENGTH);
    if (!TEST_ptr(message) || !TEST_ptr(received))
        goto end;
    for (i = 0; i < SSL3_RT_MAX_PLAIN_LENGTH; i++)
        message[i] = (unsigned char)i;

    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(SSL_set_max_send_fragment(clientssl, 512))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_true(SSL_write_ex(clientssl, message,
            SSL3_RT_MAX_PLAIN_LENGTH, &written))
        || !TEST_size_t_eq(written, SSL3_RT_MAX_PLAIN_LENGTH))
        goto end;

    while (total < SSL3_RT_MAX_PLAIN_LENGTH) {
        if (!TEST_true(SSL_read_ex(serverssl, received + total,
                SSL3_RT_MAX_PLAIN_LENGTH - total, &readbytes))
            || !TEST_size_t_gt(readbytes, 0))
            goto end;
        total += readbytes;
    }
    if (!TEST_mem_eq(received, total, message, SSL3_RT_MAX_PLAIN_LENGTH))
        goto end;
    ret = 1;

end:
    OPENSSL_free(message);
    OPENSSL_free(received);
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    ERR_clear_error();
    return ret;
}

#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS)
static int test_provider_ciphersuite_disables_ktls(void)
{
    static const unsigned char message[] = "provider kTLS exclusion";
    unsigned char received[sizeof(message)];
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    SSL_CONNECTION *clientsc;
    size_t written = 0, readbytes = 0;
    int cfd = -1, sfd = -1, ret = 0;

    if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL)))
        goto end;
    if (!ktls_enable(cfd)) {
        ret = TEST_skip("Kernel does not support kTLS");
        goto end;
    }
    if (!TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, "TLS_AES_128_GCM_SHA256"))
        || !TEST_true(create_ssl_objects2(sctx, cctx, &serverssl, &clientssl,
            sfd, cfd))
        || !TEST_true(SSL_set_options(clientssl, SSL_OP_ENABLE_KTLS))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(clientsc = SSL_CONNECTION_FROM_SSL_ONLY(clientssl)))
        goto end;
    if (!BIO_get_ktls_send(clientsc->wbio)) {
        ret = TEST_skip("Kernel does not offload AES-128-GCM");
        goto end;
    }

    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    BIO_closesocket(sfd);
    BIO_closesocket(cfd);
    serverssl = clientssl = NULL;
    sctx = cctx = NULL;
    sfd = cfd = -1;

    if (!TEST_true(create_test_sockets(&cfd, &sfd, SOCK_STREAM, NULL))
        || !TEST_true(ktls_enable(cfd))
        || !TEST_true(create_ssl_ctx_pair(libctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects2(sctx, cctx, &serverssl, &clientssl,
            sfd, cfd))
        || !TEST_true(SSL_set_options(clientssl, SSL_OP_ENABLE_KTLS))
        || !TEST_true(create_ssl_connection(serverssl, clientssl,
            SSL_ERROR_NONE))
        || !TEST_ptr(clientsc = SSL_CONNECTION_FROM_SSL_ONLY(clientssl))
        || !TEST_int_eq(SSL_get_current_cipher(clientssl)->origin,
            SSL_CIPHER_ORIGIN_PROVIDER)
        || !TEST_false(BIO_get_ktls_send(clientsc->wbio))
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(wait_until_sock_readable(sfd))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;
    ret = 1;

end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    if (sfd != -1)
        BIO_closesocket(sfd);
    if (cfd != -1)
        BIO_closesocket(cfd);
    ERR_clear_error();
    return ret;
}
#endif /* !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS) */

static int test_provider_unload_lifetime(void)
{
    static const unsigned char message[] = "provider unloaded";
    unsigned char received[sizeof(message)];
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *sctx = NULL, *cctx = NULL;
    SSL *serverssl = NULL, *clientssl = NULL;
    size_t written = 0, readbytes = 0;
    int ret = 0;

    if (!TEST_true(tls_provider_libctx_new(&localctx, &localdef, &localtls,
            "tls-provider-unload", "valid", "?provider=tls-provider"))
        || !TEST_true(create_ssl_ctx_pair(localctx, TLS_server_method(),
            TLS_client_method(), TLS1_3_VERSION, TLS1_3_VERSION,
            &sctx, &cctx, cert, privkey))
        || !TEST_true(SSL_CTX_set_num_tickets(sctx, 0))
        || !TEST_true(SSL_CTX_set_ciphersuites(sctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(SSL_CTX_set_ciphersuites(cctx, TLS_TEST_SHA256_NAME))
        || !TEST_true(create_ssl_objects(sctx, cctx, &serverssl, &clientssl,
            NULL, NULL))
        || !TEST_true(OSSL_PROVIDER_unload(localtls)))
        goto end;
    localtls = NULL;

    SSL_CTX_free(sctx);
    sctx = NULL;
    SSL_CTX_free(cctx);
    cctx = NULL;

    if (!TEST_true(create_ssl_connection(serverssl, clientssl, SSL_ERROR_NONE))
        || !TEST_true(SSL_write_ex(clientssl, message, sizeof(message),
            &written))
        || !TEST_size_t_eq(written, sizeof(message))
        || !TEST_true(SSL_read_ex(serverssl, received, sizeof(received),
            &readbytes))
        || !TEST_size_t_eq(readbytes, sizeof(message))
        || !TEST_mem_eq(received, readbytes, message, sizeof(message)))
        goto end;

    ret = 1;
end:
    SSL_free(serverssl);
    SSL_free(clientssl);
    SSL_CTX_free(sctx);
    SSL_CTX_free(cctx);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

static int test_late_provider_load_not_discovered(void)
{
    OSSL_LIB_CTX *localctx = NULL;
    OSSL_PROVIDER *localdef = NULL, *localtls = NULL;
    SSL_CTX *before = NULL, *after = NULL;
    int ret = 0;

    if (!TEST_ptr(localctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(localctx, "tls-provider-late",
            tls_provider_init))
        || !TEST_ptr(localdef = OSSL_PROVIDER_load(localctx, "default"))
        || !TEST_ptr(before = SSL_CTX_new_ex(localctx, NULL, TLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(before->provider_ciphersuites), 0)
        || !TEST_ptr(localtls = tls_provider_load(localctx,
                         "tls-provider-late", "valid"))
        || !TEST_false(SSL_CTX_set_ciphersuites(before,
            TLS_TEST_SHA256_NAME)))
        goto end;

    ERR_clear_error();
    if (!TEST_ptr(after = SSL_CTX_new_ex(localctx, NULL, TLS_method()))
        || !TEST_int_eq(sk_SSL_CIPHER_num(after->provider_ciphersuites), 1)
        || !TEST_true(SSL_CTX_set_ciphersuites(after, TLS_TEST_SHA256_NAME)))
        goto end;

    ret = 1;
end:
    SSL_CTX_free(before);
    SSL_CTX_free(after);
    tls_provider_libctx_free(localctx, localdef, localtls);
    ERR_clear_error();
    return ret;
}

OPT_TEST_DECLARE_USAGE("certfile privkeyfile\n")

int setup_tests(void)
{
    if (!test_skip_common_options()
        || !TEST_ptr(cert = test_get_argument(0))
        || !TEST_ptr(privkey = test_get_argument(1))
        || !TEST_true(tls_provider_libctx_new(&libctx, &defprov, &tlsprov,
            "tls-provider", "valid-both", "?provider=tls-provider")))
        return 0;

    ADD_TEST(test_provider_aead_kat);
    ADD_TEST(test_oversized_aead_fixture);
    ADD_ALL_TESTS(test_ciphersuite_mode, OSSL_NELEM(ciphersuite_tests));
    ADD_TEST(test_provider_registry_indexes);
    ADD_TEST(test_provider_peer_list_deduplication);
    ADD_TEST(test_property_query_exclusion);
    ADD_TEST(test_provider_composition);
    ADD_ALL_TESTS(test_ciphersuite_setter_null, 4);
    ADD_MFAIL_SAMPLED_NO_CHECK_TEST(test_provider_discovery_mfail, 64);
    ADD_MFAIL_SAMPLED_ALL_NO_CHECK_TESTS(test_ssl_ciphersuites_mfail, 6, 64);
    ADD_TEST(test_provider_hrr);
    ADD_ALL_TESTS(test_sni_context_switch, 4);
    ADD_TEST(test_switched_context_supported_ciphers);
    ADD_ALL_TESTS(test_context_switch_saved_tls13_list, 2);
    ADD_ALL_TESTS(test_sni_switch_cipher_list_policy, 2);
    ADD_TEST(test_post_handshake_context_switch);
    ADD_TEST(test_provider_descriptor_equivalence);
    ADD_TEST(test_ssl_dup_canonicalisation);
    ADD_TEST(test_ssl_dup_rejects_foreign_ciphersuite);
    ADD_TEST(test_one_sided_offer);
    ADD_TEST(test_tls12_exclusion);
    ADD_TEST(test_quic_exclusion);
    ADD_TEST(test_dtls_exclusion);
    ADD_TEST(test_provider_record_tamper);
    ADD_TEST(test_provider_large_fragmented_record);
#if !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS)
    ADD_TEST(test_provider_ciphersuite_disables_ktls);
#endif /* !defined(OPENSSL_NO_SOCK) && !defined(OPENSSL_NO_KTLS) */
    ADD_TEST(test_late_provider_load_not_discovered);
    ADD_TEST(test_provider_unload_lifetime);
    return 1;
}

void cleanup_tests(void)
{
    BIO_meth_free(corrupt_filter_method);
    tls_provider_libctx_free(libctx, defprov, tlsprov);
}
