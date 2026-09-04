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
    ADD_TEST(test_property_query_exclusion);
    ADD_MFAIL_SAMPLED_NO_CHECK_TEST(test_provider_discovery_mfail, 64);
    return 1;
}

void cleanup_tests(void)
{
    tls_provider_libctx_free(libctx, defprov, tlsprov);
}
