/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Internal tests for the SSL_CREDENTIAL object and its CERT plumbing */

#include <string.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>

#include "internal/pool.h"
#include "../ssl/ssl_local.h"
#include "testutil.h"

/* 32473.1 as TrustAnchorID relative-OID bytes */
static const uint8_t tai_id[] = { 0x81, 0xfd, 0x59, 0x01 };
/* 32473.2 as TrustAnchorID relative-OID bytes */
static const uint8_t tai_other[] = { 0x81, 0xfd, 0x59, 0x02 };
/* The trust anchor ID pattern 32473.2.{0-} */
static const uint8_t tai_group[] = { 0x81, 0xfd, 0x59, 0x81, 0xfd, 0x59, 0x02,
    0x02, 0x00, 0x80 };

static const uint8_t cert_der1[] = { 0x30, 0x03, 0x02, 0x01, 0x01 };
static const uint8_t cert_der2[] = { 0x30, 0x03, 0x02, 0x01, 0x02 };

/**
 * @brief Build a populated SSL_CREDENTIAL of type X509 from the fixtures
 * above.
 *
 * @return the credential, or NULL on failure
 */
static SSL_CREDENTIAL *make_credential(void)
{
    SSL_CREDENTIAL *cred = NULL, *ret = NULL;
    STACK_OF(CRYPTO_BUFFER) *chain = NULL;
    CRYPTO_BUFFER *buf = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(cred = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509)))
        goto err;

    if (!TEST_ptr(chain = sk_CRYPTO_BUFFER_new_null()))
        goto err;
    if (!TEST_ptr(buf = CRYPTO_BUFFER_new(cert_der1, sizeof(cert_der1), NULL))
        || !TEST_true(sk_CRYPTO_BUFFER_push(chain, buf)))
        goto err;
    buf = NULL;
    if (!TEST_ptr(buf = CRYPTO_BUFFER_new(cert_der2, sizeof(cert_der2), NULL))
        || !TEST_true(sk_CRYPTO_BUFFER_push(chain, buf)))
        goto err;
    buf = NULL;
    if (!TEST_true(ossl_ssl_credential_set1_cert_chain(cred, chain)))
        goto err;

    if (!TEST_ptr(pkey = EVP_PKEY_new())
        || !TEST_true(ossl_ssl_credential_set1_private_key(cred, pkey)))
        goto err;

    if (!TEST_true(ossl_ssl_credential_set1_trust_anchor_id(cred, tai_id,
            sizeof(tai_id))))
        goto err;

    if (!TEST_true(ossl_ssl_credential_add1_trust_anchor_group(cred, tai_group,
            sizeof(tai_group))))
        goto err;

    ret = cred;
    cred = NULL;

err:
    SSL_CREDENTIAL_free(cred);
    sk_CRYPTO_BUFFER_pop_free(chain, CRYPTO_BUFFER_free);
    CRYPTO_BUFFER_free(buf);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_credential_object(void)
{
    SSL_CREDENTIAL *cred;
    int ret = 0;

    if (!TEST_ptr(cred = make_credential()))
        return 0;

    if (!TEST_int_eq(cred->type, SSL_CREDENTIAL_TYPE_X509)
        || !TEST_int_eq(sk_CRYPTO_BUFFER_num(cred->chain), 2)
        || !TEST_ptr(cred->pkey)
        || !TEST_mem_eq(cred->trust_anchor_id, cred->trust_anchor_id_len,
            tai_id, sizeof(tai_id))
        || !TEST_size_t_eq(cred->group_count, 1)
        || !TEST_mem_eq(cred->groups[0].pattern, cred->groups[0].pattern_len,
            tai_group, sizeof(tai_group)))
        goto err;

    /* The chain buffers are shared with the credential's copy. */
    if (!TEST_mem_eq(CRYPTO_BUFFER_data(sk_CRYPTO_BUFFER_value(cred->chain, 0)),
            CRYPTO_BUFFER_len(sk_CRYPTO_BUFFER_value(cred->chain, 0)),
            cert_der1, sizeof(cert_der1)))
        goto err;

    /* Setters replace previous values. */
    if (!TEST_true(ossl_ssl_credential_set1_trust_anchor_id(cred, tai_other,
            sizeof(tai_other)))
        || !TEST_mem_eq(cred->trust_anchor_id, cred->trust_anchor_id_len,
            tai_other, sizeof(tai_other)))
        goto err;

    /* An extra reference keeps the credential alive over a free. */
    if (!TEST_true(SSL_CREDENTIAL_up_ref(cred)))
        goto err;
    SSL_CREDENTIAL_free(cred);
    if (!TEST_int_eq(sk_CRYPTO_BUFFER_num(cred->chain), 2))
        goto err;

    ret = 1;
err:
    SSL_CREDENTIAL_free(cred);
    return ret;
}

static int test_ctx_credentials(void)
{
    SSL_CTX *ctx = NULL;
    SSL_CREDENTIAL *cred1 = NULL, *cred2 = NULL;
    CERT *dup = NULL;
    int ret = 0;

    if (!TEST_ptr(ctx = SSL_CTX_new(TLS_server_method()))
        || !TEST_ptr(cred1 = make_credential())
        || !TEST_ptr(cred2 = make_credential()))
        goto err;

    /* NULL arguments are rejected. */
    if (!TEST_false(SSL_CTX_add1_credential(NULL, cred1))
        || !TEST_false(SSL_CTX_add1_credential(ctx, NULL)))
        goto err;

    /* Credentials are appended in preference order. */
    if (!TEST_true(SSL_CTX_add1_credential(ctx, cred1))
        || !TEST_true(SSL_CTX_add1_credential(ctx, cred2))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(ctx->cert->credentials), 2)
        || !TEST_ptr_eq(sk_SSL_CREDENTIAL_value(ctx->cert->credentials, 0),
            cred1)
        || !TEST_ptr_eq(sk_SSL_CREDENTIAL_value(ctx->cert->credentials, 1),
            cred2))
        goto err;

    /* Duplicating the CERT shares the credentials by reference. */
    if (!TEST_ptr(dup = ssl_cert_dup(ctx->cert))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(dup->credentials), 2)
        || !TEST_ptr_eq(sk_SSL_CREDENTIAL_value(dup->credentials, 0), cred1))
        goto err;

    ret = 1;
err:
    ssl_cert_free(dup);
    SSL_CREDENTIAL_free(cred1);
    SSL_CREDENTIAL_free(cred2);
    SSL_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_credential_object);
    ADD_TEST(test_ctx_credentials);
    return 1;
}
