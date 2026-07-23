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

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "internal/nelem.h"
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

/*
 * CertificatePropertyList parser vectors, ported from BoringSSL's
 * CredentialCertProperties test.
 */
static const struct {
    const uint8_t *props;
    size_t props_len;
    int ok;
} cpl_tests[] = {
    /* trust_anchors and an unknown property 0xbb with 0 bytes of data. */
    { (const uint8_t *)"\x00\x0b\x00\x00\x00\x03\xba\xdb\x0b\x00\xbb\x00\x00",
        13, 1 },
    /* trust_anchors and an unknown property 0xbb with 1 byte of data. */
    { (const uint8_t *)"\x00\x0c\x00\x00\x00\x03\xba\xdb\x0b\x00\xbb\x00\x01"
                       "\xba",
        14, 1 },
    /* trust_anchors and an unknown but malformed property 0xbb, missing data. */
    { (const uint8_t *)"\x00\x09\x00\x00\x00\x03\xba\xdb\x0b\x00\xbb", 11, 0 },
    /* trust_anchors and an unknown property 0xbb with incorrect length. */
    { (const uint8_t *)"\x00\x0c\x00\x00\x00\x03\xba\xdb\x0b\x00\xbb\x00\x03"
                       "\xba",
        14, 0 },
    /* trust_anchors with 0 bytes of data. */
    { (const uint8_t *)"\x00\x04\x00\x00\x00\x00", 6, 0 },
    /* trust_anchors with extra data. */
    { (const uint8_t *)"\x00\x08\x00\x00\x00\x03\xba\xdb\x0b\xbb", 10, 0 },
    /* trust_anchors with missing data. */
    { (const uint8_t *)"\x00\x06\x00\x00\x00\x03\xba\xdb", 8, 0 },
    /* Only trust_anchors. */
    { (const uint8_t *)"\x00\x07\x00\x00\x00\x03\xba\xdb\x0b", 9, 1 },
    /* Duplicate trust_anchors. */
    { (const uint8_t *)"\x00\x0e\x00\x00\x00\x03\x11\x11\x11\x00\x00\x00\x03"
                       "\x22\x22\x22",
        16, 0 },
    /* Only unknown properties. */
    { (const uint8_t *)"\x00\x08\xaa\xaa\x00\x00\xbb\xbb\x00\x00", 10, 1 },
    /* Duplicate unknown properties. */
    { (const uint8_t *)"\x00\x08\xaa\xaa\x00\x00\xaa\xaa\x00\x00", 10, 0 },
    /* Out of order unknown properties. */
    { (const uint8_t *)"\x00\x08\xbb\xbb\x00\x00\xaa\xaa\x00\x00", 10, 0 },
    /* Empty trust_anchor_groups (should have been omitted). */
    { (const uint8_t *)"\x00\x06\x00\x01\x00\x02\x00\x00", 8, 0 },
    /* trust_anchor_groups with two patterns. */
    { (const uint8_t *)"\x00\x0d\x00\x01\x00\x09\x00\x07\x02\x11\x11\x03"
                       "\x22\x22\x22",
        15, 1 },
    /* trust_anchor_groups with an empty pattern. */
    { (const uint8_t *)"\x00\x07\x00\x01\x00\x03\x00\x01\x00", 9, 1 },
    /* A pattern overrunning the trust_anchor_groups list. */
    { (const uint8_t *)"\x00\x09\x00\x01\x00\x05\x00\x03\x05\x11\x11", 11,
        0 },
    /* Trailing data after trust_anchor_groups. */
    { (const uint8_t *)"\x00\x09\x00\x01\x00\x05\x00\x02\x01\x11\x00", 11,
        0 },
    /* trust_anchor_negotiation, which has empty data. */
    { (const uint8_t *)"\x00\x04\x00\x02\x00\x00", 6, 1 },
    /* trust_anchor_negotiation with data. */
    { (const uint8_t *)"\x00\x05\x00\x02\x00\x01\x00", 7, 0 },
};

static int test_certificate_properties(int idx)
{
    SSL_CREDENTIAL *cred;
    int ret;

    if (!TEST_ptr(cred = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509)))
        return 0;
    ret = TEST_int_eq(ossl_ssl_credential_set1_certificate_properties(cred,
                          cpl_tests[idx].props, cpl_tests[idx].props_len),
        cpl_tests[idx].ok);
    if (!cpl_tests[idx].ok)
        ERR_clear_error();
    SSL_CREDENTIAL_free(cred);
    return ret;
}

/* A minimal CertificatePropertyList carrying trust_anchor_id 32473.1. */
static const uint8_t cpl_tai[] = { 0x00, 0x08, 0x00, 0x00, 0x00, 0x04,
    0x81, 0xfd, 0x59, 0x01 };
/* A CertificatePropertyList with only an unknown property (no trust anchor). */
static const uint8_t cpl_no_tai[] = { 0x00, 0x04, 0xaa, 0xaa, 0x00, 0x00 };

/* Generate an EC P-256 key with a matching self-signed certificate. */
static int make_cert_and_key(X509 **out_cert, EVP_PKEY **out_key)
{
    EVP_PKEY *key = NULL;
    X509 *x = NULL;
    X509_NAME *name = NULL;
    int ret = 0;

    if (!TEST_ptr(key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !TEST_ptr(x = X509_new())
        || !TEST_true(X509_set_version(x, X509_VERSION_3))
        || !TEST_true(ASN1_INTEGER_set(X509_get_serialNumber(x), 1))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notBefore(x), 0))
        || !TEST_ptr(X509_gmtime_adj(X509_getm_notAfter(x), 3600))
        || !TEST_true(X509_set_pubkey(x, key))
        || !TEST_ptr(name = X509_NAME_new())
        || !TEST_true(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            (const unsigned char *)"test", -1, -1, 0))
        || !TEST_true(X509_set_subject_name(x, name))
        || !TEST_true(X509_set_issuer_name(x, name))
        || !TEST_int_gt(X509_sign(x, key, EVP_sha256()), 0))
        goto err;
    *out_cert = x;
    *out_key = key;
    x = NULL;
    key = NULL;
    ret = 1;
err:
    X509_NAME_free(name);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * Build a PEM blob in a memory BIO: a CERTIFICATE PROPERTIES block carrying
 * |props|, the certificate |x|, and, if |key| is not NULL, the private key.
 * Returns the readable BIO in *out (caller frees it).
 */
static int build_pem(const uint8_t *props, size_t props_len, X509 *x,
    EVP_PKEY *key, BIO **out)
{
    BIO *bio;

    if (!TEST_ptr(bio = BIO_new(BIO_s_mem())))
        return 0;
    if (!TEST_true(PEM_write_bio(bio, "CERTIFICATE PROPERTIES", "",
            (unsigned char *)props, (long)props_len))
        || !TEST_true(PEM_write_bio_X509(bio, x))
        || (key != NULL
            && !TEST_true(PEM_write_bio_PrivateKey(bio, key, NULL, NULL, 0,
                NULL, NULL)))) {
        BIO_free(bio);
        return 0;
    }
    *out = bio;
    return 1;
}

/* Parse a single chain whose key follows it in the PEM. */
static int test_parse_bundled_key(void)
{
    X509 *x = NULL;
    EVP_PKEY *key = NULL;
    BIO *pem = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    SSL_CREDENTIAL *cred;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &key)
        || !build_pem(cpl_tai, sizeof(cpl_tai), x, key, &pem)
        || !TEST_ptr(out = sk_SSL_CREDENTIAL_new_null()))
        goto err;

    if (!TEST_true(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 1))
        goto err;
    cred = sk_SSL_CREDENTIAL_value(out, 0);
    if (!TEST_mem_eq(cred->trust_anchor_id, cred->trust_anchor_id_len,
            cpl_tai + 6, 4)
        || !TEST_ptr(cred->pkey))
        goto err;
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    BIO_free(pem);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/* Parse a chain whose key is resolved from the key bag by leaf SPKI. */
static int test_parse_separate_key(void)
{
    X509 *x = NULL;
    EVP_PKEY *key = NULL;
    BIO *pem = NULL;
    STACK_OF(EVP_PKEY) *keys = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &key)
        || !build_pem(cpl_tai, sizeof(cpl_tai), x, NULL, &pem)
        || !TEST_ptr(keys = sk_EVP_PKEY_new_null())
        || !TEST_true(sk_EVP_PKEY_push(keys, key) > 0))
        goto err;

    if (!TEST_true(SSL_parse_certificates_with_properties(pem, keys,
            out = sk_SSL_CREDENTIAL_new_null()))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 1))
        goto err;
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    sk_EVP_PKEY_free(keys);
    BIO_free(pem);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/*
 * A property list with no trust anchor ID still parses: matchability is a
 * serving-layer concern, not the parser's.
 */
static int test_parse_no_trust_anchor(void)
{
    X509 *x = NULL;
    EVP_PKEY *key = NULL;
    BIO *pem = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    SSL_CREDENTIAL *cred;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &key)
        || !build_pem(cpl_no_tai, sizeof(cpl_no_tai), x, key, &pem)
        || !TEST_ptr(out = sk_SSL_CREDENTIAL_new_null()))
        goto err;

    if (!TEST_true(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 1))
        goto err;
    cred = sk_SSL_CREDENTIAL_value(out, 0);
    if (!TEST_ptr_null(cred->trust_anchor_id))
        goto err;
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    BIO_free(pem);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/* A chain with no matching key fails the whole blob (all-or-nothing). */
static int test_parse_no_key(void)
{
    X509 *x = NULL;
    EVP_PKEY *key = NULL, *other = NULL;
    BIO *pem = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &key)
        || !build_pem(cpl_tai, sizeof(cpl_tai), x, NULL, &pem)
        || !TEST_ptr(out = sk_SSL_CREDENTIAL_new_null()))
        goto err;

    /* No key in the input and no key bag: unresolved, so the parse fails. */
    if (!TEST_false(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_R_NO_MATCHING_PRIVATE_KEY))
        goto err;
    ERR_clear_error();

    /* A key in the input that is not the leaf's does not match either. */
    BIO_free(pem);
    pem = NULL;
    if (!TEST_ptr(other = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256"))
        || !build_pem(cpl_tai, sizeof(cpl_tai), x, other, &pem))
        goto err;
    if (!TEST_false(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_R_NO_MATCHING_PRIVATE_KEY))
        goto err;
    ERR_clear_error();
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    BIO_free(pem);
    X509_free(x);
    EVP_PKEY_free(key);
    EVP_PKEY_free(other);
    return ret;
}

/*
 * Keys are matched to paths by the leaf's public key wherever they are in the
 * input, and blocks of other types are skipped.
 */
static int test_parse_keys_anywhere(void)
{
    X509 *x1 = NULL, *x2 = NULL;
    EVP_PKEY *k1 = NULL, *k2 = NULL;
    BIO *pem = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x1, &k1) || !make_cert_and_key(&x2, &k2)
        || !TEST_ptr(pem = BIO_new(BIO_s_mem()))
        || !TEST_ptr(out = sk_SSL_CREDENTIAL_new_null()))
        goto err;

    /* The second path's key, both paths, an unknown block, the first key. */
    if (!TEST_true(PEM_write_bio_PrivateKey(pem, k2, NULL, NULL, 0, NULL,
            NULL))
        || !TEST_true(PEM_write_bio(pem, "CERTIFICATE PROPERTIES", "",
            (unsigned char *)cpl_tai, (long)sizeof(cpl_tai)))
        || !TEST_true(PEM_write_bio_X509(pem, x1))
        || !TEST_true(PEM_write_bio(pem, "CERTIFICATE PROPERTIES", "",
            (unsigned char *)cpl_no_tai, (long)sizeof(cpl_no_tai)))
        || !TEST_true(PEM_write_bio_X509(pem, x2))
        || !TEST_true(PEM_write_bio(pem, "UNKNOWN", "",
            (unsigned char *)"\x01", 1))
        || !TEST_true(PEM_write_bio_PrivateKey(pem, k1, NULL, NULL, 0, NULL,
            NULL)))
        goto err;

    if (!TEST_true(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 2)
        || !TEST_int_eq(EVP_PKEY_eq(sk_SSL_CREDENTIAL_value(out, 0)->pkey, k1),
            1)
        || !TEST_int_eq(EVP_PKEY_eq(sk_SSL_CREDENTIAL_value(out, 1)->pkey, k2),
            1))
        goto err;
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    BIO_free(pem);
    X509_free(x1);
    X509_free(x2);
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return ret;
}

/* An encrypted private key in the input fails the parse. */
static int test_parse_encrypted_key(void)
{
    X509 *x = NULL;
    EVP_PKEY *key = NULL;
    BIO *pem = NULL;
    STACK_OF(SSL_CREDENTIAL) *out = NULL;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &key)
        || !build_pem(cpl_tai, sizeof(cpl_tai), x, NULL, &pem)
        || !TEST_true(PEM_write_bio_PrivateKey(pem, key, EVP_aes_128_cbc(),
            (const unsigned char *)"password", 8, NULL, NULL))
        || !TEST_ptr(out = sk_SSL_CREDENTIAL_new_null()))
        goto err;

    if (!TEST_false(SSL_parse_certificates_with_properties(pem, NULL, out))
        || !TEST_int_eq(sk_SSL_CREDENTIAL_num(out), 0)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_R_UNEXPECTED_PEM_BLOCK))
        goto err;
    ERR_clear_error();
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(out, SSL_CREDENTIAL_free);
    BIO_free(pem);
    X509_free(x);
    EVP_PKEY_free(key);
    return ret;
}

/* Build a credential whose chain is a single buffer of |size| bytes. */
static SSL_CREDENTIAL *make_sized_credential(size_t size)
{
    SSL_CREDENTIAL *cred = NULL, *ret = NULL;
    STACK_OF(CRYPTO_BUFFER) *chain = NULL;
    CRYPTO_BUFFER *buf = NULL;
    uint8_t *data = NULL;

    if (!TEST_ptr(data = OPENSSL_zalloc(size))
        || !TEST_ptr(cred = ossl_ssl_credential_new(SSL_CREDENTIAL_TYPE_X509))
        || !TEST_ptr(chain = sk_CRYPTO_BUFFER_new_null())
        || !TEST_ptr(buf = CRYPTO_BUFFER_new(data, size, NULL))
        || !TEST_true(sk_CRYPTO_BUFFER_push(chain, buf)))
        goto err;
    buf = NULL;
    if (!TEST_true(ossl_ssl_credential_set1_cert_chain(cred, chain)))
        goto err;
    ret = cred;
    cred = NULL;
err:
    SSL_CREDENTIAL_free(cred);
    sk_CRYPTO_BUFFER_pop_free(chain, CRYPTO_BUFFER_free);
    CRYPTO_BUFFER_free(buf);
    OPENSSL_free(data);
    return ret;
}

/* The wire-size comparator orders credentials smallest first. */
static int test_compare_size(void)
{
    STACK_OF(SSL_CREDENTIAL) *creds = NULL;
    SSL_CREDENTIAL *big = NULL, *small = NULL, *mid = NULL;
    int ret = 0;

    if (!TEST_ptr(creds = sk_SSL_CREDENTIAL_new_null())
        || !TEST_ptr(big = make_sized_credential(300))
        || !TEST_ptr(small = make_sized_credential(100))
        || !TEST_ptr(mid = make_sized_credential(200))
        || !TEST_true(sk_SSL_CREDENTIAL_push(creds, big) > 0)
        || !TEST_true(sk_SSL_CREDENTIAL_push(creds, small) > 0)
        || !TEST_true(sk_SSL_CREDENTIAL_push(creds, mid) > 0))
        goto err;

    sk_SSL_CREDENTIAL_set_cmp_func(creds, SSL_CREDENTIAL_size_cmp);
    sk_SSL_CREDENTIAL_sort(creds);

    if (!TEST_ptr_eq(sk_SSL_CREDENTIAL_value(creds, 0), small)
        || !TEST_ptr_eq(sk_SSL_CREDENTIAL_value(creds, 1), mid)
        || !TEST_ptr_eq(sk_SSL_CREDENTIAL_value(creds, 2), big))
        goto err;
    ret = 1;
err:
    sk_SSL_CREDENTIAL_pop_free(creds, SSL_CREDENTIAL_free);
    return ret;
}

/*
 * A bag of PEM private keys parses into a stack, skipping other blocks; an
 * encrypted key fails it.
 */
static int test_parse_private_keys(void)
{
    X509 *x = NULL;
    EVP_PKEY *k1 = NULL, *k2 = NULL;
    BIO *good = NULL, *mixed = NULL, *bad = NULL;
    STACK_OF(EVP_PKEY) *keys = NULL;
    int ret = 0;

#if defined(OPENSSL_NO_EC)
    return TEST_skip("EC is disabled");
#endif /* defined(OPENSSL_NO_EC) */

    if (!make_cert_and_key(&x, &k1)
        || !TEST_ptr(k2 = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")))
        goto err;

    /* Two keys parse into a stack of two. */
    if (!TEST_ptr(good = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_PrivateKey(good, k1, NULL, NULL, 0, NULL,
            NULL))
        || !TEST_true(PEM_write_bio_PrivateKey(good, k2, NULL, NULL, 0, NULL,
            NULL))
        || !TEST_ptr(keys = sk_EVP_PKEY_new_null()))
        goto err;
    if (!TEST_true(SSL_parse_private_keys(good, keys))
        || !TEST_int_eq(sk_EVP_PKEY_num(keys), 2))
        goto err;

    /* A certificate among the keys is skipped. */
    if (!TEST_ptr(mixed = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_X509(mixed, x))
        || !TEST_true(PEM_write_bio_PrivateKey(mixed, k1, NULL, NULL, 0, NULL,
            NULL)))
        goto err;
    if (!TEST_true(SSL_parse_private_keys(mixed, keys))
        || !TEST_int_eq(sk_EVP_PKEY_num(keys), 3))
        goto err;

    /* An encrypted key fails the whole bag, leaving the stack unchanged. */
    if (!TEST_ptr(bad = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_PrivateKey(bad, k1, NULL, NULL, 0, NULL,
            NULL))
        || !TEST_true(PEM_write_bio_PrivateKey(bad, k2, EVP_aes_128_cbc(),
            (const unsigned char *)"password", 8, NULL, NULL)))
        goto err;
    if (!TEST_false(SSL_parse_private_keys(bad, keys))
        || !TEST_int_eq(sk_EVP_PKEY_num(keys), 3)
        || !TEST_int_eq(ERR_GET_REASON(ERR_peek_last_error()),
            SSL_R_UNEXPECTED_PEM_BLOCK))
        goto err;
    ERR_clear_error();
    ret = 1;
err:
    sk_EVP_PKEY_pop_free(keys, EVP_PKEY_free);
    BIO_free(good);
    BIO_free(mixed);
    BIO_free(bad);
    X509_free(x);
    EVP_PKEY_free(k1);
    EVP_PKEY_free(k2);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_credential_object);
    ADD_TEST(test_ctx_credentials);
    ADD_ALL_TESTS(test_certificate_properties, OSSL_NELEM(cpl_tests));
    ADD_TEST(test_parse_bundled_key);
    ADD_TEST(test_parse_separate_key);
    ADD_TEST(test_parse_no_trust_anchor);
    ADD_TEST(test_parse_no_key);
    ADD_TEST(test_parse_keys_anywhere);
    ADD_TEST(test_parse_encrypted_key);
    ADD_TEST(test_compare_size);
    ADD_TEST(test_parse_private_keys);
    return 1;
}
