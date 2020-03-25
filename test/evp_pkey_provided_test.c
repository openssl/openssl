/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/serializer.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include "crypto/ecx.h"
#include "internal/nelem.h"
#include "openssl/param_build.h"
#include "crypto/evp.h"          /* For the internal API */
#include "testutil.h"

static char *datadir = NULL;

#define PRIV_TEXT    0
#define PRIV_PEM     1
#define PRIV_DER     2
#define PUB_TEXT     3
#define PUB_PEM      4
#define PUB_DER      5

static void stripcr(char *buf, size_t *len)
{
    size_t i;
    char *curr, *writ;

    for (i = *len, curr = buf, writ = buf; i > 0; i--, curr++) {
        if (*curr == '\r') {
            (*len)--;
            continue;
        }
        if (curr != writ)
            *writ = *curr;
        writ++;
    }
}

static int compare_with_file(const char *alg, int type, BIO *membio)
{
    char filename[80];
    BIO *file = NULL;
    char buf[1024];
    char *memdata, *fullfile = NULL;
    const char *suffix;
    size_t readbytes;
    int ret = 0;
    int len;
    size_t slen;

    switch (type) {
    case PRIV_TEXT:
        suffix = "priv.txt";
        break;

    case PRIV_PEM:
        suffix = "priv.pem";
        break;

    case PRIV_DER:
        suffix = "priv.der";
        break;

    case PUB_TEXT:
        suffix = "pub.txt";
        break;

    case PUB_PEM:
        suffix = "pub.pem";
        break;

    case PUB_DER:
        suffix = "pub.der";
        break;

    default:
        TEST_error("Invalid file type");
        goto err;
    }

    BIO_snprintf(filename, sizeof(filename), "%s.%s", alg, suffix);
    fullfile = test_mk_file_path(datadir, filename);
    if (!TEST_ptr(fullfile))
        goto err;

    file = BIO_new_file(fullfile, "rb");
    if (!TEST_ptr(file))
        goto err;

    if (!TEST_true(BIO_read_ex(file, buf, sizeof(buf), &readbytes))
            || !TEST_true(BIO_eof(file))
            || !TEST_size_t_lt(readbytes, sizeof(buf)))
        goto err;

    len = BIO_get_mem_data(membio, &memdata);
    if (!TEST_int_gt(len, 0))
        goto err;

    slen = len;
    if (type != PRIV_DER && type != PUB_DER) {
        stripcr(memdata, &slen);
        stripcr(buf, &readbytes);
    }

    if (!TEST_mem_eq(memdata, slen, buf, readbytes))
        goto err;

    ret = 1;
 err:
    OPENSSL_free(fullfile);
    (void)BIO_reset(membio);
    BIO_free(file);
    return ret;
}

static int test_print_key_using_pem(const char *alg, const EVP_PKEY *pk)
{
    BIO *membio = BIO_new(BIO_s_mem());
    int ret = 0;

    if (!TEST_ptr(membio))
        goto err;

    if (!TEST_true(EVP_PKEY_print_private(membio, pk, 0, NULL))
        || !TEST_true(compare_with_file(alg, PRIV_TEXT, membio))
        /* Public key in PEM form */
        || !TEST_true(PEM_write_bio_PUBKEY(membio, pk))
        || !TEST_true(compare_with_file(alg, PUB_PEM, membio))
        /* Unencrypted private key in PEM form */
        || !TEST_true(PEM_write_bio_PrivateKey(membio, pk,
                                               NULL, NULL, 0, NULL, NULL))
        || !TEST_true(compare_with_file(alg, PRIV_PEM, membio))
        /* Encrypted private key in PEM form */
        || !TEST_true(PEM_write_bio_PrivateKey(bio_out, pk, EVP_aes_256_cbc(),
                                               (unsigned char *)"pass", 4,
                                               NULL, NULL)))
        goto err;

    ret = 1;
 err:
    BIO_free(membio);
    return ret;
}

static int test_print_key_type_using_serializer(const char *alg, int type,
                                                const EVP_PKEY *pk)
{
    const char *pq;
    OSSL_SERIALIZER_CTX *ctx = NULL;
    BIO *membio = BIO_new(BIO_s_mem());
    int ret = 0;

    switch (type) {
    case PRIV_TEXT:
        pq = OSSL_SERIALIZER_PrivateKey_TO_TEXT_PQ;
        break;

    case PRIV_PEM:
        pq = OSSL_SERIALIZER_PrivateKey_TO_PEM_PQ;
        break;

    case PRIV_DER:
        pq = OSSL_SERIALIZER_PrivateKey_TO_DER_PQ;
        break;

    case PUB_TEXT:
        pq = OSSL_SERIALIZER_PUBKEY_TO_TEXT_PQ;
        break;

    case PUB_PEM:
        pq = OSSL_SERIALIZER_PUBKEY_TO_PEM_PQ;
        break;

    case PUB_DER:
        pq = OSSL_SERIALIZER_PUBKEY_TO_DER_PQ;
        break;

    default:
        TEST_error("Invalid serialization type");
        goto err;
    }

    if (!TEST_ptr(membio))
        goto err;

    /* Make a context, it's valid for several prints */
    TEST_note("Setting up a OSSL_SERIALIZER context with passphrase");
    if (!TEST_ptr(ctx = OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(pk, pq))
        /* Check that this operation is supported */
        || !TEST_ptr(OSSL_SERIALIZER_CTX_get_serializer(ctx)))
        goto err;

    /* Use no cipher.  This should give us an unencrypted PEM */
    TEST_note("Testing with no encryption");
    if (!TEST_true(OSSL_SERIALIZER_to_bio(ctx, membio))
        || !TEST_true(compare_with_file(alg, type, membio)))
        goto err;

    if (type == PRIV_PEM) {
        /* Set a passphrase to be used later */
        if (!TEST_true(OSSL_SERIALIZER_CTX_set_passphrase(ctx,
                                                          (unsigned char *)"pass",
                                                          4)))
            goto err;

        /* Use a valid cipher name */
        TEST_note("Displaying PEM encrypted with AES-256-CBC");
        if (!TEST_true(OSSL_SERIALIZER_CTX_set_cipher(ctx, "AES-256-CBC", NULL))
            || !TEST_true(OSSL_SERIALIZER_to_bio(ctx, bio_out)))
            goto err;

        /* Use an invalid cipher name, which should generate no output */
        TEST_note("NOT Displaying PEM encrypted with (invalid) FOO");
        if (!TEST_false(OSSL_SERIALIZER_CTX_set_cipher(ctx, "FOO", NULL))
            || !TEST_false(OSSL_SERIALIZER_to_bio(ctx, bio_out)))
            goto err;

        /* Clear the cipher.  This should give us an unencrypted PEM again */
        TEST_note("Testing with encryption cleared (no encryption)");
        if (!TEST_true(OSSL_SERIALIZER_CTX_set_cipher(ctx, NULL, NULL))
            || !TEST_true(OSSL_SERIALIZER_to_bio(ctx, membio))
            || !TEST_true(compare_with_file(alg, type, membio)))
            goto err;
    }
    ret = 1;
err:
    BIO_free(membio);
    OSSL_SERIALIZER_CTX_free(ctx);
    return ret;
}

static int test_print_key_using_serializer(const char *alg, const EVP_PKEY *pk)
{
    int i;
    int ret = 1;

    for (i = 0; i < 6; i++)
        ret = ret && test_print_key_type_using_serializer(alg, i, pk);

    return ret;
}

/* Array indexes used in test_fromdata_rsa */
#define N       0
#define E       1
#define D       2
#define P       3
#define Q       4
#define DP      5
#define DQ      6
#define QINV    7

static int test_fromdata_rsa(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL;
    /*
     * 32-bit RSA key, extracted from this command,
     * executed with OpenSSL 1.0.2:
     *
     * openssl genrsa 32 | openssl rsa -text
     */
    static unsigned long key_numbers[] = {
        0xbc747fc5,              /* N */
        0x10001,                 /* E */
        0x7b133399,              /* D */
        0xe963,                  /* P */
        0xceb7,                  /* Q */
        0x8599,                  /* DP */
        0xbd87,                  /* DQ */
        0xcc3b,                  /* QINV */
    };
    OSSL_PARAM fromdata_params[] = {
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_N, &key_numbers[N]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_E, &key_numbers[E]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_D, &key_numbers[D]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR, &key_numbers[P]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_FACTOR, &key_numbers[Q]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT, &key_numbers[DP]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_EXPONENT, &key_numbers[DQ]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_RSA_COEFFICIENT, &key_numbers[QINV]),
        OSSL_PARAM_END
    };

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_key_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pk, fromdata_params))
        || !TEST_int_eq(EVP_PKEY_bits(pk), 32)
        || !TEST_int_eq(EVP_PKEY_security_bits(pk), 8)
        || !TEST_int_eq(EVP_PKEY_size(pk), 4))
        goto err;

    if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
        goto err;

    if (!TEST_true(EVP_PKEY_check(key_ctx))
        || !TEST_true(EVP_PKEY_public_check(key_ctx))
        || !TEST_true(EVP_PKEY_private_check(key_ctx))
        || !TEST_true(EVP_PKEY_pairwise_check(key_ctx)))
        goto err;

    /* EVP_PKEY_copy_parameters() should fail for RSA */
    if (!TEST_ptr(copy_pk = EVP_PKEY_new())
        || !TEST_false(EVP_PKEY_copy_parameters(copy_pk, pk)))
        goto err;

    ret = test_print_key_using_pem("RSA", pk)
          && test_print_key_using_serializer("RSA", pk);

 err:
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(key_ctx);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

#ifndef OPENSSL_NO_DH
/* Array indexes used in test_fromdata_dh */
#define PRIV_KEY        0
#define PUB_KEY         1
#define FFC_P           2
#define FFC_G           3

static int test_fromdata_dh(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL, *key_ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL;
    /*
     * 32-bit DH key, extracted from this command,
     * executed with OpenSSL 1.0.2:
     *
     * openssl dhparam -out dhp.pem 32
     * openssl genpkey -paramfile dhp.pem | openssl pkey -text
     */
    static unsigned long key_numbers[] = {
        0x666c2b06,              /* priv-key */
        0x6fa6de50,              /* pub-key */
        0x8bb45f53,              /* P */
        0x2,                     /* G */
    };
    OSSL_PARAM fromdata_params[] = {
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_PRIV_KEY, &key_numbers[PRIV_KEY]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_PUB_KEY, &key_numbers[PUB_KEY]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_FFC_P, &key_numbers[FFC_P]),
        OSSL_PARAM_ulong(OSSL_PKEY_PARAM_FFC_G, &key_numbers[FFC_G]),
        OSSL_PARAM_END
    };

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL)))
        goto err;

    if (!TEST_true(EVP_PKEY_key_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pk, fromdata_params))
        || !TEST_int_eq(EVP_PKEY_bits(pk), 32)
        || !TEST_int_eq(EVP_PKEY_security_bits(pk), 0) /* Missing Q */
        || !TEST_int_eq(EVP_PKEY_size(pk), 4))
        goto err;

    if (!TEST_ptr(copy_pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
        goto err;

    ret = test_print_key_using_pem("DH", pk)
          && test_print_key_using_serializer("DH", pk);

    if (!TEST_ptr(key_ctx = EVP_PKEY_CTX_new_from_pkey(NULL, pk, "")))
        goto err;

    if (!TEST_false(EVP_PKEY_check(key_ctx))
        || !TEST_true(EVP_PKEY_public_check(key_ctx))
        || !TEST_false(EVP_PKEY_private_check(key_ctx)) /* Need a q */
        || !TEST_true(EVP_PKEY_pairwise_check(key_ctx)))
        goto err;

 err:
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_CTX_free(key_ctx);

    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
/* Array indexes used in test_fromdata_ecx */
# define PRIV_KEY        0
# define PUB_KEY         1

# define X25519_IDX      0
# define X448_IDX        1
# define ED25519_IDX     2
# define ED448_IDX       3

static int test_fromdata_ecx(int tst)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL;
    const char *alg = NULL;

    /* ED448_KEYLEN > X448_KEYLEN > X25519_KEYLEN == ED25519_KEYLEN */
    static unsigned char key_numbers[4][2][ED448_KEYLEN] = {
        /* X25519: Keys from RFC 7748 6.1 */
        {
            /* Private Key */
            {
                0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16,
                0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87,
                0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9,
                0x2c, 0x2a
            },
            /* Public Key */
            {
                0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b,
                0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d,
                0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b,
                0x4e, 0x6a
            }
        },
        /* X448: Keys from RFC 7748 6.2 */
        {
            /* Private Key */
            {
                0x9a, 0x8f, 0x49, 0x25, 0xd1, 0x51, 0x9f, 0x57, 0x75, 0xcf,
                0x46, 0xb0, 0x4b, 0x58, 0x00, 0xd4, 0xee, 0x9e, 0xe8, 0xba,
                0xe8, 0xbc, 0x55, 0x65, 0xd4, 0x98, 0xc2, 0x8d, 0xd9, 0xc9,
                0xba, 0xf5, 0x74, 0xa9, 0x41, 0x97, 0x44, 0x89, 0x73, 0x91,
                0x00, 0x63, 0x82, 0xa6, 0xf1, 0x27, 0xab, 0x1d, 0x9a, 0xc2,
                0xd8, 0xc0, 0xa5, 0x98, 0x72, 0x6b
            },
            /* Public Key */
            {
                0x9b, 0x08, 0xf7, 0xcc, 0x31, 0xb7, 0xe3, 0xe6, 0x7d, 0x22,
                0xd5, 0xae, 0xa1, 0x21, 0x07, 0x4a, 0x27, 0x3b, 0xd2, 0xb8,
                0x3d, 0xe0, 0x9c, 0x63, 0xfa, 0xa7, 0x3d, 0x2c, 0x22, 0xc5,
                0xd9, 0xbb, 0xc8, 0x36, 0x64, 0x72, 0x41, 0xd9, 0x53, 0xd4,
                0x0c, 0x5b, 0x12, 0xda, 0x88, 0x12, 0x0d, 0x53, 0x17, 0x7f,
                0x80, 0xe5, 0x32, 0xc4, 0x1f, 0xa0
            }
        },
        /* ED25519: Keys from RFC 8032 */
        {
            /* Private Key */
            {
                0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84,
                0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69,
                0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
                0x7f, 0x60
            },
            /* Public Key */
            {
                0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b,
                0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a, 0x0e, 0xe1, 0x72, 0xf3,
                0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
                0x51, 0x1a
            }
        },
        /* ED448: Keys from RFC 8032 */
        {
            /* Private Key */
            {
                0x6c, 0x82, 0xa5, 0x62, 0xcb, 0x80, 0x8d, 0x10, 0xd6, 0x32,
                0xbe, 0x89, 0xc8, 0x51, 0x3e, 0xbf, 0x6c, 0x92, 0x9f, 0x34,
                0xdd, 0xfa, 0x8c, 0x9f, 0x63, 0xc9, 0x96, 0x0e, 0xf6, 0xe3,
                0x48, 0xa3, 0x52, 0x8c, 0x8a, 0x3f, 0xcc, 0x2f, 0x04, 0x4e,
                0x39, 0xa3, 0xfc, 0x5b, 0x94, 0x49, 0x2f, 0x8f, 0x03, 0x2e,
                0x75, 0x49, 0xa2, 0x00, 0x98, 0xf9, 0x5b
            },
            /* Public Key */
            {
                0x5f, 0xd7, 0x44, 0x9b, 0x59, 0xb4, 0x61, 0xfd, 0x2c, 0xe7,
                0x87, 0xec, 0x61, 0x6a, 0xd4, 0x6a, 0x1d, 0xa1, 0x34, 0x24,
                0x85, 0xa7, 0x0e, 0x1f, 0x8a, 0x0e, 0xa7, 0x5d, 0x80, 0xe9,
                0x67, 0x78, 0xed, 0xf1, 0x24, 0x76, 0x9b, 0x46, 0xc7, 0x06,
                0x1b, 0xd6, 0x78, 0x3d, 0xf1, 0xe5, 0x0f, 0x6c, 0xd1, 0xfa,
                0x1a, 0xbe, 0xaf, 0xe8, 0x25, 0x61, 0x80
            }
        }
    };
    OSSL_PARAM x25519_fromdata_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                key_numbers[X25519_IDX][PRIV_KEY],
                                X25519_KEYLEN),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                key_numbers[X25519_IDX][PUB_KEY],
                                X25519_KEYLEN),
        OSSL_PARAM_END
    };
    OSSL_PARAM x448_fromdata_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                key_numbers[X448_IDX][PRIV_KEY],
                                X448_KEYLEN),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                key_numbers[X448_IDX][PUB_KEY],
                                X448_KEYLEN),
        OSSL_PARAM_END
    };
    OSSL_PARAM ed25519_fromdata_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                key_numbers[ED25519_IDX][PRIV_KEY],
                                ED25519_KEYLEN),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                key_numbers[ED25519_IDX][PUB_KEY],
                                ED25519_KEYLEN),
        OSSL_PARAM_END
    };
    OSSL_PARAM ed448_fromdata_params[] = {
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PRIV_KEY,
                                key_numbers[ED448_IDX][PRIV_KEY],
                                ED448_KEYLEN),
        OSSL_PARAM_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                key_numbers[ED448_IDX][PUB_KEY],
                                ED448_KEYLEN),
        OSSL_PARAM_END
    };
    OSSL_PARAM *fromdata_params = NULL;
    int bits = 0, security_bits = 0, size = 0;

    switch (tst) {
    case X25519_IDX:
        fromdata_params = x25519_fromdata_params;
        bits = X25519_BITS;
        security_bits = X25519_SECURITY_BITS;
        size = X25519_KEYLEN;
        alg = "X25519";
        break;

    case X448_IDX:
        fromdata_params = x448_fromdata_params;
        bits = X448_BITS;
        security_bits = X448_SECURITY_BITS;
        size = X448_KEYLEN;
        alg = "X448";
        break;

    case ED25519_IDX:
        fromdata_params = ed25519_fromdata_params;
        bits = ED25519_BITS;
        security_bits = ED25519_SECURITY_BITS;
        size = ED25519_KEYLEN;
        alg = "ED25519";
        break;

    case ED448_IDX:
        fromdata_params = ed448_fromdata_params;
        bits = ED448_BITS;
        security_bits = ED448_SECURITY_BITS;
        size = ED448_KEYLEN;
        alg = "ED448";
        break;
    }

    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_PKEY_key_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pk, fromdata_params))
        || !TEST_int_eq(EVP_PKEY_bits(pk), bits)
        || !TEST_int_eq(EVP_PKEY_security_bits(pk), security_bits)
        || !TEST_int_eq(EVP_PKEY_size(pk), size))
        goto err;

    if (!TEST_ptr(copy_pk = EVP_PKEY_new())
        || !TEST_false(EVP_PKEY_copy_parameters(copy_pk, pk)))
        goto err;

    ret = test_print_key_using_pem(alg, pk)
          && test_print_key_using_serializer(alg, pk);

err:
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

static int test_fromdata_ec(void)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pk = NULL, *copy_pk = NULL;
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();
    BIGNUM *ec_priv_bn = NULL;
    OSSL_PARAM *fromdata_params = NULL;
    const char *alg = "EC";
    static const unsigned char ec_pub_keydata[] = {
       0x04,
       0x1b, 0x93, 0x67, 0x55, 0x1c, 0x55, 0x9f, 0x63,
       0xd1, 0x22, 0xa4, 0xd8, 0xd1, 0x0a, 0x60, 0x6d,
       0x02, 0xa5, 0x77, 0x57, 0xc8, 0xa3, 0x47, 0x73,
       0x3a, 0x6a, 0x08, 0x28, 0x39, 0xbd, 0xc9, 0xd2,
       0x80, 0xec, 0xe9, 0xa7, 0x08, 0x29, 0x71, 0x2f,
       0xc9, 0x56, 0x82, 0xee, 0x9a, 0x85, 0x0f, 0x6d,
       0x7f, 0x59, 0x5f, 0x8c, 0xd1, 0x96, 0x0b, 0xdf,
       0x29, 0x3e, 0x49, 0x07, 0x88, 0x3f, 0x9a, 0x29
    };
    static const unsigned char ec_priv_keydata[] = {
        0x33, 0xd0, 0x43, 0x83, 0xa9, 0x89, 0x56, 0x03,
        0xd2, 0xd7, 0xfe, 0x6b, 0x01, 0x6f, 0xe4, 0x59,
        0xcc, 0x0d, 0x9a, 0x24, 0x6c, 0x86, 0x1b, 0x2e,
        0xdc, 0x4b, 0x4d, 0x35, 0x43, 0xe1, 0x1b, 0xad
    };

    if (!TEST_ptr(bld))
        goto err;
    if (!TEST_ptr(ec_priv_bn = BN_bin2bn(ec_priv_keydata,
                                         sizeof(ec_priv_keydata), NULL)))
        goto err;

    if (OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_EC_NAME,
                                        "prime256v1", 0) <= 0)
        goto err;
    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         ec_pub_keydata,
                                         sizeof(ec_pub_keydata)) <= 0)
        goto err;
    if (OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, ec_priv_bn) <= 0)
        goto err;
    if (!TEST_ptr(fromdata_params = OSSL_PARAM_BLD_to_param(bld)))
        goto err;
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg, NULL);
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(EVP_PKEY_key_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pk, fromdata_params))
        || !TEST_int_eq(EVP_PKEY_bits(pk), 256)
        || !TEST_int_eq(EVP_PKEY_security_bits(pk), 128)
        || !TEST_int_eq(EVP_PKEY_size(pk), 2 + 35 * 2))
        goto err;

    if (!TEST_ptr(copy_pk = EVP_PKEY_new())
        || !TEST_true(EVP_PKEY_copy_parameters(copy_pk, pk)))
        goto err;

    ret = test_print_key_using_pem(alg, pk)
          && test_print_key_using_serializer(alg, pk);
err:
    BN_free(ec_priv_bn);
    OSSL_PARAM_BLD_free_params(fromdata_params);
    OSSL_PARAM_BLD_free(bld);
    EVP_PKEY_free(pk);
    EVP_PKEY_free(copy_pk);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

#endif /* OPENSSL_NO_EC */

int setup_tests(void)
{
    if (!test_skip_common_options()) {
        TEST_error("Error parsing test options\n");
        return 0;
    }

    if (!TEST_ptr(datadir = test_get_argument(0)))
        return 0;

    ADD_TEST(test_fromdata_rsa);
#ifndef OPENSSL_NO_DH
    ADD_TEST(test_fromdata_dh);
#endif
#ifndef OPENSSL_NO_EC
    ADD_ALL_TESTS(test_fromdata_ecx, 4);
    ADD_TEST(test_fromdata_ec);
#endif
    return 1;
}
