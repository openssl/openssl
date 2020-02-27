/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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
    int ret = 1;

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

    if (!TEST_ptr(membio)) {
        ret = 0;
        goto err;
    }

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
        ret = 0;

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
            ret = 0;

        /* Use an invalid cipher name, which should generate no output */
        TEST_note("NOT Displaying PEM encrypted with (invalid) FOO");
        if (!TEST_false(OSSL_SERIALIZER_CTX_set_cipher(ctx, "FOO", NULL))
            || !TEST_false(OSSL_SERIALIZER_to_bio(ctx, bio_out)))
            ret = 0;

        /* Clear the cipher.  This should give us an unencrypted PEM again */
        TEST_note("Testing with encryption cleared (no encryption)");
        if (!TEST_true(OSSL_SERIALIZER_CTX_set_cipher(ctx, NULL, NULL))
            || !TEST_true(OSSL_SERIALIZER_to_bio(ctx, membio))
            || !TEST_true(compare_with_file(alg, type, membio)))
            ret = 0;
    }

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
    EVP_PKEY *pk = NULL;
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

    ret = test_print_key_using_pem("RSA", pk)
          && test_print_key_using_serializer("RSA", pk);

 err:
    EVP_PKEY_free(pk);
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
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pk = NULL;
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

    ret = test_print_key_using_pem("DH", pk)
          && test_print_key_using_serializer("DH", pk);

 err:
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}
#endif

#ifndef OPENSSL_NO_EC
/* Array indexes used in test_fromdata_ecx */
# define PRIV_KEY        0
# define PUB_KEY         1

# define X25519_IDX      0
# define X448_IDX        1

static int test_fromdata_ecx(int tst)
{
    int ret = 0;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pk = NULL;
    const char *alg = (tst == X25519_IDX) ? "X25519" : "X448";

    /* X448_KEYLEN > X25519_KEYLEN */
    static unsigned char key_numbers[2][2][X448_KEYLEN] = {
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
    OSSL_PARAM *fromdata_params;
    int bits, security_bits, size;

    if (tst == X25519_IDX) {
        fromdata_params = x25519_fromdata_params;
        bits = X25519_BITS;
        security_bits = X25519_SECURITY_BITS;
        size = X25519_KEYLEN;
    } else {
        fromdata_params = x448_fromdata_params;
        bits = X448_BITS;
        security_bits = X448_SECURITY_BITS;
        size = X448_KEYLEN;
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

    ret = test_print_key_using_pem(alg, pk)
          && test_print_key_using_serializer(alg, pk);

 err:
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}
#endif


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
    ADD_ALL_TESTS(test_fromdata_ecx, 2);
#endif
    return 1;
}
