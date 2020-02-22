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
#include "internal/nelem.h"
#include "crypto/evp.h"          /* For the internal API */
#include "testutil.h"

static int test_print_key_using_pem(const EVP_PKEY *pk)
{
    if (!TEST_true(EVP_PKEY_print_private(bio_out, pk, 0, NULL))
        /* Public key in PEM form */
        || !TEST_true(PEM_write_bio_PUBKEY(bio_out, pk))
        /* Unencrypted private key in PEM form */
        || !TEST_true(PEM_write_bio_PrivateKey(bio_out, pk,
                                               NULL, NULL, 0, NULL, NULL))
        /* Encrypted private key in PEM form */
        || !TEST_true(PEM_write_bio_PrivateKey(bio_out, pk, EVP_aes_256_cbc(),
                                               (unsigned char *)"pass", 4,
                                               NULL, NULL)))
        return 0;

    return 1;
}

static int test_print_key_using_serializer(const EVP_PKEY *pk)
{
    const char *pq = OSSL_SERIALIZER_PrivateKey_TO_PEM_PQ;
    OSSL_SERIALIZER_CTX *ctx = NULL;
    int ret = 1;

    /* Make a context, it's valid for several prints */
    TEST_note("Setting up a OSSL_SERIALIZER context with passphrase");
    if (!TEST_ptr(ctx = OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(pk, pq))
        /* Check that this operation is supported */
        || !TEST_ptr(OSSL_SERIALIZER_CTX_get_serializer(ctx))
        /* Set a passphrase to be used later */
        || !TEST_true(OSSL_SERIALIZER_CTX_set_passphrase(ctx,
                                                         (unsigned char *)"pass",
                                                         4)))
        goto err;

    /* Use no cipher.  This should give us an unencrypted PEM */
    TEST_note("Displaying PEM with no encryption");
    if (!TEST_true(OSSL_SERIALIZER_to_bio(ctx, bio_out)))
        ret = 0;

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
    TEST_note("Displaying PEM with encryption cleared (no encryption)");
    if (!TEST_true(OSSL_SERIALIZER_CTX_set_cipher(ctx, NULL, NULL))
        || !TEST_true(OSSL_SERIALIZER_to_bio(ctx, bio_out)))
        ret = 0;

err:
    OSSL_SERIALIZER_CTX_free(ctx);
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

    ret = test_print_key_using_pem(pk)
        | test_print_key_using_serializer(pk);

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

    ret = test_print_key_using_pem(pk)
        | test_print_key_using_serializer(pk);

 err:
    EVP_PKEY_free(pk);
    EVP_PKEY_CTX_free(ctx);

    return ret;
}
#endif

int setup_tests(void)
{
    ADD_TEST(test_fromdata_rsa);
#ifndef OPENSSL_NO_DH
    ADD_TEST(test_fromdata_dh);
#endif
    return 1;
}
