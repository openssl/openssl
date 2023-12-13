/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define OPENSSL_SUPPRESS_DEPRECATED

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/pkcs12.h>
#include "testutil.h"
#include "fake_cipherprov.h"

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *defltprov = NULL;
static OSSL_PROVIDER *fakeprov = NULL;
static EVP_CIPHER_CTX *cipherctx = NULL;
static EVP_CIPHER *cipherbad = NULL;
static EVP_CIPHER *ciphergood = NULL;

/* Fetch CIPHER method using a libctx and propq */
static EVP_CIPHER *fetch_cipher(OSSL_LIB_CTX *ctx,
                                const char *alg, const char *propq,
                                OSSL_PROVIDER *expected_prov)
{
    const OSSL_PROVIDER *prov;
    EVP_CIPHER *cipher = EVP_CIPHER_fetch(ctx, alg, propq);

    if (!TEST_ptr(cipher))
        return NULL;

    if (!TEST_ptr(prov = EVP_CIPHER_get0_provider(cipher)))
        goto end;

    if (!TEST_ptr_eq(prov, expected_prov)) {
        TEST_info("Fetched provider: %s, Expected provider: %s",
                  OSSL_PROVIDER_get0_name(prov),
                  OSSL_PROVIDER_get0_name(expected_prov));
        goto end;
    }

    return cipher;
end:
    EVP_CIPHER_free(cipher);
    return NULL;
}

static int evp_cipher_bad_blocksize_test(void)
{
    int ret = 0;
    static const unsigned char msg[] = "Hello";

    if (!TEST_true(EVP_EncryptInit_ex2(cipherctx, cipherbad, NULL, NULL, NULL)))
        goto end;

    if (!TEST_int_eq(EVP_Cipher(cipherctx, NULL, msg, sizeof(msg)), 0))
        goto end;

    if (!TEST_true(EVP_EncryptInit_ex2(cipherctx, ciphergood, NULL, NULL, NULL)))
        goto end;

    if (!TEST_int_eq(EVP_Cipher(cipherctx, NULL, msg, sizeof(msg)), sizeof(msg)))
        goto end;
    ret = 1;

end:
    return ret;
}

#define BUF_SIZE 32
/* Test that enc_read() handles an invalid cipher blocksize */
static int bio_cipher_read_bad_blocksize_test(void)
{
    int ret = 0;
    BIO *cipherbio, *membio;
    unsigned char buf[BUF_SIZE] = { 0 };
    unsigned char in[BUF_SIZE];

    if (!TEST_ptr(cipherbio = BIO_new(BIO_f_cipher())))
        return 0;
    if (!TEST_true(BIO_set_cipher(cipherbio, cipherbad, NULL, NULL, 1)))
        goto err;
    if (!TEST_ptr(membio = BIO_new_mem_buf(buf, sizeof(buf))))
        goto err;
    if (!TEST_ptr(BIO_push(cipherbio, membio))) {
        BIO_free(membio);
        goto err;
    }
    if (!TEST_int_eq(BIO_read(cipherbio, in, sizeof(in)), 0))
        goto err;
    ret = 1;
err:
    BIO_free_all(cipherbio);
    return ret;
}

/* Test that EVP_Cipher() fails if a cipher has a invalid blocksize */
static int krb5kdf_cipher_bad_blocksize_test(void)
{
    int ret = 0;
    EVP_KDF *kdf = NULL;
    EVP_KDF_CTX *kctx = NULL;
    OSSL_PARAM params[4], *p = params;
    unsigned char out[16];
    static unsigned char key[] = {
        0x42, 0x26, 0x3C, 0x6E, 0x89, 0xF4, 0xFC, 0x28,
        0xB8, 0xDF, 0x68, 0xEE, 0x09, 0x79, 0x9F, 0x15
    };
    static unsigned char constant[] = {
        0x00, 0x00, 0x00, 0x02, 0x99
    };

    if (!TEST_ptr(kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_KRB5KDF, NULL)))
        return 0;
    if (!TEST_ptr(kctx = EVP_KDF_CTX_new(kdf)))
        goto end;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_CIPHER,
                                            (char *)"Bad", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, key,
                                             sizeof(key));
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_CONSTANT,
                                             constant, sizeof(constant));
    *p = OSSL_PARAM_construct_end();

    if (!TEST_int_eq(EVP_KDF_derive(kctx, out, sizeof(out), params), 0))
        goto end;
    ret = 1;
end:
    EVP_KDF_free(kdf);
    EVP_KDF_CTX_free(kctx);
    return ret;
}

/*
 * A dummy PBE keygen - For the tests purposes all it is required to do is set
 * up the cipher in the ctx
 */
static int dummy_pbe_keygen(EVP_CIPHER_CTX *ctx, const char *pass,
                            int passlen, ASN1_TYPE *param,
                            const EVP_CIPHER *cipher, const EVP_MD *md,
                            int en_de)
{
    return EVP_CipherInit_ex2(ctx, cipher, NULL, NULL, 1, NULL);
}

/* Test that PKCS12_pbe_crypt_ex() handles an invalid blocksize */
static int pkcs12_pbe_cipher_bad_blocksize_test(void)
{
    int ret = 0;
    EVP_CIPHER *cipher = NULL;
    unsigned char salt[16] = { 0 };
    X509_ALGOR *algor = NULL;
    int nid;
    unsigned char *data = NULL;
    int datalen = 0;
    const unsigned char in[]= {
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
        0x03, 0x2b, 0x65, 0x6e, 0x04, 0x22, 0x04, 0x20,
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
    };

    nid = OBJ_txt2nid("Bad");
    if (!TEST_int_ne(nid, NID_undef))
        return 0;
    if (!TEST_ptr(cipher = EVP_CIPHER_meth_new(nid, 16, 16)))
        return 0;

    if (!TEST_true(EVP_add_cipher(cipher)))
        goto err;

    if (!TEST_true(EVP_PBE_alg_add_type(EVP_PBE_TYPE_OUTER, NID_pbes2, nid,
                                        NID_sha256, dummy_pbe_keygen)))
        goto err;

    if (!TEST_ptr(algor = PKCS5_pbe2_set(cipher, 1000, salt, sizeof(salt))))
        goto err;

    if (!TEST_ptr_null(PKCS12_pbe_crypt_ex(algor, "Pass", 4, in, sizeof(in),
                                           &data, &datalen, 1, libctx, NULL)))
        goto err;
    ret = 1;
err:
    EVP_CIPHER_meth_free(cipher);
    X509_ALGOR_free(algor);
    return ret;
}

int setup_tests(void)
{
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new()))
        return 0;

    if (!TEST_ptr(cipherctx = EVP_CIPHER_CTX_new()))
        return 0;

    if (!TEST_ptr(fakeprov = fake_cipher_start(libctx)))
        return 0;

    if (!TEST_ptr(defltprov = OSSL_PROVIDER_load(libctx, "default")))
        return 0;

    if (!OBJ_create("1.3.6.1.4.1.16604.998866.2", "Bad", "Bad"))
        return 0;

    /* Do a direct fetch to see it works */
    if (!TEST_ptr(cipherbad = fetch_cipher(libctx, "Bad",
                                           "provider=fake-cipher", fakeprov)))
        return 0;

    if (!TEST_ptr(ciphergood = fetch_cipher(libctx, "Good",
                                            "provider=fake-cipher", fakeprov)))
        return 0;

    ADD_TEST(evp_cipher_bad_blocksize_test);
    ADD_TEST(bio_cipher_read_bad_blocksize_test);
    ADD_TEST(krb5kdf_cipher_bad_blocksize_test);
    ADD_TEST(pkcs12_pbe_cipher_bad_blocksize_test);

    return 1;
}

void cleanup_tests(void)
{
    EVP_CIPHER_free(cipherbad);
    EVP_CIPHER_free(ciphergood);
    EVP_CIPHER_CTX_free(cipherctx);
    fake_cipher_finish(fakeprov);
    OSSL_PROVIDER_unload(defltprov);
    OSSL_LIB_CTX_free(libctx);
}
