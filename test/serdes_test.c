/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/serializer.h>
#include <openssl/deserializer.h>

#include "internal/cryptlib.h"   /* ossl_assert */

#include "testutil.h"

/*
 * TODO(3.0) Modify PEM_write_bio_PrivateKey_traditional() to handle
 * provider side EVP_PKEYs (which don't necessarily have an ameth)
 *
 * In the mean time, we use separate "downgraded" EVP_PKEYs to test
 * serializing/deserializing with "traditional" keys.
 */

static EVP_PKEY *key_RSA = NULL;
static EVP_PKEY *legacy_key_RSA = NULL;

static EVP_PKEY *make_RSA(const char *rsa_type, int make_legacy)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, rsa_type, NULL);

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will imply remain NULL if something goes wrong.
     */
    (void)(ctx != NULL
           && EVP_PKEY_keygen_init(ctx) > 0
           && EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    if (make_legacy && EVP_PKEY_get0(pkey) == NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}

/* Main test driver */

typedef int (serializer)(void **serialized, long *serialized_len,
                         void *object,
                         const char *pass, const char *pcipher,
                         const char *ser_propq);
typedef int (deserializer)(void **object,
                           void *serialized, long serialized_len,
                           const char *pass, const char *pcipher);
typedef int (checker)(int type, const void *data, size_t data_len);
typedef void (dumper)(const char *label, const void *data, size_t data_len);

static int test_serialize_deserialize(EVP_PKEY *pkey,
                                      const char *pass, const char *pcipher,
                                      serializer *serialize_cb,
                                      deserializer *deserialize_cb,
                                      checker *check_cb, dumper *dump_cb,
                                      const char *ser_propq, int make_legacy)
{
    void *serialized = NULL;
    long serialized_len = 0;
    EVP_PKEY *pkey2 = NULL;
    void *serialized2 = NULL;
    long serialized2_len = 0;
    int ok = 0;

    if (!serialize_cb(&serialized, &serialized_len, pkey,
                      pass, pcipher, ser_propq)
        || !check_cb(EVP_PKEY_base_id(pkey), serialized, serialized_len)
        || !deserialize_cb((void **)&pkey2, serialized, serialized_len,
                           pass, pcipher)
        || !TEST_int_eq(EVP_PKEY_eq(pkey, pkey2), 1))
        goto end;

    /*
     * TODO(3.0) Remove this when PEM_write_bio_PrivateKey_traditional()
     * handles provider side keys.
     */
    if (make_legacy
        && !TEST_ptr(EVP_PKEY_get0(pkey2)))
        goto end;

    /*
     * Double check the serialization, but only for unprotected keys,
     * as protected keys have a random component, which makes the output
     * differ.
     */
    if ((pass == NULL && pcipher == NULL)
        && (!serialize_cb(&serialized2, &serialized2_len, pkey2,
                          pass, pcipher, ser_propq)
            || !TEST_mem_eq(serialized, serialized_len,
                            serialized2, serialized2_len)))
        goto end;

    ok = 1;
 end:
    if (!ok)
        dump_cb("serialized result", serialized, serialized_len);

    OPENSSL_free(serialized);
    OPENSSL_free(serialized2);
    EVP_PKEY_free(pkey2);
    return ok;
}

/* Serializing and desserializing methods */

static int serialize_EVP_PKEY_prov(void **serialized, long *serialized_len,
                                   void *object,
                                   const char *pass, const char *pcipher,
                                   const char *ser_propq)
{
    EVP_PKEY *pkey = object;
    OSSL_SERIALIZER_CTX *sctx = NULL;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;

    if (!TEST_ptr(sctx = OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(pkey, ser_propq))
        || (pass != NULL
            && !TEST_true(OSSL_SERIALIZER_CTX_set_passphrase(sctx, upass,
                                                             strlen(pass))))
        || (pcipher != NULL
            && !TEST_true(OSSL_SERIALIZER_CTX_set_cipher(sctx, pcipher, NULL)))
        || !TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_true(OSSL_SERIALIZER_to_bio(sctx, mem_ser))
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*serialized = mem_buf->data)
        || !TEST_long_gt(*serialized_len = mem_buf->length, 0))
        goto end;

    /* Detach the serialized output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    OSSL_SERIALIZER_CTX_free(sctx);
    return ok;
}

static int deserialize_EVP_PKEY_prov(void **object,
                                     void *serialized, long serialized_len,
                                     const char *pass, const char *pcipher)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DESERIALIZER_CTX *dctx = NULL;
    BIO *mem_deser = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;

    if (!TEST_ptr(dctx = OSSL_DESERIALIZER_CTX_new_by_EVP_PKEY(&pkey, NULL,
                                                               NULL, NULL))
        || (pass != NULL
            && !OSSL_DESERIALIZER_CTX_set_passphrase(dctx, upass,
                                                     strlen(pass)))
        || (pcipher != NULL
            && !OSSL_DESERIALIZER_CTX_set_cipher(dctx, pcipher, NULL))
        || !TEST_ptr(mem_deser = BIO_new_mem_buf(serialized, serialized_len))
        || !TEST_true(OSSL_DESERIALIZER_from_bio(dctx, mem_deser)))
        goto end;
    ok = 1;
    *object = pkey;
 end:
    BIO_free(mem_deser);
    OSSL_DESERIALIZER_CTX_free(dctx);
    return ok;
}

static int serialize_EVP_PKEY_legacy_PEM(void **serialized,
                                         long *serialized_len,
                                         void *object,
                                         const char *pass, const char *pcipher,
                                         ossl_unused const char *ser_propq)
{
    EVP_PKEY *pkey = object;
    EVP_CIPHER *cipher = NULL;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    size_t passlen = 0;
    int ok = 0;

    if (pcipher != NULL && pass != NULL) {
        passlen = strlen(pass);
        if (!TEST_ptr(cipher = EVP_CIPHER_fetch(NULL, pcipher, NULL)))
            goto end;
    }
    if (!TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_PrivateKey_traditional(mem_ser, pkey,
                                                           cipher,
                                                           upass, passlen,
                                                           NULL, NULL))
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*serialized = mem_buf->data)
        || !TEST_long_gt(*serialized_len = mem_buf->length, 0))
        goto end;

    /* Detach the serialized output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    EVP_CIPHER_free(cipher);
    return ok;
}

/* Test cases and their dumpers / checkers */

static void dump_der(const char *label, const void *data, size_t data_len)
{
    test_output_memory(label, data, data_len);
}

static void dump_pem(const char *label, const void *data, size_t data_len)
{
    test_output_string(label, data, data_len - 1);
}

static int check_unprotected_PKCS8_DER(int type,
                                       const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    PKCS8_PRIV_KEY_INFO *p8inf =
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &datap, data_len);
    int ok = 0;

    if (TEST_ptr(p8inf)) {
        EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);

        ok = (TEST_ptr(pkey) && TEST_true(EVP_PKEY_is_a(pkey, "RSA")));
        EVP_PKEY_free(pkey);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ok;
}

static int test_unprotected_RSA_via_DER(void)
{
    return test_serialize_deserialize(key_RSA, NULL, NULL,
                                      serialize_EVP_PKEY_prov,
                                      deserialize_EVP_PKEY_prov,
                                      check_unprotected_PKCS8_DER, dump_der,
                                      OSSL_SERIALIZER_PrivateKey_TO_DER_PQ,
                                      0);
}

static int check_unprotected_PKCS8_PEM(int type,
                                       const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_PKCS8INF "-----";

    return TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_unprotected_RSA_via_PEM(void)
{
    return test_serialize_deserialize(key_RSA, NULL, NULL,
                                      serialize_EVP_PKEY_prov,
                                      deserialize_EVP_PKEY_prov,
                                      check_unprotected_PKCS8_PEM, dump_pem,
                                      OSSL_SERIALIZER_PrivateKey_TO_PEM_PQ,
                                      0);
}

static int check_unprotected_legacy_PEM(int type,
                                        const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_RSA "-----";

    return TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_unprotected_RSA_via_legacy_PEM(void)
{
    return test_serialize_deserialize(legacy_key_RSA, NULL, NULL,
                                      serialize_EVP_PKEY_legacy_PEM,
                                      deserialize_EVP_PKEY_prov,
                                      check_unprotected_legacy_PEM, dump_pem,
                                      NULL, 1);
}

static const char *pass_cipher = "AES-256-CBC";
static const char *pass = "the holy handgrenade of antioch";

static int check_protected_PKCS8_DER(int type,
                                     const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    X509_SIG *p8 = d2i_X509_SIG(NULL, &datap, data_len);
    int ok = TEST_ptr(p8);

    X509_SIG_free(p8);
    return ok;
}

static int test_protected_RSA_via_DER(void)
{
    return test_serialize_deserialize(key_RSA, pass, pass_cipher,
                                      serialize_EVP_PKEY_prov,
                                      deserialize_EVP_PKEY_prov,
                                      check_protected_PKCS8_DER, dump_der,
                                      OSSL_SERIALIZER_PrivateKey_TO_DER_PQ,
                                      0);
}

static int check_protected_PKCS8_PEM(int type,
                                     const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_PKCS8 "-----";

    return TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_protected_RSA_via_PEM(void)
{
    return test_serialize_deserialize(key_RSA, pass, pass_cipher,
                                      serialize_EVP_PKEY_prov,
                                      deserialize_EVP_PKEY_prov,
                                      check_protected_PKCS8_PEM, dump_pem,
                                      OSSL_SERIALIZER_PrivateKey_TO_PEM_PQ,
                                      0);
}

static int check_protected_legacy_PEM(int type,
                                      const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_RSA "-----";

    return
        TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1)
        && TEST_ptr(strstr(data, "\nDEK-Info: "));
}

static int test_protected_RSA_via_legacy_PEM(void)
{
    return test_serialize_deserialize(legacy_key_RSA, pass, pass_cipher,
                                      serialize_EVP_PKEY_legacy_PEM,
                                      deserialize_EVP_PKEY_prov,
                                      check_protected_legacy_PEM, dump_pem,
                                      NULL, 1);
}

int setup_tests(void)
{
    TEST_info("Generating keys...");
    if (!TEST_ptr(key_RSA = make_RSA("RSA", 0))
        || !TEST_ptr(legacy_key_RSA = make_RSA("RSA", 1))) {
        EVP_PKEY_free(key_RSA);
        EVP_PKEY_free(legacy_key_RSA);
        return 0;
    }
    TEST_info("Generating key... done");

    ADD_TEST(test_unprotected_RSA_via_DER);
    ADD_TEST(test_unprotected_RSA_via_PEM);
    ADD_TEST(test_unprotected_RSA_via_legacy_PEM);
    ADD_TEST(test_protected_RSA_via_DER);
    ADD_TEST(test_protected_RSA_via_PEM);
    ADD_TEST(test_protected_RSA_via_legacy_PEM);

    return 1;
}
