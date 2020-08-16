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
#include <openssl/params.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>

#include "internal/pem.h"        /* For PVK and "blob" PEM headers */
#include "internal/cryptlib.h"   /* ossl_assert */

#include "testutil.h"

/*
 * TODO(3.0) Modify PEM_write_bio_PrivateKey_traditional() to handle
 * provider side EVP_PKEYs (which don't necessarily have an ameth)
 *
 * In the mean time, we use separate "downgraded" EVP_PKEYs to test
 * encoding/decoding with "traditional" keys.
 */

static EVP_PKEY *make_template(const char *type, OSSL_PARAM *genparams)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name(NULL, type, NULL);

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will simply remain NULL if something goes wrong.
     */
    (void)(ctx != NULL
           && EVP_PKEY_paramgen_init(ctx) > 0
           && (genparams == NULL
               || EVP_PKEY_CTX_set_params(ctx, genparams) > 0)
           && EVP_PKEY_gen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);

    return pkey;
}

static EVP_PKEY *make_key(const char *type, EVP_PKEY *template,
                          OSSL_PARAM *genparams, int make_legacy)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx =
        template != NULL
        ? EVP_PKEY_CTX_new(template, NULL)
        : EVP_PKEY_CTX_new_from_name(NULL, type, NULL);

    /*
     * No real need to check the errors other than for the cascade
     * effect.  |pkey| will simply remain NULL if something goes wrong.
     */
    (void)(ctx != NULL
           && EVP_PKEY_keygen_init(ctx) > 0
           && (genparams == NULL
               || EVP_PKEY_CTX_set_params(ctx, genparams) > 0)
           && EVP_PKEY_keygen(ctx, &pkey) > 0);
    EVP_PKEY_CTX_free(ctx);
    if (make_legacy && EVP_PKEY_get0(pkey) == NULL) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    return pkey;
}


/* Main test driver */

/*
 * TODO(3.0) For better error output, changed the callbacks to take __FILE__
 * and __LINE__ as first two arguments, and have them use the lower case
 * functions, such as test_strn_eq(), rather than the uppercase macros
 * (TEST_strn2_eq(), for example).
 */

typedef int (encoder)(void **encoded, long *encoded_len,
                         void *object, const char *pass, const char *pcipher,
                         const char *encoder_propq);
typedef int (decoder)(void **object,
                           void *encoded, long encoded_len,
                           const char *pass);
typedef int (tester)(const void *data1, size_t data1_len,
                     const void *data2, size_t data2_len);
typedef int (checker)(const char *type, const void *data, size_t data_len);
typedef void (dumper)(const char *label, const void *data, size_t data_len);

static int test_encode_decode(const char *type, EVP_PKEY *pkey,
                                      const char *pass, const char *pcipher,
                                      encoder *encode_cb,
                                      decoder *decode_cb,
                                      tester *test_cb,
                                      checker *check_cb, dumper *dump_cb,
                                      const char *encoder_propq, int make_legacy)
{
    void *encoded = NULL;
    long encoded_len = 0;
    EVP_PKEY *pkey2 = NULL;
    void *encoded2 = NULL;
    long encoded2_len = 0;
    int ok = 0;

    if (!encode_cb(&encoded, &encoded_len, pkey,
                      pass, pcipher, encoder_propq)
        || !check_cb(type, encoded, encoded_len)
        || !decode_cb((void **)&pkey2, encoded, encoded_len,
                           pass)
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
     * Double check the encoding, but only for unprotected keys,
     * as protected keys have a random component, which makes the output
     * differ.
     */
    if ((pass == NULL && pcipher == NULL)
        && (!encode_cb(&encoded2, &encoded2_len, pkey2,
                          pass, pcipher, encoder_propq)
            || !test_cb(encoded, encoded_len,
                        encoded2, encoded2_len)))
        goto end;

    ok = 1;
 end:
    if (!ok) {
        if (encoded != NULL && encoded_len != 0)
            dump_cb("encoded result", encoded, encoded_len);
        if (encoded2 != NULL && encoded2_len != 0)
            dump_cb("re-encoded result", encoded2, encoded2_len);
    }

    OPENSSL_free(encoded);
    OPENSSL_free(encoded2);
    EVP_PKEY_free(pkey2);
    return ok;
}

/* Encoding and desencoding methods */

static int encode_EVP_PKEY_prov(void **encoded, long *encoded_len,
                                   void *object,
                                   const char *pass, const char *pcipher,
                                   const char *encoder_propq)
{
    EVP_PKEY *pkey = object;
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;

    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new_by_EVP_PKEY(pkey, encoder_propq))
        || (pass != NULL
            && !TEST_true(OSSL_ENCODER_CTX_set_passphrase(ectx, upass,
                                                             strlen(pass))))
        || (pcipher != NULL
            && !TEST_true(OSSL_ENCODER_CTX_set_cipher(ectx, pcipher, NULL)))
        || !TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_true(OSSL_ENCODER_to_bio(ectx, mem_ser))
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*encoded = mem_buf->data)
        || !TEST_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    OSSL_ENCODER_CTX_free(ectx);
    return ok;
}

static int decode_EVP_PKEY_prov(void **object,
                                     void *encoded, long encoded_len,
                                     const char *pass)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    BIO *mem_deser = NULL;
    const unsigned char *upass = (const unsigned char *)pass;
    int ok = 0;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_by_EVP_PKEY(&pkey, NULL,
                                                               NULL, NULL))
        || (pass != NULL
            && !OSSL_DECODER_CTX_set_passphrase(dctx, upass,
                                                     strlen(pass)))
        || !TEST_ptr(mem_deser = BIO_new_mem_buf(encoded, encoded_len))
        || !TEST_true(OSSL_DECODER_from_bio(dctx, mem_deser)))
        goto end;
    ok = 1;
    *object = pkey;
 end:
    BIO_free(mem_deser);
    OSSL_DECODER_CTX_free(dctx);
    return ok;
}

static int encode_EVP_PKEY_legacy_PEM(void **encoded,
                                         long *encoded_len,
                                         void *object,
                                         const char *pass, const char *pcipher,
                                         ossl_unused const char *encoder_propq)
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
        || !TEST_ptr(*encoded = mem_buf->data)
        || !TEST_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    EVP_CIPHER_free(cipher);
    return ok;
}

#ifndef OPENSSL_NO_DSA
static int encode_EVP_PKEY_MSBLOB(void **encoded,
                                     long *encoded_len,
                                     void *object,
                                     ossl_unused const char *pass,
                                     ossl_unused const char *pcipher,
                                     ossl_unused const char *encoder_propq)
{
    EVP_PKEY *pkey = object;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    int ok = 0;

    if (!TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_int_ge(i2b_PrivateKey_bio(mem_ser, pkey), 0)
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*encoded = mem_buf->data)
        || !TEST_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    return ok;
}

static int encode_public_EVP_PKEY_MSBLOB(void **encoded,
                                            long *encoded_len,
                                            void *object,
                                            ossl_unused const char *pass,
                                            ossl_unused const char *pcipher,
                                            ossl_unused const char *encoder_propq)
{
    EVP_PKEY *pkey = object;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    int ok = 0;

    if (!TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_int_ge(i2b_PublicKey_bio(mem_ser, pkey), 0)
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*encoded = mem_buf->data)
        || !TEST_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    return ok;
}

# ifndef OPENSSL_NO_RC4
static pem_password_cb pass_pw;
static int pass_pw(char *buf, int size, int rwflag, void *userdata)
{
    OPENSSL_strlcpy(buf, userdata, size);
    return strlen(userdata);
}

static int encode_EVP_PKEY_PVK(void **encoded, long *encoded_len,
                                  void *object,
                                  const char *pass,
                                  ossl_unused const char *pcipher,
                                  ossl_unused const char *encoder_propq)
{
    EVP_PKEY *pkey = object;
    BIO *mem_ser = NULL;
    BUF_MEM *mem_buf = NULL;
    int enc = (pass != NULL);
    int ok = 0;

    if (!TEST_ptr(mem_ser = BIO_new(BIO_s_mem()))
        || !TEST_int_ge(i2b_PVK_bio(mem_ser, pkey, enc,
                                    pass_pw, (void *)pass), 0)
        || !TEST_true(BIO_get_mem_ptr(mem_ser, &mem_buf) > 0)
        || !TEST_ptr(*encoded = mem_buf->data)
        || !TEST_long_gt(*encoded_len = mem_buf->length, 0))
        goto end;

    /* Detach the encoded output */
    mem_buf->data = NULL;
    mem_buf->length = 0;
    ok = 1;
 end:
    BIO_free(mem_ser);
    return ok;
}
# endif
#endif

static int test_text(const void *data1, size_t data1_len,
                     const void *data2, size_t data2_len)
{
    return TEST_strn2_eq(data1, data1_len, data2, data2_len);
}

static int test_mem(const void *data1, size_t data1_len,
                    const void *data2, size_t data2_len)
{
    return TEST_mem_eq(data1, data1_len, data2, data2_len);
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

static int check_unprotected_PKCS8_DER(const char *type,
                                       const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    PKCS8_PRIV_KEY_INFO *p8inf =
        d2i_PKCS8_PRIV_KEY_INFO(NULL, &datap, data_len);
    int ok = 0;

    if (TEST_ptr(p8inf)) {
        EVP_PKEY *pkey = EVP_PKCS82PKEY(p8inf);

        ok = (TEST_ptr(pkey) && TEST_true(EVP_PKEY_is_a(pkey, type)));
        EVP_PKEY_free(pkey);
    }
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    return ok;
}

static int test_unprotected_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_unprotected_PKCS8_DER, dump_der,
                                      OSSL_ENCODER_PrivateKey_TO_DER_PQ,
                                      0);
}

static int check_unprotected_PKCS8_PEM(const char *type,
                                       const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_PKCS8INF "-----";

    return TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_unprotected_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_text,
                                      check_unprotected_PKCS8_PEM, dump_pem,
                                      OSSL_ENCODER_PrivateKey_TO_PEM_PQ,
                                      0);
}

static int check_unprotected_legacy_PEM(const char *type,
                                        const void *data, size_t data_len)
{
    static char pem_header[80];

    return
        TEST_int_gt(BIO_snprintf(pem_header, sizeof(pem_header),
                                 "-----BEGIN %s PRIVATE KEY-----", type), 0)
        && TEST_strn_eq(data, pem_header, strlen(pem_header));
}

static int test_unprotected_via_legacy_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_legacy_PEM,
                                      decode_EVP_PKEY_prov,
                                      test_text,
                                      check_unprotected_legacy_PEM, dump_pem,
                                      NULL, 1);
}

#ifndef OPENSSL_NO_DSA
static int check_MSBLOB(const char *type, const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = b2i_PrivateKey(&datap, data_len);
    int ok = TEST_ptr(pkey);

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_unprotected_via_MSBLOB(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_MSBLOB,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_MSBLOB, dump_der,
                                      NULL, 0);
}

# ifndef OPENSSL_NO_RC4
static int check_PVK(const char *type, const void *data, size_t data_len)
{
    const unsigned char *in = data;
    unsigned int saltlen = 0, keylen = 0;
    int ok = ossl_do_PVK_header(&in, data_len, 0, &saltlen, &keylen);

    return ok;
}

static int test_unprotected_via_PVK(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_PVK,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_PVK, dump_der,
                                      NULL, 0);
}
# endif
#endif

static const char *pass_cipher = "AES-256-CBC";
static const char *pass = "the holy handgrenade of antioch";

static int check_protected_PKCS8_DER(const char *type,
                                     const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    X509_SIG *p8 = d2i_X509_SIG(NULL, &datap, data_len);
    int ok = TEST_ptr(p8);

    X509_SIG_free(p8);
    return ok;
}

static int test_protected_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, pass, pass_cipher,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_protected_PKCS8_DER, dump_der,
                                      OSSL_ENCODER_PrivateKey_TO_DER_PQ,
                                      0);
}

static int check_protected_PKCS8_PEM(const char *type,
                                     const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_PKCS8 "-----";

    return TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_protected_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, pass, pass_cipher,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_text,
                                      check_protected_PKCS8_PEM, dump_pem,
                                      OSSL_ENCODER_PrivateKey_TO_PEM_PQ,
                                      0);
}

static int check_protected_legacy_PEM(const char *type,
                                      const void *data, size_t data_len)
{
    static char pem_header[80];

    return
        TEST_int_gt(BIO_snprintf(pem_header, sizeof(pem_header),
                                 "-----BEGIN %s PRIVATE KEY-----", type), 0)
        && TEST_strn_eq(data, pem_header, strlen(pem_header))
        && TEST_ptr(strstr(data, "\nDEK-Info: "));
}

static int test_protected_via_legacy_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, pass, pass_cipher,
                                      encode_EVP_PKEY_legacy_PEM,
                                      decode_EVP_PKEY_prov,
                                      test_text,
                                      check_protected_legacy_PEM, dump_pem,
                                      NULL, 1);
}

#if !defined(OPENSSL_NO_DSA) && !defined(OPENSSL_NO_RC4)
static int test_protected_via_PVK(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, pass, NULL,
                                      encode_EVP_PKEY_PVK,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_PVK, dump_der,
                                      NULL, 0);
}
#endif

static int check_public_DER(const char *type, const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &datap, data_len);
    int ok = (TEST_ptr(pkey) && TEST_true(EVP_PKEY_is_a(pkey, type)));

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_public_via_DER(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_public_DER, dump_der,
                                      OSSL_ENCODER_PUBKEY_TO_DER_PQ,
                                      0);
}

static int check_public_PEM(const char *type, const void *data, size_t data_len)
{
    static const char pem_header[] = "-----BEGIN " PEM_STRING_PUBLIC "-----";

    return
        TEST_strn_eq(data, pem_header, sizeof(pem_header) - 1);
}

static int test_public_via_PEM(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_EVP_PKEY_prov,
                                      decode_EVP_PKEY_prov,
                                      test_text,
                                      check_public_PEM, dump_pem,
                                      OSSL_ENCODER_PUBKEY_TO_PEM_PQ,
                                      0);
}

#ifndef OPENSSL_NO_DSA
static int check_public_MSBLOB(const char *type,
                               const void *data, size_t data_len)
{
    const unsigned char *datap = data;
    EVP_PKEY *pkey = b2i_PublicKey(&datap, data_len);
    int ok = TEST_ptr(pkey);

    EVP_PKEY_free(pkey);
    return ok;
}

static int test_public_via_MSBLOB(const char *type, EVP_PKEY *key)
{
    return test_encode_decode(type, key, NULL, NULL,
                                      encode_public_EVP_PKEY_MSBLOB,
                                      decode_EVP_PKEY_prov,
                                      test_mem,
                                      check_public_MSBLOB, dump_der,
                                      NULL, 0);
}
#endif

#define KEYS(KEYTYPE)                           \
    static EVP_PKEY *key_##KEYTYPE = NULL;      \
    static EVP_PKEY *legacy_key_##KEYTYPE = NULL
#define MAKE_KEYS(KEYTYPE, KEYTYPEstr, params)                          \
    ok = ok                                                             \
        && TEST_ptr(key_##KEYTYPE =                                     \
                    make_key(KEYTYPEstr, NULL, params, 0))              \
        && TEST_ptr(legacy_key_##KEYTYPE =                              \
                    make_key(KEYTYPEstr, NULL, params, 1))
#define FREE_KEYS(KEYTYPE)                                              \
    EVP_PKEY_free(key_##KEYTYPE);                                       \
    EVP_PKEY_free(legacy_key_##KEYTYPE)

#define DOMAIN_KEYS(KEYTYPE)                    \
    static EVP_PKEY *template_##KEYTYPE = NULL; \
    static EVP_PKEY *key_##KEYTYPE = NULL;      \
    static EVP_PKEY *legacy_key_##KEYTYPE = NULL
#define MAKE_DOMAIN_KEYS(KEYTYPE, KEYTYPEstr, params)                   \
    ok = ok                                                             \
        && TEST_ptr(template_##KEYTYPE =                                \
                    make_template(KEYTYPEstr, params))                  \
        && TEST_ptr(key_##KEYTYPE =                                     \
                    make_key(KEYTYPEstr, template_##KEYTYPE, NULL, 0))  \
        && TEST_ptr(legacy_key_##KEYTYPE =                              \
                    make_key(KEYTYPEstr, template_##KEYTYPE, NULL, 1))
#define FREE_DOMAIN_KEYS(KEYTYPE)                                       \
    EVP_PKEY_free(template_##KEYTYPE);                                  \
    EVP_PKEY_free(key_##KEYTYPE);                                       \
    EVP_PKEY_free(legacy_key_##KEYTYPE)

#define IMPLEMENT_TEST_SUITE(KEYTYPE, KEYTYPEstr)                       \
    static int test_unprotected_##KEYTYPE##_via_DER(void)               \
    {                                                                   \
        return test_unprotected_via_DER(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                                   \
    static int test_unprotected_##KEYTYPE##_via_PEM(void)               \
    {                                                                   \
        return test_unprotected_via_PEM(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                                   \
    static int test_unprotected_##KEYTYPE##_via_legacy_PEM(void)        \
    {                                                                   \
        return test_unprotected_via_legacy_PEM(KEYTYPEstr,              \
                                               legacy_key_##KEYTYPE);   \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_DER(void)                 \
    {                                                                   \
        return test_protected_via_DER(KEYTYPEstr, key_##KEYTYPE);       \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_PEM(void)                 \
    {                                                                   \
        return test_protected_via_PEM(KEYTYPEstr, key_##KEYTYPE);       \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_legacy_PEM(void)          \
    {                                                                   \
        return test_protected_via_legacy_PEM(KEYTYPEstr,                \
                                             legacy_key_##KEYTYPE);     \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_DER(void)                    \
    {                                                                   \
        return test_public_via_DER(KEYTYPEstr, key_##KEYTYPE);          \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_PEM(void)                    \
    {                                                                   \
        return test_public_via_PEM(KEYTYPEstr, key_##KEYTYPE);          \
    }

#define ADD_TEST_SUITE(KEYTYPE)                                 \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_DER);             \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_PEM);             \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_legacy_PEM);      \
    ADD_TEST(test_protected_##KEYTYPE##_via_DER);               \
    ADD_TEST(test_protected_##KEYTYPE##_via_PEM);               \
    ADD_TEST(test_protected_##KEYTYPE##_via_legacy_PEM);        \
    ADD_TEST(test_public_##KEYTYPE##_via_DER);                  \
    ADD_TEST(test_public_##KEYTYPE##_via_PEM)

#ifndef OPENSSL_NO_DSA
# define IMPLEMENT_TEST_SUITE_MSBLOB(KEYTYPE, KEYTYPEstr)               \
    static int test_unprotected_##KEYTYPE##_via_MSBLOB(void)            \
    {                                                                   \
        return test_unprotected_via_MSBLOB(KEYTYPEstr, key_##KEYTYPE);  \
    }                                                                   \
    static int test_public_##KEYTYPE##_via_MSBLOB(void)                 \
    {                                                                   \
        return test_public_via_MSBLOB(KEYTYPEstr, key_##KEYTYPE);       \
    }

# define ADD_TEST_SUITE_MSBLOB(KEYTYPE)                         \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_MSBLOB);          \
    ADD_TEST(test_public_##KEYTYPE##_via_MSBLOB)

# ifndef OPENSSL_NO_RC4
#  define IMPLEMENT_TEST_SUITE_PVK(KEYTYPE, KEYTYPEstr)                 \
    static int test_unprotected_##KEYTYPE##_via_PVK(void)               \
    {                                                                   \
        return test_unprotected_via_PVK(KEYTYPEstr, key_##KEYTYPE);     \
    }                                                                   \
    static int test_protected_##KEYTYPE##_via_PVK(void)                 \
    {                                                                   \
        return test_protected_via_PVK(KEYTYPEstr, key_##KEYTYPE);       \
    }

#  define ADD_TEST_SUITE_PVK(KEYTYPE)                           \
    ADD_TEST(test_unprotected_##KEYTYPE##_via_PVK);             \
    ADD_TEST(test_protected_##KEYTYPE##_via_PVK)
# endif
#endif

#ifndef OPENSSL_NO_DH
DOMAIN_KEYS(DH);
IMPLEMENT_TEST_SUITE(DH, "DH")
DOMAIN_KEYS(DHX);
IMPLEMENT_TEST_SUITE(DHX, "X9.42 DH")
#endif
#ifndef OPENSSL_NO_DSA
DOMAIN_KEYS(DSA);
IMPLEMENT_TEST_SUITE(DSA, "DSA")
IMPLEMENT_TEST_SUITE_MSBLOB(DSA, "DSA")
# ifndef OPENSSL_NO_RC4
IMPLEMENT_TEST_SUITE_PVK(DSA, "DSA")
# endif
#endif
#ifndef OPENSSL_NO_EC
DOMAIN_KEYS(EC);
IMPLEMENT_TEST_SUITE(EC, "EC")
KEYS(ED25519);
IMPLEMENT_TEST_SUITE(ED25519, "ED25519")
KEYS(ED448);
IMPLEMENT_TEST_SUITE(ED448, "ED448")
KEYS(X25519);
IMPLEMENT_TEST_SUITE(X25519, "X25519")
KEYS(X448);
IMPLEMENT_TEST_SUITE(X448, "X448")
#endif
KEYS(RSA);
IMPLEMENT_TEST_SUITE(RSA, "RSA")
KEYS(RSA_PSS);
IMPLEMENT_TEST_SUITE(RSA_PSS, "RSA-PSS")
#ifndef OPENSSL_NO_DSA
IMPLEMENT_TEST_SUITE_MSBLOB(RSA, "RSA")
# ifndef OPENSSL_NO_RC4
IMPLEMENT_TEST_SUITE_PVK(RSA, "RSA")
# endif
#endif

int setup_tests(void)
{
    int ok = 1;

#ifndef OPENSSL_NO_DSA
    static size_t qbits = 160;  /* PVK only tolerates 160 Q bits */
    static size_t pbits = 1024; /* With 160 Q bits, we MUST use 1024 P bits */
    OSSL_PARAM DSA_params[] = {
        OSSL_PARAM_size_t("pbits", &pbits),
        OSSL_PARAM_size_t("qbits", &qbits),
        OSSL_PARAM_END
    };
#endif

#ifndef OPENSSL_NO_EC
    static char groupname[] = "prime256v1";
    OSSL_PARAM EC_params[] = {
        OSSL_PARAM_utf8_string("group", groupname, sizeof(groupname) - 1),
        OSSL_PARAM_END
    };
#endif

    /* 7 is the default magic number */
    static unsigned int rsapss_min_saltlen = 7;
    OSSL_PARAM RSA_PSS_params[] = {
        OSSL_PARAM_uint("saltlen", &rsapss_min_saltlen),
        OSSL_PARAM_END
    };

    TEST_info("Generating keys...");
#ifndef OPENSSL_NO_DH
    MAKE_DOMAIN_KEYS(DH, "DH", NULL);
    MAKE_DOMAIN_KEYS(DHX, "X9.42 DH", NULL);
#endif
#ifndef OPENSSL_NO_DSA
    MAKE_DOMAIN_KEYS(DSA, "DSA", DSA_params);
#endif
#ifndef OPENSSL_NO_EC
    MAKE_DOMAIN_KEYS(EC, "EC", EC_params);
    MAKE_KEYS(ED25519, "ED25519", NULL);
    MAKE_KEYS(ED448, "ED448", NULL);
    MAKE_KEYS(X25519, "X25519", NULL);
    MAKE_KEYS(X448, "X448", NULL);
#endif
    MAKE_KEYS(RSA, "RSA", NULL);
    MAKE_KEYS(RSA_PSS, "RSA-PSS", RSA_PSS_params);
    TEST_info("Generating key... done");

    if (ok) {
#ifndef OPENSSL_NO_DH
        ADD_TEST_SUITE(DH);
        ADD_TEST_SUITE(DHX);
#endif
#ifndef OPENSSL_NO_DSA
        ADD_TEST_SUITE(DSA);
        ADD_TEST_SUITE_MSBLOB(DSA);
# ifndef OPENSSL_NO_RC4
        ADD_TEST_SUITE_PVK(DSA);
# endif
#endif
#ifndef OPENSSL_NO_EC
        ADD_TEST_SUITE(EC);
        ADD_TEST_SUITE(ED25519);
        ADD_TEST_SUITE(ED448);
        ADD_TEST_SUITE(X25519);
        ADD_TEST_SUITE(X448);
#endif
        ADD_TEST_SUITE(RSA);
        ADD_TEST_SUITE(RSA_PSS);
#ifndef OPENSSL_NO_DSA
        ADD_TEST_SUITE_MSBLOB(RSA);
# ifndef OPENSSL_NO_RC4
        ADD_TEST_SUITE_PVK(RSA);
# endif
#endif
    }

    return 1;
}

void cleanup_tests(void)
{
#ifndef OPENSSL_NO_DH
    FREE_DOMAIN_KEYS(DH);
    FREE_DOMAIN_KEYS(DHX);
#endif
#ifndef OPENSSL_NO_DSA
    FREE_DOMAIN_KEYS(DSA);
#endif
#ifndef OPENSSL_NO_EC
    FREE_DOMAIN_KEYS(EC);
    FREE_KEYS(ED25519);
    FREE_KEYS(ED448);
    FREE_KEYS(X25519);
    FREE_KEYS(X448);
#endif
    FREE_KEYS(RSA);
    FREE_KEYS(RSA_PSS);
}
