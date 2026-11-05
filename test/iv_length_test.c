/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Functions that generate an IV into a buffer of EVP_MAX_IV_LENGTH bytes must
 * reject ciphers with a longer IV. No built-in cipher has one, so a provider
 * registers a cipher with a 32-byte IV under a name that has an OID.
 */

#include <string.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/objects.h>
#include "testutil.h"

#define LONG_IV_PROV "long-iv"
#define LONG_IV_PROPQ "provider=long-iv"
#define LONG_IV_CIPHER "AES-128-OFB"
#define LONG_IV_KEYLEN 16
#define LONG_IV_IVLEN (EVP_MAX_IV_LENGTH * 2)

static OSSL_LIB_CTX *libctx = NULL;
static OSSL_PROVIDER *deflt = NULL;
static OSSL_PROVIDER *longiv = NULL;
static EVP_CIPHER *cipher = NULL;

static int dummy_ctx;

static void *longiv_newctx(void *provctx)
{
    return &dummy_ctx;
}

static void *longiv_dupctx(void *ctx)
{
    return &dummy_ctx;
}

static void longiv_freectx(void *ctx)
{
}

static int longiv_init(void *ctx, const unsigned char *key, size_t keylen,
    const unsigned char *iv, size_t ivlen,
    const OSSL_PARAM params[])
{
    return 1;
}

static int longiv_update(void *ctx, unsigned char *out, size_t *outl,
    size_t outsize, const unsigned char *in, size_t inl)
{
    if (outsize < inl)
        return 0;
    if (inl > 0)
        memmove(out, in, inl);
    *outl = inl;
    return 1;
}

static int longiv_final(void *ctx, unsigned char *out, size_t *outl,
    size_t outsize)
{
    *outl = 0;
    return 1;
}

static int longiv_set_lengths(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, LONG_IV_KEYLEN))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN)) != NULL
        && !OSSL_PARAM_set_size_t(p, LONG_IV_IVLEN))
        return 0;
    return 1;
}

static int longiv_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE)) != NULL
        && !OSSL_PARAM_set_size_t(p, 1))
        return 0;
    if ((p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_MODE)) != NULL
        && !OSSL_PARAM_set_uint(p, EVP_CIPH_OFB_MODE))
        return 0;
    return longiv_set_lengths(params);
}

static int longiv_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
    return longiv_set_lengths(params);
}

static const OSSL_PARAM longiv_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_BLOCK_SIZE, NULL),
    OSSL_PARAM_uint(OSSL_CIPHER_PARAM_MODE, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *longiv_gettable_params(void *provctx)
{
    return longiv_params;
}

static const OSSL_PARAM *longiv_gettable_ctx_params(void *ctx, void *provctx)
{
    return longiv_params + 2;
}

static const OSSL_DISPATCH longiv_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (void (*)(void))longiv_newctx },
    { OSSL_FUNC_CIPHER_DUPCTX, (void (*)(void))longiv_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void))longiv_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))longiv_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))longiv_init },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))longiv_update },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))longiv_final },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void))longiv_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (void (*)(void))longiv_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (void (*)(void))longiv_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
        (void (*)(void))longiv_gettable_ctx_params },
    OSSL_DISPATCH_END
};

static const OSSL_ALGORITHM longiv_ciphers[] = {
    { LONG_IV_CIPHER, LONG_IV_PROPQ, longiv_cipher_functions },
    { NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *longiv_query(void *provctx, int operation_id,
    int *no_cache)
{
    *no_cache = 0;
    return operation_id == OSSL_OP_CIPHER ? longiv_ciphers : NULL;
}

static const OSSL_DISPATCH longiv_dispatch[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))longiv_query },
    OSSL_DISPATCH_END
};

static int longiv_provider_init(const OSSL_CORE_HANDLE *handle,
    const OSSL_DISPATCH *in,
    const OSSL_DISPATCH **out, void **provctx)
{
    *provctx = (void *)handle;
    *out = longiv_dispatch;
    return 1;
}

static int test_pbe2(void)
{
    X509_ALGOR *alg = PKCS5_pbe2_set_iv_ex(cipher, 2048, NULL, 0, NULL, -1,
        libctx);

    X509_ALGOR_free(alg);
    return TEST_ptr_null(alg);
}

#ifndef OPENSSL_NO_SCRYPT
static int test_pbe2_scrypt(void)
{
    X509_ALGOR *alg = PKCS5_pbe2_set_scrypt(cipher, NULL, 0, NULL, 1024, 8, 1);

    X509_ALGOR_free(alg);
    return TEST_ptr_null(alg);
}
#endif

static int test_pkcs12_pbe(void)
{
    X509_ALGOR *alg = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    if (!TEST_ptr(alg = PKCS5_pbe_set_ex(NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
                      2048, NULL, 0, libctx))
        || !TEST_ptr(ctx = EVP_CIPHER_CTX_new()))
        goto err;
    ret = TEST_int_eq(PKCS12_PBE_keyivgen_ex(ctx, "password", 8,
                          alg->parameter, cipher, EVP_sha1(), 1,
                          libctx, NULL),
        0);
err:
    EVP_CIPHER_CTX_free(ctx);
    X509_ALGOR_free(alg);
    return ret;
}

static int test_pkcs7(void)
{
    PKCS7 *p7 = NULL;
    BIO *bio = NULL;
    int ret = 0;

    if (!TEST_ptr(p7 = PKCS7_new_ex(libctx, LONG_IV_PROPQ))
        || !TEST_true(PKCS7_set_type(p7, NID_pkcs7_enveloped))
        || !TEST_true(PKCS7_set_cipher(p7, cipher)))
        goto err;
    bio = PKCS7_dataInit(p7, NULL);
    ret = TEST_ptr_null(bio);
err:
    BIO_free_all(bio);
    PKCS7_free(p7);
    return ret;
}

#ifndef OPENSSL_NO_CMS
static int test_cms_encrypted_data(void)
{
    static const unsigned char key[LONG_IV_KEYLEN] = { 0 };
    BIO *in = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 0;

    if (!TEST_ptr(in = BIO_new_mem_buf("data", 4)))
        goto err;
    cms = CMS_EncryptedData_encrypt_ex(in, cipher, key, sizeof(key),
        CMS_BINARY, libctx, LONG_IV_PROPQ);
    ret = TEST_ptr_null(cms);
err:
    CMS_ContentInfo_free(cms);
    BIO_free(in);
    return ret;
}

static int test_cms_password_recipient(void)
{
    static unsigned char pass[] = "password";
    EVP_CIPHER *aes = NULL;
    CMS_ContentInfo *cms = NULL;
    CMS_RecipientInfo *ri = NULL;
    int ret = 0;

    if (!TEST_ptr(aes = EVP_CIPHER_fetch(libctx, "AES-128-CBC", "provider=default"))
        || !TEST_ptr(cms = CMS_EnvelopedData_create_ex(aes, libctx, NULL)))
        goto err;
    ri = CMS_add0_recipient_password(cms, -1, NID_undef, NID_undef, pass,
        sizeof(pass) - 1, cipher);
    ret = TEST_ptr_null(ri);
err:
    CMS_ContentInfo_free(cms);
    EVP_CIPHER_free(aes);
    return ret;
}
#endif

int setup_tests(void)
{
    if (!TEST_ptr(libctx = OSSL_LIB_CTX_new())
        || !TEST_true(OSSL_PROVIDER_add_builtin(libctx, LONG_IV_PROV,
            longiv_provider_init))
        || !TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default"))
        || !TEST_ptr(longiv = OSSL_PROVIDER_load(libctx, LONG_IV_PROV))
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(libctx, LONG_IV_CIPHER,
                         LONG_IV_PROPQ))
        || !TEST_int_eq(EVP_CIPHER_get_iv_length(cipher), LONG_IV_IVLEN)
        || !TEST_int_ne(EVP_CIPHER_get_type(cipher), NID_undef))
        return 0;

    ADD_TEST(test_pbe2);
#ifndef OPENSSL_NO_SCRYPT
    ADD_TEST(test_pbe2_scrypt);
#endif
    ADD_TEST(test_pkcs12_pbe);
    ADD_TEST(test_pkcs7);
#ifndef OPENSSL_NO_CMS
    ADD_TEST(test_cms_encrypted_data);
    ADD_TEST(test_cms_password_recipient);
#endif
    return 1;
}

void cleanup_tests(void)
{
    EVP_CIPHER_free(cipher);
    OSSL_PROVIDER_unload(longiv);
    OSSL_PROVIDER_unload(deflt);
    OSSL_LIB_CTX_free(libctx);
}
