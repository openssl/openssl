/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include "testutil.h"

static char *alg = "digest";
static int use_default_ctx = 0;
static char *fetch_property = NULL;
static int expected_fetch_result = 1;

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_ALG_FETCH_TYPE,
    OPT_FETCH_PROPERTY,
    OPT_FETCH_FAILURE,
    OPT_USE_DEFAULTCTX,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_WITH_EXTRA_USAGE("[provname...]\n"),
        { "type", OPT_ALG_FETCH_TYPE, 's', "The fetch type to test" },
        { "property", OPT_FETCH_PROPERTY, 's', "The fetch property e.g. fips=yes" },
        { "fetchfail", OPT_FETCH_FAILURE, '-', "fetch is expected to fail" },
        { "defaultctx", OPT_USE_DEFAULTCTX, '-',
          "Use the default context if this is set" },
        { OPT_HELP_STR, 1, '-',
          "file\tProvider names to explicitly load\n" },
        { NULL }
    };
    return test_options;
}

static int calculate_digest(const EVP_MD *md, const char *msg, size_t len,
                            const unsigned char *exptd)
{
    unsigned char out[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *ctx;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_MD_CTX_new())
            || !TEST_true(EVP_DigestInit_ex(ctx, md, NULL))
            || !TEST_true(EVP_DigestUpdate(ctx, msg, len))
            || !TEST_true(EVP_DigestFinal_ex(ctx, out, NULL))
            || !TEST_mem_eq(out, SHA256_DIGEST_LENGTH, exptd,
                            SHA256_DIGEST_LENGTH)
            || !TEST_true(md == EVP_MD_CTX_md(ctx)))
        goto err;

    ret = 1;
 err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int load_providers(OPENSSL_CTX **libctx, OSSL_PROVIDER *prov[])
{
    OPENSSL_CTX *ctx;
    int ret = 0;
    size_t i;

    ctx = OPENSSL_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (test_get_argument_count() > 2)
        goto err;

    for (i = 0; i < test_get_argument_count(); ++i) {
        char *provname = test_get_argument(i);
        prov[i] = OSSL_PROVIDER_load(ctx, provname);
        if (!TEST_ptr(prov[i]))
            goto err;
    }
    ret = 1;
    *libctx = ctx;
err:
    return ret;
}

/*
 * Test EVP_MD_fetch()
 */
static int test_EVP_MD_fetch(void)
{
    OPENSSL_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    OSSL_PROVIDER *prov[2] = {NULL, NULL};
    int ret = 0;
    const char testmsg[] = "Hello world";
    const unsigned char exptd[] = {
      0x27, 0x51, 0x8b, 0xa9, 0x68, 0x30, 0x11, 0xf6, 0xb3, 0x96, 0x07, 0x2c,
      0x05, 0xf6, 0x65, 0x6d, 0x04, 0xf5, 0xfb, 0xc3, 0x78, 0x7c, 0xf9, 0x24,
      0x90, 0xec, 0x60, 0x6e, 0x50, 0x92, 0xe3, 0x26
    };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    /* Implicit fetching of the MD should produce the expected result */
    if (!TEST_true(calculate_digest(EVP_sha256(), testmsg, sizeof(testmsg),
                                    exptd))
            || !TEST_int_eq(EVP_MD_size(EVP_sha256()), SHA256_DIGEST_LENGTH)
            || !TEST_int_eq(EVP_MD_block_size(EVP_sha256()), SHA256_CBLOCK))
        goto err;

    /* Fetch the digest from a provider using properties. */
    md = EVP_MD_fetch(ctx, "SHA256", fetch_property);
    if (expected_fetch_result != 0) {
        if (!TEST_ptr(md)
            || !TEST_int_eq(EVP_MD_nid(md), NID_sha256)
            || !TEST_true(calculate_digest(md, testmsg, sizeof(testmsg), exptd))
            || !TEST_int_eq(EVP_MD_size(md), SHA256_DIGEST_LENGTH)
            || !TEST_int_eq(EVP_MD_block_size(md), SHA256_CBLOCK))
        goto err;

        /* Also test EVP_MD_up_ref() while we're doing this */
        if (!TEST_true(EVP_MD_up_ref(md)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_MD_meth_free(md);
    } else {
        if (!TEST_ptr_null(md))
            goto err;
    }
    ret = 1;

err:
    EVP_MD_meth_free(md);
    OSSL_PROVIDER_unload(prov[0]);
    OSSL_PROVIDER_unload(prov[1]);
    /* Not normally needed, but we would like to test that
     * OPENSSL_thread_stop_ex() behaves as expected.
     */
    if (ctx != NULL) {
        OPENSSL_thread_stop_ex(ctx);
        OPENSSL_CTX_free(ctx);
    }
    return ret;
}

static int encrypt_decrypt(const EVP_CIPHER *cipher, const unsigned char *msg,
                           size_t len)
{
    int ret = 0, ctlen, ptlen;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[128 / 8];
    unsigned char ct[64], pt[64];

    memset(key, 0, sizeof(key));
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
            || !TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL, 1))
            || !TEST_true(EVP_CipherUpdate(ctx, ct, &ctlen, msg, len))
            || !TEST_true(EVP_CipherFinal_ex(ctx, ct, &ctlen))
            || !TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL, 0))
            || !TEST_true(EVP_CipherUpdate(ctx, pt, &ptlen, ct, ctlen))
            || !TEST_true(EVP_CipherFinal_ex(ctx, pt, &ptlen))
            || !TEST_mem_eq(pt, ptlen, msg, len))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

/*
 * Test EVP_CIPHER_fetch()
 */
static int test_EVP_CIPHER_fetch(void)
{
    OPENSSL_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    OSSL_PROVIDER *prov[2] = {NULL, NULL};
    int ret = 0;
    const unsigned char testmsg[] = "Hello world";

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    /* Implicit fetching of the cipher should produce the expected result */
    if (!TEST_true(encrypt_decrypt(EVP_aes_128_cbc(), testmsg, sizeof(testmsg))))
        goto err;

    /* Fetch the cipher from a provider using properties. */
    cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", fetch_property);
    if (expected_fetch_result != 0) {
        if (!TEST_ptr(cipher)
            || !TEST_true(encrypt_decrypt(cipher, testmsg, sizeof(testmsg)))) {
            if (!TEST_true(EVP_CIPHER_up_ref(cipher)))
                goto err;
            /* Ref count should now be 2. Release first one here */
            EVP_CIPHER_meth_free(cipher);
        }
    } else {
        if (!TEST_ptr_null(cipher))
            goto err;
    }
    ret = 1;
err:
    EVP_CIPHER_meth_free(cipher);
    OSSL_PROVIDER_unload(prov[0]);
    OSSL_PROVIDER_unload(prov[1]);
    OPENSSL_CTX_free(ctx);
    return ret;
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_ALG_FETCH_TYPE:
            alg = opt_arg();
            break;
        case OPT_FETCH_PROPERTY:
            fetch_property = opt_arg();
            break;
        case OPT_FETCH_FAILURE:
            expected_fetch_result = 0;
            break;
        case OPT_USE_DEFAULTCTX:
            use_default_ctx = 1;
            break;
        case OPT_TEST_CASES:
           break;
        default:
        case OPT_ERR:
            return 0;
        }
    }
    if (strcmp(alg, "digest") == 0)
        ADD_TEST(test_EVP_MD_fetch);
    else
        ADD_TEST(test_EVP_CIPHER_fetch);
    return 1;
}
