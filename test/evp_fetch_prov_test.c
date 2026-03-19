/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * SHA256 low level APIs are deprecated for public use, but still ok for
 * internal use.  Note, that due to symbols not being exported, only the
 * #defines can be accessed.  In this case SHA256_CBLOCK.
 */
#include "internal/deprecated.h"

#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/provider.h>
#include "internal/sizes.h"
#include "testutil.h"
#include "crypto/evp.h"
#include "../crypto/evp/evp_local.h"

static char *config_file = NULL;
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
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

const OPTIONS *test_get_options(void)
{
    static const OPTIONS test_options[] = {
        OPT_TEST_OPTIONS_WITH_EXTRA_USAGE("[provname...]\n"),
        { "config", OPT_CONFIG_FILE, '<', "The configuration file to use for the libctx" },
        { "type", OPT_ALG_FETCH_TYPE, 's', "The fetch type to test" },
        { "property", OPT_FETCH_PROPERTY, 's', "The fetch property e.g. provider=fips" },
        { "fetchfail", OPT_FETCH_FAILURE, '-', "fetch is expected to fail" },
        { "defaultctx", OPT_USE_DEFAULTCTX, '-',
            "Use the default context if this is set" },
        { OPT_HELP_STR, 1, '-', "file\tProvider names to explicitly load\n" },
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
        || !TEST_true(md == EVP_MD_CTX_get0_md(ctx)))
        goto err;

    ret = 1;
err:
    EVP_MD_CTX_free(ctx);
    return ret;
}

static int load_providers(OSSL_LIB_CTX **libctx, OSSL_PROVIDER *prov[])
{
    OSSL_LIB_CTX *ctx = NULL;
    int ret = 0;
    size_t i;

    ctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(OSSL_LIB_CTX_load_config(ctx, config_file)))
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
    if (ret == 0)
        OSSL_LIB_CTX_free(ctx);
    return ret;
}

static void unload_providers(OSSL_LIB_CTX **libctx, OSSL_PROVIDER *prov[])
{
    if (prov[0] != NULL)
        OSSL_PROVIDER_unload(prov[0]);
    if (prov[1] != NULL)
        OSSL_PROVIDER_unload(prov[1]);
    /* Not normally needed, but we would like to test that
     * OPENSSL_thread_stop_ex() behaves as expected.
     */
    if (libctx != NULL && *libctx != NULL) {
        OPENSSL_thread_stop_ex(*libctx);
        OSSL_LIB_CTX_free(*libctx);
    }
}

static int test_legacy_provider_unloaded(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    int rc = 0;

    ctx = OSSL_LIB_CTX_new();
    if (!TEST_ptr(ctx))
        goto err;

    if (!TEST_true(OSSL_LIB_CTX_load_config(ctx, config_file)))
        goto err;

    if (!TEST_int_eq(OSSL_PROVIDER_available(ctx, "legacy"), 0))
        goto err;

    rc = 1;
err:
    OSSL_LIB_CTX_free(ctx);
    return rc;
}

static X509_ALGOR *make_algor(int nid)
{
    X509_ALGOR *algor;

    if (!TEST_ptr(algor = X509_ALGOR_new())
        || !TEST_true(X509_ALGOR_set0(algor, OBJ_nid2obj(nid),
            V_ASN1_UNDEF, NULL))) {
        X509_ALGOR_free(algor);
        return NULL;
    }
    return algor;
}

/*
 * Test EVP_MD_fetch()
 */
static int test_md(const EVP_MD *md)
{
    const char testmsg[] = "Hello world";
    const unsigned char exptd[] = {
        0x27, 0x51, 0x8b, 0xa9, 0x68, 0x30, 0x11, 0xf6, 0xb3, 0x96, 0x07, 0x2c,
        0x05, 0xf6, 0x65, 0x6d, 0x04, 0xf5, 0xfb, 0xc3, 0x78, 0x7c, 0xf9, 0x24,
        0x90, 0xec, 0x60, 0x6e, 0x50, 0x92, 0xe3, 0x26
    };

    return TEST_ptr(md)
        && TEST_true(EVP_MD_is_a(md, "SHA256"))
        && TEST_true(calculate_digest(md, testmsg, sizeof(testmsg), exptd))
        && TEST_int_eq(EVP_MD_get_size(md), SHA256_DIGEST_LENGTH)
        && TEST_int_eq(EVP_MD_get_block_size(md), SHA256_CBLOCK);
}

static int test_implicit_EVP_MD_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    ret = (use_default_ctx == 0 || load_providers(&ctx, prov))
        && test_md(EVP_sha256());

    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_MD_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_MD *md = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    md = EVP_MD_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_md(md))
            goto err;

        /* Also test EVP_MD_up_ref() while we're doing this */
        if (!TEST_true(EVP_MD_up_ref(md)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_MD_free(md);
    } else {
        if (!TEST_ptr_null(md))
            goto err;
    }
    ret = 1;

err:
    EVP_MD_free(md);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_EVP_MD_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_MD *md = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_LIB_CTX *ctx2 = OSSL_LIB_CTX_new();
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(ctx2)
        || !TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", NULL))
        || !TEST_true(test_md(md))
        || !TEST_int_ne(md->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MD_free(md);
    md = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", NULL))
        || !TEST_true(test_md(md))
        || !TEST_int_eq(md->origin, EVP_ORIG_FROZEN)
        || !TEST_ptr(md = EVP_MD_fetch(ctx, "SHA-256", NULL))
        || !TEST_true(test_md(md))
        || !TEST_int_eq(md->origin, EVP_ORIG_FROZEN)
        || !TEST_ptr(md = EVP_MD_fetch(ctx, "2.16.840.1.101.3.4.2.1", NULL))
        || !TEST_true(test_md(md))
        || !TEST_int_eq(md->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_MD_free(md);

    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "?fips=true"))
        || !TEST_true(test_md(md))
        || !TEST_int_eq(md->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MD_free(md);

    /* Falls back to slow path */
    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA256", "?provider=default"))
        || !TEST_true(test_md(md))
        || !TEST_int_ne(md->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MD_free(md);

    if (!TEST_ptr(md = EVP_MD_fetch(ctx, "SHA1", NULL))
        || !TEST_int_eq(md->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MD_free(md);

    if (!TEST_ptr(md = EVP_MD_fetch(ctx2, "SHA1", "?fips=true"))
        || !TEST_int_ne(md->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MD_free(md);
    if (!TEST_ptr(md = EVP_MD_fetch(ctx2, "SHA1", NULL))
        || !TEST_int_ne(md->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    unload_providers(&ctx, prov);
    OSSL_LIB_CTX_free(ctx2);
    EVP_MD_free(md);
    return ret;
}

static int test_explicit_EVP_MD_fetch_by_name(void)
{
    return test_explicit_EVP_MD_fetch("SHA256");
}

/*
 * idx 0: Allow names from OBJ_obj2txt()
 * idx 1: Force an OID in text form from OBJ_obj2txt()
 */
static int test_explicit_EVP_MD_fetch_by_X509_ALGOR(int idx)
{
    int ret = 0;
    X509_ALGOR *algor = make_algor(NID_sha256);
    const ASN1_OBJECT *obj;
    char id[OSSL_MAX_NAME_SIZE] = { 0 };

    if (algor == NULL)
        return 0;

    X509_ALGOR_get0(&obj, NULL, NULL, algor);
    switch (idx) {
    case 0:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 0), 0))
            goto end;
        break;
    case 1:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 1), 0))
            goto end;
        break;
    }

    ret = test_explicit_EVP_MD_fetch(id);
end:
    X509_ALGOR_free(algor);
    return ret;
}

static int calculate_mac(const EVP_MAC *mac, const unsigned char *msg, size_t len,
    const unsigned char *expected, size_t expected_len)
{
    unsigned char out[EVP_MAX_MD_SIZE];
    const unsigned char key[] = "0123456789abcd";
    EVP_MAC_CTX *ctx = NULL;
    OSSL_PARAM params[2], *p = params;
    size_t out_len = 0;
    int ret = 0;

    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, "SHA256", 0);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_MAC_CTX_new((EVP_MAC *)mac))
        || !TEST_true(EVP_MAC_init(ctx, key, sizeof(key) - 1, params))
        || !TEST_true(EVP_MAC_update(ctx, msg, len))
        || !TEST_true(EVP_MAC_final(ctx, out, &out_len, sizeof(out)))
        || !TEST_size_t_eq(out_len, expected_len)
        || !TEST_mem_eq(out, out_len, expected, expected_len))
        goto err;

    ret = 1;
err:
    EVP_MAC_CTX_free(ctx);
    return ret;
}

static int test_mac(const EVP_MAC *mac)
{
    const unsigned char testmsg[] = "Hello world";
    const unsigned char expected[] = {
        0xf2, 0x71, 0x5a, 0xad, 0x1d, 0x68, 0x3c, 0xdd,
        0xbc, 0xa7, 0x5a, 0x1e, 0x79, 0xed, 0xac, 0x57,
        0xf6, 0xb0, 0xd4, 0xbb, 0x15, 0xe1, 0x7f, 0x6b,
        0x47, 0x62, 0x58, 0xb1, 0xbc, 0x0d, 0xf4, 0x4f
    };

    return TEST_ptr(mac)
        && TEST_true(EVP_MAC_is_a(mac, "HMAC"))
        && TEST_true(calculate_mac(mac, testmsg, sizeof(testmsg) - 1,
            expected, sizeof(expected)));
}

static int test_EVP_MAC_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_MAC *mac = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(mac = EVP_MAC_fetch(ctx, "HMAC", NULL))
        || !TEST_true(test_mac(mac))
        || !TEST_int_ne(mac->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MAC_free(mac);
    mac = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(mac = EVP_MAC_fetch(ctx, "HMAC", NULL))
        || !TEST_true(test_mac(mac))
        || !TEST_int_eq(mac->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_MAC_free(mac);
    mac = NULL;

    if (!TEST_ptr(mac = EVP_MAC_fetch(ctx, "HMAC", "?fips=true"))
        || !TEST_true(test_mac(mac))
        || !TEST_int_eq(mac->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_MAC_free(mac);
    mac = NULL;

    /* Falls back to slow path */
    if (!TEST_ptr(mac = EVP_MAC_fetch(ctx, "HMAC", "?provider=default"))
        || !TEST_true(test_mac(mac))
        || !TEST_int_ne(mac->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_MAC_free(mac);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_MAC_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    EVP_MAC *mac = NULL;
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(mac = EVP_MAC_fetch(ctx, "HMAC", NULL))
        || !TEST_true(test_mac(mac)))
        goto err;
    ret = 1;
err:
    EVP_MAC_free(mac);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_MAC_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_MAC *mac = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    mac = EVP_MAC_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_mac(mac))
            goto err;

        if (!TEST_true(EVP_MAC_up_ref(mac)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_MAC_free(mac);
    } else {
        if (!TEST_ptr_null(mac))
            goto err;
    }
    ret = 1;
err:
    EVP_MAC_free(mac);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_MAC_fetch_by_name(void)
{
    return test_explicit_EVP_MAC_fetch("HMAC");
}

static int derive_pbkdf2(EVP_KDF *kdf)
{
    int ret = 0;
    EVP_KDF_CTX *ctx = NULL;
    unsigned char out[25];
    static const unsigned char password[] = "passwordPASSWORDpassword";
    static const unsigned char salt[] = "saltSALTsaltSALTsaltSALTsaltSALTsalt";
    unsigned int iterations = 4096;
    int mode = 0;
    OSSL_PARAM params[6], *p = params;
    static const unsigned char expected[sizeof(out)] = {
        0x34, 0x8c, 0x89, 0xdb, 0xcb, 0xd3, 0x2b, 0x2f,
        0x32, 0xd8, 0x14, 0xb8, 0x11, 0x6e, 0x84, 0xcf,
        0x2b, 0x17, 0x34, 0x7e, 0xbc, 0x18, 0x00, 0x18,
        0x1c
    };

    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD,
        (void *)password,
        sizeof(password) - 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT,
        (void *)salt, sizeof(salt) - 1);
    *p++ = OSSL_PARAM_construct_uint(OSSL_KDF_PARAM_ITER, &iterations);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "sha256", 0);
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_PKCS5, &mode);
    *p = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx = EVP_KDF_CTX_new(kdf))
        || !TEST_int_gt(EVP_KDF_derive(ctx, out, sizeof(out), params), 0)
        || !TEST_mem_eq(out, sizeof(out), expected, sizeof(expected)))
        goto err;
    ret = 1;
err:
    EVP_KDF_CTX_free(ctx);
    return ret;
}

static int test_kdf(EVP_KDF *kdf, const char *name)
{
    return TEST_ptr(kdf)
        && TEST_ptr(EVP_KDF_get0_provider(kdf))
        && TEST_true(EVP_KDF_is_a(kdf, name))
        && TEST_true(derive_pbkdf2(kdf));
}

static int test_implicit_EVP_KDF_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    EVP_KDF *kdf = NULL;
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(kdf = EVP_KDF_fetch(ctx, OSSL_KDF_NAME_PBKDF2, NULL))
        || !TEST_true(test_kdf(kdf, OSSL_KDF_NAME_PBKDF2)))
        goto err;
    ret = 1;
err:
    EVP_KDF_free(kdf);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KDF_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_KDF *kdf = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    kdf = EVP_KDF_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_kdf(kdf, id))
            goto err;

        if (!TEST_true(EVP_KDF_up_ref(kdf)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_KDF_free(kdf);
    } else {
        if (!TEST_ptr_null(kdf))
            goto err;
    }
    ret = 1;
err:
    EVP_KDF_free(kdf);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_EVP_KDF_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_KDF *kdf = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(kdf = EVP_KDF_fetch(ctx, "PBKDF2", NULL))
        || !TEST_true(test_kdf(kdf, "PBKDF2"))
        || !TEST_int_ne(kdf->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KDF_free(kdf);
    kdf = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(kdf = EVP_KDF_fetch(ctx, "PBKDF2", NULL))
        || !TEST_true(test_kdf(kdf, "PBKDF2"))
        || !TEST_int_eq(kdf->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_KDF_free(kdf);
    kdf = NULL;

    if (!TEST_ptr(kdf = EVP_KDF_fetch(ctx, "PBKDF2", "?fips=true"))
        || !TEST_true(test_kdf(kdf, "PBKDF2"))
        || !TEST_int_eq(kdf->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KDF_free(kdf);
    kdf = NULL;

    /* Falls back to slow path */
    if (!TEST_ptr(kdf = EVP_KDF_fetch(ctx, "PBKDF2", "?provider=default"))
        || !TEST_true(test_kdf(kdf, "PBKDF2"))
        || !TEST_int_ne(kdf->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_KDF_free(kdf);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KDF_fetch_by_name(void)
{
    return test_explicit_EVP_KDF_fetch("PBKDF2");
}

/*
 * Test EVP_CIPHER_fetch()
 */
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
        || !TEST_true(EVP_CipherUpdate(ctx, ct, &ctlen, msg, (int)len))
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

static int test_cipher(const EVP_CIPHER *cipher)
{
    const unsigned char testmsg[] = "Hello world";

    return TEST_ptr(cipher)
        && TEST_true(encrypt_decrypt(cipher, testmsg, sizeof(testmsg)));
}

static int test_ec_keyexch(OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY_CTX *gctx1 = NULL, *gctx2 = NULL, *dctx = NULL;
    EVP_PKEY *key1 = NULL, *key2 = NULL;
    unsigned char secret1[256], secret2[256];
    size_t secret1_len = 0, secret2_len = 0;
    OSSL_PARAM params[2];
    int ret = 0;

    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
        "prime256v1", 0);
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(gctx1 = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq))
        || !TEST_true(EVP_PKEY_keygen_init(gctx1))
        || !TEST_true(EVP_PKEY_CTX_set_params(gctx1, params))
        || !TEST_true(EVP_PKEY_keygen(gctx1, &key1))
        || !TEST_ptr(gctx2 = EVP_PKEY_CTX_new_from_name(libctx, "EC", propq))
        || !TEST_true(EVP_PKEY_keygen_init(gctx2))
        || !TEST_true(EVP_PKEY_CTX_set_params(gctx2, params))
        || !TEST_true(EVP_PKEY_keygen(gctx2, &key2))
        || !TEST_ptr(dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key1, propq))
        || !TEST_true(EVP_PKEY_derive_init(dctx))
        || !TEST_true(EVP_PKEY_derive_set_peer(dctx, key2))
        || !TEST_true(EVP_PKEY_derive(dctx, NULL, &secret1_len))
        || !TEST_size_t_le(secret1_len, sizeof(secret1))
        || !TEST_true(EVP_PKEY_derive(dctx, secret1, &secret1_len)))
        goto end;

    EVP_PKEY_CTX_free(dctx);
    dctx = NULL;

    if (!TEST_ptr(dctx = EVP_PKEY_CTX_new_from_pkey(libctx, key2, propq))
        || !TEST_true(EVP_PKEY_derive_init(dctx))
        || !TEST_true(EVP_PKEY_derive_set_peer(dctx, key1))
        || !TEST_true(EVP_PKEY_derive(dctx, NULL, &secret2_len))
        || !TEST_size_t_le(secret2_len, sizeof(secret2))
        || !TEST_true(EVP_PKEY_derive(dctx, secret2, &secret2_len))
        || !TEST_size_t_eq(secret1_len, secret2_len)
        || !TEST_mem_eq(secret1, secret1_len, secret2, secret2_len))
        goto end;

    ret = 1;
end:
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_CTX_free(gctx1);
    EVP_PKEY_CTX_free(gctx2);
    EVP_PKEY_free(key1);
    EVP_PKEY_free(key2);
    return ret;
}

static int test_keymgmt(OSSL_LIB_CTX *libctx, const char *propq,
    const EVP_KEYMGMT *keymgmt, const char *name)
{
    return TEST_ptr(keymgmt)
        && TEST_ptr(EVP_KEYMGMT_get0_provider(keymgmt))
        && TEST_true(EVP_KEYMGMT_is_a(keymgmt, name))
        && test_ec_keyexch(libctx, propq);
}

static int test_ml_kem_keyexch(OSSL_LIB_CTX *libctx, const char *propq)
{
    int ret = 0;
    EVP_PKEY *privkey = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    unsigned char *ciphertext = NULL, *secret_enc = NULL, *secret_dec = NULL;
    size_t ciphertext_len = 0, secret_enc_len = 0, secret_dec_len = 0;

    if (!TEST_ptr(privkey = EVP_PKEY_Q_keygen(libctx, propq, "ML-KEM-768"))
        || !TEST_ptr(pctx = EVP_PKEY_CTX_new_from_pkey(libctx, privkey, propq))
        || !TEST_int_eq(EVP_PKEY_encapsulate_init(pctx, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_encapsulate(pctx, NULL, &ciphertext_len, NULL, &secret_enc_len), 1))
        goto err;

    ciphertext = OPENSSL_zalloc(ciphertext_len);
    secret_enc = OPENSSL_zalloc(secret_enc_len);
    if (!TEST_ptr(ciphertext)
        || !TEST_ptr(secret_enc)
        || !TEST_int_gt(EVP_PKEY_encapsulate(pctx, ciphertext, &ciphertext_len,
                            secret_enc, &secret_enc_len),
            0))
        goto err;

    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    if (!TEST_ptr(pctx = EVP_PKEY_CTX_new_from_pkey(libctx, privkey, propq))
        || !TEST_int_eq(EVP_PKEY_decapsulate_init(pctx, NULL), 1)
        || !TEST_int_eq(EVP_PKEY_decapsulate(pctx, NULL, &secret_dec_len, ciphertext, ciphertext_len), 1)
        || !TEST_size_t_eq(secret_dec_len, secret_enc_len))
        goto err;

    secret_dec = OPENSSL_zalloc(secret_dec_len);
    if (!TEST_ptr(secret_dec)
        || !TEST_int_gt(EVP_PKEY_decapsulate(pctx, secret_dec, &secret_dec_len,
                            ciphertext, ciphertext_len),
            0)
        || !TEST_size_t_eq(secret_dec_len, secret_enc_len)
        || !TEST_mem_eq(secret_dec, secret_dec_len, secret_enc, secret_enc_len))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(privkey);
    OPENSSL_free(ciphertext);
    OPENSSL_free(secret_enc);
    OPENSSL_free(secret_dec);
    EVP_PKEY_CTX_free(pctx);

    return ret;
}

static int test_kem(OSSL_LIB_CTX *libctx, const char *propq,
    const EVP_KEM *kem, const char *name)
{
    return TEST_ptr(kem)
        && TEST_ptr(EVP_KEM_get0_provider(kem))
        && TEST_true(EVP_KEM_is_a(kem, name))
        && test_ml_kem_keyexch(libctx, propq);
}

static int test_rsa_enc_dec(OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char plaintext[] = "Hello world";
    unsigned char *ciphertext = NULL, *decrypted = NULL;
    size_t ciphertext_len, decrypted_len;
    int ret = 0;

    /* Encrypt */
    if (!TEST_ptr(pkey = EVP_PKEY_Q_keygen(libctx, propq, "RSA", 4096))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq))
        || !TEST_int_eq(EVP_PKEY_encrypt_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), 1)
        || !TEST_int_eq(EVP_PKEY_encrypt(ctx, NULL, &ciphertext_len,
                            plaintext, sizeof(plaintext)),
            1)
        || !TEST_ptr(ciphertext = OPENSSL_malloc(ciphertext_len))
        || !TEST_int_eq(EVP_PKEY_encrypt(ctx, ciphertext, &ciphertext_len,
                            plaintext, sizeof(plaintext)),
            1))
        goto err;

    /* Decrypt */
    if (!TEST_int_eq(EVP_PKEY_decrypt_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING), 1)
        || !TEST_int_eq(EVP_PKEY_decrypt(ctx, NULL, &decrypted_len, ciphertext,
                            ciphertext_len),
            1)
        || !TEST_ptr(decrypted = OPENSSL_malloc(decrypted_len))
        || !TEST_int_eq(EVP_PKEY_decrypt(ctx, decrypted, &decrypted_len,
                            ciphertext, ciphertext_len),
            1)
        || !TEST_int_eq(strcasecmp((const char *)plaintext, (const char *)decrypted), 0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(ciphertext);
    OPENSSL_free(decrypted);

    return ret;
}

static int test_asym_cipher(EVP_ASYM_CIPHER *cipher, const char *name,
    OSSL_LIB_CTX *ctx, const char *propq)
{
    return TEST_ptr(cipher)
        && TEST_ptr(EVP_ASYM_CIPHER_get0_provider(cipher))
        && TEST_true(EVP_ASYM_CIPHER_is_a(cipher, name))
        && TEST_true(test_rsa_enc_dec(ctx, propq));
}

static int test_EVP_KEYMGMT_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH) || defined(OPENSSL_NO_EC)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_KEYMGMT *keymgmt = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "EC", NULL))
        || !TEST_true(test_keymgmt(ctx, NULL, keymgmt, "EC"))
        || !TEST_int_ne(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEYMGMT_free(keymgmt);
    keymgmt = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "EC", NULL))
        || !TEST_true(test_keymgmt(ctx, NULL, keymgmt, "EC"))
        || !TEST_int_eq(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEYMGMT_free(keymgmt);
    keymgmt = NULL;

    if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "EC", "?fips=true"))
        || !TEST_true(test_keymgmt(ctx, "?fips=true", keymgmt, "EC"))
        || !TEST_int_eq(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEYMGMT_free(keymgmt);
    keymgmt = NULL;

    if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "RSA", "?fips=true"))
        || !TEST_int_eq(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;
    if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "RSA", NULL))
        || !TEST_int_eq(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;

    /*
     * A mismatched propq should use the regular fetch path rather than the
     * frozen fast path.
     */
    if (!TEST_ptr(keymgmt = EVP_KEYMGMT_fetch(ctx, "EC", "?provider=default"))
        || !TEST_true(test_keymgmt(ctx, "?provider=default", keymgmt, "EC"))
        || !TEST_int_ne(keymgmt->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_KEYMGMT_free(keymgmt);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_KEYMGMT_fetch(void)
{
#if defined(OPENSSL_NO_EC)
    return 1;
#endif

    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    ret = test_ec_keyexch(ctx, NULL);
err:
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEYMGMT_fetch(const char *id)
{
#if defined(OPENSSL_NO_EC)
    return 1;
#endif

    OSSL_LIB_CTX *ctx = NULL;
    EVP_KEYMGMT *keymgmt = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    keymgmt = EVP_KEYMGMT_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_keymgmt(ctx, fetch_property, keymgmt, id))
            goto err;

        if (!TEST_true(EVP_KEYMGMT_up_ref(keymgmt)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_KEYMGMT_free(keymgmt);
    } else {
        if (!TEST_ptr_null(keymgmt))
            goto err;
    }
    ret = 1;
err:
    EVP_KEYMGMT_free(keymgmt);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEYMGMT_fetch_by_name(void)
{
    return test_explicit_EVP_KEYMGMT_fetch("EC");
}

static int test_explicit_EVP_KEYMGMT_fetch_by_X509_ALGOR(int idx)
{
#if defined(OPENSSL_NO_EC)
    return 1;
#endif

    int ret = 0;
    X509_ALGOR *algor = make_algor(NID_X9_62_id_ecPublicKey);
    const ASN1_OBJECT *obj;
    char id[OSSL_MAX_NAME_SIZE] = { 0 };

    if (algor == NULL)
        return 0;

    X509_ALGOR_get0(&obj, NULL, NULL, algor);
    switch (idx) {
    case 0:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 0), 0))
            goto end;
        break;
    case 1:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 1), 0))
            goto end;
        break;
    }

    ret = test_explicit_EVP_KEYMGMT_fetch(id);
end:
    X509_ALGOR_free(algor);
    return ret;
}

static int test_EVP_KEM_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH) || defined(OPENSSL_NO_ML_KEM)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_KEM *kem = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(kem = EVP_KEM_fetch(ctx, "ML-KEM-768", NULL))
        || !TEST_true(test_kem(ctx, NULL, kem, "ML-KEM-768"))
        || !TEST_int_ne(kem->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEM_free(kem);
    kem = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(kem = EVP_KEM_fetch(ctx, "ML-KEM-768", NULL))
        || !TEST_true(test_kem(ctx, NULL, kem, "ML-KEM-768"))
        || !TEST_int_eq(kem->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_KEM_free(kem);
    kem = NULL;

    if (!TEST_ptr(kem = EVP_KEM_fetch(ctx, "ML-KEM-768", "?fips=true"))
        || !TEST_true(test_kem(ctx, "?fips=true", kem, "ML-KEM-768"))
        || !TEST_int_eq(kem->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEM_free(kem);
    kem = NULL;

    /*
     * A mismatched propq should use the regular fetch path rather than the
     * frozen fast path.
     */
    if (!TEST_ptr(kem = EVP_KEM_fetch(ctx, "ML-KEM-768", "?provider=default"))
        || !TEST_true(test_kem(ctx, "?provider=default", kem, "ML-KEM-768"))
        || !TEST_int_ne(kem->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_KEM_free(kem);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEM_fetch(const char *id)
{
#if defined(OPENSSL_NO_ML_KEM)
    return 1;
#endif

    OSSL_LIB_CTX *ctx = NULL;
    EVP_KEM *kem = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    kem = EVP_KEM_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_kem(ctx, fetch_property, kem, id))
            goto err;

        if (!TEST_true(EVP_KEM_up_ref(kem)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_KEM_free(kem);
    } else {
        if (!TEST_ptr_null(kem))
            goto err;
    }
    ret = 1;
err:
    EVP_KEM_free(kem);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEM_fetch_by_name(void)
{
#if defined(OPENSSL_NO_ML_KEM)
    return 1;
#endif

    return test_explicit_EVP_KEM_fetch("ML-KEM-768");
}

/*
 * idx 0: Allow names from OBJ_obj2txt()
 * idx 1: Force an OID in text form from OBJ_obj2txt()
 */
static int test_explicit_EVP_KEM_fetch_by_X509_ALGOR(int idx)
{
#if defined(OPENSSL_NO_ML_KEM)
    return 1;
#endif

    int ret = 0;
    X509_ALGOR *algor = make_algor(NID_ML_KEM_768);
    const ASN1_OBJECT *obj;
    char id[OSSL_MAX_NAME_SIZE] = { 0 };

    if (algor == NULL)
        return 0;

    X509_ALGOR_get0(&obj, NULL, NULL, algor);
    switch (idx) {
    case 0:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 0), 0))
            goto end;
        break;
    case 1:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 1), 0))
            goto end;
        break;
    }

    ret = test_explicit_EVP_KEM_fetch(id);
end:
    X509_ALGOR_free(algor);
    return ret;
}

static int test_EVP_CIPHER_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_CIPHER *cipher = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", NULL))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_ne(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_CIPHER_free(cipher);

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", "?provider=default"))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_ne(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_CIPHER_free(cipher);
    cipher = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", NULL))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_CIPHER_free(cipher);

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", "?fips=true"))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_CIPHER_free(cipher);

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-CBC", "?provider=default"))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_ne(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_CIPHER_free(cipher);

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-ECB", "?fips=true"))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_CIPHER_free(cipher);
    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(ctx, "AES-128-ECB", NULL))
        || !TEST_true(test_cipher(cipher))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_CIPHER_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    ret = (use_default_ctx == 0 || load_providers(&ctx, prov))
        && test_cipher(EVP_aes_128_cbc());

    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_CIPHER_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    cipher = EVP_CIPHER_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!test_cipher(cipher))
            goto err;

        if (!TEST_true(EVP_CIPHER_up_ref(cipher)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_CIPHER_free(cipher);
    } else {
        if (!TEST_ptr_null(cipher))
            goto err;
    }
    ret = 1;
err:
    EVP_CIPHER_free(cipher);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_CIPHER_fetch_by_name(void)
{
    return test_explicit_EVP_CIPHER_fetch("AES-128-CBC");
}

/*
 * idx 0: Allow names from OBJ_obj2txt()
 * idx 1: Force an OID in text form from OBJ_obj2txt()
 */
static int test_explicit_EVP_CIPHER_fetch_by_X509_ALGOR(int idx)
{
    int ret = 0;
    X509_ALGOR *algor = make_algor(NID_aes_128_cbc);
    const ASN1_OBJECT *obj;
    char id[OSSL_MAX_NAME_SIZE] = { 0 };

    if (algor == NULL)
        return 0;

    X509_ALGOR_get0(&obj, NULL, NULL, algor);
    switch (idx) {
    case 0:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 0), 0))
            goto end;
        break;
    case 1:
        if (!TEST_int_gt(OBJ_obj2txt(id, sizeof(id), obj, 1), 0))
            goto end;
        break;
    }

    ret = test_explicit_EVP_CIPHER_fetch(id);
end:
    X509_ALGOR_free(algor);
    return ret;
}

static int test_EVP_RAND_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_RAND *rand = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "HASH-DRBG", NULL))
        || !TEST_int_ne(rand->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_RAND_free(rand);
    rand = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(rand = EVP_RAND_fetch(ctx, "HASH-DRBG", NULL))
        || !TEST_int_eq(rand->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_RAND_free(rand);
    rand = NULL;

    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "HASH-DRBG", "?fips=true"))
        || !TEST_int_eq(rand->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_RAND_free(rand);
    rand = NULL;

    /* Falls back to slow path */
    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "HASH-DRBG", "?provider=default"))
        || !TEST_int_ne(rand->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_RAND_free(rand);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_RAND_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    EVP_RAND *rand = NULL;
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(rand = EVP_RAND_fetch(ctx, "HASH-DRBG", NULL)))
        goto err;
    ret = 1;
err:
    EVP_RAND_free(rand);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_RAND_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_RAND *rand = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    rand = EVP_RAND_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!TEST_true(EVP_RAND_up_ref(rand)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_RAND_free(rand);
    } else {
        if (!TEST_ptr_null(rand))
            goto err;
    }
    ret = 1;
err:
    EVP_RAND_free(rand);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_RAND_fetch_by_name(void)
{
    return test_explicit_EVP_RAND_fetch("HASH-DRBG");
}

static int test_EVP_ASYM_CIPHER_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH) || defined(OPENSSL_NO_ML_KEM)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_ASYM_CIPHER *cipher = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(cipher = EVP_ASYM_CIPHER_fetch(ctx, "RSA", NULL))
        || !TEST_true(test_asym_cipher(cipher, "RSA", ctx, NULL))
        || !TEST_int_ne(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_ASYM_CIPHER_free(cipher);
    cipher = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(cipher = EVP_ASYM_CIPHER_fetch(ctx, "RSA", NULL))
        || !TEST_true(test_asym_cipher(cipher, "RSA", ctx, NULL))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_ASYM_CIPHER_free(cipher);

    if (!TEST_ptr(cipher = EVP_ASYM_CIPHER_fetch(ctx, "RSA", "?fips=true"))
        || !TEST_true(test_asym_cipher(cipher, "RSA", ctx, "?fips=true"))
        || !TEST_int_eq(cipher->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_ASYM_CIPHER_free(cipher);

    /*
     * A mismatched propq should use the regular fetch path rather than the
     * frozen fast path.
     */
    if (!TEST_ptr(cipher = EVP_ASYM_CIPHER_fetch(ctx, "RSA", "?provider=default"))
        || !TEST_true(test_asym_cipher(cipher, "RSA", ctx, "?provider=default"))
        || !TEST_int_ne(cipher->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_ASYM_CIPHER_free(cipher);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_ASYM_CIPHER_fetch(void)
{
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    EVP_ASYM_CIPHER *cipher = NULL;
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(cipher = EVP_ASYM_CIPHER_fetch(ctx, "RSA", NULL)))
        goto err;
    ret = 1;
err:
    EVP_ASYM_CIPHER_free(cipher);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_ASYM_CIPHER_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_ASYM_CIPHER *cipher = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    cipher = EVP_ASYM_CIPHER_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!TEST_true(EVP_ASYM_CIPHER_up_ref(cipher)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_ASYM_CIPHER_free(cipher);
    } else {
        if (!TEST_ptr_null(cipher))
            goto err;
    }
    ret = 1;
err:
    EVP_ASYM_CIPHER_free(cipher);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_ASYM_CIPHER_fetch_by_name(void)
{
    return test_explicit_EVP_ASYM_CIPHER_fetch("RSA");
}

static EVP_PKEY *generate_dh_key(void)
{
    EVP_PKEY_CTX *ctx;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", "ffdhe4096", 0),
        OSSL_PARAM_construct_end()
    };

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "DH", NULL))
        || !TEST_int_eq(EVP_PKEY_keygen_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_CTX_set_params(ctx, params), 1)
        || !TEST_int_eq(EVP_PKEY_keygen(ctx, &pkey), 1)) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

static int derive_secret(EVP_PKEY *priv, EVP_PKEY *peer,
    unsigned char **secret, size_t *secret_len)
{
    EVP_PKEY_CTX *ctx;
    int ret = 0;

    *secret = NULL;
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(NULL, priv, NULL))
        || !TEST_int_eq(EVP_PKEY_derive_init(ctx), 1)
        || !TEST_int_eq(EVP_PKEY_derive_set_peer(ctx, peer), 1)
        || !TEST_int_eq(EVP_PKEY_derive(ctx, NULL, secret_len), 1)
        || !TEST_ptr(*secret = OPENSSL_malloc(*secret_len))
        || !TEST_int_eq(EVP_PKEY_derive(ctx, *secret, secret_len), 1)) {
        OPENSSL_free(*secret);
        *secret = NULL;
        *secret_len = 0;
        goto err;
    }

    ret = 1;
err:
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_dh_derive(OSSL_LIB_CTX *libctx, const char *propq)
{
    EVP_PKEY *alice = NULL, *bob = NULL;
    unsigned char *secret1 = NULL, *secret2 = NULL;
    size_t secret1_len = 0, secret2_len = 0;
    int ret = 0;

    if (!TEST_ptr(alice = generate_dh_key())
        || !TEST_ptr(bob = generate_dh_key())
        || !TEST_int_eq(derive_secret(alice, bob, &secret1, &secret1_len), 1)
        || !TEST_size_t_gt(secret1_len, 0)
        || !TEST_int_eq(derive_secret(bob, alice, &secret2, &secret2_len), 1)
        || !TEST_size_t_gt(secret2_len, 0)
        || !TEST_size_t_eq(secret1_len, secret2_len)
        || !TEST_int_eq(memcmp(secret1, secret2, secret1_len), 0))
        goto err;

    ret = 1;
err:
    EVP_PKEY_free(alice);
    EVP_PKEY_free(bob);
    OPENSSL_free(secret1);
    OPENSSL_free(secret2);

    return ret;
}

static int test_keyexch(OSSL_LIB_CTX *ctx, const char *propq, EVP_KEYEXCH *exchange, const char *name)
{
    return TEST_ptr(exchange)
        && TEST_ptr(EVP_KEYEXCH_get0_provider(exchange))
        && TEST_true(EVP_KEYEXCH_is_a(exchange, name))
        && TEST_true(test_dh_derive(ctx, propq));
}

static int test_EVP_KEYEXCH_fetch_freeze(void)
{
#if defined(OPENSSL_NO_CACHED_FETCH) || defined(OPENSSL_NO_DH)
    /*
     * Test does not make sense if cached fetch is disabled.
     * There's nothing to freeze, and test will fail.
     */
    return 1;
#endif

    EVP_KEYEXCH *exchange = NULL;
    int ret = 0;
    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };

    if (use_default_ctx == 0 && !load_providers(&ctx, prov))
        goto err;

    if (!TEST_ptr(exchange = EVP_KEYEXCH_fetch(ctx, "DH", NULL))
        || !TEST_true(test_keyexch(ctx, NULL, exchange, "DH"))
        || !TEST_int_ne(exchange->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEYEXCH_free(exchange);
    exchange = NULL;

    if (!TEST_int_eq(OSSL_LIB_CTX_freeze(ctx, "?fips=true"), 1)
        || !TEST_ptr(exchange = EVP_KEYEXCH_fetch(ctx, "DH", NULL))
        || !TEST_true(test_keyexch(ctx, NULL, exchange, "DH"))
        || !TEST_int_eq(exchange->origin, EVP_ORIG_FROZEN))
        goto err;
    /* Technically, frozen version doesn't need to be freed */
    EVP_KEYEXCH_free(exchange);

    if (!TEST_ptr(exchange = EVP_KEYEXCH_fetch(ctx, "DH", "?fips=true"))
        || !TEST_true(test_keyexch(ctx, "?fips=true", exchange, "DH"))
        || !TEST_int_eq(exchange->origin, EVP_ORIG_FROZEN))
        goto err;
    EVP_KEYEXCH_free(exchange);

    /*
     * A mismatched propq should use the regular fetch path rather than the
     * frozen fast path.
     */
    if (!TEST_ptr(exchange = EVP_KEYEXCH_fetch(ctx, "DH", "?provider=default"))
        || !TEST_true(test_keyexch(ctx, "?provider=default", exchange, "DH"))
        || !TEST_int_ne(exchange->origin, EVP_ORIG_FROZEN))
        goto err;

    ret = 1;
err:
    EVP_KEYEXCH_free(exchange);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_implicit_EVP_KEYEXCH_fetch(void)
{
#if defined(OPENSSL_NO_DH)
    return 1;
#endif

    OSSL_LIB_CTX *ctx = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    EVP_KEYEXCH *exchange = NULL;
    int ret = 0;

    if (use_default_ctx == 0 && !TEST_true(load_providers(&ctx, prov)))
        goto err;

    if (!TEST_ptr(exchange = EVP_KEYEXCH_fetch(ctx, "DH", NULL)))
        goto err;

    ret = 1;
err:
    EVP_KEYEXCH_free(exchange);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEYEXCH_fetch(const char *id)
{
    OSSL_LIB_CTX *ctx = NULL;
    EVP_KEYEXCH *exchange = NULL;
    OSSL_PROVIDER *prov[2] = { NULL, NULL };
    int ret = 0;

    if (use_default_ctx == 0 && !TEST_true(load_providers(&ctx, prov)))
        goto err;

    exchange = EVP_KEYEXCH_fetch(ctx, id, fetch_property);
    if (expected_fetch_result != 0) {
        if (!TEST_true(EVP_KEYEXCH_up_ref(exchange)))
            goto err;
        /* Ref count should now be 2. Release first one here */
        EVP_KEYEXCH_free(exchange);
    } else {
        if (!TEST_ptr_null(exchange))
            goto err;
    }
    ret = 1;
err:
    EVP_KEYEXCH_free(exchange);
    unload_providers(&ctx, prov);
    return ret;
}

static int test_explicit_EVP_KEYEXCH_fetch_by_name(void)
{
#if defined(OPENSSL_NO_DH)
    return 1;
#endif

    return test_explicit_EVP_KEYEXCH_fetch("DH");
}

int setup_tests(void)
{
    OPTION_CHOICE o;

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            break;
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
    ADD_TEST(test_legacy_provider_unloaded);
    if (strcmp(alg, "digest") == 0) {
        ADD_TEST(test_EVP_MD_fetch_freeze);
        ADD_TEST(test_implicit_EVP_MD_fetch);
        ADD_TEST(test_explicit_EVP_MD_fetch_by_name);
        ADD_ALL_TESTS_NOSUBTEST(test_explicit_EVP_MD_fetch_by_X509_ALGOR, 2);
    } else if (strcmp(alg, "cipher") == 0) {
        ADD_TEST(test_EVP_CIPHER_fetch_freeze);
        ADD_TEST(test_implicit_EVP_CIPHER_fetch);
        ADD_TEST(test_explicit_EVP_CIPHER_fetch_by_name);
        ADD_ALL_TESTS_NOSUBTEST(test_explicit_EVP_CIPHER_fetch_by_X509_ALGOR, 2);
    } else if (strcmp(alg, "kdf") == 0) {
        ADD_TEST(test_EVP_KDF_fetch_freeze);
        ADD_TEST(test_implicit_EVP_KDF_fetch);
        ADD_TEST(test_explicit_EVP_KDF_fetch_by_name);
    } else if (strcmp(alg, "rand") == 0) {
        ADD_TEST(test_EVP_RAND_fetch_freeze);
        ADD_TEST(test_implicit_EVP_RAND_fetch);
        ADD_TEST(test_explicit_EVP_RAND_fetch_by_name);
    } else if (strcmp(alg, "mac") == 0) {
        ADD_TEST(test_EVP_MAC_fetch_freeze);
        ADD_TEST(test_implicit_EVP_MAC_fetch);
        ADD_TEST(test_explicit_EVP_MAC_fetch_by_name);
    } else if (strcmp(alg, "kmgmt") == 0) {
        ADD_TEST(test_EVP_KEYMGMT_fetch_freeze);
        ADD_TEST(test_implicit_EVP_KEYMGMT_fetch);
        ADD_TEST(test_explicit_EVP_KEYMGMT_fetch_by_name);
        ADD_ALL_TESTS_NOSUBTEST(test_explicit_EVP_KEYMGMT_fetch_by_X509_ALGOR, 2);
    } else if (strcmp(alg, "kem") == 0) {
        ADD_TEST(test_EVP_KEM_fetch_freeze);
        ADD_TEST(test_explicit_EVP_KEM_fetch_by_name);
        ADD_ALL_TESTS_NOSUBTEST(test_explicit_EVP_KEM_fetch_by_X509_ALGOR, 2);
    } else if (strcmp(alg, "asymcipher") == 0) {
        ADD_TEST(test_EVP_ASYM_CIPHER_fetch_freeze);
        ADD_TEST(test_implicit_EVP_ASYM_CIPHER_fetch);
        ADD_TEST(test_explicit_EVP_ASYM_CIPHER_fetch_by_name);
    } else if (strcmp(alg, "evp_keyexch") == 0) {
        ADD_TEST(test_EVP_KEYEXCH_fetch_freeze);
        ADD_TEST(test_implicit_EVP_KEYEXCH_fetch);
        ADD_TEST(test_explicit_EVP_KEYEXCH_fetch_by_name);
    } else {
        TEST_error("Unknown fetch type: %s", alg);
        return 0;
    }
    return 1;
}
