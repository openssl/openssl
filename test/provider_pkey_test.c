/*
 * Copyright 2021-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>
#include <string.h>
#include <openssl/provider.h>
#include <openssl/params.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include "testutil.h"
#include "fake_rsaprov.h"

static OSSL_LIB_CTX *libctx = NULL;
extern int key_deleted; /* From fake_rsaprov.c */

/* Fetch SIGNATURE method using a libctx and propq */
static int fetch_sig(OSSL_LIB_CTX *ctx, const char *alg, const char *propq,
                     OSSL_PROVIDER *expected_prov)
{
    OSSL_PROVIDER *prov;
    EVP_SIGNATURE *sig = EVP_SIGNATURE_fetch(ctx, "RSA", propq);
    int ret = 0;

    if (!TEST_ptr(sig))
        return 0;

    if (!TEST_ptr(prov = EVP_SIGNATURE_get0_provider(sig)))
        goto end;

    if (!TEST_ptr_eq(prov, expected_prov)) {
        TEST_info("Fetched provider: %s, Expected provider: %s",
                  OSSL_PROVIDER_get0_name(prov),
                  OSSL_PROVIDER_get0_name(expected_prov));
        goto end;
    }

    ret = 1;
end:
    EVP_SIGNATURE_free(sig);
    return ret;
}


static int test_pkey_sig(void)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    int i, ret = 0;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        return 0;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    /* Do a direct fetch to see it works */
    if (!TEST_true(fetch_sig(libctx, "RSA", "provider=fake-rsa", fake_rsa))
        || !TEST_true(fetch_sig(libctx, "RSA", "?provider=fake-rsa", fake_rsa)))
        goto end;

    /* Construct a pkey using precise propq to use our provider */
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA",
                                                   "provider=fake-rsa"))
        || !TEST_true(EVP_PKEY_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, NULL))
        || !TEST_ptr(pkey))
        goto end;

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* try exercising signature_init ops a few times */
    for (i = 0; i < 3; i++) {
        size_t siglen;

        /*
         * Create a signing context for our pkey with optional propq.
         * The sign init should pick both keymgmt and signature from
         * fake-rsa as the key is not exportable.
         */
        if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey,
                                                       "?provider=default")))
            goto end;

        /*
         * If this picks the wrong signature without realizing it
         * we can get a segfault or some internal error. At least watch
         * whether fake-rsa sign_init is exercised by calling sign.
         */
        if (!TEST_int_eq(EVP_PKEY_sign_init(ctx), 1))
            goto end;

        if (!TEST_int_eq(EVP_PKEY_sign(ctx, NULL, &siglen, NULL, 0), 1)
            || !TEST_size_t_eq(siglen, 256))
            goto end;

        EVP_PKEY_CTX_free(ctx);
        ctx = NULL;
    }

    ret = 1;

end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_alternative_keygen_init(void)
{
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    const OSSL_PROVIDER *provider;
    const char *provname;
    int ret = 0;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    /* first try without the fake RSA provider loaded */
    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", NULL)))
        goto end;

    if (!TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0))
        goto end;

    if (!TEST_ptr(provider = EVP_PKEY_CTX_get0_provider(ctx)))
        goto end;

    if (!TEST_ptr(provname = OSSL_PROVIDER_get0_name(provider)))
        goto end;

    if (!TEST_str_eq(provname, "default"))
        goto end;

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;

    /* now load fake RSA and try again */
    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        return 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA",
                                                   "?provider=fake-rsa")))
        goto end;

    if (!TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0))
        goto end;

    if (!TEST_ptr(provider = EVP_PKEY_CTX_get0_provider(ctx)))
        goto end;

    if (!TEST_ptr(provname = OSSL_PROVIDER_get0_name(provider)))
        goto end;

    if (!TEST_str_eq(provname, "fake-rsa"))
        goto end;

    ret = 1;

end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    EVP_PKEY_CTX_free(ctx);
    return ret;
}

static int test_pkey_eq(void)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    EVP_PKEY *pkey_fake = NULL;
    EVP_PKEY *pkey_dflt = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM *params = NULL;
    int ret = 0;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        return 0;

    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    /* Construct a public key for fake-rsa */
    if (!TEST_ptr(params = fake_rsa_key_params(0))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA",
                                                      "provider=fake-rsa"))
        || !TEST_true(EVP_PKEY_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pkey_fake, EVP_PKEY_PUBLIC_KEY,
                                        params))
        || !TEST_ptr(pkey_fake))
        goto end;

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    OSSL_PARAM_free(params);
    params = NULL;

    /* Construct a public key for default */
    if (!TEST_ptr(params = fake_rsa_key_params(0))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA",
                                                      "provider=default"))
        || !TEST_true(EVP_PKEY_fromdata_init(ctx))
        || !TEST_true(EVP_PKEY_fromdata(ctx, &pkey_dflt, EVP_PKEY_PUBLIC_KEY,
                                        params))
        || !TEST_ptr(pkey_dflt))
        goto end;

    EVP_PKEY_CTX_free(ctx);
    ctx = NULL;
    OSSL_PARAM_free(params);
    params = NULL;

    /* now test for equality */
    if (!TEST_int_eq(EVP_PKEY_eq(pkey_fake, pkey_dflt), 1))
        goto end;

    ret = 1;
end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey_fake);
    EVP_PKEY_free(pkey_dflt);
    OSSL_PARAM_free(params);
    return ret;
}

static int test_pkey_store(int idx)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_LOADER *loader = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info;
    const char *propq = idx == 0 ? "?provider=fake-rsa"
                                 : "?provider=default";

    /* It's important to load the default provider first for this test */
    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        goto end;

    if (!TEST_ptr(loader = OSSL_STORE_LOADER_fetch(libctx, "fake_rsa",
                                                   propq)))
        goto end;

    OSSL_STORE_LOADER_free(loader);

    if (!TEST_ptr(ctx = OSSL_STORE_open_ex("fake_rsa:test", libctx, propq,
                                           NULL, NULL, NULL, NULL, NULL)))
        goto end;

    while (!OSSL_STORE_eof(ctx)
           && (info = OSSL_STORE_load(ctx)) != NULL
           && pkey == NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
        OSSL_STORE_INFO_free(info);
        info = NULL;
    }

    if (!TEST_ptr(pkey) || !TEST_int_eq(EVP_PKEY_is_a(pkey, "RSA"), 1))
        goto end;

    ret = 1;

end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    OSSL_STORE_close(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static int test_pkey_delete(void)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_LOADER *loader = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    OSSL_STORE_INFO *info;
    const char *propq = "?provider=fake-rsa";

    /* It's important to load the default provider first for this test */
    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        goto end;

    if (!TEST_ptr(loader = OSSL_STORE_LOADER_fetch(libctx, "fake_rsa",
                                                   propq)))
        goto end;

    OSSL_STORE_LOADER_free(loader);

    /* First iteration: load key, check it, delete it */
    if (!TEST_ptr(ctx = OSSL_STORE_open_ex("fake_rsa:test", libctx, propq,
                                           NULL, NULL, NULL, NULL, NULL)))
        goto end;

    while (!OSSL_STORE_eof(ctx)
           && (info = OSSL_STORE_load(ctx)) != NULL
           && pkey == NULL) {
        if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_PKEY)
            pkey = OSSL_STORE_INFO_get1_PKEY(info);
        OSSL_STORE_INFO_free(info);
        info = NULL;
    }

    if (!TEST_ptr(pkey) || !TEST_int_eq(EVP_PKEY_is_a(pkey, "RSA"), 1))
        goto end;
    EVP_PKEY_free(pkey);
    pkey = NULL;

    if (!TEST_int_eq(OSSL_STORE_delete("fake_rsa:test", libctx, propq,
                                       NULL, NULL, NULL), 1))
        goto end;
    if (!TEST_int_eq(OSSL_STORE_close(ctx), 1))
        goto end;

    /* Second iteration: load key should fail */
    if (!TEST_ptr(ctx = OSSL_STORE_open_ex("fake_rsa:test", libctx, propq,
                                           NULL, NULL, NULL, NULL, NULL)))
        goto end;

    while (!OSSL_STORE_eof(ctx)) {
           info = OSSL_STORE_load(ctx);
	   if (!TEST_ptr_null(info))
               goto end;
    }

    ret = 1;

end:
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    OSSL_STORE_close(ctx);
    fake_rsa_restore_store_state();
    return ret;
}

static int fake_pw_read_string(UI *ui, UI_STRING *uis)
{
    const char *passphrase = FAKE_PASSPHRASE;

    if (UI_get_string_type(uis) == UIT_PROMPT) {
        UI_set_result(ui, uis, passphrase);
        return 1;
    }

    return 0;
}

static int test_pkey_store_open_ex(void)
{
    OSSL_PROVIDER *deflt = NULL;
    OSSL_PROVIDER *fake_rsa = NULL;
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_STORE_LOADER *loader = NULL;
    OSSL_STORE_CTX *ctx = NULL;
    const char *propq = "?provider=fake-rsa";
    UI_METHOD *ui_method = NULL;

    /* It's important to load the default provider first for this test */
    if (!TEST_ptr(deflt = OSSL_PROVIDER_load(libctx, "default")))
        goto end;

    if (!TEST_ptr(fake_rsa = fake_rsa_start(libctx)))
        goto end;

    if (!TEST_ptr(loader = OSSL_STORE_LOADER_fetch(libctx, "fake_rsa",
                                                   propq)))
        goto end;

    OSSL_STORE_LOADER_free(loader);

    if (!TEST_ptr(ui_method= UI_create_method("PW Callbacks")))
        goto end;

    if (UI_method_set_reader(ui_method, fake_pw_read_string))
        goto end;

    if (!TEST_ptr(ctx = OSSL_STORE_open_ex("fake_rsa:openpwtest", libctx, propq,
                                           ui_method, NULL, NULL, NULL, NULL)))
        goto end;

    /* retry w/o ui_method to ensure we actually enter pw checks and fail */
    OSSL_STORE_close(ctx);
    if (!TEST_ptr_null(ctx = OSSL_STORE_open_ex("fake_rsa:openpwtest", libctx,
                                                propq, NULL, NULL, NULL, NULL,
                                                NULL)))
        goto end;

    ret = 1;

end:
    UI_destroy_method(ui_method);
    fake_rsa_finish(fake_rsa);
    OSSL_PROVIDER_unload(deflt);
    OSSL_STORE_close(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

#define DEFAULT_PROVIDER_IDX    0
#define FAKE_RSA_PROVIDER_IDX   1

static int reset_ctx_providers(OSSL_LIB_CTX **ctx, OSSL_PROVIDER *providers[2], const char *prop)
{
    OSSL_PROVIDER_unload(providers[DEFAULT_PROVIDER_IDX]);
    providers[DEFAULT_PROVIDER_IDX] = NULL;
    fake_rsa_finish(providers[FAKE_RSA_PROVIDER_IDX]);
    providers[FAKE_RSA_PROVIDER_IDX] = NULL;
    OSSL_LIB_CTX_free(*ctx);
    *ctx = NULL;

    if (!TEST_ptr(*ctx = OSSL_LIB_CTX_new())
        || !TEST_ptr(providers[DEFAULT_PROVIDER_IDX] = OSSL_PROVIDER_load(*ctx, "default"))
        || !TEST_ptr(providers[FAKE_RSA_PROVIDER_IDX] = fake_rsa_start(*ctx))
        || !TEST_true(EVP_set_default_properties(*ctx, prop)))
        return 0;
    return 1;
}

struct test_pkey_decoder_properties_t {
    const char *provider_props;
    const char *explicit_props;
    int curr_provider_idx;
};

static int test_pkey_provider_decoder_props(void)
{
    OSSL_LIB_CTX *my_libctx = NULL;
    OSSL_PROVIDER *providers[2] = { NULL };
    struct test_pkey_decoder_properties_t properties_test[] = {
        { "?provider=fake-rsa", NULL, FAKE_RSA_PROVIDER_IDX },
        { "?provider=default", NULL, DEFAULT_PROVIDER_IDX },
        { NULL, "?provider=fake-rsa", FAKE_RSA_PROVIDER_IDX },
        { NULL, "?provider=default", DEFAULT_PROVIDER_IDX },
        { NULL, "provider=fake-rsa", FAKE_RSA_PROVIDER_IDX },
        { NULL, "provider=default", DEFAULT_PROVIDER_IDX },
    };
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    BIO *bio_priv = NULL;
    unsigned char *encoded_pub = NULL;
    int len_pub;
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *p8 = NULL;
    size_t i;
    int ret = 0;

    if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", "provider=default"))
        || !TEST_int_gt(EVP_PKEY_keygen_init(ctx), 0)
        || !TEST_int_gt(EVP_PKEY_keygen(ctx, &pkey), 0)
        || !TEST_ptr(bio_priv = BIO_new(BIO_s_mem()))
        || !TEST_true(PEM_write_bio_PrivateKey(bio_priv, pkey, NULL, NULL, 0, NULL, NULL))
        || !TEST_int_gt((len_pub = i2d_PUBKEY(pkey, &encoded_pub)), 0)
        || !TEST_ptr(p8 = EVP_PKEY2PKCS8(pkey)))
        goto end;
    EVP_PKEY_free(pkey);
    pkey = NULL;

    for (i = 0; i < OSSL_NELEM(properties_test); i++) {
        const char *libctx_prop = properties_test[i].provider_props;
        const char *explicit_prop = properties_test[i].explicit_props;
        /* *curr_provider will be updated in reset_ctx_providers */
        OSSL_PROVIDER **curr_provider = &providers[properties_test[i].curr_provider_idx];

        /*
         * Decoding a PEM-encoded key uses the properties to select the right provider.
         * Using a PEM-encoding adds an extra decoder before the key is created.
         */
        if (!TEST_int_eq(reset_ctx_providers(&my_libctx, providers, libctx_prop), 1))
            goto end;
        if (!TEST_int_ge(BIO_seek(bio_priv, 0), 0)
            || !TEST_ptr(pkey = PEM_read_bio_PrivateKey_ex(bio_priv, NULL, NULL, NULL, my_libctx,
                                                           explicit_prop))
            || !TEST_ptr_eq(EVP_PKEY_get0_provider(pkey), *curr_provider))
            goto end;
        EVP_PKEY_free(pkey);
        pkey = NULL;

        /* Decoding a DER-encoded X509_PUBKEY uses the properties to select the right provider */
        if (!TEST_int_eq(reset_ctx_providers(&my_libctx, providers, libctx_prop), 1))
            goto end;
        p = encoded_pub;
        if (!TEST_ptr(pkey = d2i_PUBKEY_ex(NULL, &p, len_pub, my_libctx, explicit_prop))
            || !TEST_ptr_eq(EVP_PKEY_get0_provider(pkey), *curr_provider))
            goto end;
        EVP_PKEY_free(pkey);
        pkey = NULL;

        /* Decoding a PKCS8_PRIV_KEY_INFO uses the properties to select the right provider */
        if (!TEST_int_eq(reset_ctx_providers(&my_libctx, providers, libctx_prop), 1))
            goto end;
        if (!TEST_ptr(pkey = EVP_PKCS82PKEY_ex(p8, my_libctx, explicit_prop))
            || !TEST_ptr_eq(EVP_PKEY_get0_provider(pkey), *curr_provider))
            goto end;
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

    ret = 1;

end:
    PKCS8_PRIV_KEY_INFO_free(p8);
    BIO_free(bio_priv);
    OPENSSL_free(encoded_pub);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    OSSL_PROVIDER_unload(providers[DEFAULT_PROVIDER_IDX]);
    fake_rsa_finish(providers[FAKE_RSA_PROVIDER_IDX]);
    OSSL_LIB_CTX_free(my_libctx);
    return ret;
}

int setup_tests(void)
{
    libctx = OSSL_LIB_CTX_new();
    if (libctx == NULL)
        return 0;

    ADD_TEST(test_pkey_sig);
    ADD_TEST(test_alternative_keygen_init);
    ADD_TEST(test_pkey_eq);
    ADD_ALL_TESTS(test_pkey_store, 2);
    ADD_TEST(test_pkey_delete);
    ADD_TEST(test_pkey_store_open_ex);
    ADD_TEST(test_pkey_provider_decoder_props);

    return 1;
}

void cleanup_tests(void)
{
    OSSL_LIB_CTX_free(libctx);
}
