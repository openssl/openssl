/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include "testutil.h"
#include "internal/nelem.h"

/* golden list of AEAD ciphers that should end up in aead_list */
static const char *const aead_algs[] = {
    /* always present: no-aes / no-gcm / no-ccm do not exist */
    "AES-128-GCM",
    "AES-192-GCM",
    "AES-256-GCM",
    "AES-128-CCM",
    "AES-192-CCM",
    "AES-256-CCM",
#ifndef OPENSSL_NO_OCB
    "AES-128-OCB",
    "AES-192-OCB",
    "AES-256-OCB",
#endif
#ifndef OPENSSL_NO_SIV
    /* plain SIV and GCM-SIV share one guard: defltprov.c, build.info */
    "AES-128-SIV",
    "AES-192-SIV",
    "AES-256-SIV",
    "AES-128-GCM-SIV",
    "AES-192-GCM-SIV",
    "AES-256-GCM-SIV",
#endif
#if !defined(OPENSSL_NO_CHACHA) && !defined(OPENSSL_NO_POLY1305)
    "ChaCha20-Poly1305",
#endif
#ifndef OPENSSL_NO_ARIA
    "ARIA-128-GCM",
    "ARIA-192-GCM",
    "ARIA-256-GCM",
    "ARIA-128-CCM",
    "ARIA-192-CCM",
    "ARIA-256-CCM",
#endif
#ifndef OPENSSL_NO_SM4
    "SM4-GCM",
    "SM4-CCM", /* SM4 is 128-bit key only */
#endif
#ifndef OPENSSL_NO_ASCON128
    "ASCON-AEAD128",
#endif
};

/* maximum AEAD tag buffer size */
#define EVPTEST_TAG_LEN_MAX EVP_MAX_MD_SIZE

/* default AEAD tag length for standard modes (GCM, CCM, OCB, etc.) */
#define EVPTEST_TAG_LEN_DEFAULT 16

typedef struct {
    const EVP_CIPHER *ciph;
    const char *name;
    int keylen;
    int ivlen;
    int mode;
    int taglen;
    unsigned int found : 1;
} AEAD_DATA;

/* populated from aead_algs[] by setup_aead_list(); same indices */
static AEAD_DATA aead_list[OSSL_NELEM(aead_algs)];

static void collect_aead_cipher_cb(EVP_CIPHER *ciph, void *arg)
{
    const char *name = NULL;
    size_t i = 0;

    size_t *unknown = arg;

    if (ciph == NULL
        /*
         * Only collect AEAD ciphers for this test file.
         *
         * Note: unlike evp_extra_test.c's cipher_list, EVP_CIPH_SIV_MODE is
         * intentionally NOT excluded here -- it's a valid AEAD mode and this
         * test file exists in part to give it real coverage.
         */
        || (EVP_CIPHER_get_flags(ciph) & EVP_CIPH_FLAG_AEAD_CIPHER) == 0
        /*
         * Exclude legacy TLS Encrypt-then-MAC (ETM) ciphers.
         *
         * These are special-purpose stitched TLS ciphers with a
         * different calling sequence that breaks this test's logic.
         */
        || EVP_CIPHER_is_a(ciph, "AES-128-CBC-HMAC-SHA1")
        || EVP_CIPHER_is_a(ciph, "AES-256-CBC-HMAC-SHA1")
        || EVP_CIPHER_is_a(ciph, "AES-128-CBC-HMAC-SHA256")
        || EVP_CIPHER_is_a(ciph, "AES-256-CBC-HMAC-SHA256")
        || EVP_CIPHER_is_a(ciph, "AES-128-CBC-HMAC-SHA1-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-128-CBC-HMAC-SHA256-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-128-CBC-HMAC-SHA512-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-192-CBC-HMAC-SHA1-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-192-CBC-HMAC-SHA256-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-192-CBC-HMAC-SHA512-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-256-CBC-HMAC-SHA1-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-256-CBC-HMAC-SHA256-ETM")
        || EVP_CIPHER_is_a(ciph, "AES-256-CBC-HMAC-SHA512-ETM")
        /* fetch name */
        || (name = EVP_CIPHER_get0_name(ciph)) == NULL)
        return;

    /* TODO: debug for CI-only failure, remove */
    TEST_info("collect_aead_cipher_cb: discovered %s from provider %s", name,
        OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(ciph)));

    for (i = 0; i < OSSL_NELEM(aead_list); i++) {
        if (OPENSSL_strcasecmp(aead_list[i].name, name) == 0) {
            aead_list[i].found = 1;
            return;
        }
    }

    /* an AEAD the golden list does not know about */
    TEST_info("collect_aead_cipher_cb: %s discovered at runtime but not in"
              " aead_algs[]",
        name);
    (*unknown)++;
}

/*
 * Populate aead_list from aead_algs[]. If anything fails here, we abort
 * since tests expect a correctly populated list rather than a partial one.
 */
static int setup_aead_list(void)
{
    AEAD_DATA *info = NULL;
    size_t i;

    for (i = 0; i < OSSL_NELEM(aead_algs); i++) {
        info = &aead_list[i];

        if (!TEST_ptr(info->ciph = EVP_CIPHER_fetch(NULL, aead_algs[i], NULL))) {
            TEST_info("setup_aead_list: %s failed to fetch", aead_algs[i]);
            return 0;
        }

        info->name = aead_algs[i];
        info->keylen = EVP_CIPHER_get_key_length(info->ciph);
        info->ivlen = EVP_CIPHER_get_iv_length(info->ciph);
        info->mode = EVP_CIPHER_get_mode(info->ciph);
        info->taglen = EVPTEST_TAG_LEN_DEFAULT;
    }

    return 1;
}

static void cleanup_aead_list(void)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(aead_list); i++)
        EVP_CIPHER_free((EVP_CIPHER *)aead_list[i].ciph);
}

/*
 * CCM requires the total payload length to be declared up front (via an
 * EVP_CipherUpdate call with a NULL input buffer) before AAD or payload
 * can be processed. For a zero-length payload test, this declares a
 * length of 0, then feeds in AAD. For all other AEAD modes this is a
 * no-op.
 */
static int prepare_ccm_no_payload(EVP_CIPHER_CTX *ctx,
    const AEAD_DATA *info)
{
    static const unsigned char aad[] = "CCM empty-payload Final regression";
    int outlen = 0;

    if (info->mode != EVP_CIPH_CCM_MODE)
        return 1;

    return EVP_CipherUpdate(ctx, NULL, &outlen, NULL, 0) > 0
        && EVP_CipherUpdate(ctx, NULL, &outlen, aad,
               (int)sizeof(aad) - 1)
        > 0;
}

/*-
 * A zero-length AEAD message driven through the one-shot EVP_Cipher() interface
 * must agree with the streaming EVP_CipherFinal_ex() path. This checks:
 * - an empty message yields the same tag via both interfaces
 * - the true tag passes verification on decrypt
 * - the modified tag fails verification on decrypt
 * For CCM, each operation declares a zero payload length and supplies AAD, but
 * deliberately omits the payload Update that would otherwise authenticate it.
 */
static int test_evp_oneshot_aead_zerolen(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx_stream = NULL; /* reference: final only */
    EVP_CIPHER_CTX *ctx_oneshot = NULL; /* encrypt via EVP_Cipher(in == NULL) */
    EVP_CIPHER_CTX *ctx_dec = NULL; /* decrypt via EVP_Cipher(in == NULL) */
    EVP_CIPHER_CTX *ctx_dec_bad = NULL; /* decrypt with a corrupted tag */
    EVP_CIPHER_CTX *ctx_dec_s = NULL; /* streaming decrypt */
    EVP_CIPHER_CTX *ctx_dec_s_bad = NULL; /* streaming decrypt, corrupted tag */

    OSSL_PARAM get_tagparams[2];
    OSSL_PARAM set_tagparams[2];

    int taglen = info->taglen;
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };

    unsigned char ct[16] = { 0 }; /* scratch out; AEAD finalize writes no data */

    unsigned char tag_stream[EVPTEST_TAG_LEN_MAX] = { 0 };
    unsigned char tag_oneshot[EVPTEST_TAG_LEN_MAX] = { 0 };
    unsigned char tag_bad[EVPTEST_TAG_LEN_MAX] = { 0 };

    int i = 0, finlen = 0, testresult = 0;

    /* Adding more verbose testing output messages */
    TEST_info("test_evp_oneshot_aead_zerolen: idx=%d, cipher=%s", idx, info->name);

    for (i = 0; i < info->keylen; i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->ivlen; i++)
        iv[i] = (unsigned char)(0xB0 + i);

    /* reference: streaming finalize of an empty message */
    if (!TEST_ptr(ctx_stream = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_stream, info->ciph, key, iv,
            NULL))
        || !TEST_true(prepare_ccm_no_payload(ctx_stream, info))
        || !TEST_true(EVP_EncryptFinal_ex(ctx_stream, ct, &finlen))) {
        TEST_info("stream encrypt final (reference) failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /* clamp to the negotiated tag length if the cipher reports one */
    i = EVP_CIPHER_CTX_get_tag_length(ctx_stream);
    if (i > 0)
        taglen = i;

    /* bound the memcpy, should never happen but helps static analysis */
    if (!TEST_int_le(taglen, EVPTEST_TAG_LEN_MAX)) {
        TEST_info("tag length exceeds buffer: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    get_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_stream, taglen);
    get_tagparams[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx_stream, get_tagparams))) {
        TEST_info("stream get tag failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /* one-shot encrypt: finalize the empty message with in == NULL */
    if (!TEST_ptr(ctx_oneshot = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_oneshot, info->ciph, key, iv,
            NULL))
        || !TEST_true(prepare_ccm_no_payload(ctx_oneshot, info))
        || !TEST_int_ge(EVP_Cipher(ctx_oneshot, ct, NULL, 0), 0)) {
        TEST_info("one-shot encrypt final failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    get_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_oneshot, taglen);
    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx_oneshot, get_tagparams))
        || !TEST_mem_eq(tag_oneshot, taglen, tag_stream, taglen)) {
        TEST_info("one-shot get tag / compare failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /* one-shot decrypt: the correct tag must verify via in == NULL */
    set_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_stream, taglen);
    set_tagparams[1] = OSSL_PARAM_construct_end();
    if (!TEST_ptr(ctx_dec = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx_dec, set_tagparams))
        || !TEST_true(prepare_ccm_no_payload(ctx_dec, info))
        || !TEST_int_ge(EVP_Cipher(ctx_dec, ct, NULL, 0), 0)) {
        TEST_info("one-shot decrypt, good tag failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /*
     * ...and a corrupted tag must be rejected. EVP_Cipher() returns < 0 on a
     * failed one-shot, so a non-negative result here means verification was
     * skipped or wrongly accepted the bad tag.
     */
    memcpy(tag_bad, tag_stream, taglen);
    tag_bad[0] ^= 0x01;
    set_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_bad, taglen);
    if (!TEST_ptr(ctx_dec_bad = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec_bad, info->ciph, key, iv,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx_dec_bad, set_tagparams))
        || !TEST_true(prepare_ccm_no_payload(ctx_dec_bad, info))
        || !TEST_int_lt(EVP_Cipher(ctx_dec_bad, ct, NULL, 0), 0)) {
        TEST_info("one-shot decrypt, bad tag failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /* streaming decrypt: the correct tag must verify via EVP_DecryptFinal_ex */
    set_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_stream, taglen);
    if (!TEST_ptr(ctx_dec_s = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec_s, info->ciph, key, iv,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx_dec_s, set_tagparams))
        || !TEST_true(prepare_ccm_no_payload(ctx_dec_s, info))
        || !TEST_true(EVP_DecryptFinal_ex(ctx_dec_s, ct, &finlen))) {
        TEST_info("stream decrypt, good tag failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    /* streaming decrypt: a corrupted tag must be rejected */
    set_tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag_bad, taglen);
    if (!TEST_ptr(ctx_dec_s_bad = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec_s_bad, info->ciph, key, iv,
            NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx_dec_s_bad, set_tagparams))
        || !TEST_true(prepare_ccm_no_payload(ctx_dec_s_bad, info))
        || !TEST_false(EVP_DecryptFinal_ex(ctx_dec_s_bad, ct, &finlen))) {
        TEST_info("stream decrypt, bad tag failed: idx=%d cipher=%s"
                  " mode=%d keylen=%d ivlen=%d taglen=%d",
            idx, info->name, info->mode, info->keylen, info->ivlen,
            taglen);
        goto err;
    }

    testresult = 1;
err:
    EVP_CIPHER_CTX_free(ctx_stream);
    EVP_CIPHER_CTX_free(ctx_oneshot);
    EVP_CIPHER_CTX_free(ctx_dec);
    EVP_CIPHER_CTX_free(ctx_dec_bad);
    EVP_CIPHER_CTX_free(ctx_dec_s);
    EVP_CIPHER_CTX_free(ctx_dec_s_bad);
    return testresult;
}

/*
 * Regression test for EVP_CIPHER_do_all_provided(),
 * combined with a sanity check for expected AEAD algs in the static list.
 * - every cipher in aead_algs[] must be discovered (tracked by found)
 * - every discovered cipher must be in aead_algs[] (tracked by unknown)
 * Meant to catch:
 * - ciphers falling out of dynamic discovery for unexpected reasons
 * - ciphers discovered dynamically for unexpected reasons
 * Could happen for reasons like build system errors, flags shifting, etc.
 */
static int test_evp_aead_provided(void)
{
    size_t i, unknown = 0;
    int testresult = 0;

    EVP_CIPHER_do_all_provided(NULL, collect_aead_cipher_cb, &unknown);

    /* TODO: debug for CI-only failure, remove */
    TEST_info("test_evp_aead_provided: %zu golden, %zu unknown",
        OSSL_NELEM(aead_list), unknown);

    for (i = 0; i < OSSL_NELEM(aead_list); i++) {
        if (!TEST_true(aead_list[i].found)) {
            TEST_info("test_evp_aead_provided: %s NOT dynamically discovered",
                aead_list[i].name);
            goto err;
        }
    }

    if (!TEST_size_t_eq(unknown, 0))
        goto err;

    testresult = 1;
err:
    return testresult;
}

int setup_tests(void)
{
    if (!setup_aead_list())
        return 0;

    ADD_TEST(test_evp_aead_provided);
    ADD_ALL_TESTS(test_evp_oneshot_aead_zerolen, OSSL_NELEM(aead_list));
    return 1;
}

void cleanup_tests(void)
{
    cleanup_aead_list();
}
