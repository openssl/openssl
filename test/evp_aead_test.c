/*
 * Copyright 2023-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/proverr.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
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

static OSSL_LIB_CTX *testctx = NULL;
static char *testpropq = NULL;
/*
 * keylen, ivlen, mode and taglen start at defaults (upper bounds)
 * and are resolved by test_evp_aead_params()
 */
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
        /* defaults, resolved later by test_evp_aead_params() */
        info->keylen = EVP_MAX_KEY_LENGTH;
        info->ivlen = EVP_MAX_IV_LENGTH;
        info->mode = -1;
        info->taglen = EVPTEST_TAG_LEN_MAX;
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

/*
 * Every EVP-level view of an AEAD cipher must agree with the provider:
 * - OSSL_CIPHER_PARAM_KEYLEN / IVLEN / MODE via EVP_CIPHER_get_params()
 *   match EVP_CIPHER_get_key_length() / get_iv_length() / get_mode()
 * - OSSL_CIPHER_PARAM_AEAD_TAGLEN on a fresh ctx is non-zero and matches
 *   EVP_CIPHER_CTX_get_tag_length()
 * - all fit the fixed-size buffers used by the other tests
 *
 * Resolved values are written back into aead_list[idx].
 */
static int test_evp_aead_params(int idx)
{
    AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM params[4];
    size_t keylen = 0, ivlen = 0, taglen = 0;
    unsigned int mode = 0;
    int testresult = 0;

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_KEYLEN,
        &keylen);
    params[1] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_IVLEN,
        &ivlen);
    params[2] = OSSL_PARAM_construct_uint(OSSL_CIPHER_PARAM_MODE, &mode);
    params[3] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_get_params((EVP_CIPHER *)info->ciph, params))
        || !TEST_size_t_le(keylen, EVP_MAX_KEY_LENGTH)
        || !TEST_size_t_le(ivlen, EVP_MAX_IV_LENGTH)) {
        TEST_info("%s: cipher param query", info->name);
        goto err;
    }

    if (!TEST_int_eq(EVP_CIPHER_get_key_length(info->ciph), (int)keylen)
        || !TEST_int_eq(EVP_CIPHER_get_iv_length(info->ciph), (int)ivlen)
        || !TEST_int_eq(EVP_CIPHER_get_mode(info->ciph), (int)mode)) {
        TEST_info("%s: cipher accessors disagree with param query",
            info->name);
        goto err;
    }

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, info->ciph, NULL, NULL,
            NULL))) {
        TEST_info("%s: init", info->name);
        goto err;
    }

    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_TAGLEN,
        &taglen);
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx, params))
        || !TEST_size_t_gt(taglen, 0)
        || !TEST_size_t_le(taglen, EVPTEST_TAG_LEN_MAX)) {
        TEST_info("%s: taglen param query", info->name);
        goto err;
    }

    if (!TEST_int_eq(EVP_CIPHER_CTX_get_tag_length(ctx), (int)taglen)) {
        TEST_info("%s: taglen accessor disagrees with param query",
            info->name);
        goto err;
    }

    info->keylen = (int)keylen;
    info->ivlen = (int)ivlen;
    info->mode = (int)mode;
    info->taglen = (int)taglen;
    testresult = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return testresult;
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
 * With AEAD ciphers, associated data must precede the payload. Once plaintext
 * or ciphertext processing has begun, a further AAD update (out == NULL) must
 * be rejected, and the rejection must be reported the same way across every
 * AEAD: ERR_LIB_PROV / PROV_R_UPDATE_CALL_OUT_OF_ORDER. The invariant is
 * checked in both the encrypt and decrypt directions.
 */
static int test_evp_aead_late_aad(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx_enc = NULL; /* late AAD after plaintext: must fail */
    EVP_CIPHER_CTX *ctx_dec = NULL; /* late AAD after ciphertext: must fail */
    EVP_CIPHER_CTX *ctx_c_enc = NULL; /* as ctx_enc, EVP_Cipher() interface */
    EVP_CIPHER_CTX *ctx_c_dec = NULL; /* as ctx_dec, EVP_Cipher() interface */

    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char aad[] = "aad";
    unsigned char msg[] = "message";
    unsigned char out[sizeof(msg) + EVP_MAX_BLOCK_LENGTH];

    int i = 0, len = 0, testresult = 0;

    if (info->mode == EVP_CIPH_CCM_MODE /* fails at first AAD */
        || info->mode == EVP_CIPH_SIV_MODE /* accepts late AAD */
        || info->mode == EVP_CIPH_OCB_MODE) /* accepts late AAD */
        return 1;

    for (i = 0; i < info->keylen && i < (int)sizeof(key); i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->ivlen && i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(0xB0 + i);

    /* encrypt: aad, then plaintext, then a late aad update must be rejected */
    ERR_clear_error();
    if (!TEST_ptr(ctx_enc = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_enc, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx_enc, NULL, &len, aad, sizeof(aad)))
        || !TEST_true(EVP_EncryptUpdate(ctx_enc, out, &len, msg, sizeof(msg)))
        || !TEST_false(EVP_EncryptUpdate(ctx_enc, NULL, &len, aad, sizeof(aad)))
        || !TEST_err_r(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER)) {
        TEST_info("test_evp_aead_late_aad %s: encrypt", info->name);
        goto err;
    }

    /*
     * decrypt: same sequence, late aad after ciphertext must be rejected.
     * the ciphertext content is irrelevant; the tag is never finalized here.
     */
    ERR_clear_error();
    if (!TEST_ptr(ctx_dec = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_DecryptUpdate(ctx_dec, NULL, &len, aad, sizeof(aad)))
        || !TEST_true(EVP_DecryptUpdate(ctx_dec, out, &len, msg, sizeof(msg)))
        || !TEST_false(EVP_DecryptUpdate(ctx_dec, NULL, &len, aad, sizeof(aad)))
        || !TEST_err_r(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER)) {
        TEST_info("test_evp_aead_late_aad %s: decrypt", info->name);
        goto err;
    }

    /* encrypt, EVP_Cipher() interface: out == NULL is AAD, same as update */
    ERR_clear_error();
    if (!TEST_ptr(ctx_c_enc = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_c_enc, info->ciph, key, iv, NULL))
        || !TEST_int_ge(EVP_Cipher(ctx_c_enc, NULL, aad, sizeof(aad)), 0)
        || !TEST_int_ge(EVP_Cipher(ctx_c_enc, out, msg, sizeof(msg)), 0)
        || !TEST_int_lt(EVP_Cipher(ctx_c_enc, NULL, aad, sizeof(aad)), 0)
        || !TEST_err_r(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER)) {
        TEST_info("test_evp_aead_late_aad %s: encrypt (EVP_Cipher)", info->name);
        goto err;
    }

    /* decrypt, EVP_Cipher() interface */
    ERR_clear_error();
    if (!TEST_ptr(ctx_c_dec = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_c_dec, info->ciph, key, iv, NULL))
        || !TEST_int_ge(EVP_Cipher(ctx_c_dec, NULL, aad, sizeof(aad)), 0)
        || !TEST_int_ge(EVP_Cipher(ctx_c_dec, out, msg, sizeof(msg)), 0)
        || !TEST_int_lt(EVP_Cipher(ctx_c_dec, NULL, aad, sizeof(aad)), 0)
        || !TEST_err_r(ERR_LIB_PROV, PROV_R_UPDATE_CALL_OUT_OF_ORDER)) {
        TEST_info("test_evp_aead_late_aad %s: decrypt (EVP_Cipher)", info->name);
        goto err;
    }

    testresult = 1;
err:
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
    EVP_CIPHER_CTX_free(ctx_c_enc);
    EVP_CIPHER_CTX_free(ctx_c_dec);
    return testresult;
}

/*
 * After Final, a further Update on the same context must be rejected, both
 * encrypting and decrypting.
 *
 * TODO: also check the error reason (PROV_R_CIPHER_OPERATION_FAILED, as GCM
 * and CCM report); SIV, GCM-SIV and ChaCha20-Poly1305 currently reject
 * without raising one.
 */
static int test_evp_aead_finished_ctx(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx_enc = NULL;
    EVP_CIPHER_CTX *ctx_dec = NULL;

    OSSL_PARAM tagparams[2];

    int taglen = info->taglen;
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char tag[EVPTEST_TAG_LEN_MAX] = { 0 };

    static const unsigned char msg[] = "finished context regression";
    unsigned char ct[sizeof(msg) + EVP_MAX_BLOCK_LENGTH] = { 0 };
    unsigned char pt[sizeof(msg) + EVP_MAX_BLOCK_LENGTH] = { 0 };

    int i = 0, len = 0, testresult = 0;

    for (i = 0; i < info->keylen; i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->ivlen; i++)
        iv[i] = (unsigned char)(0xB0 + i);

    /* encrypt: Init, (CCM len), Update, Final */
    if (!TEST_ptr(ctx_enc = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_enc, info->ciph, key, iv, NULL))
        || (info->mode == EVP_CIPH_CCM_MODE
            && !TEST_true(EVP_EncryptUpdate(ctx_enc, NULL, &len, NULL,
                sizeof(msg))))
        || !TEST_true(EVP_EncryptUpdate(ctx_enc, ct, &len, msg, sizeof(msg)))
        || !TEST_true(EVP_EncryptFinal_ex(ctx_enc, ct + len, &len))) {
        TEST_info("%s: encrypt", info->name);
        goto err;
    }

    tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag, taglen);
    tagparams[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx_enc, tagparams))) {
        TEST_info("%s: encrypt get tag", info->name);
        goto err;
    }

    /* the finished encrypt context must reject another Update */
    if (!TEST_false(EVP_EncryptUpdate(ctx_enc, pt, &len, msg, sizeof(msg)))) {
        TEST_info("%s: encrypt Update after Final", info->name);
        goto err;
    }

    /* decrypt: Init, set tag, (CCM len), Update, Final, compare */
    if (!TEST_ptr(ctx_dec = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_CIPHER_CTX_set_params(ctx_dec, tagparams))
        || (info->mode == EVP_CIPH_CCM_MODE
            && !TEST_true(EVP_DecryptUpdate(ctx_dec, NULL, &len, NULL,
                sizeof(msg))))
        || !TEST_true(EVP_DecryptUpdate(ctx_dec, pt, &len, ct, sizeof(msg)))
        || !TEST_true(EVP_DecryptFinal_ex(ctx_dec, pt + len, &len))
        || !TEST_mem_eq(pt, sizeof(msg), msg, sizeof(msg))) {
        TEST_info("%s: decrypt", info->name);
        goto err;
    }

    /* the finished decrypt context must reject another Update */
    if (!TEST_false(EVP_DecryptUpdate(ctx_dec, pt, &len, ct, sizeof(msg)))) {
        TEST_info("%s: decrypt Update after Final", info->name);
        goto err;
    }

    testresult = 1;
err:
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
    return testresult;
}

/*-
 * Pairwise consistency of the two documented ways to read the tag from an
 * encrypt context after EVP_EncryptFinal_ex():
 * - EVP_CIPHER_CTX_ctrl(EVP_CTRL_AEAD_GET_TAG)
 * - EVP_CIPHER_CTX_get_params(OSSL_CIPHER_PARAM_AEAD_TAG)
 * Both are read-only per the manual, so on the same context each must succeed
 * and return the same bytes.
 */
static int test_evp_aead_get_tag_pairwise(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    OSSL_PARAM get_tagparams[2];
    static const unsigned char aad[] = "get tag pairwise";
    static const unsigned char pt[] = "ctrl and params must agree";
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char ct[sizeof(pt) + EVP_MAX_BLOCK_LENGTH] = { 0 };
    unsigned char tag_ctrl[EVPTEST_TAG_LEN_MAX] = { 0 };
    unsigned char tag_params[EVPTEST_TAG_LEN_MAX] = { 0 };
    int taglen = info->taglen;
    int i = 0, outlen = 0, finlen = 0, testresult = 0;

    for (i = 0; i < info->keylen; i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->ivlen; i++)
        iv[i] = (unsigned char)(0xB0 + i);

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, info->ciph, key, iv, NULL))
        /* ccm must be told the payload length before aad or payload */
        || (info->mode == EVP_CIPH_CCM_MODE
            && !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, NULL,
                (int)sizeof(pt) - 1)))
        || !TEST_true(EVP_EncryptUpdate(ctx, NULL, &outlen, aad,
            (int)sizeof(aad) - 1))
        || !TEST_true(EVP_EncryptUpdate(ctx, ct, &outlen, pt,
            (int)sizeof(pt) - 1))
        || !TEST_true(EVP_EncryptFinal_ex(ctx, ct + outlen, &finlen)))
        goto err;

    /* read via ctrl */
    if (!TEST_true(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, taglen,
            tag_ctrl))) {
        TEST_info("ctrl tag read failed: cipher=%s taglen=%d",
            info->name, taglen);
        goto err;
    }

    /* read via params, same context */
    get_tagparams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag_params, taglen);
    get_tagparams[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx, get_tagparams))) {
        TEST_info("params tag read failed: cipher=%s taglen=%d",
            info->name, taglen);
        goto err;
    }

    if (!TEST_mem_eq(tag_ctrl, taglen, tag_params, taglen)) {
        TEST_info("ctrl and params tags differ: cipher=%s taglen=%d",
            info->name, taglen);
        goto err;
    }

    testresult = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return testresult;
}

/*
 * Cross-driver round-trip test for AEAD one-shot vs streaming paths.
 *
 * The streaming path (EVP_CipherUpdate/Final, dispatched to
 * OSSL_FUNC_CIPHER_UPDATE/_FINAL) is treated as the oracle.  For each
 * AEAD configuration we encrypt and decrypt the same (key, iv, aad, pt),
 * driving the body in two combinations:
 *
 *   1.  body encrypt via EVP_Cipher() (one-shot, OSSL_FUNC_CIPHER_CIPHER),
 *       body decrypt via EVP_CipherUpdate (streaming).
 *   2.  body encrypt via EVP_CipherUpdate, body decrypt via EVP_Cipher().
 *
 * Both combinations must recover the plaintext and verify the tag.  AAD
 * is always fed via EVP_CipherUpdate(NULL, ...): OCB's one-shot is body
 * only and the asymmetric "AAD streaming, body one-shot" call shape is
 * the natural pattern a caller reaching for EVP_Cipher() for throughput
 * would write anyway.
 *
 * CVE-2026-45445 (AES-OCB EVP_Cipher() ignored IV) was a silent failure
 * in this matrix: the one-shot encrypt path produced ciphertext under
 * Offset_0 = 0 regardless of IV, which the streaming decrypt path then
 * could not verify.  Adding this cross-check catches the same class of
 * bug for any future AEAD whose one-shot dispatch diverges from its
 * streaming dispatch.
 */
typedef struct {
    const char *name; /* EVP_CIPHER fetch name */
    size_t keylen;
    size_t ivlen;
    size_t taglen;
    int is_ccm; /* needs length-up-front + tag-before-body dance */
} AEAD_ONESHOT_CFG;

static const AEAD_ONESHOT_CFG aead_oneshot_cfgs[] = {
    { "AES-128-GCM", 16, 12, 16, 0 },
    { "AES-256-GCM", 32, 12, 16, 0 },
    { "AES-128-CCM", 16, 12, 16, 1 },
    { "AES-256-CCM", 32, 12, 16, 1 },
    { "AES-128-OCB", 16, 12, 16, 0 },
    { "AES-256-OCB", 32, 12, 16, 0 },
    { "ChaCha20-Poly1305", 32, 12, 16, 0 }
};

static int aead_oneshot_op(const AEAD_ONESHOT_CFG *cfg, int enc,
    int oneshot_body, const unsigned char *key,
    const unsigned char *iv, const unsigned char *aad,
    size_t aad_len, const unsigned char *in, size_t in_len,
    unsigned char *out, unsigned char *tag, const char **why)
{
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *cipher = NULL;
    int outl = 0, tmpl = 0;
    int ok = 0;
    int body_rv;

    *why = NULL;

    if (!TEST_ptr(cipher = EVP_CIPHER_fetch(testctx, cfg->name, testpropq))) {
        *why = "CIPHER_FETCH";
        goto end;
    }
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())) {
        *why = "CTX_NEW";
        goto end;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc))) {
        *why = "INIT_CIPHER";
        goto end;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN,
                         (int)cfg->ivlen, NULL),
            0)) {
        *why = "SET_IVLEN";
        goto end;
    }
    if (cfg->is_ccm) {
        /* Placeholder taglen on encrypt, real tag on decrypt; both before key+iv. */
        if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                             (int)cfg->taglen, enc ? NULL : tag),
                0)) {
            *why = "CCM_SET_TAG";
            goto end;
        }
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, enc))) {
        *why = "INIT_KEY_IV";
        goto end;
    }
    if (cfg->is_ccm) {
        if (!TEST_true(EVP_CipherUpdate(ctx, NULL, &outl, NULL, (int)in_len))) {
            *why = "CCM_LEN_DECL";
            goto end;
        }
    }
    if (aad_len > 0
        && !TEST_true(EVP_CipherUpdate(ctx, NULL, &outl, aad, (int)aad_len))) {
        *why = "AAD";
        goto end;
    }
    if (!enc && !cfg->is_ccm
        && !TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG,
                            (int)cfg->taglen, tag),
            0)) {
        *why = "SET_TAG";
        goto end;
    }

    if (oneshot_body) {
        body_rv = EVP_Cipher(ctx, out, in, (unsigned int)in_len);
        if (cfg->is_ccm && !enc) {
            /* CCM decrypt: 0 means tag verify failed, < 0 means error. */
            if (!TEST_int_gt(body_rv, 0)) {
                *why = "ONESHOT_DECRYPT";
                goto end;
            }
        } else {
            if (!TEST_int_ge(body_rv, 0)) {
                *why = "ONESHOT_BODY";
                goto end;
            }
        }
        outl = (int)in_len;
    } else {
        if (!TEST_true(EVP_CipherUpdate(ctx, out, &outl, in, (int)in_len))) {
            *why = enc ? "STREAM_BODY_ENC" : "STREAM_BODY_DEC";
            goto end;
        }
    }

    if (!cfg->is_ccm) {
        if (!TEST_true(EVP_CipherFinal_ex(ctx, out + outl, &tmpl))) {
            *why = enc ? "FINAL_ENC" : "FINAL_DEC";
            goto end;
        }
    }

    if (enc) {
        if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                             (int)cfg->taglen, tag),
                0)) {
            *why = "GET_TAG";
            goto end;
        }
    }
    ok = 1;
end:
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);
    return ok;
}

/*
 * For each AEAD row we run two AAD modes, and within each AAD mode two
 * cross-driver round trips:
 *
 *   aad_mode 0:  no AAD.  Critical for catching the OCB-style bug: any
 *                EVP_CipherUpdate(NULL, aad, ...) call before the body
 *                would itself pass through the (correct) streaming
 *                handler and apply the buffered IV, masking the one-shot
 *                handler's failure to do so.  With aad_len == 0 we make
 *                EVP_Cipher() the very first cipher operation on the
 *                context, which is the shape the bug requires.
 *
 *   aad_mode 1:  with AAD via streaming.  Catches divergence between the
 *                drivers when AAD is in play.
 *
 *   leg 0:       encrypt-oneshot   + decrypt-streaming
 *   leg 1:       encrypt-streaming + decrypt-oneshot
 *
 * The test index encodes (cipher, aad_mode) so a failure points at both.
 */
static int test_aead_oneshot_roundtrip(int idx)
{
    static const unsigned char fixed_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    static const unsigned char fixed_iv[12] = {
        0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab
    };
    static const unsigned char fixed_aad[] = "extra:context";
    static const unsigned char fixed_pt[] = "THE QUICK BROWN FOX JUMPS OVER LAZY!!";
    const AEAD_ONESHOT_CFG *cfg = &aead_oneshot_cfgs[idx / 2];
    int with_aad = idx % 2;
    size_t aad_len = with_aad ? sizeof(fixed_aad) - 1 : 0;
    size_t pt_len = sizeof(fixed_pt) - 1;
    EVP_CIPHER *probe = NULL;
    unsigned char ct[64], pt[64];
    unsigned char tag_oneshot[16], tag_stream[16];
    const char *why = NULL;
    int leg, ok = 0;

    /*
     * Probe for the cipher: a build with no-ocb / no-chacha / etc. will
     * not have it, and we treat that as a pass (nothing to test here).
     */
    ERR_set_mark();
    probe = EVP_CIPHER_fetch(testctx, cfg->name, testpropq);
    ERR_pop_to_mark();
    if (probe == NULL) {
        TEST_info("skipping, '%s' is not available", cfg->name);
        return 1;
    }
    EVP_CIPHER_free(probe);

    for (leg = 0; leg <= 1; leg++) {
        int enc_oneshot = (leg == 0);
        unsigned char *tag = enc_oneshot ? tag_oneshot : tag_stream;

        memset(ct, 0, sizeof(ct));
        memset(pt, 0, sizeof(pt));
        memset(tag, 0, cfg->taglen);

        if (!aead_oneshot_op(cfg, /*enc=*/1, /*oneshot_body=*/enc_oneshot,
                fixed_key, fixed_iv, fixed_aad, aad_len,
                fixed_pt, pt_len, ct, tag, &why)) {
            TEST_error("%s (%s): encrypt leg %d (%s body) failed at %s",
                cfg->name, with_aad ? "with AAD" : "no AAD",
                leg, enc_oneshot ? "oneshot" : "stream",
                why ? why : "?");
            goto end;
        }
        if (!aead_oneshot_op(cfg, /*enc=*/0, /*oneshot_body=*/!enc_oneshot,
                fixed_key, fixed_iv, fixed_aad, aad_len,
                ct, pt_len, pt, tag, &why)) {
            TEST_error("%s (%s): decrypt leg %d (%s body) failed at %s",
                cfg->name, with_aad ? "with AAD" : "no AAD",
                leg, enc_oneshot ? "stream" : "oneshot",
                why ? why : "?");
            goto end;
        }
        if (!TEST_mem_eq(pt, pt_len, fixed_pt, pt_len)) {
            TEST_error("%s (%s): leg %d: recovered plaintext differs",
                cfg->name, with_aad ? "with AAD" : "no AAD", leg);
            goto end;
        }
    }

    /*
     * Both legs share the same (key, iv, aad, pt) and must therefore
     * agree on the tag bit-for-bit, regardless of which driver computed
     * it.  This catches the OCB-style failure where the one-shot path
     * silently emits a different ciphertext/tag from the streaming path.
     */
    if (!TEST_mem_eq(tag_oneshot, cfg->taglen, tag_stream, cfg->taglen)) {
        TEST_error("%s (%s): oneshot-encrypt tag != streaming-encrypt tag",
            cfg->name, with_aad ? "with AAD" : "no AAD");
        goto end;
    }
    ok = 1;
end:
    return ok;
}
/*-
 * A tag must be set before decrypting; EVP_DecryptFinal_ex() must reject
 * finalization when no tag has been supplied. Applies to every AEAD in
 * aead_list except the modes skipped below.
 */
static int test_evp_final_no_tag(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx_enc = NULL;
    EVP_CIPHER_CTX *ctx_dec = NULL;
    OSSL_PARAM params[2];
    unsigned char tag[16];
    unsigned char data[5] = { 1, 1, 1, 1, 1 };
    unsigned char ctext[EVP_MAX_BLOCK_LENGTH] = { 0 };
    unsigned char plaintext[sizeof(data)] = { 0 };
    int ctext_len = 0, len = 0, testresult = 0;
    unsigned char key[EVP_MAX_KEY_LENGTH] = {
        0xc9, 0xee, 0xa3, 0x0c, 0x1c, 0x59, 0x0c, 0x8b, 0xd8, 0xbb, 0xa1, 0x1c,
        0xbc, 0x3a, 0x56, 0xe7, 0xb7, 0xe1, 0x9f, 0xfd, 0x3b, 0x4a, 0xa3, 0xd5,
        0xc4, 0xdc, 0x2e, 0x62, 0xe6, 0x75, 0x15, 0x5c
    };
    unsigned char iv[EVP_MAX_IV_LENGTH] = {
        0x03, 0x2d, 0x79, 0xef, 0xed, 0x2e, 0xad, 0x3e, 0x0b, 0xdc, 0x8f, 0x57,
        0x0d, 0x0e, 0x0f, 0x10
    };

    /*
     * CCM requires the tag and payload length to be declared up front. OCB
     * emits plaintext before the tag check. SIV and GCM-SIV verify in the
     * payload update rather than in final. Skipped until the interface
     * behavior for these modes is settled.
     */
    if (info->mode == EVP_CIPH_CCM_MODE
        || info->mode == EVP_CIPH_OCB_MODE
        || info->mode == EVP_CIPH_SIV_MODE
        || info->mode == EVP_CIPH_GCM_SIV_MODE)
        return 1;

    if (!TEST_int_le(info->keylen, (int)sizeof(key))
        || !TEST_int_le(info->ivlen, (int)sizeof(iv))
        || !TEST_int_le(info->taglen, (int)sizeof(tag))) {
        TEST_info("%s: keylen %d, ivlen %d or taglen %d exceeds the buffers",
            EVP_CIPHER_get0_name(info->ciph), info->keylen, info->ivlen,
            info->taglen);
        goto err;
    }

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag, sizeof(tag));
    params[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(ctx_enc = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx_enc, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(ctx_enc, ctext, &ctext_len, data,
            sizeof(data)))
        || !TEST_true(EVP_EncryptFinal_ex(ctx_enc, ctext + ctext_len, &len))
        || !TEST_true(EVP_CIPHER_CTX_get_params(ctx_enc, params))) {
        TEST_info("%s: encrypt or tag retrieval failed",
            EVP_CIPHER_get0_name(info->ciph));
        goto err;
    }
    ctext_len += len;

    /* No tag is set on the decrypt side, so finalization must fail. */
    if (!TEST_ptr(ctx_dec = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx_dec, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_DecryptUpdate(ctx_dec, plaintext, &len, ctext,
            ctext_len))
        || !TEST_mem_eq(plaintext, sizeof(data), data, sizeof(data))
        || !TEST_false(EVP_DecryptFinal_ex(ctx_dec, plaintext + len, &len))) {
        TEST_info("%s: decrypt without tag did not behave as expected",
            EVP_CIPHER_get0_name(info->ciph));
        goto err;
    }

    testresult = 1;
err:
    EVP_CIPHER_CTX_free(ctx_enc);
    EVP_CIPHER_CTX_free(ctx_dec);
    return testresult;
}

/*
 * After a completed encrypt, a further Update on the same context must be
 * rejected, and the Final that follows must fail as well instead of reporting
 * the earlier success.
 *
 * How a cipher gets there differs: GCM, OCB and ASCON mark the context
 * finished, while SIV does its single crypto operation inside the payload
 * Update and lets any later failed operation overwrite the stored result.
 *
 * CCM, GCM-SIV and ChaCha20-Poly1305 are skipped: Final currently succeeds
 * after the rejected Update, and what it should do is not settled yet.
 */
static int test_evp_aead_enc_retval(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *enc_ctx = NULL;
    OSSL_PARAM tagparams[2];

    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char tag[EVPTEST_TAG_LEN_MAX] = { 0 };

    static const unsigned char in[] = "input";
    unsigned char ct[sizeof(in) + EVP_MAX_BLOCK_LENGTH] = { 0 };

    int i = 0, len = 0, ret = 0;

    if (info->mode == EVP_CIPH_CCM_MODE
        || info->mode == EVP_CIPH_GCM_SIV_MODE
        || EVP_CIPHER_is_a(info->ciph, "ChaCha20-Poly1305"))
        return 1;

    for (i = 0; i < info->keylen; i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->ivlen; i++)
        iv[i] = (unsigned char)(0xB0 + i);

    tagparams[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
        tag, info->taglen);
    tagparams[1] = OSSL_PARAM_construct_end();

    if (!TEST_ptr(enc_ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(enc_ctx, info->ciph, key, iv, NULL))
        || !TEST_true(EVP_EncryptUpdate(enc_ctx, ct, &len, in, sizeof(in)))
        || !TEST_true(EVP_EncryptFinal_ex(enc_ctx, ct + len, &len))
        || !TEST_true(EVP_CIPHER_CTX_get_params(enc_ctx, tagparams))) {
        TEST_info("%s: encrypt", info->name);
        goto err;
    }

    /* Encryption is fine, provoke error by repeating it on the same context */
    if (!TEST_false(EVP_EncryptUpdate(enc_ctx, ct, &len, in, sizeof(in)))
        || !TEST_false(EVP_EncryptFinal_ex(enc_ctx, ct + len, &len))) {
        TEST_info("%s: encrypt Update, Final after Final", info->name);
        goto err;
    }

    ret = 1;
err:
    ERR_clear_error();
    EVP_CIPHER_CTX_free(enc_ctx);
    return ret;
}

int setup_tests(void)
{
    size_t i = 0;

    if (setup_aead_list() == 0)
        return 0;

    /* resolve aead_list before registering, tests run in arbitrary order */
    for (i = 0; i < OSSL_NELEM(aead_list); i++) {
        if (test_evp_aead_params((int)i) == 0)
            TEST_info("%s: unresolved, tests will fail", aead_list[i].name);
    }

    ADD_TEST(test_evp_aead_provided);
    ADD_ALL_TESTS(test_evp_aead_params, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_oneshot_aead_zerolen, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_aead_late_aad, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_aead_finished_ctx, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_aead_get_tag_pairwise, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_final_no_tag, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_evp_aead_enc_retval, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_aead_oneshot_roundtrip, 2 * OSSL_NELEM(aead_oneshot_cfgs));
    return 1;
}

void cleanup_tests(void)
{
    cleanup_aead_list();
}
