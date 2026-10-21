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

/*
 * An update with no input and a nonzero length must fail, except for the
 * CCM message length, which is passed with no input and no output. This is
 * checked for both encryption and decryption.
 */
static int test_evp_aead_update_null_input(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char out[16] = { 0xAB }, untouched[16] = { 0xAB };
    int outl = 0, testresult = 0;

    /* encrypt: no input, no output -- valid only as the CCM message length */
    ERR_clear_error();
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, info->ciph, key, iv, NULL)))
        goto err;
    if (info->mode == EVP_CIPH_CCM_MODE) {
        if (!TEST_true(EVP_EncryptUpdate(ctx, NULL, &outl, NULL, 16))) {
            TEST_info("encrypt CCM length rejected: idx=%d cipher=%s",
                idx, info->name);
            goto err;
        }
    } else if (!TEST_false(EVP_EncryptUpdate(ctx, NULL, &outl, NULL, 16))
        || !TEST_err_r(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER)) {
        TEST_info("encrypt no input, no output: idx=%d cipher=%s",
            idx, info->name);
        goto err;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* encrypt: no input with an output buffer -- always fails, writes nothing */
    ERR_clear_error();
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_EncryptInit_ex2(ctx, info->ciph, key, iv, NULL))
        || !TEST_false(EVP_EncryptUpdate(ctx, out, &outl, NULL, 16))
        || !TEST_err_r(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER)
        || !TEST_int_eq(outl, 0)
        || !TEST_mem_eq(out, sizeof(out), untouched, sizeof(untouched))) {
        TEST_info("encrypt no input, with output: idx=%d cipher=%s",
            idx, info->name);
        goto err;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* decrypt: no input, no output -- valid only as the CCM message length */
    ERR_clear_error();
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx, info->ciph, key, iv, NULL)))
        goto err;
    if (info->mode == EVP_CIPH_CCM_MODE) {
        if (!TEST_true(EVP_DecryptUpdate(ctx, NULL, &outl, NULL, 16))) {
            TEST_info("decrypt CCM length rejected: idx=%d cipher=%s",
                idx, info->name);
            goto err;
        }
    } else if (!TEST_false(EVP_DecryptUpdate(ctx, NULL, &outl, NULL, 16))
        || !TEST_err_r(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER)) {
        TEST_info("decrypt no input, no output: idx=%d cipher=%s",
            idx, info->name);
        goto err;
    }
    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    /* decrypt: no input with an output buffer -- always fails, writes nothing */
    ERR_clear_error();
    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())
        || !TEST_true(EVP_DecryptInit_ex2(ctx, info->ciph, key, iv, NULL))
        || !TEST_false(EVP_DecryptUpdate(ctx, out, &outl, NULL, 16))
        || !TEST_err_r(ERR_LIB_PROV, ERR_R_PASSED_NULL_PARAMETER)
        || !TEST_int_eq(outl, 0)
        || !TEST_mem_eq(out, sizeof(out), untouched, sizeof(untouched))) {
        TEST_info("decrypt no input, with output: idx=%d cipher=%s",
            idx, info->name);
        goto err;
    }

    testresult = 1;
err:
    ERR_clear_error();
    EVP_CIPHER_CTX_free(ctx);
    return testresult;
}
/*
 * Verify stale key is not being used after providing a new key in multiple steps.
 * This test performs a full round of encryption and then changes the
 * key and then the IV in a multi-step init.
 * This is compared to another context without reinitialization to check
 * if the new key is loaded correctly.
 */
static int test_evp_stale_key_reinit(int idx)
{
    const AEAD_DATA *info = &aead_list[idx];
    EVP_CIPHER_CTX *ctx_reinit = NULL; /* used to test multi step init KEY->IV */
    EVP_CIPHER_CTX *ctx_onestep = NULL; /* base test with single step init */

    OSSL_PARAM ivparams[2];
    OSSL_PARAM tagparams[2];
    OSSL_PARAM get_tagparams[2];

    int ivlen = info->ivlen;
    unsigned char key[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char key2[EVP_MAX_KEY_LENGTH] = { 0 };
    unsigned char iv[EVP_MAX_IV_LENGTH] = { 0 };
    unsigned char iv2[EVP_MAX_IV_LENGTH] = { 0 };

    size_t pt_size = 0, j = 0;
    unsigned char pt[128] = { 0 };

    unsigned char ct[128] = { 0 };
    int ct_len = 0;
    int ct_fin_len = 0;

    unsigned char ct_reinit[128] = { 0 };
    int ct_reinit_len = 0;
    int ct_reinit_fin_len = 0;

    unsigned char ct_onestep[128] = { 0 };
    int ct_onestep_len = 0;
    int ct_onestep_fin_len = 0;

    int taglen = info->taglen;
    unsigned char tag[EVPTEST_TAG_LEN_MAX] = { 0 };
    unsigned char tag_reinit[EVPTEST_TAG_LEN_MAX] = { 0 };
    unsigned char tag_onestep[EVPTEST_TAG_LEN_MAX] = { 0 };

    int blocksz = 0, tmplen = 0, testresult = 1, i = 0;
    char *errmsg = NULL;

    ivparams[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_IVLEN, &ivlen);
    ivparams[1] = OSSL_PARAM_construct_end();
    tagparams[0] = OSSL_PARAM_construct_int(OSSL_CIPHER_PARAM_AEAD_TAGLEN, &taglen);
    tagparams[1] = OSSL_PARAM_construct_end();

    blocksz = EVP_CIPHER_get_block_size(info->ciph);
    pt_size = (blocksz > 1) ? (size_t)blocksz * 2 : 31;

    for (i = 0; i < info->keylen && i < (int)sizeof(key); i++)
        key[i] = (unsigned char)(0xA0 + i);
    for (i = 0; i < info->keylen && i < (int)sizeof(key2); i++)
        key2[i] = (unsigned char)(0xF0 + i);

    for (i = 0; i < info->ivlen && i < (int)sizeof(iv); i++)
        iv[i] = (unsigned char)(0xB0 + i);
    for (i = 0; i < info->ivlen && i < (int)sizeof(iv2); i++)
        iv2[i] = (unsigned char)(0xDA + i);

    for (j = 0; j < pt_size; j++)
        pt[j] = (unsigned char)(0xA7);

    if (!TEST_ptr(ctx_reinit = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_REINIT_ALLOC";
        goto err;
    }

    if (!TEST_true(EVP_EncryptInit_ex(ctx_reinit, info->ciph,
            NULL, NULL, NULL))) {
        errmsg = "CTX_FIRST_INIT";
        goto err;
    }

    if (info->taglen > 0 && info->mode == EVP_CIPH_CCM_MODE) {
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_reinit, ivparams))) {
            errmsg = "CCM_SET_IVLEN";
            goto err;
        }
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_reinit, tagparams))) {
            errmsg = "CCM_SET_TAGLEN";
            goto err;
        }
    }
    /* Initialize first with key */
    if (!TEST_true(EVP_EncryptInit_ex(ctx_reinit, NULL, NULL, key, iv))) {
        errmsg = "FIRST_KEY_INIT";
        goto err;
    }

    /* disable padding for non-aed block-aligned pt */
    if (info->taglen == 0 && blocksz > 1)
        EVP_CIPHER_CTX_set_padding(ctx_reinit, 0);

    if (info->taglen > 0 && info->mode == EVP_CIPH_CCM_MODE
        && !TEST_true(EVP_EncryptUpdate(ctx_reinit, NULL,
            &tmplen, NULL, (int)pt_size))) {
        errmsg = "CCM_DECLARE_PTLEN";
        goto err;
    }

    if (!TEST_true(EVP_EncryptUpdate(ctx_reinit, ct, &ct_len,
            pt, (int)pt_size))) {
        errmsg = "ENCRYPT_UPDATE";
        goto err;
    }

    if (!TEST_true(EVP_EncryptFinal_ex(ctx_reinit, ct + ct_len,
            &ct_fin_len))) {
        errmsg = "ENCRYPT_FINAL";
        goto err;
    }

    ct_len += ct_fin_len;
    if (info->taglen > 0) {
        /* override taglen from context if available */
        int tl = EVP_CIPHER_CTX_get_tag_length(ctx_reinit);

        if (tl > 0)
            taglen = tl;

        get_tagparams[0] = OSSL_PARAM_construct_octet_string(
            OSSL_CIPHER_PARAM_AEAD_TAG, tag, taglen);
        get_tagparams[1] = OSSL_PARAM_construct_end();

        if (!TEST_true(EVP_CIPHER_CTX_get_params(ctx_reinit,
                                                  get_tagparams))) {
            errmsg = "AEAD_GET_TAG";
            goto err;
        }
    }
    /* use same context with a different key and iv in multiple steps */
    if (!TEST_true(EVP_EncryptInit_ex(ctx_reinit, NULL, NULL, key2, NULL))) {
        errmsg = "REINIT_KEY";
        goto err;
    }

    if (!TEST_true(EVP_EncryptInit_ex(ctx_reinit, NULL, NULL, NULL, iv2))) {
        errmsg = "REINIT_IV";
        goto err;
    }

    if (info->taglen > 0 && info->mode == EVP_CIPH_CCM_MODE
        && !TEST_true(EVP_EncryptUpdate(ctx_reinit, NULL,
            &tmplen, NULL, (int)pt_size))) {
        errmsg = "CCM_DECLARE_PTLEN";
        goto err;
    }

    if (!TEST_true(EVP_EncryptUpdate(ctx_reinit, ct_reinit,
            &ct_reinit_len, pt, (int)pt_size))) {
        errmsg = "ENCRYPT_UPDATE";
        goto err;
    }

    if (!TEST_true(EVP_EncryptFinal_ex(ctx_reinit,
            ct_reinit + ct_reinit_len, &ct_reinit_fin_len))) {
        errmsg = "ENCRYPT_FINAL";
        goto err;
    }

    ct_reinit_len += ct_reinit_fin_len;
    get_tagparams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag_reinit, taglen);

    if (info->taglen > 0
        && !TEST_true(EVP_CIPHER_CTX_get_params(ctx_reinit,
                                                get_tagparams))) {
        errmsg = "AEAD_GET_TAG";
        goto err;
    }
    /* Initialize in a single step */
    if (!TEST_ptr(ctx_onestep = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_ALLOC_BASE_CASE";
        goto err;
    }

    if (!TEST_true(EVP_EncryptInit_ex(ctx_onestep, info->ciph,
            NULL, NULL, NULL))) {
        errmsg = "BASE_CASE_INIT";
        goto err;
    }

    if (info->taglen > 0 && info->mode == EVP_CIPH_CCM_MODE) {
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_onestep, ivparams))) {
            errmsg = "CCM_SET_IVLEN";
            goto err;
        }
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_onestep, tagparams))) {
            errmsg = "CCM_SET_TAGLEN";
            goto err;
        }
    }

    if (!TEST_true(EVP_EncryptInit_ex(ctx_onestep, NULL, NULL, key2, iv2))) {
        errmsg = "SINGLE_STEP_INIT";
        goto err;
    }

    if (info->taglen == 0 && blocksz > 1)
        EVP_CIPHER_CTX_set_padding(ctx_onestep, 0);

    if (info->taglen > 0 && info->mode == EVP_CIPH_CCM_MODE
        && !TEST_true(EVP_EncryptUpdate(ctx_onestep, NULL,
            &tmplen, NULL, (int)pt_size))) {
        errmsg = "CCM_DECLARE_PTLEN";
        goto err;
    }

    if (!TEST_true(EVP_EncryptUpdate(ctx_onestep, ct_onestep,
            &ct_onestep_len, pt, (int)pt_size))) {
        errmsg = "ENCRYPT_UPDATE";
        goto err;
    }

    if (!TEST_true(EVP_EncryptFinal_ex(ctx_onestep,
            ct_onestep + ct_onestep_len, &ct_onestep_fin_len))) {
        errmsg = "ENCRYPT_FINAL_ONE_STEP";
        goto err;
    }

    ct_onestep_len += ct_onestep_fin_len;
    get_tagparams[0] = OSSL_PARAM_construct_octet_string(
        OSSL_CIPHER_PARAM_AEAD_TAG, tag_onestep, taglen);

    if (info->taglen > 0
        && !TEST_true(EVP_CIPHER_CTX_get_params(ctx_onestep,
                                                get_tagparams))) {
        errmsg = "AEAD_GET_TAG";
        goto err;
    }
    /* Compare single-call vs key->iv */
    if (!TEST_int_eq(ct_reinit_len, ct_onestep_len)
        || !TEST_mem_eq(ct_reinit, ct_reinit_len,
                        ct_onestep, ct_onestep_len)) {
        errmsg = "CT_MISMATCH_SINGLE_vs_REINIT";
        goto err;
    }

    if (info->taglen > 0
        && !TEST_mem_eq(tag_onestep, taglen, tag_reinit, taglen)) {
        errmsg = "TAG_MISMATCH_SINGLE_vs_REINIT";
        goto err;
    }

err:
    if (errmsg != NULL) {
        TEST_info("evp_stale_key_reinit_test %d, %s: %s",
            idx, errmsg, info->name);
        testresult = 0;
    }

    EVP_CIPHER_CTX_free(ctx_onestep);
    EVP_CIPHER_CTX_free(ctx_reinit);
    return testresult;
}

static const unsigned char kGCMResetKey[] = {
    0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94,
    0x67, 0x30, 0x83, 0x08, 0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
    0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const unsigned char iGCMResetIV1[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};

static const unsigned char iGCMResetIV2[] = {
    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
};

static const unsigned char gcmResetPlaintext[] = {
    0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5,
    0xaf, 0xf5, 0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
    0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95,
    0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
    0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57, 0xba, 0x63, 0x7b, 0x39
};

static const unsigned char gcmResetCiphertext1[] = {
    0xc3, 0x76, 0x2d, 0xf1, 0xca, 0x78, 0x7d, 0x32, 0xae, 0x47, 0xc1, 0x3b,
    0xf1, 0x98, 0x44, 0xcb, 0xaf, 0x1a, 0xe1, 0x4d, 0x0b, 0x97, 0x6a, 0xfa,
    0xc5, 0x2f, 0xf7, 0xd7, 0x9b, 0xba, 0x9d, 0xe0, 0xfe, 0xb5, 0x82, 0xd3,
    0x39, 0x34, 0xa4, 0xf0, 0x95, 0x4c, 0xc2, 0x36, 0x3b, 0xc7, 0x3f, 0x78,
    0x62, 0xac, 0x43, 0x0e, 0x64, 0xab, 0xe4, 0x99, 0xf4, 0x7c, 0x9b, 0x1f
};

static const unsigned char gcmResetCiphertext2[] = {
    0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07, 0xf4, 0x7f, 0x37, 0xa3,
    0x2a, 0x84, 0x42, 0x7d, 0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
    0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa, 0x8c, 0xb0, 0x8e, 0x48,
    0x59, 0x0d, 0xbb, 0x3d, 0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
    0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a, 0xbc, 0xc9, 0xf6, 0x62
};

static const unsigned char gcmAAD[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2
};

static const unsigned char gcmResetTag1[] = {
    0x3a, 0x33, 0x7d, 0xbf, 0x46, 0xa7, 0x92, 0xc4, 0x5e, 0x45, 0x49, 0x13,
    0xfe, 0x2e, 0xa8, 0xf2
};

static const unsigned char gcmResetTag2[] = {
    0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68, 0xcd, 0xdf, 0x88, 0x53,
    0xbb, 0x2d, 0x55, 0x1b
};

typedef struct {
    const unsigned char *iv1;
    const unsigned char *iv2;
    const unsigned char *expected1;
    const unsigned char *expected2;
    const unsigned char *tag1;
    const unsigned char *tag2;
    size_t ivlen1;
    size_t ivlen2;
    size_t expectedlen1;
    size_t expectedlen2;
} TEST_GCM_IV_REINIT_st;

static const TEST_GCM_IV_REINIT_st gcm_reinit_tests[] = {
    { iGCMResetIV1, iGCMResetIV2, gcmResetCiphertext1, gcmResetCiphertext2,
        gcmResetTag1, gcmResetTag2, sizeof(iGCMResetIV1), sizeof(iGCMResetIV2),
        sizeof(gcmResetCiphertext1), sizeof(gcmResetCiphertext2) },
    { iGCMResetIV2, iGCMResetIV1, gcmResetCiphertext2, gcmResetCiphertext1,
        gcmResetTag2, gcmResetTag1, sizeof(iGCMResetIV2), sizeof(iGCMResetIV1),
        sizeof(gcmResetCiphertext2), sizeof(gcmResetCiphertext1) }
};

static int test_gcm_reinit(int idx)
{
    int outlen1, outlen2, outlen3;
    int testresult = 0;
    unsigned char outbuf[1024];
    unsigned char tag[16];
    const TEST_GCM_IV_REINIT_st *t = &gcm_reinit_tests[idx];
    EVP_CIPHER_CTX *ctx = NULL;
    EVP_CIPHER *type = NULL;
    size_t taglen = sizeof(tag);
    char *errmsg = NULL;

    if (!TEST_ptr(ctx = EVP_CIPHER_CTX_new())) {
        errmsg = "CTX_ALLOC";
        goto err;
    }
    if (!TEST_ptr(type = EVP_CIPHER_fetch(NULL, "aes-256-gcm", NULL))) {
        errmsg = "CIPHER_FETCH";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, type, NULL, NULL, NULL, 1))) {
        errmsg = "ENC_INIT";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                         (int)t->ivlen1, NULL),
            0)) {
        errmsg = "SET_IVLEN1";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, kGCMResetKey, t->iv1, 1))) {
        errmsg = "SET_IV1";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, NULL, &outlen3, gcmAAD, sizeof(gcmAAD)))) {
        errmsg = "AAD1";
        goto err;
    }
    EVP_CIPHER_CTX_set_padding(ctx, 0);
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, gcmResetPlaintext,
            sizeof(gcmResetPlaintext)))) {
        errmsg = "CIPHER_UPDATE1";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL1";
        goto err;
    }
    if (!TEST_mem_eq(t->expected1, t->expectedlen1, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT1";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                         (int)taglen, tag),
            0)) {
        errmsg = "GET_TAG1";
        goto err;
    }
    if (!TEST_mem_eq(t->tag1, taglen, tag, taglen)) {
        errmsg = "TAG_ERROR1";
        goto err;
    }
    /* Now reinit */
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                         (int)t->ivlen2, NULL),
            0)) {
        errmsg = "SET_IVLEN2";
        goto err;
    }
    if (!TEST_true(EVP_CipherInit_ex(ctx, NULL, NULL, NULL, t->iv2, -1))) {
        errmsg = "SET_IV2";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, NULL, &outlen3, gcmAAD, sizeof(gcmAAD)))) {
        errmsg = "AAD2";
        goto err;
    }
    if (!TEST_true(EVP_CipherUpdate(ctx, outbuf, &outlen1, gcmResetPlaintext,
            sizeof(gcmResetPlaintext)))) {
        errmsg = "CIPHER_UPDATE2";
        goto err;
    }
    if (!TEST_true(EVP_CipherFinal_ex(ctx, outbuf + outlen1, &outlen2))) {
        errmsg = "CIPHER_FINAL2";
        goto err;
    }
    if (!TEST_mem_eq(t->expected2, t->expectedlen2, outbuf, outlen1 + outlen2)) {
        errmsg = "WRONG_RESULT2";
        goto err;
    }
    if (!TEST_int_gt(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG,
                         (int)taglen, tag),
            0)) {
        errmsg = "GET_TAG2";
        goto err;
    }
    if (!TEST_mem_eq(t->tag2, taglen, tag, taglen)) {
        errmsg = "TAG_ERROR2";
        goto err;
    }
    testresult = 1;
err:
    if (errmsg != NULL)
        TEST_info("evp_init_test %d: %s", idx, errmsg);
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(type);
    return testresult;
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
    ADD_ALL_TESTS(test_evp_aead_update_null_input, OSSL_NELEM(aead_list));
    ADD_ALL_TESTS(test_gcm_reinit, OSSL_NELEM(gcm_reinit_tests));
    ADD_ALL_TESTS(test_evp_stale_key_reinit, OSSL_NELEM(aead_list));
    return 1;
}

void cleanup_tests(void)
{
    cleanup_aead_list();
}
