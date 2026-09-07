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

/*
 * Dynamically discover all applicable AEAD ciphers and verify their
 * behavior at the EVP interface level. This test should require zero
 * maintenance when new AEAD ciphers are added, as the discovery loop
 * handles them.
 *
 * This is a copy of the cipher_list discovery mechanism in
 * evp_extra_test.c, narrowed to AEAD ciphers only. Unlike that file,
 * EVP_CIPH_SIV_MODE is deliberately NOT excluded here -- SIV mode is
 * an AEAD mode and belongs in this table.
 */

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
} AEAD_DATA;

static AEAD_DATA *aead_list = NULL;
static int aead_list_n = 0;

static int seen_name(const char *name)
{
    int i = 0;

    if (name == NULL) {
        return 1;
    }
    for (i = 0; i < aead_list_n; i++) {
        if (OPENSSL_strcasecmp(aead_list[i].name, name) == 0)
            return 1;
    }
    return 0;
}

static void collect_aead_cipher_cb(EVP_CIPHER *ciph, void *arg)
{
    AEAD_DATA *info = NULL;
    const char *name = NULL;

    size_t *allocated = arg;

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
        /* fetch name and skip potential dupes */
        || (name = EVP_CIPHER_get0_name(ciph)) == NULL
        || seen_name(name) == 1)
        return;

    /* First pass only counts ciphers to allocate memory. */
    if (allocated != NULL) {
        (*allocated)++;
        return;
    }

    info = &aead_list[aead_list_n];

    if (!EVP_CIPHER_up_ref(ciph))
        return;

    info->ciph = ciph;
    info->name = name;
    info->keylen = EVP_CIPHER_get_key_length(ciph);
    info->ivlen = EVP_CIPHER_get_iv_length(ciph);
    info->mode = EVP_CIPHER_get_mode(ciph);
    info->taglen = EVPTEST_TAG_LEN_DEFAULT;

    aead_list_n++;
}

static int setup_aead_list(void)
{
    size_t aead_list_size = 0;

    aead_list = NULL;
    aead_list_n = 0;

    /* First pass counts only, to know how much to allocate. */
    EVP_CIPHER_do_all_provided(NULL, collect_aead_cipher_cb, &aead_list_size);

    if (!TEST_size_t_gt(aead_list_size, 0))
        return 0;

    aead_list = OPENSSL_malloc(aead_list_size * sizeof(*aead_list));
    if (!TEST_ptr(aead_list))
        return 0;

    /* Second pass actually populates aead_list. */
    EVP_CIPHER_do_all_provided(NULL, collect_aead_cipher_cb, NULL);
    return TEST_true(aead_list_n > 0);
}

static void cleanup_aead_list(void)
{
    int i;

    if (aead_list == NULL)
        return;

    for (i = 0; i < aead_list_n; i++) {
        if (aead_list[i].ciph != NULL)
            EVP_CIPHER_free((EVP_CIPHER *)aead_list[i].ciph);
    }

    OPENSSL_free(aead_list);
    aead_list = NULL;
    aead_list_n = 0;
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

int setup_tests(void)
{
    if (!setup_aead_list())
        return 0;

    ADD_ALL_TESTS(test_evp_oneshot_aead_zerolen, aead_list_n);
    ADD_ALL_TESTS(test_evp_aead_late_aad, aead_list_n);
    return 1;
}

void cleanup_tests(void)
{
    cleanup_aead_list();
}
