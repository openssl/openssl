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
        TEST_info("evp_stale_key_integrity_test %d, %s: %s",
            idx, errmsg, info->name);
        testresult = 0;
    }

    EVP_CIPHER_CTX_free(ctx_onestep);
    EVP_CIPHER_CTX_free(ctx_reinit);

    return testresult;
}

int setup_tests(void)
{
    if (!setup_aead_list())
        return 0;

    ADD_ALL_TESTS(test_evp_oneshot_aead_zerolen, aead_list_n);
    ADD_ALL_TESTS(test_evp_stale_key_reinit, aead_list_n);
    return 1;
}

void cleanup_tests(void)
{
    cleanup_aead_list();
}
