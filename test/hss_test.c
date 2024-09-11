/*
 * Copyright 2023-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include <openssl/evp.h>
#include <openssl/thread.h>
#include <openssl/hss.h>
#include <openssl/rand.h>
#include "crypto/hss.h"
#include "internal/nelem.h"
#include "testutil.h"
#include "hss.inc"

typedef enum OPTION_choice {
    OPT_ERR = -1,
    OPT_EOF = 0,
    OPT_PUB,
    OPT_SIG,
    OPT_CONFIG_FILE,
    OPT_TEST_ENUM
} OPTION_CHOICE;

static OSSL_LIB_CTX *libctx = NULL;
static char *propq = NULL;
static OSSL_PROVIDER *nullprov = NULL;
static OSSL_PROVIDER *libprov = NULL;
static OSSL_PROVIDER *fake_rand = NULL;
static char *pubfilename = NULL;
static char *sigfilename = NULL;

static EVP_PKEY *hsspubkey_from_data(const unsigned char *data, size_t datalen)
{
    int ret;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *key = NULL;
    OSSL_PARAM params[2];

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                                  (unsigned char *)data, datalen);
    params[1] = OSSL_PARAM_construct_end();
    ret = TEST_ptr(ctx = EVP_PKEY_CTX_new_from_name(libctx, "HSS", propq))
          && TEST_int_eq(EVP_PKEY_fromdata_init(ctx), 1)
          && (EVP_PKEY_fromdata(ctx, &key, EVP_PKEY_PUBLIC_KEY, params) == 1);
    if (ret == 0) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int hss_pubkey_decoder_test(void)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[0];
    EVP_PKEY *pub = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    const unsigned char *data;
    size_t data_len;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pub, "xdr", NULL,
                                                       "HSS",
                                                       OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                                       libctx, propq)))
        goto err;
    data = td->pub;
    data_len = td->publen;
    if (!TEST_true(OSSL_DECODER_from_data(dctx, &data, &data_len)))
        goto err;
    ret = 1;
err:
    EVP_PKEY_free(pub);
    OSSL_DECODER_CTX_free(dctx);
    return ret;
}

static int hss_pkey_verify_test(int tst)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[tst];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;

    ret = TEST_ptr(pkey = hsspubkey_from_data(td->pub, td->publen))
          && TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq))
          && TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq))
          && TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, NULL), 1)
          && TEST_int_eq(EVP_PKEY_verify(ctx, td->sig, td->siglen,
                                         td->msg, td->msglen), 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(sig);
    return ret;
}

static int hss_pkey_verify_update_test(int tst)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[tst];
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    int sz = (td->msglen / 3);

    ret = TEST_ptr(pkey = hsspubkey_from_data(td->pub, td->publen))
          && TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq))
          && TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq))
          && TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, NULL), 1)
          && TEST_int_eq(EVP_PKEY_CTX_set_signature(ctx, td->sig, td->siglen), 1)
          && TEST_int_eq(EVP_PKEY_verify_message_update(ctx, td->msg, sz), 1)
          && TEST_int_eq(EVP_PKEY_verify_message_update(ctx, td->msg + sz,
                                                        td->msglen - sz), 1)
          && TEST_int_eq(EVP_PKEY_verify_message_final(ctx), 1);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);
    EVP_SIGNATURE_free(sig);
    return ret;
}

static int hss_pkey_verify_fail_test(void)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[0];
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if (!TEST_ptr(pkey = hsspubkey_from_data(td->pub, td->publen))
        || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)))
        goto end;
    if (!TEST_int_eq(EVP_PKEY_verify_init(ctx), -2))
        goto end;
    ret = 1;
end:
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ret;
}

static int hss_verify_bad_sig_test(void)
{
    int ret = 0, i;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[1];
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *sig_data = NULL, corrupt_mask = 0x01;
    /*
     * Corrupt every 3rd byte to run less tests. The smallest element of an XDR
     * encoding is 4 bytes, so this will corrupt every element.
     */
    const int step = 3;

    /* Copy the signature so that we can corrupt it */
    sig_data = OPENSSL_memdup(td->sig, td->siglen);
    if (sig_data == NULL)
        return 0;

    if (!TEST_ptr(pkey = hsspubkey_from_data(td->pub, td->publen))
            || !TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)))
        goto end;

    for (i = 0; i < (int)td->siglen; i += step) {
        sig_data[i] ^= corrupt_mask; /* corrupt a byte */
        if (i > 0)
            sig_data[i - step] ^= corrupt_mask; /* Reset the previously corrupt byte */

        if (!TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, NULL), 1))
            goto end;
        if (!TEST_int_eq(EVP_PKEY_verify(ctx, sig_data, td->siglen,
                                         td->msg, td->msglen), 0)) {
            ret = -1;
            goto end;
        }
    }

    ret = 1;
end:
    if (ret == -1)
        TEST_note("Incorrectly passed when %dth byte of signature"
                  " was corrupted", i);
    EVP_SIGNATURE_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(sig_data);

    return ret == 1;
}

/*
 * Test that using the incorrect signature lengths (both shorter and longer)
 * fail.
 * NOTE: It does not get an out of bounds read due to the signature
 * knowing how large it should be
 */
static int hss_verify_bad_sig_len_test(void)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[1];
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t siglen;
    const int step = 3;

    if (!TEST_ptr(pkey = hsspubkey_from_data(td->pub, td->publen))
            || !TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)))
        goto end;

    ret = 0;
    for (siglen = 0; siglen < td->siglen + 4 ; siglen += step) {
        if (siglen == td->siglen)   /* ignore the size that should pass */
            continue;
        if (!TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, NULL), 1))
            goto end;
        if (!TEST_int_eq(EVP_PKEY_verify(ctx, td->sig, siglen,
                                         td->msg, td->msglen), 0)) {
            ret = -1;
            goto end;
        }
    }

    ret = 1;
end:
    if (ret == -1)
        TEST_note("Incorrectly accepted signature key of length"
                  " %ld (expected %ld)", siglen, td->siglen);
    EVP_SIGNATURE_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

static int hss_verify_bad_pub_sig_test(void)
{
    HSS_ACVP_TEST_DATA *td = &hss_testdata[1];
    int ret = 0, i;
    EVP_PKEY *pkey = NULL;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    unsigned char *pub = NULL;
    const int step = 1;

    /* Copy the public key data so that we can corrupt it */
    if (!TEST_ptr(pub = OPENSSL_memdup(td->pub, td->publen)))
        return 0;

    if (!TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq)))
        goto end;

    for (i = 0; i < (int)td->publen; i += step) {
        if (i > 0) {
            EVP_PKEY_free(pkey);
            EVP_PKEY_CTX_free(ctx);
            pkey = NULL;
            ctx = NULL;
            pub[i - step] ^= 1;
        }
        pub[3] ^= 1;
        /* Corrupting the public key may cause the key load to fail */
        pkey = hsspubkey_from_data(pub, td->publen);
        if (pkey == NULL)
            continue;
        if (!TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pkey, propq)))
            continue;
        if (!TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, NULL), 1))
            continue;
        /* We expect the verify to fail */
        if (!TEST_int_eq(EVP_PKEY_verify(ctx, td->sig, td->siglen,
                                         td->msg, td->msglen), 0)) {
            ret = -1;
            goto end;
        }
    }

    ret = 1;
end:
    if (ret == -1)
        TEST_note("Incorrectly passed when byte %d of the public key"
                  " was corrupted", i);
    EVP_SIGNATURE_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(pub);

    return ret == 1;
}

static int hss_bad_pub_len_test(void)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[1];
    EVP_PKEY *pkey = NULL;
    size_t publen = 0;

    for (publen = 0; publen <= td->publen + 4; publen += 3 ) {
        if (publen == td->publen)
            continue;
        if (!TEST_ptr_null(pkey = hsspubkey_from_data(td->pub, publen)))
            goto end;
    }
    ret = 1;
end:
    if (ret == 0)
        TEST_note("Incorrectly accepted public key of length %ld (expected %ld)",
                  publen, td->publen);
    EVP_PKEY_free(pkey);

    return ret == 1;
}

/* Coverage testing for internal HSS related functions */
static int hss_decode_fail_test(void)
{
    int ret = 0;
    HSS_KEY *pub;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[0];

    if (!TEST_ptr(pub = ossl_hss_key_new(libctx, propq)))
        goto end;
    if (!TEST_true(ossl_hss_pubkey_decode(td->pub, td->publen, pub)))
        goto end;
    if (!TEST_int_eq(ossl_hss_sig_decode(pub, td->sig, 1), 0))
        goto end;
    if (!TEST_int_eq(ossl_hss_sig_decode(pub, td->sig, SIZE_MAX), 0))
        goto end;

    ret = 1;
end:
    ossl_hss_key_free(pub);
    return ret;
}

static int hss_pubkey_decoder_fail_test(void)
{
    int ret = 0;
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[0];
    const unsigned char *pdata;
    size_t pdatalen;
    static const unsigned char pub_bad_L[] = {
        0x00,0x00,0x00,0x08,0x00,0x00,0x00,0x01
    };
    static const unsigned char pub_bad_LMSType[] = {
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xAA
    };
    static const unsigned char pub_bad_OTSType[] = {
        0x00,0x00,0x00,0x01,0x00,0x00,0x00,0x01,0x00,0x00,0x00,0xAA
    };

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, NULL, NULL, "HSS",
                                                       selection,
                                                       libctx, propq)))
        return 0;

    pdata = td->pub;
    pdatalen = 7;
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdatalen = SIZE_MAX;
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdata = pub_bad_L;
    pdatalen = sizeof(pub_bad_L);
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdata = pub_bad_LMSType;
    pdatalen = sizeof(pub_bad_LMSType);
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    pdata = pub_bad_OTSType;
    pdatalen = sizeof(pub_bad_OTSType);
    if (!TEST_false(OSSL_DECODER_from_data(dctx, &pdata, &pdatalen)))
        goto end;

    ret = 1;
end:
    EVP_PKEY_free(pkey);
    OSSL_DECODER_CTX_free(dctx);
    return ret;
}

static EVP_PKEY *key_decode_from_bio(BIO *bio, const char *keytype)
{
    EVP_PKEY *pkey = NULL;
    OSSL_DECODER_CTX *dctx = NULL;
    int selection = 0;

    if (!TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&pkey, NULL, NULL,
                                                       keytype,
                                                       selection,
                                                       libctx, propq)))
        return NULL;

    if (!TEST_true(OSSL_DECODER_from_bio(dctx, bio))) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }
    OSSL_DECODER_CTX_free(dctx);
    return pkey;
}

static EVP_PKEY *key_decode_from_data(const unsigned char *data, size_t datalen,
                                      const char *keytype)
{
    BIO *bio;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(bio = BIO_new_mem_buf(data, datalen)))
        return NULL;
    key = key_decode_from_bio(bio, keytype);
    BIO_free(bio);
    return key;
}

static int hss_key_eq_test(void)
{
    int ret = 0;
    EVP_PKEY *key[4] = { NULL, NULL, NULL, NULL };
    HSS_ACVP_TEST_DATA *td1 = &hss_testdata[0];
    HSS_ACVP_TEST_DATA *td2 = &hss_testdata[1];
#ifndef OPENSSL_NO_EC
    EVP_PKEY *eckey = NULL;
#endif
    if (!TEST_ptr(key[0] = hsspubkey_from_data(td1->pub, td1->publen))
        || !TEST_ptr(key[1] = hsspubkey_from_data(td1->pub, td1->publen))
        || !TEST_ptr(key[2] = key_decode_from_data(td1->pub, td1->publen, NULL))
        || !TEST_ptr(key[3] = hsspubkey_from_data(td2->pub, td2->publen)))
        goto end;

    ret = TEST_int_eq(EVP_PKEY_eq(key[0], key[1]), 1)
          && TEST_int_eq(EVP_PKEY_eq(key[0], key[2]), 1)
          && TEST_int_ne(EVP_PKEY_eq(key[0], key[3]), 1);
    if (ret == 0)
        goto end;
#ifndef OPENSSL_NO_EC
    if (!TEST_ptr(eckey = EVP_PKEY_Q_keygen(libctx, propq, "EC", "P-256")))
        goto end;
    ret = TEST_int_ne(EVP_PKEY_eq(key[0], eckey), 1);
    EVP_PKEY_free(eckey);
#endif
end:
    EVP_PKEY_free(key[3]);
    EVP_PKEY_free(key[2]);
    EVP_PKEY_free(key[1]);
    EVP_PKEY_free(key[0]);
    return ret;
}

static int hss_key_validate_test(void)
{
    int ret = 0;
    HSS_ACVP_TEST_DATA *td = &hss_testdata[0];
    EVP_PKEY_CTX *vctx = NULL;
    EVP_PKEY *key = NULL;

    if (!TEST_ptr(key = hsspubkey_from_data(td->pub, td->publen)))
         return 0;
    if (!TEST_ptr(vctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq)))
        goto end;
    ret = TEST_int_eq(EVP_PKEY_check(vctx), 1);
    EVP_PKEY_CTX_free(vctx);
end:
    EVP_PKEY_free(key);
    return ret;
}

#ifndef OPENSSL_NO_HSS_GEN

static unsigned char entropy[4096];
static int rpos = 0;

static int set_entropy(const unsigned char *ent1, size_t ent1len,
                       const unsigned char *ent2, size_t ent2len)
{
    rpos = 0;
    if ((ent1len + ent2len) > sizeof(entropy))
        return 0;
    memcpy(entropy, ent1, ent1len);
    if (ent2 != NULL)
        memcpy(entropy + ent1len, ent2, ent2len);
    return 1;
}

static int fbytes(unsigned char *buf, size_t num, ossl_unused const char *name,
                  EVP_RAND_CTX *ctx)
{
    if (rpos + num > sizeof(entropy)) {
        memset(buf, 0, num);
    } else {
        memcpy(buf, entropy + rpos, num);
        rpos += num;
    }
    return 1;
}

/*
 * The HSS RFC related test vectors can be used to perform deterministic
 * signature KAT's, by extracting information from the raw data for the
 * private key, public key & signature.
 * The q values embedded in the signature can be used to figure out how many
 * keypairs we need to skip.
 */
static int extract_sign_data(HSS_ACVP_TEST_DATA *t, uint32_t *out_levels,
                             uint32_t *lms_type, uint32_t *ots_type,
                             uint64_t *out_qindex)
{
    uint32_t i, levels, sigoff;
    uint64_t qindex, scale, q[OSSL_HSS_MAX_L] = { 0 };
    /*
     * Extract Level and types from public key blob for level 0
     * Extra types for additional level from the signature.
     */
    levels = t->pub[3];
    lms_type[0] = t->pub[7];
    ots_type[0] = t->pub[11];
    sigoff = 4;
    for (i = 0; i < levels; ++i) {
        const LMS_PARAMS *lms_params = ossl_lms_params_get(lms_type[i]);
        const LM_OTS_PARAMS *ots_params = ossl_lm_ots_params_get(ots_type[i]);

        q[i] = t->sig[sigoff + 3];
        /* Go to the offset of the public key field */
        sigoff += (4 * 3 + lms_params->n * (1 + ots_params->p + lms_params->h));
        if (i != (levels -1)) {
            lms_type[i + 1] = t->sig[sigoff + 3];
            ots_type[i + 1] = t->sig[sigoff + 7];
            /* skip over public key fields */
            sigoff += 4 * 2 + 16 + lms_params->n;
        }
    }
    if (!TEST_true(sigoff == (uint32_t)t->siglen))
        return 0;
    /*
     * Use the signature 'q' values to calculate what the keypair index is
     * If we are dealing with a 3 level tree with sizes of i * j * k
     * where i is the root, and k is the leaf, and we have
     * q1 = 0..i-1, q2 = 0..j-1, q3 = 0..k-1
     *
     * the index would be q3 + k * q2 + j * k * q1.
     * So we need to go from the leaf up..
     */
    scale = 1;
    qindex = 0;
    for (i = levels; i > 0; --i) {
        const LMS_PARAMS *lms_params = ossl_lms_params_get(lms_type[i - 1]);

        qindex += scale * q[i - 1];
        scale *= (1 << lms_params->h);
    }
    *out_levels = levels;
    *out_qindex = qindex;
    return 1;
}

static const char *lms_names[OSSL_HSS_MAX_L] = {
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L1,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L2,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L3,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L4,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L5,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L6,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L7,
    OSSL_PKEY_PARAM_HSS_LMS_TYPE_L8
};
static const char *ots_names[OSSL_HSS_MAX_L] = {
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L1,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L2,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L3,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L4,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L5,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L6,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L7,
    OSSL_PKEY_PARAM_HSS_OTS_TYPE_L8,
};

static int hss_pkey_sign_test(int tst)
{
    int ret = 0;
    uint32_t i, levels;
    HSS_ACVP_TEST_DATA *t = &hss_testdata[tst];
    EVP_PKEY_CTX *genctx = NULL;
    EVP_PKEY_CTX *signctx = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY *reserve = NULL;
    EVP_SIGNATURE *sigalg = NULL;
    OSSL_ENCODER_CTX *ectx = NULL;
    uint64_t qindex;
    uint32_t lms_type[OSSL_HSS_MAX_L] = { 0 };
    uint32_t ots_type[OSSL_HSS_MAX_L] = { 0 };
    OSSL_PARAM params[2 + 2 * OSSL_HSS_MAX_L], *prm = params;
    unsigned char *sig = NULL;
    size_t siglen = 0;
    unsigned char *hsspubdata = NULL;
    size_t hsspubdatalen = 0;

    /*
     * Skip if the test does not specify the private key, this
     * is required for deterministic signing
     */
    if (t->priv == NULL)
        return 1;
    if (!extract_sign_data(t, &levels, lms_type, ots_type, &qindex))
        goto err;

    if (!TEST_ptr(genctx = EVP_PKEY_CTX_new_from_name(libctx, "HSS", propq))
            || !TEST_int_eq(EVP_PKEY_keygen_init(genctx), 1))
        goto err;

    *prm++ = OSSL_PARAM_construct_uint32(OSSL_PKEY_PARAM_HSS_LEVELS, &levels);
    for (i = 0; i < levels; i++) {
        *prm++ = OSSL_PARAM_construct_uint32(lms_names[i], &lms_type[i]);
        *prm++ = OSSL_PARAM_construct_uint32(ots_names[i], &ots_type[i]);
    }
    *prm = OSSL_PARAM_construct_end();
    if (!TEST_int_gt(EVP_PKEY_CTX_set_params(genctx, params), 0))
        goto err;

    /*
     * The private key SEED and I are randomly generated, so override
     * RAND to supply this data.
     */
    fake_rand_set_callback(RAND_get0_private(libctx), &fbytes);
    if (!TEST_true(set_entropy(t->priv,t->privlen, NULL, 0)))
        goto err;

    if (!TEST_int_gt(EVP_PKEY_generate(genctx, &key), 0))
        goto err;

    if (!TEST_ptr(ectx = OSSL_ENCODER_CTX_new_for_pkey(key, OSSL_KEYMGMT_SELECT_PUBLIC_KEY,
                                                       "xdr", NULL, NULL)))
        goto err;
    /* Save the public key for verifying later */
    hsspubdata = NULL;
    if (!TEST_true(OSSL_ENCODER_to_data(ectx, &hsspubdata, &hsspubdatalen)))
        goto err;
    if (!TEST_mem_eq(hsspubdata, hsspubdatalen, t->pub, t->publen))
        goto err;

    if (!TEST_ptr(sigalg = EVP_SIGNATURE_fetch(libctx, "HSS", propq)))
        goto err;

    /* Skip over the keygen keypairs that were already used by the testcase */
    if (!TEST_ptr(reserve = EVP_PKEY_reserve(key, qindex)))
        goto err;
    EVP_PKEY_free(reserve);

    if (!TEST_ptr(signctx = EVP_PKEY_CTX_new_from_pkey(libctx, key, propq)))
        goto err;
    siglen = t->siglen;
    if (!TEST_int_eq(EVP_PKEY_sign_message_init(signctx, sigalg, NULL), 1)
            || !TEST_ptr(sig = OPENSSL_malloc(t->siglen))
            || !TEST_int_eq(EVP_PKEY_sign(signctx, sig, &siglen,
                                          t->msg, t->msglen), 1)
            || !TEST_mem_eq(sig, siglen, t->sig, t->siglen))
        goto err;
    ret = 1;
err:
    OPENSSL_free(sig);
    OPENSSL_free(hsspubdata);
    OSSL_ENCODER_CTX_free(ectx);
    EVP_SIGNATURE_free(sigalg);
    EVP_PKEY_CTX_free(signctx);
    EVP_PKEY_CTX_free(genctx);
    EVP_PKEY_free(key);
    return ret;
}

    //        EVP_PKEY_print_private(bio_out, key, 0, NULL);
            //{
            //    unsigned char out[256];
            //    size_t outlen = 256;
            //    if (!EVP_Q_digest(libctx, "SHA1", propq, sig, siglen, out, &outlen))
            //        goto err;
            //    printf("\n---------------\nSignature SHA1 Checksum: %d: %s\n", i, OPENSSL_buf2hexstr(out, outlen));
            //}
    /*
            EVP_PKEY_print_private(bio_out, key, 0, NULL);
            if (!EVP_PKEY_get_size_t_param(key, OSSL_PKEY_PARAM_HSS_KEYS_REMAINING, &sz)
                    || !TEST_size_t_eq(sz, remaining))
                goto err;

            {
                HSS_KEY *tst;
                if (!TEST_ptr(tst = ossl_hss_key_new(libctx, propq)))
                    goto err;
                if (!TEST_true(ossl_hss_pubkey_decode(hsspubdata, hsspubdatalen, tst)))
                    goto err;
                ossl_hss_decode(tst, sig, siglen);
                ossl_hss_sig_to_text(bio_out, tst, OSSL_KEYMGMT_SELECT_KEYPAIR);
            }
    */
#endif

static size_t load_file(const char *filename, unsigned char **out)
{
    long retl = 0;
    size_t bytes;
    unsigned char buf[2048];
    BIO *membio = NULL, *in = NULL;

    if (!TEST_ptr(membio = BIO_new(BIO_s_mem()))
        || !TEST_ptr(in = BIO_new_file(filename, "rb")))
        goto err;

    while (!BIO_eof(in)) {
        if (!BIO_read_ex(in, buf, sizeof(buf), &bytes))
            break;
        if (BIO_write(membio, buf, bytes) != (int)bytes)
            break;
    }
    retl = BIO_get_mem_data(membio, out);
    BIO_set_flags(membio, BIO_FLAGS_MEM_RDONLY);
err:
    BIO_free(in);
    BIO_free(membio);
    return retl >= 0 ? retl : 0;
}

static EVP_PKEY *load_key(const char *filename)
{
    BIO *bio;
    EVP_PKEY *pkey;

    if (!TEST_ptr(bio = BIO_new_file(filename, "rb")))
        return NULL;
    pkey = key_decode_from_bio(bio, "HSS");

    BIO_free(bio);
    return pkey;
}

/* Verify a HSS signature that was generated using another toolkit */
static int hss_verify_hss_file_test(int tst)
{
    int ret = 0;
    EVP_SIGNATURE *sig = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_PARAM *p = NULL;
    EVP_PKEY *pub = NULL;
    unsigned char *sigdata = NULL;
    size_t sigdata_len = 0;

    if (!TEST_ptr(pub = load_key(pubfilename)))
        return 0;
    sigdata_len = load_file(sigfilename, &sigdata);
    if (!TEST_int_gt(sigdata_len, 0))
        goto err;

    if (!TEST_ptr(sig = EVP_SIGNATURE_fetch(libctx, "HSS", propq))
            || !TEST_ptr(ctx = EVP_PKEY_CTX_new_from_pkey(libctx, pub, propq)))
        goto err;

    if (tst == 1) {
        uint32_t threads = 8;

        p = params;
        params[0] = OSSL_PARAM_construct_uint32(OSSL_SIGNATURE_PARAM_THREADS,
                                                &threads);
    }
    if (!TEST_int_eq(EVP_PKEY_verify_message_init(ctx, sig, p), 1)
            || !TEST_int_eq(EVP_PKEY_verify(ctx, sigdata, sigdata_len,
                                            (unsigned char *)"ABC", 3), 1))
        goto err;

    ret = 1;
 err:
    EVP_SIGNATURE_free(sig);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pub);
    OPENSSL_free(sigdata);
    return ret;
}

const OPTIONS *test_get_options(void)
{
    static const OPTIONS options[] = {
        OPT_TEST_OPTIONS_DEFAULT_USAGE,
        { "pub", OPT_PUB, '<', "HSS public key filename" },
        { "sig", OPT_SIG, '<', "HSS signature filename" },
        { "config", OPT_CONFIG_FILE, '<',
          "The configuration file to use for the libctx" },
        { NULL }
    };
    return options;
}

int setup_tests(void)
{
    OPTION_CHOICE o;
    char *config_file = NULL;

    /* Swap the libctx to test non-default context only */
    propq = "provider=default";

    while ((o = opt_next()) != OPT_EOF) {
        switch (o) {
        case OPT_PUB:
            pubfilename = opt_arg();
            break;
        case OPT_SIG:
            sigfilename = opt_arg();
            break;
        case OPT_CONFIG_FILE:
            config_file = opt_arg();
            propq = "";
            break;
        case OPT_TEST_CASES:
           break;
        default:
        case OPT_ERR:
            return 0;
        }
    }

    if (!test_get_libctx(&libctx, &nullprov, config_file, &libprov, NULL))
        return 0;

    fake_rand = fake_rand_start(libctx);
    if (!OSSL_set_max_threads(libctx, 16))
        return 0;
    if (pubfilename != NULL && sigfilename != NULL) {
        ADD_ALL_TESTS(hss_verify_hss_file_test, 2);
    } else {
        ADD_ALL_TESTS(hss_pkey_verify_test, OSSL_NELEM(hss_testdata));
        ADD_ALL_TESTS(hss_pkey_verify_update_test, OSSL_NELEM(hss_testdata));
        ADD_TEST(hss_pkey_verify_fail_test);
        ADD_TEST(hss_verify_bad_sig_test);
        ADD_TEST(hss_pubkey_decoder_test);
        ADD_TEST(hss_verify_bad_sig_len_test);
        ADD_TEST(hss_verify_bad_pub_sig_test);
        ADD_TEST(hss_bad_pub_len_test);
        ADD_TEST(hss_decode_fail_test);
        ADD_TEST(hss_pubkey_decoder_fail_test);
        ADD_TEST(hss_key_eq_test);
        ADD_TEST(hss_key_validate_test);
#ifndef OPENSSL_NO_HSS_GEN
        ADD_ALL_TESTS(hss_pkey_sign_test, OSSL_NELEM(hss_testdata));
#endif
    }
    return 1;
}

void cleanup_tests(void)
{
    fake_rand_finish(fake_rand);
    OSSL_PROVIDER_unload(nullprov);
    OSSL_PROVIDER_unload(libprov);
    OSSL_LIB_CTX_free(libctx);
}
