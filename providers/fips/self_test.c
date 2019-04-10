/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "self_test.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/ossl_typ.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/rsa.h>
#include <openssl/dsa.h>
#include <openssl/hmac.h>

#define FIPS_STATE_INIT     0
#define FIPS_STATE_RUNNING  1
#define FIPS_STATE_SELFTEST 2
#define FIPS_STATE_ERROR    3

/* The size of a temp buffer used to read in data */
#define INTEGRITY_BUF_SIZE (4 * 1024)

static int FIPS_state = FIPS_STATE_INIT;
static SELF_TEST_CB SELF_TEST_cb = NULL;
#if 0
static unsigned char fixed_key[32] = {0};
#endif

void SELF_TEST_EVENT_init(ST_EVENT *ev)
{
    size_t n = 0;

    if (ev == NULL)
        return;

    if (SELF_TEST_cb != NULL) {
        ev->params[n++] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_TEST_PHASE,
                                                   &ev->phase, NULL);
        ev->params[n++] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_TEST_TYPE,
                                                   &ev->type, NULL);
        ev->params[n++] = OSSL_PARAM_construct_int(OSSL_PROV_PARAM_TEST_DESC,
                                                   &ev->desc, NULL);
    }
    ev->params[n++] = OSSL_PARAM_construct_end();
}

/*
 * Can be used during application testing to log that a test has started.
 */
void SELF_TEST_EVENT_onbegin(ST_EVENT *ev, int type, int desc)
{
    if (ev != NULL && SELF_TEST_cb != NULL) {
        ev->phase = SELF_TEST_PHASE_START;
        ev->type = type;
        ev->desc = desc;
        (void)SELF_TEST_cb(ev->params);
    }
}

/*
 * Can be used during application testing to log that a test has either
 * passed or failed.
 */
void SELF_TEST_EVENT_onend(ST_EVENT *ev, int ret)
{
    if (ev != NULL && SELF_TEST_cb != NULL) {
        ev->phase = (ret == 0 ? SELF_TEST_PHASE_PASS : SELF_TEST_PHASE_FAIL);
        (void)SELF_TEST_cb(ev->params);

        ev->phase = SELF_TEST_PHASE_NONE;
        ev->type = SELF_TEST_TYPE_NONE;
        ev->desc = SELF_TEST_DESC_NONE;
    }
}

/*
 * Used for failure testing.
 *
 * Call the applications SELF_TEST_cb() if it exists.
 * If the application callback decides to return 0 then the first byte of 'data'
 * is modified (corrupted). This is used to modify output signatures or
 * ciphertext before they are verified or decrypted.
 */
void SELF_TEST_EVENT_oncorrupt_byte(ST_EVENT *ev, unsigned char *bytes)
{
    if (ev != NULL && SELF_TEST_cb != NULL) {
        ev->phase = SELF_TEST_PHASE_CORRUPT;
        if (!SELF_TEST_cb(ev->params))
            bytes[0] ^= 1;
    }
}

/*
 * For RSA key generation it is not known whether the key pair will be used
 * for key transport or signatures. FIPS 140-2 IG 9.9 states that in this case
 * either a signature verification OR an encryption operation may be used to
 * perform the pairwise consistency check. The simpler encrypt/decrypt operation
 * has been chosen for this case.
 */
int SELF_TEST_keygen_pairwise_test_rsa(RSA *rsa)
{
    int ret = 1;
#if 0
    unsigned int ciphertxt_len;
    unsigned char *ciphertxt;
    const unsigned char plaintxt[16] = {0};
    unsigned char decoded[256];
    unsigned int decoded_len;
    unsigned int plaintxt_len = (unsigned int)sizeof(plaintxt_len);
    int padding = RSA_PKCS1_PADDING;
    ST_EVENT ev;

    SELF_TEST_EVENT_init(&ev);
    SELF_TEST_EVENT_onbegin(&ev, SELF_TEST_TYPE_PCT,
                            SELF_TEST_DESC_PCT_RSA_PKCS1);

    ciphertxt_len = RSA_size(rsa);
    ciphertxt = OPENSSL_zalloc(ciphertxt_len);
    if (ciphertxt == NULL) {
        goto err;
    }

    ciphertxt_len = RSA_public_encrypt(plaintxt_len, plaintxt, ciphertxt, rsa,
                                       padding);
    if (ciphertxt_len <= 0)
        goto err;
    if (ciphertxt_len == plaintxt_len
            && memcmp(decoded, plaintxt, plaintxt_len) == 0) {
        goto err;
    }

    SELF_TEST_EVENT_oncorrupt_byte(&ev, ciphertxt);

    decoded_len = RSA_private_decrypt(ciphertxt_len, ciphertxt, decoded, rsa,
                                      padding);
    if (decoded_len != plaintxt_len
            || memcmp(decoded, plaintxt,  decoded_len) != 0) {
        goto err;
    }
    ret = 0;
err:
    SELF_TEST_EVENT_onend(&ev, ret);
    OPENSSL_free(ciphertxt);
#endif
    return ret;
}

int SELF_TEST_keygen_pairwise_test_ecdsa(EC_KEY *eckey)
{
    int ret = 1;
#if 0
    unsigned char dgst[16] = {0};
    int dgst_len = (int)sizeof(dgst);
    ECDSA_SIG *sig = NULL;
    ST_EVENT ev;

    SELF_TEST_EVENT_init(&ev);
    SELF_TEST_EVENT_onbegin(&ev, SELF_TEST_TYPE_PCT, SELF_TEST_DESC_PCT_ECDSA);

    sig = ECDSA_do_sign(dgst, dgst_len, eckey);
    if (sig == NULL)
        goto err;

    SELF_TEST_EVENT_oncorrupt_byte(&ev, dgst);

    if (ECDSA_do_verify(dgst, dgst_len, sig, eckey) != 1)
        goto err;

    ret = 0;
err:
    SELF_TEST_EVENT_onend(&ev, ret);
    ECDSA_SIG_free(sig);
#endif
    return ret;
}

int SELF_TEST_keygen_pairwise_test_dsa(DSA *dsa)
{
    int ret = 1;
#if 0
    unsigned char dgst[16] = {0};
    unsigned int dgst_len = (unsigned int)sizeof(dgst);
    DSA_SIG *sig = NULL;
    ST_EVENT ev;

    SELF_TEST_EVENT_init(&ev);
    SELF_TEST_EVENT_onbegin(&ev, SELF_TEST_TYPE_PCT, SELF_TEST_DESC_PCT_DSA);

    sig = DSA_do_sign(dgst, (int)dgst_len, dsa);
    if (sig == NULL)
        goto err;

    SELF_TEST_EVENT_oncorrupt_byte(&ev, dgst);

    if (DSA_do_verify(dgst, dgst_len, sig, dsa) != 1)
        goto err;

    ret = 0;
err:
    SELF_TEST_EVENT_onend(&ev, ret);
    DSA_SIG_free(sig);
#endif
    return ret;
}

/*
 * Calculate the HMAC SHA256 of data read using a BIO and read_cb, and verify
 * the result matches the expected value.
 * Return 1 if verified, or 0 if it fails.
 */
static int verify_integrity(BIO *bio, BIO_READ_CB read_cb,
                            unsigned char *expected, size_t expected_len,
                            ST_EVENT *ev, int type)
{
#if 0
    int ret = 0;
    HMAC_CTX *ctx = NULL;
    unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int out_len = 0;
    size_t bytes_read = 0;
    unsigned char buf[INTEGRITY_BUF_SIZE];
    const EVP_MD *md = EVP_sha256();

    SELF_TEST_EVENT_onbegin(ev, type, SELF_TEST_DESC_INTEGRITY_HMAC);

    /* TODO - Is HMAC_ the correct interface to call ? */
    ctx = HMAC_CTX_new();
    if (ctx == NULL)
        goto err;

    if (!HMAC_Init_ex(ctx, fixed_key, (int)sizeof(fixed_key), md, NULL))
        goto err;
    while (1) {
        ret = read_cb(bio, buf, sizeof(buf), &bytes_read);
        if (ret != 1)
            break;
        if (!HMAC_Update(ctx, buf, bytes_read))
            goto err;
    }
    if (!HMAC_Final(ctx, out, &out_len))
        goto err;

    SELF_TEST_EVENT_oncorrupt_byte(ev, out);

    if (expected_len != (size_t)out_len
            || memcmp(expected, out, (size_t)out_len) != 0)
        goto err;
    ret = 0;
err:
    SELF_TEST_EVENT_onend(ev, ret);
    HMAC_CTX_free(ctx);
    return ret;
#else
    return 1;
#endif
}

#if 0
/*
 * Load in a configuration hex string and convert it to bytes.
 * Needs to move into the core, so the value can be passed as a param
 * to the FIPS module.
 */
static int st_get_hex_data(SELF_TEST_POST_PARAMS *params, const char *name,
                           unsigned char *out, size_t *out_len)
{
    int ret = 1;
    long len;
    unsigned char *buf = NULL;
    char *value;

    if (params->conf == NULL || params->conf_get_string_cb == NULL)
        return 0;

    value = params->conf_get_string_cb(params->conf, "fips", name);
    buf = OPENSSL_hexstr2buf(value, &len);
    if (buf != NULL) {
        *out_len = (size_t)len;
        memcpy(out, buf, *out_len);
        ret = 0;
    }
    OPENSSL_free(buf);
    return ret;
}
#endif

/* This API is triggered either on loading of the FIPS module or on demand */
int SELF_TEST_post(SELF_TEST_POST_PARAMS *params)
{
    int ok = 0;
    int kats_already_passed = 0;
    int on_demand_test = (FIPS_state != FIPS_STATE_INIT);
    BIO *bio_module = NULL, *bio_indicator = NULL;
    ST_EVENT ev;

    if (params == NULL)
        goto end;
    if (FIPS_state == FIPS_STATE_ERROR || FIPS_state == FIPS_STATE_SELFTEST)
        goto end;

    SELF_TEST_cb = params->test_cb;
    SELF_TEST_EVENT_init(&ev);

    bio_module = (*params->bio_new_file_cb)(params->module_filename, "rb");

    /* Always check the integrity of the fips module */
    if (bio_module == NULL
            || !verify_integrity(bio_module, params->bio_read_cb,
                                 params->module_checksum_data,
                                 params->module_checksum_len,
                                 &ev, SELF_TEST_TYPE_MODULE_INTEGRITY))
        goto end;

    /* This will be NULL during installation - so the self test will run */
    if (params->indicator_data != NULL) {
        /*
         * If the kats have already passed indicator is set - then check the
         * integrity of the indicator.
         */
        bio_indicator = (*params->bio_new_buffer_cb)(params->indicator_data,
                                                     strlen(params->indicator_data));
        if (bio_indicator == NULL
                || !verify_integrity(bio_indicator, params->bio_read_cb,
                                     params->indicator_checksum_data,
                                     params->indicator_checksum_len,
                                     &ev, SELF_TEST_TYPE_INSTALL_INTEGRITY))
            goto end;
        else
            kats_already_passed = 1;
    }

    /* Only runs the KAT's during installation OR on_demand() */
    if (on_demand_test || kats_already_passed == 0) {
        if (!self_test_kats(&ev))
            goto end;
    }
    ok = 1;
end:
    (*params->bio_free_cb)(bio_indicator);
    (*params->bio_free_cb)(bio_module);

    FIPS_state = ok ? FIPS_STATE_RUNNING : FIPS_STATE_ERROR;

    return ok;
}
