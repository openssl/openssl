/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*-
 * Table driven EC parameter and key generation tests.
 *
 * Every curve is exercised in this process.  The generation is driven
 * through EVP_PKEY_CTX_ctrl_str() with the same option names the
 * "openssl genpkey" application passes to -pkeyopt, so the provider side
 * of the application's code path is covered here.  The application's own
 * command line surface is covered separately by
 * test/recipes/20-test_app_genec.t, which needs only a handful of curves
 * because the option handling does not vary between them.
 */

#include <string.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/crypto.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>
#include <openssl/err.h>
#include <openssl/evp.h>

#include "testutil.h"

static const char *const curves[] = {
    "secp112r1",
    "secp112r2",
    "secp128r1",
    "secp128r2",
    "secp160k1",
    "secp160r1",
    "secp160r2",
    "secp192k1",
    "secp224k1",
    "secp224r1",
    "secp256k1",
    "secp384r1",
    "secp521r1",
    "prime192v1",
    "prime192v2",
    "prime192v3",
    "prime239v1",
    "prime239v2",
    "prime239v3",
    "prime256v1",
    "wap-wsg-idm-ecid-wtls6",
    "wap-wsg-idm-ecid-wtls7",
    "wap-wsg-idm-ecid-wtls8",
    "wap-wsg-idm-ecid-wtls9",
    "wap-wsg-idm-ecid-wtls12",
    "brainpoolP160r1",
    "brainpoolP160t1",
    "brainpoolP192r1",
    "brainpoolP192t1",
    "brainpoolP224r1",
    "brainpoolP224t1",
    "brainpoolP256r1",
    "brainpoolP256t1",
    "brainpoolP320r1",
    "brainpoolP320t1",
    "brainpoolP384r1",
    "brainpoolP384t1",
    "brainpoolP512r1",
    "brainpoolP512t1",
#if !defined(OPENSSL_NO_EC2M)
    "sect113r1",
    "sect113r2",
    "sect131r1",
    "sect131r2",
    "sect163k1",
    "sect163r1",
    "sect163r2",
    "sect193r1",
    "sect193r2",
    "sect233k1",
    "sect233r1",
    "sect239k1",
    "sect283k1",
    "sect283r1",
    "sect409k1",
    "sect409r1",
    "sect571k1",
    "sect571r1",
    "c2pnb163v1",
    "c2pnb163v2",
    "c2pnb163v3",
    "c2pnb176v1",
    "c2tnb191v1",
    "c2tnb191v2",
    "c2tnb191v3",
    "c2pnb208w1",
    "c2tnb239v1",
    "c2tnb239v2",
    "c2tnb239v3",
    "c2pnb272w1",
    "c2pnb304w1",
    "c2tnb359v1",
    "c2pnb368w1",
    "c2tnb431r1",
    "wap-wsg-idm-ecid-wtls1",
    "wap-wsg-idm-ecid-wtls3",
    "wap-wsg-idm-ecid-wtls4",
    "wap-wsg-idm-ecid-wtls5",
    "wap-wsg-idm-ecid-wtls10",
    "wap-wsg-idm-ecid-wtls11",
#endif /* !defined(OPENSSL_NO_EC2M) */
    /*
     * The SM2 curve is deliberately absent.  A key generated on it as an
     * EC key decodes back as an SM2 key, so it does not satisfy the round
     * trip below.  It is covered by test/recipes/20-test_app_genec.t,
     * which only requires that generation and output succeed.
     */
    "P-192",
    "P-224",
    "P-256",
    "P-384",
    "P-521",
#if !defined(OPENSSL_NO_EC2M)
    "B-163",
    "B-233",
    "B-283",
    "B-409",
    "B-571",
    "K-163",
    "K-233",
    "K-283",
    "K-409",
    "K-571",
#endif /* !defined(OPENSSL_NO_EC2M) */
};

#if !defined(OPENSSL_NO_EC2M)
/* Curves that have no assigned OID and so cannot use a named encoding. */
static const char *const explicit_only_curves[] = {
    "Oakley-EC2N-3",
    "Oakley-EC2N-4",
};
#endif /* !defined(OPENSSL_NO_EC2M) */

static const char *const param_encodings[] = { "named_curve", "explicit" };

static const char *const formats[] = { "PEM", "DER" };

/**
 * @brief Generate EC parameters or an EC key on a named curve.
 *
 * The curve and the parameter encoding are set with the same option
 * names the genpkey application accepts via -pkeyopt.  No test
 * assertions are made here so that callers can also use this to check
 * that a combination is correctly rejected.
 *
 * @param curve the name of the curve to generate on
 * @param param_enc the parameter encoding, "named_curve" or "explicit"
 * @param params_only 1 to generate parameters only, 0 to generate a key
 * @returns the generated EVP_PKEY, or NULL on failure
 */
static EVP_PKEY *gen_ec(const char *curve, const char *param_enc,
    int params_only)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;

    if ((ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL)) == NULL)
        return NULL;

    if (params_only) {
        if (EVP_PKEY_paramgen_init(ctx) <= 0)
            goto end;
    } else {
        if (EVP_PKEY_keygen_init(ctx) <= 0)
            goto end;
    }

    if (EVP_PKEY_CTX_ctrl_str(ctx, "ec_paramgen_curve", curve) <= 0
        || EVP_PKEY_CTX_ctrl_str(ctx, "ec_param_enc", param_enc) <= 0)
        goto end;

    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        EVP_PKEY_free(pkey);
        pkey = NULL;
    }

end:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/**
 * @brief Encode a key or parameter set into a freshly allocated buffer.
 *
 * No test assertions are made here so that callers can also use this to
 * check that an encoding is correctly refused.
 *
 * @param pkey the key or parameter set to encode
 * @param selection the EVP_PKEY_* selection to encode
 * @param structure the encoder output structure name
 * @param format the encoding to use, "PEM" or "DER"
 * @param out where to store the allocated encoding, freed by the caller
 * @param out_len where to store the length of the encoding
 * @returns 1 on success, 0 on failure
 */
static int encode_pkey(EVP_PKEY *pkey, int selection, const char *structure,
    const char *format, unsigned char **out, size_t *out_len)
{
    OSSL_ENCODER_CTX *ectx = NULL;
    BIO *mem = NULL;
    BUF_MEM *buf = NULL;
    int ret = 0;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, selection, format, structure,
        NULL);
    if (ectx == NULL || OSSL_ENCODER_CTX_get_num_encoders(ectx) == 0)
        goto end;

    if ((mem = BIO_new(BIO_s_mem())) == NULL
        || !OSSL_ENCODER_to_bio(ectx, mem)
        || BIO_get_mem_ptr(mem, &buf) <= 0
        || buf->length == 0)
        goto end;

    if ((*out = OPENSSL_memdup(buf->data, buf->length)) == NULL)
        goto end;
    *out_len = buf->length;
    ret = 1;

end:
    BIO_free(mem);
    OSSL_ENCODER_CTX_free(ectx);
    return ret;
}

/**
 * @brief Encode a key, decode the result, and encode it a second time.
 *
 * The two encodings must be identical.  This is compared rather than the
 * key objects themselves because an explicit encoding of a curve that is
 * an alias of another curve does not decode to an object that
 * EVP_PKEY_eq() considers equal to the original, even though the key
 * material survives intact.
 *
 * @param pkey the key or parameter set to round trip
 * @param selection the EVP_PKEY_* selection to encode and decode
 * @param structure the encoder output structure name
 * @param format the encoding to use, "PEM" or "DER"
 * @returns 1 if the re-encoding matched the original encoding, 0 otherwise
 */
static int round_trip(EVP_PKEY *pkey, int selection, const char *structure,
    const char *format)
{
    OSSL_DECODER_CTX *dctx = NULL;
    EVP_PKEY *decoded = NULL;
    BIO *in = NULL;
    unsigned char *first = NULL, *second = NULL;
    size_t first_len = 0, second_len = 0;
    int ret = 0;

    if (!TEST_true(encode_pkey(pkey, selection, structure, format, &first,
            &first_len)))
        goto end;

    /*
     * Decode from a separate read only BIO.  Resetting the BIO written to
     * by the encoder would discard the encoding rather than rewind it.
     */
    if (!TEST_ptr(in = BIO_new_mem_buf(first, (int)first_len))
        || !TEST_ptr(dctx = OSSL_DECODER_CTX_new_for_pkey(&decoded, format,
                         structure, NULL, selection, NULL, NULL))
        || !TEST_true(OSSL_DECODER_from_bio(dctx, in))
        || !TEST_ptr(decoded))
        goto end;

    if (!TEST_true(encode_pkey(decoded, selection, structure, format, &second,
            &second_len)))
        goto end;

    ret = TEST_mem_eq(first, first_len, second, second_len);

end:
    OPENSSL_free(first);
    OPENSSL_free(second);
    EVP_PKEY_free(decoded);
    OSSL_DECODER_CTX_free(dctx);
    BIO_free(in);
    return ret;
}

/**
 * @brief Render a key as text, as the genpkey -text option does.
 *
 * @param pkey the key or parameter set to print
 * @param params_only 1 if pkey holds parameters only, 0 if it holds a key
 * @returns 1 on success, 0 on failure
 */
static int print_ec(EVP_PKEY *pkey, int params_only)
{
    BIO *bio = NULL;
    int ret = 0;

    if (!TEST_ptr(bio = BIO_new(BIO_s_null())))
        return 0;

    if (params_only)
        ret = TEST_int_gt(EVP_PKEY_print_params(bio, pkey, 0, NULL), 0);
    else
        ret = TEST_int_gt(EVP_PKEY_print_private(bio, pkey, 0, NULL), 0);

    BIO_free(bio);
    return ret;
}

/**
 * @brief Generate parameters on one curve in every supported encoding.
 *
 * @param idx the index into the curve table
 * @returns 1 on success, 0 on failure
 */
static int test_genec_params(int idx)
{
    const char *curve = curves[idx];
    EVP_PKEY *pkey = NULL;
    size_t i, j;
    int ret = 0;

    for (i = 0; i < OSSL_NELEM(param_encodings); i++) {
        EVP_PKEY_free(pkey);
        pkey = NULL;

        if (!TEST_ptr(pkey = gen_ec(curve, param_encodings[i], 1))
            || !print_ec(pkey, 1))
            goto end;

        for (j = 0; j < OSSL_NELEM(formats); j++)
            if (!round_trip(pkey, EVP_PKEY_KEY_PARAMETERS, "type-specific",
                    formats[j]))
                goto end;
    }
    ret = 1;

end:
    if (ret == 0)
        TEST_info("EC parameter generation failed for curve %s", curve);
    EVP_PKEY_free(pkey);
    return ret;
}

/**
 * @brief Generate a key on one curve in every supported encoding.
 *
 * @param idx the index into the curve table
 * @returns 1 on success, 0 on failure
 */
static int test_genec_key(int idx)
{
    const char *curve = curves[idx];
    EVP_PKEY *pkey = NULL;
    size_t i, j;
    int ret = 0;

    for (i = 0; i < OSSL_NELEM(param_encodings); i++) {
        EVP_PKEY_free(pkey);
        pkey = NULL;

        if (!TEST_ptr(pkey = gen_ec(curve, param_encodings[i], 0))
            || !print_ec(pkey, 0))
            goto end;

        for (j = 0; j < OSSL_NELEM(formats); j++)
            if (!round_trip(pkey, EVP_PKEY_KEYPAIR, "PrivateKeyInfo",
                    formats[j])
                || !round_trip(pkey, EVP_PKEY_PUBLIC_KEY,
                    "SubjectPublicKeyInfo", formats[j]))
                goto end;
    }
    ret = 1;

end:
    if (ret == 0)
        TEST_info("EC key generation failed for curve %s", curve);
    EVP_PKEY_free(pkey);
    return ret;
}

#if !defined(OPENSSL_NO_EC2M)
/**
 * @brief Check a curve that only supports an explicit parameter encoding.
 *
 * Generation itself succeeds for either encoding; it is the structured
 * encoding of a named curve that must be refused, because the curve has
 * no OID to name it by.
 *
 * @param idx the index into the explicit only curve table
 * @returns 1 on success, 0 on failure
 */
static int test_genec_explicit_only(int idx)
{
    const char *curve = explicit_only_curves[idx];
    EVP_PKEY *pkey = NULL;
    unsigned char *enc = NULL;
    size_t enc_len = 0, j;
    int ret = 0;

    if (!TEST_ptr(pkey = gen_ec(curve, "named_curve", 1)))
        goto end;

    for (j = 0; j < OSSL_NELEM(formats); j++) {
        ERR_set_mark();
        ret = encode_pkey(pkey, EVP_PKEY_KEY_PARAMETERS, "type-specific",
            formats[j], &enc, &enc_len);
        ERR_pop_to_mark();
        OPENSSL_free(enc);
        enc = NULL;
        if (!TEST_false(ret)) {
            ret = 0;
            goto end;
        }
    }
    ret = 0;

    EVP_PKEY_free(pkey);
    if (!TEST_ptr(pkey = gen_ec(curve, "explicit", 1))
        || !print_ec(pkey, 1))
        goto end;

    for (j = 0; j < OSSL_NELEM(formats); j++)
        if (!round_trip(pkey, EVP_PKEY_KEY_PARAMETERS, "type-specific",
                formats[j]))
            goto end;
    ret = 1;

end:
    if (ret == 0)
        TEST_info("explicit only curve %s failed", curve);
    OPENSSL_free(enc);
    EVP_PKEY_free(pkey);
    return ret;
}
#endif /* !defined(OPENSSL_NO_EC2M) */

/**
 * @brief Check that an unknown curve name is rejected.
 *
 * @returns 1 on success, 0 on failure
 */
static int test_genec_unknown_curve(void)
{
    EVP_PKEY *pkey;

    ERR_set_mark();
    pkey = gen_ec("bogus_foobar_curve", "named_curve", 1);
    ERR_pop_to_mark();

    if (!TEST_ptr_null(pkey)) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    return 1;
}

int setup_tests(void)
{
    ADD_ALL_TESTS(test_genec_params, OSSL_NELEM(curves));
    ADD_ALL_TESTS(test_genec_key, OSSL_NELEM(curves));
#if !defined(OPENSSL_NO_EC2M)
    ADD_ALL_TESTS(test_genec_explicit_only, OSSL_NELEM(explicit_only_curves));
#endif /* !defined(OPENSSL_NO_EC2M) */
    ADD_TEST(test_genec_unknown_curve);
    return 1;
}
