/*
 * Copyright 2024-2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/opensslconf.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#ifndef OPENSSL_NO_STDIO
#include <stdio.h>
#endif
#include <crypto/ml_kem.h>
#include "ml_kem_local.h"
#include "testutil.h"
#include "testutil/output.h"

static uint8_t ml_kem_private_entropy[] = {
    /* Seed for genkey */
    0x7c, 0x99, 0x35, 0xa0, 0xb0, 0x76, 0x94, 0xaa, 0x0c, 0x6d, 0x10, 0xe4,
    0xdb, 0x6b, 0x1a, 0xdd, 0x2f, 0xd8, 0x1a, 0x25, 0xcc, 0xb1, 0x48, 0x03,
    0x2d, 0xcd, 0x73, 0x99, 0x36, 0x73, 0x7f, 0x2d, 0x86, 0x26, 0xed, 0x79,
    0xd4, 0x51, 0x14, 0x08, 0x00, 0xe0, 0x3b, 0x59, 0xb9, 0x56, 0xf8, 0x21,
    0x0e, 0x55, 0x60, 0x67, 0x40, 0x7d, 0x13, 0xdc, 0x90, 0xfa, 0x9e, 0x8b,
    0x87, 0x2b, 0xfb, 0x8f
};
static uint8_t ml_kem_public_entropy[] = {
    /* Seed for encap */
    0x14, 0x7c, 0x03, 0xf7, 0xa5, 0xbe, 0xbb, 0xa4, 0x06, 0xc8, 0xfa, 0xe1,
    0x87, 0x4d, 0x7f, 0x13, 0xc8, 0x0e, 0xfe, 0x79, 0xa3, 0xa9, 0xa8, 0x74,
    0xcc, 0x09, 0xfe, 0x76, 0xf6, 0x99, 0x76, 0x15,
    /* Seed for decap on length error */
    0x4e, 0x6f, 0x74, 0x20, 0x74, 0x68, 0x65, 0x20, 0x64, 0x72, 0x6f, 0x69,
    0x64, 0x73, 0x20, 0x79, 0x6f, 0x75, 0x27, 0x72, 0x65, 0x20, 0x6c, 0x6f,
    0x6f, 0x6b, 0x69, 0x6e, 0x67, 0x20, 0x66, 0x6f
};
static uint8_t ml_kem_expected_rho[3][ML_KEM_RANDOM_BYTES] = {
    { 0x7e, 0xfb, 0x9e, 0x40, 0xc3, 0xbf, 0x0f, 0xf0, 0x43, 0x29, 0x86, 0xae,
        0x4b, 0xc1, 0xa2, 0x42, 0xce, 0x99, 0x21, 0xaa, 0x9e, 0x22, 0x44, 0x88,
        0x19, 0x58, 0x5d, 0xea, 0x30, 0x8e, 0xb0, 0x39 },
    { 0x16, 0x2e, 0xc0, 0x98, 0xa9, 0x00, 0xb1, 0x2d, 0xd8, 0xfa, 0xbb, 0xfb,
        0x3f, 0xe8, 0xcb, 0x1d, 0xc4, 0xe8, 0x31, 0x5f, 0x2a, 0xf0, 0xd3, 0x2f,
        0x00, 0x17, 0xae, 0x13, 0x6e, 0x19, 0xf0, 0x28 },
    { 0x29, 0xb4, 0xf9, 0xf8, 0xcf, 0xba, 0xdf, 0x2e, 0x41, 0x86, 0x9a, 0xbf,
        0xba, 0xd1, 0x07, 0x38, 0xad, 0x04, 0xcc, 0x75, 0x2b, 0xc2, 0x0c, 0x39,
        0x47, 0x46, 0x85, 0x0e, 0x0c, 0x48, 0x47, 0xdb }
};
static uint8_t ml_kem_expected_ctext_sha256[3][32] = {
    { 0xbc, 0x29, 0xd7, 0xdf, 0x8b, 0xc5, 0x46, 0x5d, 0x98, 0x06, 0x01, 0xd8,
        0x00, 0x25, 0x97, 0x93, 0xe2, 0x60, 0x38, 0x25, 0xa5, 0x72, 0xda, 0x6c,
        0xd1, 0x98, 0xa5, 0x12, 0xcc, 0x6d, 0x1a, 0x34 },
    { 0x36, 0x82, 0x9a, 0x2f, 0x35, 0xcb, 0xf4, 0xde, 0xb6, 0x2c, 0x0a, 0x12,
        0xa1, 0x5c, 0x22, 0xda, 0xe9, 0xf8, 0xd2, 0xc2, 0x52, 0x56, 0x6f, 0xc2,
        0x4f, 0x88, 0xab, 0xe8, 0x05, 0xcb, 0x57, 0x5e },
    { 0x50, 0x81, 0x36, 0xa1, 0x3f, 0x8a, 0x79, 0x20, 0xe3, 0x43, 0x44, 0x98,
        0xc6, 0x97, 0x5c, 0xbb, 0xab, 0x45, 0x7d, 0x80, 0x93, 0x09, 0xeb, 0x2f,
        0x92, 0x45, 0x3e, 0x74, 0x09, 0x73, 0x82, 0x10 }
};
static uint8_t ml_kem_expected_shared_secret[3][32] = {
    { 0x31, 0x98, 0x39, 0xe8, 0x2a, 0xb6, 0xb2, 0x22, 0xde, 0x7b, 0x61, 0x9e,
        0x80, 0xda, 0x83, 0x91, 0x52, 0x2b, 0xbb, 0x37, 0x67, 0x70, 0x18, 0x49,
        0x4a, 0x47, 0x42, 0xc5, 0x3f, 0x9a, 0xbf, 0xdf },
    { 0xe7, 0x18, 0x4a, 0x09, 0x75, 0xee, 0x34, 0x70, 0x87, 0x8d, 0x2d, 0x15,
        0x9e, 0xc8, 0x31, 0x29, 0xc8, 0xae, 0xc2, 0x53, 0xd4, 0xee, 0x17, 0xb4,
        0x81, 0x03, 0x11, 0xd1, 0x98, 0xcd, 0x03, 0x68 },
    { 0x48, 0x9d, 0xd1, 0xe9, 0xc2, 0xbe, 0x4a, 0xf3, 0x48, 0x2b, 0xdb, 0x35,
        0xbb, 0x26, 0xce, 0x76, 0x0e, 0x6e, 0x41, 0x4d, 0xa6, 0xec, 0xbe, 0x48,
        0x99, 0x85, 0x74, 0x8a, 0x82, 0x5f, 0x1c, 0xd6 },
};

static int sanity_test(void)
{
    static const int alg[3] = {
        EVP_PKEY_ML_KEM_512,
        EVP_PKEY_ML_KEM_768,
        EVP_PKEY_ML_KEM_1024
    };
    EVP_RAND_CTX *privctx;
    EVP_RAND_CTX *pubctx;
    EVP_MD *sha256 = EVP_MD_fetch(NULL, "sha256", NULL);
    uint8_t *decap_entropy;
    int i, ret = 0;

    if (!TEST_ptr(sha256))
        return 0;

    if (!TEST_ptr(privctx = RAND_get0_private(NULL))
        || !TEST_ptr(pubctx = RAND_get0_public(NULL))) {
        ret = -1;
        goto err;
    }

    decap_entropy = ml_kem_public_entropy + ML_KEM_RANDOM_BYTES;

    for (i = 0; i < (int)OSSL_NELEM(alg); ++i) {
        OSSL_PARAM params[3];
        uint8_t hash[32];
        uint8_t shared_secret[ML_KEM_SHARED_SECRET_BYTES];
        uint8_t shared_secret2[ML_KEM_SHARED_SECRET_BYTES];
        uint8_t *encoded_public_key = NULL;
        uint8_t *ciphertext = NULL;
        ML_KEM_KEY *private_key = NULL;
        ML_KEM_KEY *public_key = NULL;
        int ret2 = -1;
        unsigned char c;
        unsigned int strength = 256;
        const ML_KEM_VINFO *v;

        /* Configure the private RNG to output just the keygen seed */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
            ml_kem_private_entropy,
            sizeof(ml_kem_private_entropy));
        params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
        params[2] = OSSL_PARAM_construct_end();
        if (!TEST_true(EVP_RAND_CTX_set_params(privctx, params))) {
            ret = -1;
            goto err;
        }

        public_key = ossl_ml_kem_key_new(NULL, NULL, alg[i]);
        private_key = ossl_ml_kem_key_new(NULL, NULL, alg[i]);
        if (private_key == NULL || public_key == NULL
            || (v = ossl_ml_kem_key_vinfo(public_key)) == NULL)
            goto done;

        encoded_public_key = OPENSSL_malloc(v->pubkey_bytes);
        ciphertext = OPENSSL_malloc(v->ctext_bytes);
        if (encoded_public_key == NULL || ciphertext == NULL)
            goto done;

        ret2 = -2;
        /* Generate a private key */
        if (!ossl_ml_kem_genkey(encoded_public_key, v->pubkey_bytes,
                private_key))
            goto done;

        /* Check that no more entropy is available! */
        if (!TEST_int_le(RAND_priv_bytes(&c, 1), 0))
            goto done;

        ret2 = -3;
        /* Check that we got the expected 'rho' value in the ciphertext */
        if (!TEST_mem_eq(encoded_public_key + v->vector_bytes,
                ML_KEM_RANDOM_BYTES,
                ml_kem_expected_rho[i],
                ML_KEM_RANDOM_BYTES))
            goto done;

        ret2 = -4;
        /* Create the expected associated public key */
        if (!ossl_ml_kem_parse_public_key(encoded_public_key, v->pubkey_bytes,
                public_key))
            goto done;

        /* Configure the public RNG to output the encap and decap seeds */
        params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
            ml_kem_public_entropy,
            sizeof(ml_kem_public_entropy));
        if (!TEST_true(EVP_RAND_CTX_set_params(pubctx, params)))
            goto done;

        /* encaps - decaps test: validate shared secret equality */
        ret2 = -5;
        if (!ossl_ml_kem_encap_rand(ciphertext, v->ctext_bytes,
                shared_secret, sizeof(shared_secret),
                public_key))
            goto done;

        ret2 = -6;
        /* Check the ciphertext hash */
        if (!TEST_true(EVP_Digest(ciphertext, v->ctext_bytes,
                hash, NULL, sha256, NULL))
            || !TEST_mem_eq(hash, sizeof(hash),
                ml_kem_expected_ctext_sha256[i],
                sizeof(ml_kem_expected_ctext_sha256[i])))
            goto done;

        /* Check for the expected shared secret */
        if (!TEST_mem_eq(shared_secret, sizeof(shared_secret),
                ml_kem_expected_shared_secret[i],
                ML_KEM_SHARED_SECRET_BYTES))
            goto done;

        /* Now decapsulate the ciphertext */
        ret2 = -7;
        if (!ossl_ml_kem_decap(shared_secret2, sizeof(shared_secret2),
                ciphertext, v->ctext_bytes, private_key))
            goto done;

        /* Check for the same shared secret */
        if (!TEST_mem_eq(shared_secret, sizeof(shared_secret),
                shared_secret2, sizeof(shared_secret2)))
            goto done;

        ret2 = -8;
        /* Now a quick negative test by zeroing the ciphertext */
        memset(ciphertext, 0, v->ctext_bytes);
        if (!TEST_true(ossl_ml_kem_decap(shared_secret2, sizeof(shared_secret2),
                ciphertext, v->ctext_bytes,
                private_key)))
            goto done;

        /* Ensure we have a mismatch */
        if (!TEST_mem_ne(shared_secret, sizeof(shared_secret),
                shared_secret2, sizeof(shared_secret2)))
            goto done;

        ret2 = -9;
        /*
         * Change the ciphertext length, decap should fail, but and consume the
         * last batch of entropy to return a fake shared secret, just in case.
         */
        if (!TEST_false(ossl_ml_kem_decap(shared_secret2, sizeof(shared_secret2),
                ciphertext, v->ctext_bytes - 1,
                private_key)))
            goto done;

        if (!TEST_mem_eq(shared_secret2, sizeof(shared_secret2),
                decap_entropy, ML_KEM_SHARED_SECRET_BYTES))
            goto done;

        /* Check that no more entropy is available! */
        if (!TEST_int_le(RAND_bytes(&c, 1), 0))
            goto done;

        ret2 = 0;

    done:
        if (ret2 != 0)
            ret = ret2;
        ossl_ml_kem_key_free(private_key);
        ossl_ml_kem_key_free(public_key);
        OPENSSL_free(encoded_public_key);
        OPENSSL_free(ciphertext);
    }

err:
    EVP_MD_free(sha256);
    return ret == 0;
}

static int decap_mfail_test(void)
{
    EVP_RAND_CTX *privctx, *pubctx;
    OSSL_PARAM params[3];
    uint8_t shared_secret[ML_KEM_SHARED_SECRET_BYTES];
    uint8_t decap_secret[ML_KEM_SHARED_SECRET_BYTES];
    uint8_t *encoded_public_key = NULL;
    uint8_t *ciphertext = NULL;
    ML_KEM_KEY *private_key = NULL;
    ML_KEM_KEY *public_key = NULL;
    unsigned int strength = 256;
    const ML_KEM_VINFO *v;
    int rc, ret = -1;

    if (!TEST_ptr(privctx = RAND_get0_private(NULL))
        || !TEST_ptr(pubctx = RAND_get0_public(NULL)))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
        ml_kem_private_entropy, sizeof(ml_kem_private_entropy));
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_RAND_CTX_set_params(privctx, params)))
        goto err;

    public_key = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
    private_key = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_768);
    if (private_key == NULL || public_key == NULL
        || (v = ossl_ml_kem_key_vinfo(public_key)) == NULL)
        goto err;

    encoded_public_key = OPENSSL_malloc(v->pubkey_bytes);
    ciphertext = OPENSSL_malloc(v->ctext_bytes);
    if (encoded_public_key == NULL || ciphertext == NULL)
        goto err;

    if (!ossl_ml_kem_genkey(encoded_public_key, v->pubkey_bytes, private_key)
        || !ossl_ml_kem_parse_public_key(encoded_public_key, v->pubkey_bytes,
            public_key))
        goto err;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
        ml_kem_public_entropy, sizeof(ml_kem_public_entropy));
    if (!TEST_true(EVP_RAND_CTX_set_params(pubctx, params)))
        goto err;

    if (!ossl_ml_kem_encap_rand(ciphertext, v->ctext_bytes,
            shared_secret, sizeof(shared_secret), public_key))
        goto err;

    MFAIL_start();
    rc = ossl_ml_kem_decap(decap_secret, sizeof(decap_secret),
        ciphertext, v->ctext_bytes, private_key);
    MFAIL_end();

    if (rc == 1
        && !TEST_mem_eq(decap_secret, sizeof(decap_secret),
            shared_secret, sizeof(shared_secret)))
        goto err;

    ret = rc;
err:
    ossl_ml_kem_key_free(private_key);
    ossl_ml_kem_key_free(public_key);
    OPENSSL_free(encoded_public_key);
    OPENSSL_free(ciphertext);
    return ret;
}

#if ML_KEM_AVX512_ELIGIBLE
/*
 * The AVX-512 polynomial arithmetic must be bit-exact with the generic C, not
 * merely congruent mod q: the surrounding ML-KEM code encodes coefficients
 * directly.  Forward and inverse NTT, both single-polynomial base
 * multiplications, the fused dot product, its transpose-add form, and the
 * inverse NTT of that dot product are compared with the generic functions
 * in ml_kem.c.
 *
 * A key generation, encapsulation, and decapsulation must also increment the
 * dispatched AVX-512 counters for the NTT, both inverse-NTT wrappers, the
 * fused accumulator, and the transpose-add accumulator.  Those counters live
 * in the wrappers assigned by ml_kem_ntt_init(), so a missed pointer fails
 * even when those three operations succeed.  The single-product multiply
 * wrappers stay installed but are not on this path.
 */

/*
 * Patterns 1-3 use coefficients near q - 1.  A uniformly random polynomial
 * rarely does.  These inputs exercise the deferred reductions; reaching the
 * stated 8q bound also depends on how the signs align across the levels.
 */
static void fill_poly(uint16_t *p, int pattern)
{
    int i;

    for (i = 0; i < ML_KEM_DEGREE; i++) {
        switch (pattern) {
        case 0:
            p[i] = (uint16_t)(test_random() % ML_KEM_PRIME);
            break;
        case 1:
            p[i] = ML_KEM_PRIME - 1;
            break;
        case 2:
            p[i] = (i & 1) ? ML_KEM_PRIME - 1 : 0;
            break;
        default:
            p[i] = (uint16_t)(ML_KEM_PRIME - 1 - (test_random() & 3));
            break;
        }
    }
}

static int avx512_dispatch_increased(void)
{
    EVP_RAND_CTX *privctx, *pubctx;
    OSSL_PARAM params[3];
    ML_KEM_KEY *private_key = NULL, *public_key = NULL;
    const ML_KEM_VINFO *v;
    uint8_t *encoded_public_key = NULL, *ciphertext = NULL;
    uint8_t shared_secret[ML_KEM_SHARED_SECRET_BYTES];
    uint8_t shared_secret2[ML_KEM_SHARED_SECRET_BYTES];
    unsigned int strength = 256;
    unsigned int ntt0, intt0, demont0, mult0, madd0, acc0, tadd0;
    unsigned int ntt1, intt1, demont1, mult1, madd1, acc1, tadd1;
    int ok = 0;

    ossl_ml_kem_avx512_dispatch_counts(&ntt0, &intt0, &demont0, &mult0, &madd0,
        &acc0, &tadd0);

    if (!TEST_ptr(privctx = RAND_get0_private(NULL))
        || !TEST_ptr(pubctx = RAND_get0_public(NULL)))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
        ml_kem_private_entropy, sizeof(ml_kem_private_entropy));
    params[1] = OSSL_PARAM_construct_uint(OSSL_RAND_PARAM_STRENGTH, &strength);
    params[2] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_RAND_CTX_set_params(privctx, params)))
        return 0;

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_RAND_PARAM_TEST_ENTROPY,
        ml_kem_public_entropy, sizeof(ml_kem_public_entropy));
    params[1] = OSSL_PARAM_construct_end();
    if (!TEST_true(EVP_RAND_CTX_set_params(pubctx, params)))
        return 0;

    private_key = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_512);
    public_key = ossl_ml_kem_key_new(NULL, NULL, EVP_PKEY_ML_KEM_512);
    if (!TEST_ptr(private_key) || !TEST_ptr(public_key)
        || !TEST_ptr(v = ossl_ml_kem_key_vinfo(private_key)))
        goto err;

    encoded_public_key = OPENSSL_malloc(v->pubkey_bytes);
    ciphertext = OPENSSL_malloc(v->ctext_bytes);
    if (!TEST_ptr(encoded_public_key) || !TEST_ptr(ciphertext))
        goto err;

    if (!TEST_true(ossl_ml_kem_genkey(encoded_public_key, v->pubkey_bytes,
            private_key))
        || !TEST_true(ossl_ml_kem_parse_public_key(encoded_public_key,
            v->pubkey_bytes, public_key))
        || !TEST_true(ossl_ml_kem_encap_rand(ciphertext, v->ctext_bytes,
            shared_secret, sizeof(shared_secret), public_key))
        || !TEST_true(ossl_ml_kem_decap(shared_secret2, sizeof(shared_secret2),
            ciphertext, v->ctext_bytes, private_key)))
        goto err;

    ossl_ml_kem_avx512_dispatch_counts(&ntt1, &intt1, &demont1, &mult1, &madd1,
        &acc1, &tadd1);
    if (!TEST_int_gt((int)ntt1, (int)ntt0)
        || !TEST_int_gt((int)intt1, (int)intt0)
        || !TEST_int_gt((int)demont1, (int)demont0)
        || !TEST_int_gt((int)acc1, (int)acc0)
        || !TEST_int_gt((int)tadd1, (int)tadd0))
        goto err;

    ok = 1;
err:
    ossl_ml_kem_key_free(private_key);
    ossl_ml_kem_key_free(public_key);
    OPENSSL_free(encoded_public_key);
    OPENSSL_free(ciphertext);
    return ok;
}

static int avx512_arith_test(void)
{
    scalar lhs, rhs, acc, got, want;
    int iter, pattern;

    if (!ossl_ml_kem_ntt_avx512_capable()) {
        TEST_info("AVX-512 unavailable, ML-KEM arithmetic not exercised");
        return 1;
    }

    if (!avx512_dispatch_increased())
        return 0;

    for (iter = 0; iter < 512; iter++) {
        for (pattern = 0; pattern < 4; pattern++) {
            fill_poly(lhs.c, pattern);
            fill_poly(rhs.c, pattern);
            fill_poly(acc.c, pattern);

            want = lhs;
            ossl_ml_kem_scalar_ntt_generic(&want);
            got = lhs;
            ossl_ml_kem_scalar_ntt_avx512(got.c);
            if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                return 0;

            want = lhs;
            ossl_ml_kem_scalar_inverse_ntt_generic(&want);
            got = lhs;
            ossl_ml_kem_scalar_inverse_ntt_avx512(got.c);
            if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                return 0;

            ossl_ml_kem_scalar_mult_generic(&want, &lhs, &rhs);
            memset(got.c, 0xA5, sizeof(got.c));
            ossl_ml_kem_scalar_mult_avx512(got.c, lhs.c, rhs.c);
            if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                return 0;

            want = acc;
            ossl_ml_kem_scalar_mult_add_generic(&want, &lhs, &rhs);
            got = acc;
            ossl_ml_kem_scalar_mult_add_avx512(got.c, lhs.c, rhs.c);
            if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                return 0;
        }
    }

    /*
     * Fused accumulator against the generic mult / mult-add chain, for every
     * ML-KEM rank.  The transpose form is one output row of A^T * s + e.
     */
    for (iter = 0; iter < 64; iter++) {
        for (pattern = 0; pattern < 4; pattern++) {
            scalar vec_l[4], vec_r[4], mat[16], avec[4], err, row;
            int rank, k, rowi;

            for (rank = 2; rank <= 4; rank++) {
                for (k = 0; k < rank; k++) {
                    fill_poly(vec_l[k].c, pattern);
                    fill_poly(vec_r[k].c, pattern);
                }
                ossl_ml_kem_scalar_mult_generic(&want, &vec_l[0], &vec_r[0]);
                for (k = 1; k < rank; k++)
                    ossl_ml_kem_scalar_mult_add_generic(&want, &vec_l[k],
                        &vec_r[k]);
                memset(got.c, 0xA5, sizeof(got.c));
                ossl_ml_kem_basemul_acc_avx512(got.c, vec_l[0].c, vec_r[0].c,
                    rank);
                if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                    return 0;

                ossl_ml_kem_scalar_inverse_ntt_generic(&want);
                memset(got.c, 0xA5, sizeof(got.c));
                ossl_ml_kem_basemul_acc_intt_avx512(got.c, vec_l[0].c,
                    vec_r[0].c, rank);
                if (!TEST_mem_eq(got.c, sizeof(got.c), want.c, sizeof(want.c)))
                    return 0;

                for (k = 0; k < rank * rank; k++)
                    fill_poly(mat[k].c, pattern);
                for (k = 0; k < rank; k++)
                    fill_poly(avec[k].c, pattern);
                fill_poly(err.c, pattern);
                for (rowi = 0; rowi < rank; rowi++) {
                    row = err;
                    for (k = 0; k < rank; k++)
                        ossl_ml_kem_scalar_mult_add_generic(&row,
                            &mat[rowi + k * rank], &avec[k]);
                    got = err;
                    ossl_ml_kem_basemul_acc_transpose_add_avx512(got.c,
                        mat[rowi].c, avec[0].c, rank);
                    if (!TEST_mem_eq(got.c, sizeof(got.c), row.c, sizeof(row.c)))
                        return 0;
                }
            }
        }
    }

    return 1;
}
#endif /* ML_KEM_AVX512_ELIGIBLE */

int setup_tests(void)
{
    if (!TEST_true(RAND_set_DRBG_type(NULL, "TEST-RAND", "fips=no", NULL, NULL)))
        return 0;

    ADD_TEST(sanity_test);
    ADD_MFAIL_TEST(decap_mfail_test);
#if ML_KEM_AVX512_ELIGIBLE
    ADD_TEST(avx512_arith_test);
#endif
    return 1;
}
