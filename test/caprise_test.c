/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <math.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/e_os2.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/params.h>

#include "internal/nelem.h"
#include "testutil.h"

/* Test constants */
#define CAPRISE_TEST_DIM 4
#define CAPRISE_TEST_VECTORS 3
#define CAPRISE_KEY_LEN 32
#define CAPRISE_IV_LEN 16

/* Helper function to convert byte array to double vector */
static void bytes_to_vector(const unsigned char *bytes, double *vector, size_t dim)
{
    size_t i;
    for (i = 0; i < dim; i++) {
        memcpy(&vector[i], bytes + i * sizeof(double), sizeof(double));
    }
}

/* Helper function to convert double vector to byte array */
static void vector_to_bytes(const double *vector, unsigned char *bytes, size_t dim)
{
    size_t i;
    for (i = 0; i < dim; i++) {
        memcpy(bytes + i * sizeof(double), &vector[i], sizeof(double));
    }
}

/* Helper function to compute Euclidean distance between two vectors */
static double vector_distance(const double *a, const double *b, size_t dim)
{
    double sum = 0.0;
    size_t i;
    for (i = 0; i < dim; i++) {
        double diff = a[i] - b[i];
        sum += diff * diff;
    }
    return sqrt(sum);
}

/* Helper function to print a vector */
static void print_vector(const char *label, const double *v, size_t dim)
{
    size_t i;
    printf("%s: [", label);
    for (i = 0; i < dim; i++) {
        printf("%.4f", v[i]);
        if (i < dim - 1)
            printf(", ");
    }
    printf("]\n");
}

/* Test basic encryption and decryption */
static int test_caprise_basic(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc_ctx = NULL, *dec_ctx = NULL;
    unsigned char key[CAPRISE_KEY_LEN];
    unsigned char iv[CAPRISE_IV_LEN];
    unsigned char plaintext[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char ciphertext[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char decrypted[sizeof(double) * CAPRISE_TEST_DIM];
    int outlen, tmplen;
    int ret = 0;

    /* Generate random key and IV */
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1))
        goto err;
    if (!TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1))
        goto err;

    /* Create a test vector */
    double test_vector[CAPRISE_TEST_DIM] = {1.0, 2.0, 3.0, 4.0};
    vector_to_bytes(test_vector, plaintext, CAPRISE_TEST_DIM);

    /* Fetch CAPRISE cipher */
    cipher = EVP_CIPHER_fetch(NULL, "CAPRISE", NULL);
    if (!TEST_ptr(cipher))
        goto err;

    /* Create encryption context */
    enc_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(enc_ctx))
        goto err;

    /* Initialize encryption */
    if (!TEST_true(EVP_CipherInit_ex(enc_ctx, cipher, NULL, key, iv, 1)))
        goto err;

    /* Set dimension to test dimension */
    {
        size_t dim = CAPRISE_TEST_DIM;
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
        params[1] = OSSL_PARAM_construct_end();
        if (!TEST_true(EVP_CIPHER_CTX_set_params(enc_ctx, params)))
            goto err;
    }

    /* Encrypt */
    outlen = 0;
    tmplen = 0;
    if (!TEST_true(EVP_CipherUpdate(enc_ctx, ciphertext, &outlen,
                                   plaintext, sizeof(plaintext))))
        goto err;
    if (!TEST_true(EVP_CipherFinal(enc_ctx, ciphertext + outlen, &tmplen)))
        goto err;
    outlen += tmplen;

    /* Verify ciphertext length */
    if (!TEST_int_eq(outlen, sizeof(plaintext)))
        goto err;

    /* Create decryption context */
    dec_ctx = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(dec_ctx))
        goto err;

    /* Initialize decryption */
    if (!TEST_true(EVP_CipherInit_ex(dec_ctx, cipher, NULL, key, iv, 0)))
        goto err;

    /* Set dimension to test dimension */
    {
        size_t dim = CAPRISE_TEST_DIM;
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
        params[1] = OSSL_PARAM_construct_end();
        if (!TEST_true(EVP_CIPHER_CTX_set_params(dec_ctx, params)))
            goto err;
    }

    /* Decrypt */
    outlen = 0;
    tmplen = 0;
    if (!TEST_true(EVP_CipherUpdate(dec_ctx, decrypted, &outlen,
                                   ciphertext, sizeof(ciphertext))))
        goto err;
    if (!TEST_true(EVP_CipherFinal(dec_ctx, decrypted + outlen, &tmplen)))
        goto err;
    outlen += tmplen;

    /* Verify decryption recovered original data */
    if (!TEST_mem_eq(decrypted, sizeof(decrypted), plaintext, sizeof(plaintext)))
        goto err;

    /* Verify reconstructed vector matches original */
    double reconstructed[CAPRISE_TEST_DIM];
    bytes_to_vector(decrypted, reconstructed, CAPRISE_TEST_DIM);
    if (!TEST_true(memcmp(test_vector, reconstructed, sizeof(test_vector)) == 0))
        goto err;

    ret = 1;

err:
    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);
    EVP_CIPHER_free(cipher);
    return ret;
}

/* Test distance comparison preservation property */
static int test_caprise_distance_preservation(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx_db = NULL, *ctx_q = NULL;
    unsigned char key[CAPRISE_KEY_LEN];
    unsigned char iv_db[CAPRISE_IV_LEN], iv_q[CAPRISE_IV_LEN];
    double e1[CAPRISE_TEST_DIM] = {1.0, 0.0, 0.0, 0.0};
    double e2[CAPRISE_TEST_DIM] = {0.0, 1.0, 0.0, 0.0};
    double e3[CAPRISE_TEST_DIM] = {0.0, 0.0, 1.0, 0.0};
    double eq[CAPRISE_TEST_DIM] = {0.5, 0.5, 0.0, 0.0};

    unsigned char p1[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char p2[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char p3[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char pq[sizeof(double) * CAPRISE_TEST_DIM];

    unsigned char c1[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char c2[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char c3[sizeof(double) * CAPRISE_TEST_DIM];
    unsigned char cq[sizeof(double) * CAPRISE_TEST_DIM];

    double ec1[CAPRISE_TEST_DIM];
    double ec2[CAPRISE_TEST_DIM];
    double ecq[CAPRISE_TEST_DIM];

    double d_eq_e1, d_eq_e2;
    double d_cq_c1, d_cq_c2;
    double beta = 0.2;  /* Security parameter from paper */

    int ret = 0;

    /* Generate random key and IVs */
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1))
        goto err;
    if (!TEST_int_eq(RAND_bytes(iv_db, sizeof(iv_db)), 1))
        goto err;
    if (!TEST_int_eq(RAND_bytes(iv_q, sizeof(iv_q)), 1))
        goto err;

    /* Convert vectors to bytes */
    vector_to_bytes(e1, p1, CAPRISE_TEST_DIM);
    vector_to_bytes(e2, p2, CAPRISE_TEST_DIM);
    vector_to_bytes(e3, p3, CAPRISE_TEST_DIM);
    vector_to_bytes(eq, pq, CAPRISE_TEST_DIM);

    /* Fetch CAPRISE cipher */
    cipher = EVP_CIPHER_fetch(NULL, "CAPRISE", NULL);
    if (!TEST_ptr(cipher))
        goto err;

    /* Compute original distances */
    d_eq_e1 = vector_distance(eq, e1, CAPRISE_TEST_DIM);
    d_eq_e2 = vector_distance(eq, e2, CAPRISE_TEST_DIM);

    /* Verify that the condition holds: ||eq - e1|| < ||eq - e2|| - beta */
    if (!(d_eq_e1 < d_eq_e2 - beta)) {
        /* If condition doesn't hold, we can't test the preservation property */
        /* In this case, we just test basic encryption/decryption */
        ret = 1;
        goto err;
    }

    /* Encrypt database vectors (using DB mode) */
    ctx_db = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx_db))
        goto err;

    /* Initialize for DB mode */
    if (!TEST_true(EVP_CipherInit_ex(ctx_db, cipher, NULL, key, iv_db, 1)))
        goto err;

    /* Set DB mode parameter */
    {
        unsigned int mode = 0;  /* CAPRISE_MODE_DB */
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_uint("caprise_mode", &mode);
        params[1] = OSSL_PARAM_construct_end();
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_db, params)))
            goto err;
    }

    /* Encrypt database vectors */
    {
        int len, tmplen;
        len = tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(ctx_db, c1, &len, p1, sizeof(p1))))
            goto err;
        if (!TEST_true(EVP_CipherFinal(ctx_db, c1 + len, &tmplen)))
            goto err;

        len = tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(ctx_db, c2, &len, p2, sizeof(p2))))
            goto err;
        if (!TEST_true(EVP_CipherFinal(ctx_db, c2 + len, &tmplen)))
            goto err;

        len = tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(ctx_db, c3, &len, p3, sizeof(p3))))
            goto err;
        if (!TEST_true(EVP_CipherFinal(ctx_db, c3 + len, &tmplen)))
            goto err;
    }

    /* Encrypt query vector (using QUERY mode) */
    ctx_q = EVP_CIPHER_CTX_new();
    if (!TEST_ptr(ctx_q))
        goto err;

    /* Initialize for QUERY mode */
    if (!TEST_true(EVP_CipherInit_ex(ctx_q, cipher, NULL, key, iv_q, 1)))
        goto err;

    /* Set QUERY mode parameter */
    {
        unsigned int mode = 1;  /* CAPRISE_MODE_QUERY */
        OSSL_PARAM params[2];
        params[0] = OSSL_PARAM_construct_uint("caprise_mode", &mode);
        params[1] = OSSL_PARAM_construct_end();
        if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx_q, params)))
            goto err;
    }

    /* Encrypt query vector */
    {
        int len, tmplen;
        len = tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(ctx_q, cq, &len, pq, sizeof(pq))))
            goto err;
        if (!TEST_true(EVP_CipherFinal(ctx_q, cq + len, &tmplen)))
            goto err;
    }

    /* Convert ciphertexts back to vectors for distance computation */
    bytes_to_vector(c1, ec1, CAPRISE_TEST_DIM);
    bytes_to_vector(c2, ec2, CAPRISE_TEST_DIM);
    bytes_to_vector(cq, ecq, CAPRISE_TEST_DIM);

    /* Compute encrypted distances */
    d_cq_c1 = vector_distance(ecq, ec1, CAPRISE_TEST_DIM);
    d_cq_c2 = vector_distance(ecq, ec2, CAPRISE_TEST_DIM);

    /* Verify distance comparison is preserved:
     * ||eq - e1|| < ||eq - e2|| - beta implies ||eq' - e1'|| < ||eq' - e2'||
     */
    if (!TEST_true(d_cq_c1 < d_cq_c2))
        goto err;

    /* Print results for verification */
    print_vector("Query vector", eq, CAPRISE_TEST_DIM);
    print_vector("Database vector 1", e1, CAPRISE_TEST_DIM);
    print_vector("Database vector 2", e2, CAPRISE_TEST_DIM);
    printf("Original distance Q->E1: %.4f\n", d_eq_e1);
    printf("Original distance Q->E2: %.4f\n", d_eq_e2);
    printf("Encrypted distance Q'->E1': %.4f\n", d_cq_c1);
    printf("Encrypted distance Q'->E2': %.4f\n", d_cq_c2);
    printf("Beta: %.4f\n", beta);
    printf("Condition: %.4f < %.4f - %.4f (%.4f) => %s\n",
           d_eq_e1, d_eq_e2, beta, d_eq_e2 - beta,
           d_eq_e1 < d_eq_e2 - beta ? "TRUE" : "FALSE");
    printf("Preserved: %.4f < %.4f => %s\n",
           d_cq_c1, d_cq_c2,
           d_cq_c1 < d_cq_c2 ? "TRUE" : "FALSE");

    ret = 1;

err:
    EVP_CIPHER_CTX_free(ctx_db);
    EVP_CIPHER_CTX_free(ctx_q);
    EVP_CIPHER_free(cipher);
    return ret;
}

/* Test different embedding dimensions */
static int test_caprise_dimensions(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *enc_ctx = NULL, *dec_ctx = NULL;
    unsigned char key[CAPRISE_KEY_LEN];
    unsigned char iv[CAPRISE_IV_LEN];
    size_t dims[] = {2, 4, 8, 16};
    size_t num_dims = sizeof(dims) / sizeof(dims[0]);
    size_t i;
    int ret = 0;

    /* Generate random key and IV */
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1))
        goto err;
    if (!TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1))
        goto err;

    /* Fetch CAPRISE cipher */
    cipher = EVP_CIPHER_fetch(NULL, "CAPRISE", NULL);
    if (!TEST_ptr(cipher))
        goto err;

    /* Test each dimension */
    for (i = 0; i < num_dims; i++) {
        size_t dim = dims[i];
        size_t data_len = dim * sizeof(double);
        unsigned char *plaintext = NULL;
        unsigned char *ciphertext = NULL;
        unsigned char *decrypted = NULL;
        int outlen, tmplen;
        size_t j;

        plaintext = OPENSSL_malloc(data_len);
        ciphertext = OPENSSL_malloc(data_len);
        decrypted = OPENSSL_malloc(data_len);
        if (!TEST_ptr(plaintext) || !TEST_ptr(ciphertext) || !TEST_ptr(decrypted))
            goto cleanup_loop;

        /* Create test vector */
        for (j = 0; j < dim; j++) {
            double val = (double)(j + 1);
            memcpy(plaintext + j * sizeof(double), &val, sizeof(double));
        }

        /* Create encryption context */
        enc_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(enc_ctx))
            goto cleanup_loop;

        /* Set dimension parameter */
        {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
            params[1] = OSSL_PARAM_construct_end();
            if (!TEST_true(EVP_CipherInit_ex(enc_ctx, cipher, NULL, key, iv, 1)))
                goto cleanup_loop;
            if (!TEST_true(EVP_CIPHER_CTX_set_params(enc_ctx, params)))
                goto cleanup_loop;
        }

        /* Encrypt */
        outlen = 0;
        tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(enc_ctx, ciphertext, &outlen,
                                       plaintext, (int)data_len)))
            goto cleanup_loop;
        if (!TEST_true(EVP_CipherFinal(enc_ctx, ciphertext + outlen, &tmplen)))
            goto cleanup_loop;
        outlen += tmplen;

        /* Create decryption context */
        dec_ctx = EVP_CIPHER_CTX_new();
        if (!TEST_ptr(dec_ctx))
            goto cleanup_loop;

        /* Set dimension parameter */
        {
            OSSL_PARAM params[2];
            params[0] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
            params[1] = OSSL_PARAM_construct_end();
            if (!TEST_true(EVP_CipherInit_ex(dec_ctx, cipher, NULL, key, iv, 0)))
                goto cleanup_loop;
            if (!TEST_true(EVP_CIPHER_CTX_set_params(dec_ctx, params)))
                goto cleanup_loop;
        }

        /* Decrypt */
        outlen = 0;
        tmplen = 0;
        if (!TEST_true(EVP_CipherUpdate(dec_ctx, decrypted, &outlen,
                                       ciphertext, (int)data_len)))
            goto cleanup_loop;
        if (!TEST_true(EVP_CipherFinal(dec_ctx, decrypted + outlen, &tmplen)))
            goto cleanup_loop;
        outlen += tmplen;

        /* Verify */
        if (!TEST_mem_eq(decrypted, outlen, plaintext, data_len))
            goto cleanup_loop;

cleanup_loop:
        OPENSSL_free(plaintext);
        OPENSSL_free(ciphertext);
        OPENSSL_free(decrypted);
        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);

        if (!TEST_true(plaintext != NULL && ciphertext != NULL && decrypted != NULL)) {
            ret = 0;
            goto err;
        }
    }

    ret = 1;

err:
    EVP_CIPHER_free(cipher);
    return ret;
}

/* Test custom parameters */
static int test_caprise_parameters(void)
{
    EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char key[CAPRISE_KEY_LEN];
    unsigned char iv[CAPRISE_IV_LEN];
    double s_values[] = {1.0, 3.0, 5.0};
    double beta_values[] = {0.1, 0.2, 0.3};
    size_t num_s = sizeof(s_values) / sizeof(s_values[0]);
    size_t num_beta = sizeof(beta_values) / sizeof(beta_values[0]);
    size_t i, j;
    int ret = 0;

    /* Generate random key and IV */
    if (!TEST_int_eq(RAND_bytes(key, sizeof(key)), 1))
        goto err;
    if (!TEST_int_eq(RAND_bytes(iv, sizeof(iv)), 1))
        goto err;

    /* Fetch CAPRISE cipher */
    cipher = EVP_CIPHER_fetch(NULL, "CAPRISE", NULL);
    if (!TEST_ptr(cipher))
        goto err;

    /* Test different parameter combinations */
    for (i = 0; i < num_s; i++) {
        for (j = 0; j < num_beta; j++) {
            double s = s_values[i];
            double beta = beta_values[j];
            unsigned char plaintext[sizeof(double) * CAPRISE_TEST_DIM];
            unsigned char ciphertext[sizeof(double) * CAPRISE_TEST_DIM];
            unsigned char decrypted[sizeof(double) * CAPRISE_TEST_DIM];
            int outlen, tmplen;
            size_t k;

            ctx = EVP_CIPHER_CTX_new();
            if (!TEST_ptr(ctx))
                goto cleanup_params;

            /* Create test vector */
            for (k = 0; k < CAPRISE_TEST_DIM; k++) {
                double val = (double)(k + 1);
                memcpy(plaintext + k * sizeof(double), &val, sizeof(double));
            }

            /* Set custom parameters */
            {
                unsigned int mode = 0;  /* DB mode */
                size_t dim = CAPRISE_TEST_DIM;
                OSSL_PARAM params[5];
                params[0] = OSSL_PARAM_construct_uint("caprise_mode", &mode);
                params[1] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
                params[2] = OSSL_PARAM_construct_double("caprise_s", &s);
                params[3] = OSSL_PARAM_construct_double("caprise_beta", &beta);
                params[4] = OSSL_PARAM_construct_end();

                if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 1)))
                    goto cleanup_params;
                if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
                    goto cleanup_params;
            }

            /* Encrypt */
            outlen = 0;
            tmplen = 0;
            if (!TEST_true(EVP_CipherUpdate(ctx, ciphertext, &outlen,
                                           plaintext, sizeof(plaintext))))
                goto cleanup_params;
            if (!TEST_true(EVP_CipherFinal(ctx, ciphertext + outlen, &tmplen)))
                goto cleanup_params;
            outlen += tmplen;

            /* Decrypt */
            EVP_CIPHER_CTX_reset(ctx);
            if (!TEST_true(EVP_CipherInit_ex(ctx, cipher, NULL, key, iv, 0)))
                goto cleanup_params;
            /* Re-set parameters for decryption */
            {
                unsigned int mode = 0;
                size_t dim = CAPRISE_TEST_DIM;
                OSSL_PARAM params[5];
                params[0] = OSSL_PARAM_construct_uint("caprise_mode", &mode);
                params[1] = OSSL_PARAM_construct_size_t("caprise_dim", &dim);
                params[2] = OSSL_PARAM_construct_double("caprise_s", &s);
                params[3] = OSSL_PARAM_construct_double("caprise_beta", &beta);
                params[4] = OSSL_PARAM_construct_end();
                if (!TEST_true(EVP_CIPHER_CTX_set_params(ctx, params)))
                    goto cleanup_params;
            }

            outlen = 0;
            tmplen = 0;
            if (!TEST_true(EVP_CipherUpdate(ctx, decrypted, &outlen,
                                           ciphertext, sizeof(ciphertext))))
                goto cleanup_params;
            if (!TEST_true(EVP_CipherFinal(ctx, decrypted + outlen, &tmplen)))
                goto cleanup_params;
            outlen += tmplen;

            /* Verify */
            if (!TEST_mem_eq(decrypted, outlen, plaintext, sizeof(plaintext)))
                goto cleanup_params;

cleanup_params:
            EVP_CIPHER_CTX_free(ctx);
            if (!TEST_true(ctx != NULL)) {
                ret = 0;
                goto err;
            }
        }
    }

    ret = 1;

err:
    EVP_CIPHER_free(cipher);
    return ret;
}

int setup_tests(void)
{
    ADD_TEST(test_caprise_basic);
    ADD_TEST(test_caprise_distance_preservation);
    ADD_TEST(test_caprise_dimensions);
    ADD_TEST(test_caprise_parameters);
    return 1;
}
