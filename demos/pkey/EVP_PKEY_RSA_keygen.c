/*-
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Example showing how to generate an RSA key, store it to a PEM file, and 
 * extract values from the generated key, and dump them to standard output.
 */

#include <stdio.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>

/*
 * Generates a new 4096-bit RSA key pair.
 */
static EVP_PKEY *do_rsa_keygen()
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    OSSL_PARAM params[2];
    size_t rsa_key_size = 4096;
    
    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0)
        goto cleanup;

    /* 
     * It is also possible to set the RSA key size using 
     * EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 4096)
     */
     
    params[0] = OSSL_PARAM_construct_size_t(OSSL_PKEY_PARAM_RSA_BITS, 
                                            &rsa_key_size);
    params[1] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_CTX_set_params(ctx, params) <= 0)
        goto cleanup;

    fprintf(stdout, "Generating 4096-bit RSA key pair...\n");
    EVP_PKEY_keygen(ctx, &pkey);

cleanup:
    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* 
 * Saves the generated key pair as plaintext to a PEM file.
 */
static int do_save_key_pem(EVP_PKEY *pkey, const char *file_name)
{
    FILE *fp = NULL;
    int res;

    fp = fopen(file_name, "w");
    if (fp == NULL)
        return 0;

    fprintf(stdout, "Saving plaintext RSA keypair to %s...\n", file_name);
    res = PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    return res;
}

/*
 * Dumps a BIGNUM to a file pointer with a label and indentation.
 */
static int do_bn_dump_indent_fp(FILE *fp, BIGNUM *bn, const char *label, 
                                int indent)
{
    unsigned char *tmp_buf = NULL;
    int tmp_buf_len = 0;
    int bn_size = BN_num_bytes(bn);
    int res = 0;

    if (bn == NULL || bn_size <=0)
        return 0;

    tmp_buf = OPENSSL_zalloc(bn_size);
    if (tmp_buf == NULL)
        return 0;

    tmp_buf_len = BN_bn2bin(bn, tmp_buf);
    if (tmp_buf_len <= 0)
        goto cleanup;

    fprintf(fp, "%s:\n", label);
    BIO_dump_indent_fp(fp, tmp_buf, tmp_buf_len, indent);

    res = 1;
cleanup:
    OPENSSL_free(tmp_buf);

    return res;
}
    
/*
 * Extracts the RSA key pair parameters and dumps them to stdout
 */
static int do_get_key_params(EVP_PKEY *pkey)
{
    size_t rsa_key_size;
    BIGNUM *n = NULL, *e = NULL, *d = NULL, *p = NULL, *q = NULL;
    BIGNUM *dp = NULL, *dq = NULL, *qinv = NULL;
    int res = 0;

    if ((EVP_PKEY_get_size_t_param(pkey, OSSL_PKEY_PARAM_RSA_BITS, 
                                   &rsa_key_size) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &d) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &p) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &q) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &dp) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &dq) <= 0) ||
        (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, 
                               &qinv) <= 0))
            goto cleanup;

    /* 
     * Also can use EVP_PKEY_print_private_fp(stdout, pkey, 2, NULL);
     */

    fprintf(stdout, "Dumping RSA key pair parameters...\n");
    fprintf(stdout, "RSA key size: %zu bits\n", rsa_key_size);

    if ((do_bn_dump_indent_fp(stdout, n, "Modulus", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, e, "Public exponent", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, d, "Private exponent", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, p, "Prime 1", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, q, "Prime 2", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, dp, "Exponent 1", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, dq, "Exponent 2", 2) == 0) ||
        (do_bn_dump_indent_fp(stdout, qinv, "Coefficient", 2) == 0))
        goto cleanup;

    res = 1;
cleanup:
    BN_free(n);
    BN_free(e);
    BN_free(d);
    BN_free(p);
    BN_free(q);
    BN_free(dp);
    BN_free(dq);
    BN_free(qinv);

    return res;
}

int main(void)
{
    int res = 0;
    EVP_PKEY *pkey = NULL;

    ERR_load_crypto_strings();

    pkey = do_rsa_keygen();
    if (pkey == NULL)
        goto cleanup;

    if (do_save_key_pem(pkey, "rsa_keypair.pem") <= 0)
        goto cleanup;

    if (do_get_key_params(pkey) <= 0)
        goto cleanup;

    res = 1;
cleanup:
    if (res != 1)
        ERR_print_errors_fp(stderr);

    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    ERR_free_strings();

    return 0;
}
