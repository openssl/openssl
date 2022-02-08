/*
 * Copyright 2012-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple SM4 GCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/* SM4-GCM test data obtained from RFC8998 */

/* SM4 key */
static const unsigned char gcm_key[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};

/* Unique initialisation vector */
static const unsigned char gcm_iv[] = {
    0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd
};

/* Example plaintext to encrypt */
static const unsigned char gcm_pt[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
static const unsigned char gcm_aad[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2
};

/* Expected ciphertext value */
static const unsigned char gcm_ct[] = {
    0x17, 0xf3, 0x99, 0xf0, 0x8c, 0x67, 0xd5, 0xee, 0x19, 0xd0, 0xdc, 0x99,
    0x69, 0xc4, 0xbb, 0x7d, 0x5f, 0xd4, 0x6f, 0xd3, 0x75, 0x64, 0x89, 0x06,
    0x91, 0x57, 0xb2, 0x82, 0xbb, 0x20, 0x07, 0x35, 0xd8, 0x27, 0x10, 0xca,
    0x5c, 0x22, 0xf0, 0xcc, 0xfa, 0x7c, 0xbf, 0x93, 0xd4, 0x96, 0xac, 0x15,
    0xa5, 0x68, 0x34, 0xcb, 0xcf, 0x98, 0xc3, 0x97, 0xb4, 0x02, 0x4a, 0x26,
    0x91, 0x23, 0x3b, 0x8d
};

/* Expected AEAD Tag value */
static const unsigned char gcm_tag[] = {
    0x83, 0xde, 0x35, 0x41, 0xe4, 0xc2, 0xb5, 0x81, 0x77, 0xe0, 0x65, 0xa9,
    0xbf, 0x7b, 0x62, 0xec
};

/*
 * A library context and property query can be used to select & filter
 * algorithm implementations. If they are NULL then the default library
 * context and properties are used.
 */
OSSL_LIB_CTX *libctx = NULL;
const char *propq = NULL;

int sm4_gcm_encrypt(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, tmplen;
    size_t gcm_ivlen = sizeof(gcm_iv);
    unsigned char outbuf[1024];
    unsigned char outtag[16];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    printf("SM4 GCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, gcm_pt, sizeof(gcm_pt));

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "SM4-GCM", propq)) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     * For demonstration purposes the IV is being set here. In a compliant
     * application the IV would be generated internally so the iv passed in
     * would be NULL.
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
        goto err;

    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
        goto err;

    /* Encrypt plaintext */
    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, gcm_pt, sizeof(gcm_pt)))
        goto err;

    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);

    /* Finalise: note get no output for GCM */
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &tmplen))
        goto err;

    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  outtag, 16);

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        goto err;

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outtag, 16);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int sm4_gcm_decrypt(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, rv;
    size_t gcm_ivlen = sizeof(gcm_iv);
    unsigned char outbuf[1024];
    OSSL_PARAM params[2] = {
        OSSL_PARAM_END, OSSL_PARAM_END
    };

    printf("SM4 GCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, gcm_ct, sizeof(gcm_ct));

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "SM4-GCM", propq)) == NULL)
        goto err;

    /* Set IV length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &gcm_ivlen);

    /*
     * Initialise an encrypt operation with the cipher/mode, key, IV and
     * IV length parameter.
     */
    if (!EVP_DecryptInit_ex2(ctx, cipher, gcm_key, gcm_iv, params))
        goto err;

    /* Zero or more calls to specify any AAD */
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, gcm_aad, sizeof(gcm_aad)))
        goto err;

    /* Decrypt plaintext */
    if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, sizeof(gcm_ct)))
        goto err;

    /* Output decrypted block */
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);

    /* Set expected tag value. */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (void*)gcm_tag, sizeof(gcm_tag));

    if (!EVP_CIPHER_CTX_set_params(ctx, params))
        goto err;

    /* Finalise: note get no output for GCM */
    rv = EVP_DecryptFinal_ex(ctx, outbuf, &outlen);
    /*
     * Print out return value. If this is not successful authentication
     * failed and plaintext is not trustworthy.
     */
    printf("Tag Verify %s\n", rv > 0 ? "Successful!" : "Failed!");

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int main(int argc, char **argv)
{
    if (!sm4_gcm_encrypt())
        return 1;

    if (!sm4_gcm_decrypt())
        return 1;

    return 0;
}
