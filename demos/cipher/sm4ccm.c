/*
 * Copyright 2013-2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple SM4 CCM authenticated encryption with additional data (AEAD)
 * demonstration program.
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

/* SM4-CCM test data obtained from RFC8998 */

/* SM4 key */
static const unsigned char ccm_key[] = {
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98,
    0x76, 0x54, 0x32, 0x10
};

/* Unique nonce to be used for this message */
static const unsigned char ccm_nonce[] = {
    0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00, 0xab, 0xcd
};

/*
 * Example of Additional Authenticated Data (AAD), i.e. unencrypted data
 * which can be authenticated using the generated Tag value.
 */
static const unsigned char ccm_adata[] = {
    0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
    0xde, 0xad, 0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2
};

/* Example plaintext to encrypt */
static const unsigned char ccm_pt[] = {
    0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xbb, 0xbb, 0xbb, 0xbb,
    0xbb, 0xbb, 0xbb, 0xbb, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xdd, 0xee, 0xee, 0xee, 0xee,
    0xee, 0xee, 0xee, 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xee, 0xaa, 0xaa, 0xaa, 0xaa,
    0xaa, 0xaa, 0xaa, 0xaa
};

/* Expected ciphertext value */
static const unsigned char ccm_ct[] = {
    0x48, 0xaf, 0x93, 0x50, 0x1f, 0xa6, 0x2a, 0xdb, 0xcd, 0x41, 0x4c, 0xce,
    0x60, 0x34, 0xd8, 0x95, 0xdd, 0xa1, 0xbf, 0x8f, 0x13, 0x2f, 0x04, 0x20,
    0x98, 0x66, 0x15, 0x72, 0xe7, 0x48, 0x30, 0x94, 0xfd, 0x12, 0xe5, 0x18,
    0xce, 0x06, 0x2c, 0x98, 0xac, 0xee, 0x28, 0xd9, 0x5d, 0xf4, 0x41, 0x6b,
    0xed, 0x31, 0xa2, 0xf0, 0x44, 0x76, 0xc1, 0x8b, 0xb4, 0x0c, 0x84, 0xa7,
    0x4b, 0x97, 0xdc, 0x5b
};

/* Expected AEAD Tag value */
static const unsigned char ccm_tag[] = {
    0x16, 0x84, 0x2d, 0x4f, 0xa1, 0x86, 0xf5, 0x6a, 0xb3, 0x32, 0x56, 0x97,
    0x1f, 0xa1, 0x10, 0xf4
};

/*
 * A library context and property query can be used to select & filter
 * algorithm implementations. If they are NULL then the default library
 * context and properties are used.
 */
OSSL_LIB_CTX *libctx = NULL;
const char *propq = NULL;


int sm4_ccm_encrypt(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, tmplen;
    size_t ccm_nonce_len = sizeof(ccm_nonce);
    size_t ccm_tag_len = sizeof(ccm_tag);
    unsigned char outbuf[1024];
    unsigned char outtag[16];
    OSSL_PARAM params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    printf("SM4 CCM Encrypt:\n");
    printf("Plaintext:\n");
    BIO_dump_fp(stdout, ccm_pt, sizeof(ccm_pt));

    /* Create a context for the encrypt operation */
    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "SM4-CCM", propq)) == NULL)
        goto err;

    /* Set nonce length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &ccm_nonce_len);
    /* Set tag length */
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  NULL, ccm_tag_len);

    /*
     * Initialise encrypt operation with the cipher & mode,
     * nonce length and tag length parameters.
     */
    if (!EVP_EncryptInit_ex2(ctx, cipher, NULL, NULL, params))
        goto err;

    /* Initialise key and nonce */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce))
        goto err;

    /* Set plaintext length: only needed if AAD is used */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, NULL, sizeof(ccm_pt)))
        goto err;

    /* Zero or one call to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, ccm_adata, sizeof(ccm_adata)))
        goto err;

    /* Encrypt plaintext: can only be called once */
    if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, ccm_pt, sizeof(ccm_pt)))
        goto err;

    /* Output encrypted block */
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, outbuf, outlen);

    /* Finalise: note get no output for CCM */
    if (!EVP_EncryptFinal_ex(ctx, NULL, &tmplen))
        goto err;

    /* Get tag */
    params[0] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  outtag, ccm_tag_len);
    params[1] = OSSL_PARAM_construct_end();

    if (!EVP_CIPHER_CTX_get_params(ctx, params))
        goto err;

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outtag, ccm_tag_len);

    ret = 1;
err:
    if (!ret)
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_free(cipher);
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int sm4_ccm_decrypt(void)
{
    int ret = 0;
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int outlen, rv;
    unsigned char outbuf[1024];
    size_t ccm_nonce_len = sizeof(ccm_nonce);
    OSSL_PARAM params[3] = {
        OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END
    };

    printf("SM4 CCM Decrypt:\n");
    printf("Ciphertext:\n");
    BIO_dump_fp(stdout, ccm_ct, sizeof(ccm_ct));

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL)
        goto err;

    /* Fetch the cipher implementation */
    if ((cipher = EVP_CIPHER_fetch(libctx, "SM4-CCM", propq)) == NULL)
        goto err;

    /* Set nonce length if default 96 bits is not appropriate */
    params[0] = OSSL_PARAM_construct_size_t(OSSL_CIPHER_PARAM_AEAD_IVLEN,
                                            &ccm_nonce_len);
    /* Set tag length */
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                                  (unsigned char *)ccm_tag,
                                                  sizeof(ccm_tag));
    /*
     * Initialise decrypt operation with the cipher & mode,
     * nonce length and expected tag parameters.
     */
    if (!EVP_DecryptInit_ex2(ctx, cipher, NULL, NULL, params))
        goto err;

    /* Specify key and IV */
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, ccm_key, ccm_nonce))
        goto err;

    /* Set ciphertext length: only needed if we have AAD */
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, NULL, sizeof(ccm_ct)))
        goto err;

    /* Zero or one call to specify any AAD */
    if (!EVP_DecryptUpdate(ctx, NULL, &outlen, ccm_adata, sizeof(ccm_adata)))
        goto err;

    /* Decrypt plaintext, verify tag: can only be called once */
    rv = EVP_DecryptUpdate(ctx, outbuf, &outlen, ccm_ct, sizeof(ccm_ct));

    /* Output decrypted block: if tag verify failed we get nothing */
    if (rv > 0) {
        printf("Tag verify successful!\nPlaintext:\n");
        BIO_dump_fp(stdout, outbuf, outlen);
    } else {
        printf("Tag verify failed!\nPlaintext not available\n");
        goto err;
    }
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
    if (!sm4_ccm_encrypt())
        return 1;

    if (!sm4_ccm_decrypt())
        return 1;

    return 0;
}
