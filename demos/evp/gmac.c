/*
 * Copyright 2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * Simple AES GMAC test program, uses the same NIST data used for the FIPS
 * self test but uses the application level EVP APIs.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

/* AES-GMAC test data from NIST public test vectors */

static const unsigned char gmac_key[] = { 0x77, 0xbe, 0x63, 0x70, 0x89, 0x71, 0xc4, 0xe2,
               0x40, 0xd1, 0xcb, 0x79, 0xe8, 0xd7, 0x7f, 0xeb };
static const unsigned char gmac_iv[] = { 0xe0, 0xe0, 0x0f, 0x19, 0xfe, 0xd7, 0xba, 0x01,
              0x36, 0xa7, 0x97, 0xf3 };
static const unsigned char gmac_aad[] = { 0x7a, 0x43, 0xec, 0x1d, 0x9c, 0x0a, 0x5a, 0x78,
               0xa0, 0xb1, 0x65, 0x33, 0xa6, 0x21, 0x3c, 0xab };

static const unsigned char gmac_tag[] = { 0x20, 0x9f, 0xcc, 0x8d, 0x36, 0x75, 0xed, 0x93,
               0x8e, 0x9c, 0x71, 0x66, 0x70, 0x9d, 0xd9, 0x46 };

static int aes_gmac(void)
{
    EVP_CIPHER_CTX *ctx;
    int outlen, tmplen;
    unsigned char outbuf[1024];
    int ret = 0;

    printf("AES GMAC:\n");
    printf("Authenticated Data:\n");
    BIO_dump_fp(stdout, gmac_aad, sizeof(gmac_aad));

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        printf("EVP_CIPHER_CTX_new: failed\n");
        goto err;
    }

    /* Set cipher type and mode */
    if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
        printf("EVP_EncryptInit_ex: failed\n");
        goto err;
    }

    /* Set IV length if default 96 bits is not appropriate */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, sizeof(gmac_iv),
                             NULL)) {
        printf("EVP_CIPHER_CTX_ctrl: set IV length failed\n");
        goto err;
    }

    /* Initialise key and IV */
    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, gmac_key, gmac_iv)) {
        printf("EVP_EncryptInit_ex: set key and IV failed\n");
        goto err;
    }

    /* Zero or more calls to specify any AAD */
    if (!EVP_EncryptUpdate(ctx, NULL, &outlen, gmac_aad, sizeof(gmac_aad))) {
        printf("EVP_EncryptUpdate: setting AAD failed\n");
        goto err;
    }

    /* Finalise: note get no output for GMAC */
    if (!EVP_EncryptFinal_ex(ctx, outbuf, &outlen)) {
        printf("EVP_EncryptFinal_ex: failed\n");
        goto err;
    }

    /* Get tag */
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outbuf)) {
        printf("EVP_CIPHER_CTX_ctrl: failed\n");
        goto err;
    }

    /* Output tag */
    printf("Tag:\n");
    BIO_dump_fp(stdout, outbuf, 16);

    /* Is the tag correct? */
    if (memcmp(outbuf, gmac_tag, sizeof(gmac_tag)) != 0) {
        printf("Expected:\n");
        BIO_dump_fp(stdout, gmac_tag, sizeof(gmac_tag));
    } else 
        ret = 1;
err:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int main(int argc, char **argv)
{
    return aes_gmac() ? EXIT_SUCCESS : EXIT_FAILURE;
}
