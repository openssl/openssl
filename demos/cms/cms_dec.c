/*
 * Copyright 2008-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Simple S/MIME decryption example */
#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

int main(int argc, char **argv)
{
    BIO *in = NULL, *out = NULL, *tbio = NULL;
    X509 *rcert = NULL;
    EVP_PKEY *rkey = NULL;
    CMS_ContentInfo *cms = NULL;
    int ret = 1;

    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    /* Read in recipient certificate and private key */
    tbio = BIO_new_file("smrsa1.pem", "r");
    if (tbio == NULL)
        goto err;

    rcert = PEM_read_bio_X509(tbio, NULL, 0, NULL);
    if (rcert == NULL)
        goto err;

    BIO_reset(tbio);

    rkey = PEM_read_bio_PrivateKey(tbio, NULL, 0, NULL);
    if (rkey == NULL)
        goto err;

    /* Open S/MIME message to decrypt */

    in = BIO_new_file("smencr.txt", "r");
    if (in == NULL)
        goto err;

    /* Parse message */
    cms = SMIME_read_CMS(in, NULL);
    if (cms == NULL)
        goto err;

    out = BIO_new_file("decout.txt", "w");
    if (out == NULL)
        goto err;

    /* Decrypt S/MIME message */
    if (!CMS_decrypt(cms, rkey, rcert, NULL, out, 0))
        goto err;

    printf("Successfully decrypted contents of file smencr.txt into file"
           "\ndecout.txt using certificate and private key from file"
           "\nsmrsa1.pem\n");
    ret = 0;

 err:

    if (ret) {
        fprintf(stderr, "Error Decrypting Data\n");
        ERR_print_errors_fp(stderr);
    }

    CMS_ContentInfo_free(cms);
    X509_free(rcert);
    EVP_PKEY_free(rkey);
    BIO_free(in);
    BIO_free(out);
    BIO_free(tbio);
    return ret;
}
