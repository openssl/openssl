/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "ssltestlib.h"

int create_ssl_ctx_pair(const SSL_METHOD *sm, const SSL_METHOD *cm,
                        SSL_CTX **sctx, SSL_CTX **cctx, char *certfile,
                        char *privkeyfile)
{
    SSL_CTX *serverctx = NULL;
    SSL_CTX *clientctx = NULL;

    serverctx = SSL_CTX_new(sm);
    clientctx = SSL_CTX_new(cm);
    if (serverctx == NULL || clientctx == NULL) {
        printf("Failed to create SSL_CTX\n");
        goto err;
    }

    if (SSL_CTX_use_certificate_file(serverctx, certfile,
                                     SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load server certificate\n");
        goto err;
    }
    if (SSL_CTX_use_PrivateKey_file(serverctx, privkeyfile,
                                    SSL_FILETYPE_PEM) <= 0) {
        printf("Failed to load server private key\n");
    }
    if (SSL_CTX_check_private_key(serverctx) <= 0) {
        printf("Failed to check private key\n");
        goto err;
    }

    *sctx = serverctx;
    *cctx = clientctx;

    return 1;
 err:
    SSL_CTX_free(serverctx);
    SSL_CTX_free(clientctx);
    return 0;
}

#define MAXLOOPS    100000

/*
 * NOTE: Transfers control of the BIOs - this function will free them on error
 */
int create_ssl_connection(SSL_CTX *serverctx, SSL_CTX *clientctx, SSL **sssl,
                          SSL **cssl, BIO *s_to_c_fbio, BIO *c_to_s_fbio)
{
    int retc = -1, rets = -1, err, abortctr = 0;
    int clienterr = 0, servererr = 0;
    SSL *serverssl, *clientssl;
    BIO *s_to_c_bio = NULL, *c_to_s_bio = NULL;

    if (*sssl == NULL)
        serverssl = SSL_new(serverctx);
    else
        serverssl = *sssl;
    if (*cssl == NULL)
        clientssl = SSL_new(clientctx);
    else
        clientssl = *cssl;

    if (serverssl == NULL || clientssl == NULL) {
        printf("Failed to create SSL object\n");
        goto error;
    }

    s_to_c_bio = BIO_new(BIO_s_mem());
    c_to_s_bio = BIO_new(BIO_s_mem());
    if (s_to_c_bio == NULL || c_to_s_bio == NULL) {
        printf("Failed to create mem BIOs\n");
        goto error;
    }

    if (s_to_c_fbio != NULL)
        s_to_c_bio = BIO_push(s_to_c_fbio, s_to_c_bio);
    if (c_to_s_fbio != NULL)
        c_to_s_bio = BIO_push(c_to_s_fbio, c_to_s_bio);
    if (s_to_c_bio == NULL || c_to_s_bio == NULL) {
        printf("Failed to create chained BIOs\n");
        goto error;
    }

    /* Set Non-blocking IO behaviour */
    BIO_set_mem_eof_return(s_to_c_bio, -1);
    BIO_set_mem_eof_return(c_to_s_bio, -1);

    /* Up ref these as we are passing them to two SSL objects */
    BIO_up_ref(s_to_c_bio);
    BIO_up_ref(c_to_s_bio);

    SSL_set_bio(serverssl, c_to_s_bio, s_to_c_bio);
    SSL_set_bio(clientssl, s_to_c_bio, c_to_s_bio);

    /* BIOs will now be freed when SSL objects are freed */
    s_to_c_bio = c_to_s_bio = NULL;
    s_to_c_fbio = c_to_s_fbio = NULL;

    do {
        err = SSL_ERROR_WANT_WRITE;
        while (!clienterr && retc <= 0 && err == SSL_ERROR_WANT_WRITE) {
            retc = SSL_connect(clientssl);
            if (retc <= 0)
                err = SSL_get_error(clientssl, retc);
        }

        if (!clienterr && retc <= 0 && err != SSL_ERROR_WANT_READ) {
            printf("SSL_connect() failed %d, %d\n", retc, err);
            clienterr = 1;
        }

        err = SSL_ERROR_WANT_WRITE;
        while (!servererr && rets <= 0 && err == SSL_ERROR_WANT_WRITE) {
            rets = SSL_accept(serverssl);
            if (rets <= 0)
                err = SSL_get_error(serverssl, rets);
        }

        if (!servererr && rets <= 0 && err != SSL_ERROR_WANT_READ) {
            printf("SSL_accept() failed %d, %d\n", retc, err);
            servererr = 1;
        }
        if (clienterr && servererr)
            goto error;
        if (++abortctr == MAXLOOPS) {
            printf("No progress made\n");
            goto error;
        }
    } while (retc <=0 || rets <= 0);

    *sssl = serverssl;
    *cssl = clientssl;

    return 1;

 error:
    if (*sssl == NULL) {
        SSL_free(serverssl);
        BIO_free(s_to_c_bio);
        BIO_free(s_to_c_fbio);
    }
    if (*cssl == NULL) {
        SSL_free(clientssl);
        BIO_free(c_to_s_bio);
        BIO_free(c_to_s_fbio);
    }

    return 0;
}
