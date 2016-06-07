/*
 * Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>


int main(int argc, char *argv[])
{
    SSL_CTX *ctx = NULL;
    SSL *con = NULL;
    BIO *err;
    int testresult = 0;

    err = BIO_new_fp(stderr, BIO_NOCLOSE | BIO_FP_TEXT);

    CRYPTO_set_mem_debug(1);
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    /* Test tlsext_status_type */
    ctx = SSL_CTX_new(TLS_method());

    if (SSL_CTX_get_tlsext_status_type(ctx) != -1) {
        printf("Unexpected initial value for "
               "SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    con = SSL_new(ctx);

    if (SSL_get_tlsext_status_type(con) != -1) {
        printf("Unexpected initial value for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    if (!SSL_set_tlsext_status_type(con, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_get_tlsext_status_type(con) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type()\n");
        goto end;
    }

    SSL_free(con);
    con = NULL;

    if (!SSL_CTX_set_tlsext_status_type(ctx, TLSEXT_STATUSTYPE_ocsp)) {
        printf("Unexpected fail for SSL_CTX_set_tlsext_status_type()\n");
        goto end;
    }

    if (SSL_CTX_get_tlsext_status_type(ctx) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_CTX_get_tlsext_status_type()\n");
        goto end;
    }

    con = SSL_new(ctx);

    if (SSL_get_tlsext_status_type(con) != TLSEXT_STATUSTYPE_ocsp) {
        printf("Unexpected result for SSL_get_tlsext_status_type() (test 2)\n");
        goto end;
    }

    testresult = 1;

 end:
    SSL_free(con);
    SSL_CTX_free(ctx);

#ifndef OPENSSL_NO_CRYPTO_MDEBUG
    if (CRYPTO_mem_leaks(err) <= 0)
        testresult = 0;
#endif
    BIO_free(err);

    if (testresult)
        printf("PASS\n");

    return testresult?0:1;
}
