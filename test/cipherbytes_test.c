/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL licenses, (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <stdio.h>

#include <openssl/opensslconf.h>
#include <openssl/err.h>
#include <openssl/e_os2.h>
#include <openssl/ssl.h>
#include <openssl/ssl3.h>
#include <openssl/tls1.h>

#include "e_os.h"
#include "test_main.h"
#include "testutil.h"

static int test_empty(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk = NULL, *scsv = NULL;
    const unsigned char bytes[] = {0x00};

    if (SSL_bytes_to_cipher_list(s, bytes, 0, 0, &sk, &scsv) ||
        sk != NULL || scsv != NULL)
        return 0;
    return 1;
}

static int test_unsupported(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk, *scsv;
    /* ECDH-RSA-AES256 (unsupported), ECDHE-ECDSA-AES128, <unassigned> */
    const unsigned char bytes[] = {0xc0, 0x0f, 0x00, 0x2f, 0x01, 0x00};

    if (!SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes), 0, &sk, &scsv) ||
        sk == NULL || sk_SSL_CIPHER_num(sk) != 1 || scsv == NULL ||
        sk_SSL_CIPHER_num(scsv) != 0)
        return 0;
    if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
                "AES128-SHA") != 0)
        return 0;

    sk_SSL_CIPHER_free(sk);
    sk_SSL_CIPHER_free(scsv);
    return 1;
}

static int test_v2(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk, *scsv;
    /* ECDHE-ECDSA-AES256GCM, SSL2_RC4_1238_WITH_MD5,
     * ECDHE-ECDSA-CHACHA20-POLY1305 */
    const unsigned char bytes[] = {0x00, 0x00, 0x35, 0x01, 0x00, 0x80,
                                   0x00, 0x00, 0x33};

    if (!SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes), 1, &sk, &scsv) ||
        sk == NULL || sk_SSL_CIPHER_num(sk) != 2 || scsv == NULL ||
        sk_SSL_CIPHER_num(scsv) != 0)
        return 0;
    if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
               "AES256-SHA") != 0 ||
        strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 1)),
               "DHE-RSA-AES128-SHA") != 0)
        return 0;
    sk_SSL_CIPHER_free(sk);
    sk_SSL_CIPHER_free(scsv);
    return 1;
}

static int test_v3(SSL *s)
{
    STACK_OF(SSL_CIPHER) *sk, *scsv;
    /* ECDHE-ECDSA-AES256GCM, ECDHE-ECDSA-CHACHAPOLY, DHE-RSA-AES256GCM,
     * EMPTY-RENEGOTIATION-INFO-SCSV, FALLBACK-SCSV */
    const unsigned char bytes[] = {0x00, 0x2f, 0x00, 0x33, 0x00, 0x9f, 0x00, 0xff,
                                   0x56, 0x00};

    if (!SSL_bytes_to_cipher_list(s, bytes, sizeof(bytes), 0, &sk, &scsv) ||
        sk == NULL || sk_SSL_CIPHER_num(sk) != 3 || scsv == NULL ||
        sk_SSL_CIPHER_num(scsv) != 2)
        return 0;
    if (strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 0)),
               "AES128-SHA") != 0 ||
        strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 1)),
               "DHE-RSA-AES128-SHA") != 0 ||
        strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(sk, 2)),
               "DHE-RSA-AES256-GCM-SHA384") != 0 ||
        strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(scsv, 0)),
               "TLS_EMPTY_RENEGOTIATION_INFO_SCSV") != 0 ||
        strcmp(SSL_CIPHER_get_name(sk_SSL_CIPHER_value(scsv, 1)),
               "TLS_FALLBACK_SCSV") != 0)
        return 0;
    sk_SSL_CIPHER_free(sk);
    sk_SSL_CIPHER_free(scsv);
    return 1;
}

int main(int argc, char **argv)
{
    SSL_CTX *ctx;
    SSL *s;

    ctx = SSL_CTX_new(TLS_server_method());
    s = SSL_new(ctx);
    OPENSSL_assert(s != NULL);

    if (!test_empty(s))
        return 1;

    if (!test_unsupported(s))
        return 1;

    if (!test_v2(s))
        return 1;

    if (!test_v3(s))
        return 1;

    printf("PASS\n");
    SSL_free(s);
    SSL_CTX_free(ctx);
    return 0;
}
