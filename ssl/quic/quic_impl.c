/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/macros.h>
#include <openssl/objects.h>
#include "quic_local.h"

int ossl_quic_new(SSL *s)
{
    return s->method->ssl_clear(s);
}

void ossl_quic_free(SSL *s)
{
    return;
}

int ossl_quic_clear(SSL *s)
{
    return 1;
}

int ossl_quic_accept(SSL *s)
{
    return 1;
}

int ossl_quic_connect(SSL *s)
{
    return 1;
}

int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    BIO *rbio = SSL_get_rbio(s);

    if (rbio == NULL)
        return 0;

    return BIO_read_ex(rbio, buf, len, readbytes);
}

int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    return 1;
}

int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    BIO *wbio = SSL_get_wbio(s);

    if (wbio == NULL)
        return 0;

    return BIO_write_ex(wbio, buf, len, written);
}

int ossl_quic_shutdown(SSL *s)
{
    return 1;
}

long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    return 0;
}

long ossl_quic_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg)
{
    return 0;
}

long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return 0;
}

long ossl_quic_ctx_callback_ctrl(SSL_CTX *s, int cmd, void (*fp) (void))
{
    return 0;
}

size_t ossl_quic_pending(const SSL *s)
{
    return 0;
}

long ossl_quic_default_timeout(void)
{
    return 0;
}

int ossl_quic_num_ciphers(void)
{
    return 1;
}

const SSL_CIPHER *ossl_quic_get_cipher(unsigned int u)
{
    static const SSL_CIPHER ciph = { 0 };

    return &ciph;
}

int ossl_quic_renegotiate_check(SSL *ssl, int initok)
{
    return 1;
}
