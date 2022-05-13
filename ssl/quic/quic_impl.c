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

__owur int ossl_quic_new(SSL *s)
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

__owur int ossl_quic_accept(SSL *s)
{
    return 1;
}

__owur int ossl_quic_connect(SSL *s)
{
    return 1;
}

__owur int ossl_quic_read(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    return 1;
}

__owur int ossl_quic_peek(SSL *s, void *buf, size_t len, size_t *readbytes)
{
    return 1;
}

__owur int ossl_quic_write(SSL *s, const void *buf, size_t len, size_t *written)
{
    return 1;
}

__owur int ossl_quic_shutdown(SSL *s)
{
    return 1;
}

__owur long ossl_quic_ctrl(SSL *s, int cmd, long larg, void *parg)
{
    return 0;
}

__owur long ossl_quic_ctx_ctrl(SSL_CTX *s, int cmd, long larg, void *parg)
{
    return 0;
}

__owur long ossl_quic_callback_ctrl(SSL *s, int cmd, void (*fp) (void))
{
    return 0;
}

__owur long ossl_quic_ctx_callback_ctrl(SSL_CTX *s, int cmd, void (*fp) (void))
{
    return 0;
}

__owur size_t ossl_quic_pending(const SSL *s)
{
    return 0;
}
