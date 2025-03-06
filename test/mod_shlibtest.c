/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/ssl.h>

int do_test_create_ssl_ctx(void)
{
    SSL_CTX *ctx = NULL;

    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS, NULL) == 0)
        return 0;

    ctx = SSL_CTX_new(TLS_method());
    if (ctx != NULL)
        SSL_CTX_free(ctx);

    return ctx != NULL;
}
