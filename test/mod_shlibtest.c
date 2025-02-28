/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 *
 */

#include <openssl/ssl.h>

int do_test_just_init(void)
{
    return OPENSSL_init_ssl(OPENSSL_INIT_ENGINE_ALL_BUILTIN | OPENSSL_INIT_LOAD_SSL_STRINGS, NULL);
}

int do_test_create_ssl_ctx(void)
{
    SSL_CTX *ctx = NULL;

    if (do_test_just_init() == 1) {
        ctx = SSL_CTX_new(TLS_method());
        if (ctx != NULL)
            SSL_CTX_free(ctx);
    }

    return ctx != NULL;
}
