/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>

static struct {
    const char *name;
    OSSL_provider_init_fn *init;
    unsigned int is_fallback:1;
} const predefined_providers[] = {
#if 0                            /* Until it exists for real */
    { "default", ossl_default_provider_init, 1 },
#endif
    { NULL, NULL, 0 }
};
