/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include "provider_local.h"

OSSL_provider_init_fn ossl_default_provider_init;

const struct predefined_providers_st predefined_providers[] = {
    { "default", ossl_default_provider_init, 1 },
    { NULL, NULL, 0 }
};
