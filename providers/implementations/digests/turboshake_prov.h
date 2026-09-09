/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_PROVIDERS_IMPLEMENTATIONS_DIGESTS_TURBOSHAKE_PROV_H
#define OSSL_PROVIDERS_IMPLEMENTATIONS_DIGESTS_TURBOSHAKE_PROV_H

#include "internal/sha3.h"

int ossl_turboshake_init_keccak(KECCAK1600_CTX *ctx, size_t bitlen,
    unsigned int domain, size_t xoflen);

#endif
