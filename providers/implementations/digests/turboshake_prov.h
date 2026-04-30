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

/**
 * @brief Initialize a Keccak sponge for TurboSHAKE or KangarooTwelve.
 *
 * Resets the state and installs the Keccak-p[1600,12] methods.
 *
 * @param ctx sponge context to initialize
 * @param bitlen security strength in bits, 128 or 256
 * @param domain domain separation byte, from 1 to 127 inclusive
 * @param xoflen default output length in bytes
 * @returns 1 on success, or 0 on an invalid domain or initialization failure
 */
int ossl_turboshake_init_keccak(KECCAK1600_CTX *ctx, size_t bitlen,
    unsigned int domain, size_t xoflen);

#endif
