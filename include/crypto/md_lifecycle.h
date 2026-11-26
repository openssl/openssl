/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#ifndef OSSL_CRYPTO_MD_LIFECYCLE_H
#define OSSL_CRYPTO_MD_LIFECYCLE_H
#pragma once

/*
 * The states of the digest life-cycle, see life_cycle-digest(7). The EVP
 * layer enforces the transitions between them; the digest implementations
 * that track their own position use the same names.
 */
typedef enum {
    MD_STATE_NEWED = 0,
    MD_STATE_INITIALISED,
    MD_STATE_UPDATED,
    MD_STATE_FINALED,
    MD_STATE_SQUEEZED,
    MD_STATE_FAILED,
    MD_STATE_COUNT
} MD_STATE;

#endif
