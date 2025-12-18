/*
 * Copyright 2007-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <assert.h>
#include <openssl/seed.h>
#include "crypto/evp.h"
#include "evp_local.h"

IMPLEMENT_BLOCK_CIPHER(seed, ks, SEED, EVP_SEED_KEY, NID_seed,
    16, 16, 16, 128, EVP_CIPH_FLAG_DEFAULT_ASN1)
