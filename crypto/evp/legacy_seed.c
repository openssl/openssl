/*
 * Copyright 2007-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

/*
 * EVP_seed_ecb()
 * EVP_seed_cbc()
 * EVP_seed_ofb()
 * EVP_seed_cfb128()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(seed, NID_seed, 128, 16, 16, 128, 0)
