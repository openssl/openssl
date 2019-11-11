/*
 * Copyright 2017-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 Ribose Inc. All Rights Reserved.
 * Ported from Ribose contributions from Botan.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"
#include "evp_local.h"

/*
 * EVP_sm4_ecb()
 * EVP_sm4_cbc()
 * EVP_sm4_ofb()
 * EVP_sm4_cfb128()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(sm4, NID_sm4, 128, 16, 16, 128, 0)

/* EVP_sm4_ctr() */
IMPLEMENT_EVP_CIPHER_CONST2(sm4, NID_sm4_ctr, 128, 1, 16, ctr, CTR, 0)
