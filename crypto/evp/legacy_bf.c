/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */


#include "crypto/evp.h"
#include "evp_local.h"

/*
 * EVP_bf_ecb()
 * EVP_bf_cbc()
 * EVP_bf_ofb()
 * EVP_bf_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(bf, NID_bf, 128, 8, 8, 64,
                                  EVP_CIPH_VARIABLE_LENGTH)
