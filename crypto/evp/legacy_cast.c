/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

/*
 * EVP_cast5_ecb()
 * EVP_cast5_cbc()
 * EVP_cast5_ofb()
 * EVP_cast5_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(cast5, NID_cast5, 128, 8, 8, 64,
                                  EVP_CIPH_VARIABLE_LENGTH)
