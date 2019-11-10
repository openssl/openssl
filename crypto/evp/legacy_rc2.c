/*
 * Copyright 1995-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

/*
 * EVP_rc2_ecb()
 * EVP_rc2_cbc()
 * EVP_rc2_ofb()
 * EVP_rc2_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(rc2, NID_rc2, 128, 8, 8, 64,
                                  EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT)
/* EVP_rc2_64_cbc() */
IMPLEMENT_EVP_CIPHER_CONST2(rc2_64, NID_rc2_64_cbc, 64, 8, 8, cbc, CBC,
                            EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT)
/* EVP_rc2_40_cbc() */
IMPLEMENT_EVP_CIPHER_CONST2(rc2_40, NID_rc2_40_cbc, 40, 8, 8, cbc, CBC,
                            EVP_CIPH_VARIABLE_LENGTH | EVP_CIPH_CTRL_INIT)
