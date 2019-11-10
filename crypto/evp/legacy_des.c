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
 * EVP_des_ecb()
 * EVP_des_cbc()
 * EVP_des_ofb()
 * EVP_des_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(des, NID_des, 64, 8, 8, 64,
                                  EVP_CIPH_RAND_KEY)
/* EVP_des_cfb8() */
IMPLEMENT_EVP_CIPHER_CONST2(des, NID_des_cfb8, 64, 8, 8, cfb8, CFB,
                            EVP_CIPH_RAND_KEY)
/* EVP_des_cfb1() */
IMPLEMENT_EVP_CIPHER_CONST2(des, NID_des_cfb8, 64, 8, 8, cfb1, CFB,
                            EVP_CIPH_RAND_KEY)
