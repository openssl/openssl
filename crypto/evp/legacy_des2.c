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
 * EVP_des_ede_ecb()
 * EVP_des_ede_cbc()
 * EVP_des_ede_ofb()
 * EVP_des_ede_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(des_ede, NID_des_ede, 128, 8, 8, 64,
                                  EVP_CIPH_RAND_KEY)


const EVP_CIPHER *EVP_des_ede(void)
{
    return &des_ede_ecb;
}
