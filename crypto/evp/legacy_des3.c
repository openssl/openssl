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
 * EVP_des_ede3_ecb()
 * EVP_des_ede3_cbc()
 * EVP_des_ede3_ofb()
 * EVP_des_ede3_cfb64()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes2(des_ede3, NID_des_ede3, 192, 8, 8, 64,
                                  EVP_CIPH_RAND_KEY)

/* EVP_des_ede3_cfb8() */
IMPLEMENT_EVP_CIPHER_CONST2(des_ede3, NID_des_ede3_cfb8, 192, 8, 8, cfb8, CFB,
                            EVP_CIPH_RAND_KEY)
/* EVP_des_ede3_cfb1() */
IMPLEMENT_EVP_CIPHER_CONST2(des_ede3, NID_des_ede3_cfb1, 192, 8, 8, cfb1, CFB,
                            EVP_CIPH_RAND_KEY)


const EVP_CIPHER *EVP_des_ede3(void)
{
    return &des_ede3_ecb;
}


static const EVP_CIPHER des3_wrap = {
    NID_id_smime_alg_CMS3DESwrap,
    8, 24, 0,
    EVP_CIPH_WRAP_MODE | EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER
    | EVP_CIPH_FLAG_DEFAULT_ASN1
};

const EVP_CIPHER *EVP_des_ede3_wrap(void)
{
    return &des3_wrap;
}
