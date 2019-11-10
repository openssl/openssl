/*
 * Copyright 2006-2018 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/opensslconf.h>
#include <openssl/evp.h>
#include "crypto/evp.h"

/*
 * EVP_camellia_128_cbc()
 * EVP_camellia_128_ecb(
 * EVP_camellia_128_ofb()
 * EVP_camellia_128_cfb128()
 * EVP_camellia_128_cfb1()
 * EVP_camellia_128_cfb8()
 * EVP_camellia_128_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(camellia, NID_camellia, 128, 0)
/*
 * EVP_camellia_192_cbc()
 * EVP_camellia_192_ecb(
 * EVP_camellia_192_ofb()
 * EVP_camellia_192_cfb128()
 * EVP_camellia_192_cfb1()
 * EVP_camellia_192_cfb8()
 * EVP_camellia_192_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(camellia, NID_camellia, 192, 0)
/*
 * EVP_camellia_256_cbc()
 * EVP_camellia_256_ecb(
 * EVP_camellia_256_ofb()
 * EVP_camellia_256_cfb128()
 * EVP_camellia_256_cfb1()
 * EVP_camellia_256_cfb8()
 * EVP_camellia_256_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(camellia, NID_camellia, 256, 0)
