/*
 * Copyright 2017-2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2017, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/evp.h"

/*
 * EVP_aria_128_cbc()
 * EVP_aria_128_ecb(
 * EVP_aria_128_ofb()
 * EVP_aria_128_cfb128()
 * EVP_aria_128_cfb1()
 * EVP_aria_128_cfb8()
 * EVP_aria_128_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aria, NID_aria, 128, 0)
/*
 * EVP_aria_192_cbc()
 * EVP_aria_192_ecb(
 * EVP_aria_192_ofb()
 * EVP_aria_192_cfb128()
 * EVP_aria_192_cfb1()
 * EVP_aria_192_cfb8()
 * EVP_aria_192_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aria, NID_aria, 192, 0)
/*
 * EVP_aria_256_cbc()
 * EVP_aria_256_ecb(
 * EVP_aria_256_ofb()
 * EVP_aria_256_cfb128()
 * EVP_aria_256_cfb1()
 * EVP_aria_256_cfb8()
 * EVP_aria_256_ctr()
 */
IMPLEMENT_EVP_CIPHER_CONST_modes(aria, NID_aria, 256, 0)

/* EVP_aria_128_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_128_gcm, 128, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aria_192_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_192_gcm, 192, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aria_256_gcm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_256_gcm, 256, 1, 12, gcm, GCM, EVP_CIPH_AEAD_FLAGS)

/* EVP_aria_128_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_128_ccm, 128, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aria_192_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_192_ccm, 192, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)
/* EVP_aria_256_ccm() */
IMPLEMENT_EVP_CIPHER_CONST(aria, NID_aria_256_ccm, 256, 1, 12, ccm, CCM, EVP_CIPH_AEAD_FLAGS)

