/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/types.h"

#ifndef OPENSSL_NO_EC
int ossl_ecx_dhkem_derive_private(ECX_KEY *ecx, unsigned char *privout,
                                  const unsigned char *ikm, size_t ikmlen);
int ossl_ec_dhkem_derive_private(EC_KEY *ec, BIGNUM *privout,
                                 const unsigned char *ikm, size_t ikmlen);
#endif
