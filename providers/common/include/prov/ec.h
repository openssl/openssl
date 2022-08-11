/*
 * Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/types.h"

int ossl_ec_match_params(const EC_KEY *key1, const EC_KEY *key2);
int ossl_ecx_match_params(const ECX_KEY *key1, const ECX_KEY *key2);
