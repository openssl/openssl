/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "cipher_aes_xts.h"

#ifdef FIPS_MODE
const int allow_insecure_decrypt = 0;
#else
const int allow_insecure_decrypt = 1;
#endif /* FIPS_MODE */
