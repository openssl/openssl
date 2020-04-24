/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/sm3.h"
#include "prov/digestcommon.h"
#include "prov/implementations.h"

/* sm3_functions */
IMPLEMENT_digest_functions(sm3, SM3_CTX,
                           SM3_CBLOCK, SM3_DIGEST_LENGTH, 0,
                           sm3_init, sm3_update, sm3_final)
