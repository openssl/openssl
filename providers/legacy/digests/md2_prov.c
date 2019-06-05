/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/md2.h>

#include "internal/core_mkdigest.h"
#include "internal/provider_algs.h"

OSSL_FUNC_DIGEST_CONSTRUCT(md2, MD2_CTX,
                           MD2_BLOCK, MD2_DIGEST_LENGTH,
                           MD2_Init, MD2_Update, MD2_Final)
