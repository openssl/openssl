/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#define NAME_1          X25519
#define NAME_2          MLKEM768

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>

#include "crypto/ecx.h"
#include "crypto/ml_kem.h"

#include "hybrid_kem.inc"

const OSSL_PARAM OSSL_NAME(ctx_gettable_params)[] = {
    OSSL_PARAM_END
};

const OSSL_PARAM OSSL_NAME(ctx_settable_params)[] = {
    OSSL_PARAM_utf8_string(OSSL_KEM_PARAM_OPERATION, NULL, 0),
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_IKME, NULL, 0),
    OSSL_PARAM_END
};
