/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "crypto/fn_constants.h"

/* 1 / sqrt(2) * 2^256, rounded up */
OSSL_FN_STATIC_DEFINE(inv_sqrt_2, OSSL_FN_LIMBS_N(256),
    OSSL_FN_ULONG64_C(0xED17AC85, 0x83339916),
    OSSL_FN_ULONG64_C(0x1D6F60BA, 0x893BA84C),
    OSSL_FN_ULONG64_C(0x597D89B3, 0x754ABE9F),
    OSSL_FN_ULONG64_C(0xB504F333, 0xF9DE6484));
