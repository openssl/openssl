/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/**
 * @file Static OSSL_FN constant storage declarations.
 *
 * These declarations pair with OSSL_FN_STATIC_DEFINE in corresponding
 * crypto/fn/fn_*_consts.c files.  The unions give fixed numerical
 * constants (mathematical constants, group parameters) an OSSL_FN
 * backing in .rodata.
 */

#ifndef OPENSSL_FN_CONSTANTS_H
#define OPENSSL_FN_CONSTANTS_H
#pragma once

#include "crypto/fn_intern.h"

/*
 * 1 / sqrt(2) * 2^256, rounded up.
 * 4 limbs on 64-bit, 8 limbs on 32-bit.
 */
#if OSSL_FN_BYTES == 8
OSSL_FN_STATIC_DECLARE(inv_sqrt_2, 4);
#else
OSSL_FN_STATIC_DECLARE(inv_sqrt_2, 8);
#endif

#endif /* OPENSSL_FN_CONSTANTS_H */
