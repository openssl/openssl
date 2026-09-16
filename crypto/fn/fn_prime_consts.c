/*
 * Copyright 2026 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* Prime machinery constants */

#include "crypto/fn_constants.h"
#include "../bn/bn_prime.h" /* For BN_DEF() */

/*
 * See SP800 89 5.3.3 (Step f)
 * The product of the set of primes ranging from 3 to 751.
 * This includes 751 (which is not currently included in SP 800-89).
 *
 * The BN_DEF() initializers pack each 64-bit limb as one or two array
 * entries depending on limb width, keeping the value identical on 32-bit
 * and 64-bit.
 */
OSSL_FN_STATIC_DEFINE(small_prime_factors,
    OSSL_FN_SMALL_PRIME_FACTORS_LIMBS,
    BN_DEF(0x3ef4e3e1, 0xc4309333), BN_DEF(0xcd2d655f, 0x71161eb6),
    BN_DEF(0x0bf94862, 0x95e2238c), BN_DEF(0x24f7912b, 0x3eb233d3),
    BN_DEF(0xbf26c483, 0x6b55514b), BN_DEF(0x5a144871, 0x0a84d817),
    BN_DEF(0x9b82210a, 0x77d12fee), BN_DEF(0x97f050b3, 0xdb5b93c2),
    BN_DEF(0x4d6c026b, 0x4acad6b9), BN_DEF(0x54aec893, 0xeb7751f3),
    BN_DEF(0x36bc85c4, 0xdba53368), BN_DEF(0x7f5ec78e, 0xd85a1b28),
    BN_DEF(0x6b322244, 0x2eb072d8), BN_DEF(0x5e2b3aea, 0xbba51112),
    BN_DEF(0x0e2486bf, 0x36ed1a6c), BN_DEF(0xec0c5727, 0x5f270460),
    (OSSL_FN_ULONG)0x000017b1);
