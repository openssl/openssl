/*
 * Copyright 2017 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2014 Cryptography Research, Inc.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 *
 * Originally written by Mike Hamburg
 */

#include "field.h"

mask_t gf_isr(gf a, const gf x)
{
    gf L0, L1, L2;
    gf_sqr(L1, x);
    gf_mul(L2, x, L1);
    gf_sqr(L1, L2);
    gf_mul(L2, x, L1);
    gf_sqrn(L1, L2, 3);
    gf_mul(L0, L2, L1);
    gf_sqrn(L1, L0, 3);
    gf_mul(L0, L2, L1);
    gf_sqrn(L2, L0, 9);
    gf_mul(L1, L0, L2);
    gf_sqr(L0, L1);
    gf_mul(L2, x, L0);
    gf_sqrn(L0, L2, 18);
    gf_mul(L2, L1, L0);
    gf_sqrn(L0, L2, 37);
    gf_mul(L1, L2, L0);
    gf_sqrn(L0, L1, 37);
    gf_mul(L1, L2, L0);
    gf_sqrn(L0, L1, 111);
    gf_mul(L2, L1, L0);
    gf_sqr(L0, L2);
    gf_mul(L1, x, L0);
    gf_sqrn(L0, L1, 223);
    gf_mul(L1, L2, L0);
    gf_sqr(L2, L1);
    gf_mul(L0, L2, x);
    gf_copy(a, L1);
    return gf_eq(L0, ONE);
}
