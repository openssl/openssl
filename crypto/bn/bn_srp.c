/*
 * Copyright 2014-2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "bn_local.h"
#include "internal/nelem.h"

#ifndef OPENSSL_NO_SRP

#include <openssl/srp.h>
#include "crypto/bn_srp.h"
#include "crypto/fn_constants.h"

/*
 * The OSSL_FN static storage backing these BIGNUM views is defined in
 * crypto/fn/fn_srp_consts.c.
 */

/* Macro to make a BIGNUM view over OSSL_FN static storage */

#define make_srp_bn(bignum, x)                                         \
    const BIGNUM ossl_##bignum = {                                     \
        .data = (OSSL_FN *)&ossl_fn_static_##x##_storage.fn,           \
        .d = (BN_ULONG *)ossl_fn_static_##x##_storage.fixed.d,         \
        .top = (int)OSSL_NELEM(ossl_fn_static_##x##_storage.fixed.d),  \
        .dmax = (int)OSSL_NELEM(ossl_fn_static_##x##_storage.fixed.d), \
        .flags = BN_FLG_STATIC_DATA,                                   \
    }

make_srp_bn(bn_group_1024, bn_group_1024);
make_srp_bn(bn_group_1536, bn_group_1536);
make_srp_bn(bn_group_2048, bn_group_2048);
make_srp_bn(bn_group_3072, bn_group_3072);
make_srp_bn(bn_group_4096, bn_group_4096);
make_srp_bn(bn_group_6144, bn_group_6144);
make_srp_bn(bn_group_8192, bn_group_8192);
make_srp_bn(bn_generator_19, bn_generator_19);
make_srp_bn(bn_generator_5, bn_generator_5);
make_srp_bn(bn_generator_2, bn_generator_2);

#endif
