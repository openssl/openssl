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

#include <openssl/dh.h>
#include "crypto/bn_dh.h"
#include "crypto/fn_constants.h"

/*
 * The OSSL_FN static storage backing these BIGNUM views is defined in
 * crypto/fn/fn_dh_consts.c.
 */

/* Macro to make a BIGNUM view over OSSL_FN static storage */

#define make_dh_bn(x)                                                  \
    extern const BIGNUM ossl_bignum_##x;                               \
    const BIGNUM ossl_bignum_##x = {                                   \
        .data = (OSSL_FN *)&ossl_fn_static_##x##_storage.fn,           \
        .d = (BN_ULONG *)ossl_fn_static_##x##_storage.fixed.d,         \
        .top = (int)OSSL_NELEM(ossl_fn_static_##x##_storage.fixed.d),  \
        .dmax = (int)OSSL_NELEM(ossl_fn_static_##x##_storage.fixed.d), \
        .flags = BN_FLG_STATIC_DATA,                                   \
    }

make_dh_bn(const_2);
make_dh_bn(dh1024_160_p);
make_dh_bn(dh1024_160_q);
make_dh_bn(dh1024_160_g);
make_dh_bn(dh2048_224_p);
make_dh_bn(dh2048_224_q);
make_dh_bn(dh2048_224_g);
make_dh_bn(dh2048_256_p);
make_dh_bn(dh2048_256_q);
make_dh_bn(dh2048_256_g);
make_dh_bn(ffdhe2048_p);
make_dh_bn(ffdhe2048_q);
make_dh_bn(ffdhe3072_p);
make_dh_bn(ffdhe3072_q);
make_dh_bn(ffdhe4096_p);
make_dh_bn(ffdhe4096_q);
make_dh_bn(ffdhe6144_p);
make_dh_bn(ffdhe6144_q);
make_dh_bn(ffdhe8192_p);
make_dh_bn(ffdhe8192_q);

#ifndef FIPS_MODULE
make_dh_bn(modp_1536_p);
make_dh_bn(modp_1536_q);
#endif
make_dh_bn(modp_2048_p);
make_dh_bn(modp_2048_q);
make_dh_bn(modp_3072_p);
make_dh_bn(modp_3072_q);
make_dh_bn(modp_4096_p);
make_dh_bn(modp_4096_q);
make_dh_bn(modp_6144_p);
make_dh_bn(modp_6144_q);
make_dh_bn(modp_8192_p);
make_dh_bn(modp_8192_q);
