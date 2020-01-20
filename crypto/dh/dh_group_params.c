/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* DH parameters from RFC7919 and RFC3526 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dh_local.h"
#include <openssl/bn.h>
#include <openssl/objects.h>
#include "crypto/bn_dh.h"

static DH *dh_param_init(const BIGNUM *p, int32_t nbits)
{
    BIGNUM *q = NULL;
    DH *dh = DH_new();

    if (dh == NULL)
        return NULL;

    q = BN_dup(p);
    /* Set q = (p - 1) / 2 (p is known to be odd so just shift right ) */
    if (q == NULL || !BN_rshift1(q, q)) {
        BN_free(q);
        DH_free(dh);
        return NULL;
    }
    dh->params.p = (BIGNUM *)p;
    dh->params.q = (BIGNUM *)q;
    dh->params.g = (BIGNUM *)&_bignum_const_2;
    dh->length = nbits; /* Private key length = 2 * s */
    dh->dirty_cnt++;
    return dh;
}

DH *DH_new_by_nid(int nid)
{
    /*
     * The last parameter specified in these fields is
     * 2 * max_target_security_strength.
     * See SP800-56Ar3 Table(s) 25 & 26.
     */
    switch (nid) {
    case NID_ffdhe2048:
        return dh_param_init(&_bignum_ffdhe2048_p, 225);
    case NID_ffdhe3072:
        return dh_param_init(&_bignum_ffdhe3072_p, 275);
    case NID_ffdhe4096:
        return dh_param_init(&_bignum_ffdhe4096_p, 325);
    case NID_ffdhe6144:
        return dh_param_init(&_bignum_ffdhe6144_p, 375);
    case NID_ffdhe8192:
        return dh_param_init(&_bignum_ffdhe8192_p, 400);
#ifndef FIPS_MODE
    case NID_modp_1536:
        return dh_param_init(&_bignum_modp_1536_p, 190);
#endif
    case NID_modp_2048:
        return dh_param_init(&_bignum_modp_2048_p, 225);
    case NID_modp_3072:
        return dh_param_init(&_bignum_modp_3072_p, 275);
    case NID_modp_4096:
        return dh_param_init(&_bignum_modp_4096_p, 325);
    case NID_modp_6144:
        return dh_param_init(&_bignum_modp_6144_p, 375);
    case NID_modp_8192:
        return dh_param_init(&_bignum_modp_8192_p, 400);
    default:
        DHerr(DH_F_DH_NEW_BY_NID, DH_R_INVALID_PARAMETER_NID);
        return NULL;
    }
}

int DH_get_nid(const DH *dh)
{
    int nid;

    if (BN_get_word(dh->params.g) != 2)
        return NID_undef;
    if (!BN_cmp(dh->params.p, &_bignum_ffdhe2048_p))
        nid = NID_ffdhe2048;
    else if (!BN_cmp(dh->params.p, &_bignum_ffdhe3072_p))
        nid = NID_ffdhe3072;
    else if (!BN_cmp(dh->params.p, &_bignum_ffdhe4096_p))
        nid = NID_ffdhe4096;
    else if (!BN_cmp(dh->params.p, &_bignum_ffdhe6144_p))
        nid = NID_ffdhe6144;
    else if (!BN_cmp(dh->params.p, &_bignum_ffdhe8192_p))
        nid = NID_ffdhe8192;
#ifndef FIPS_MODE
    else if (!BN_cmp(dh->params.p, &_bignum_modp_1536_p))
        nid = NID_modp_1536;
#endif
    else if (!BN_cmp(dh->params.p, &_bignum_modp_2048_p))
        nid = NID_modp_2048;
    else if (!BN_cmp(dh->params.p, &_bignum_modp_3072_p))
        nid = NID_modp_3072;
    else if (!BN_cmp(dh->params.p, &_bignum_modp_4096_p))
        nid = NID_modp_4096;
    else if (!BN_cmp(dh->params.p, &_bignum_modp_6144_p))
        nid = NID_modp_6144;
    else if (!BN_cmp(dh->params.p, &_bignum_modp_8192_p))
        nid = NID_modp_8192;
    else
        return NID_undef;

    /* Verify q is correct if it exists */
    if (dh->params.q != NULL) {
        BIGNUM *q = BN_dup(dh->params.p);

        /* Check q = p * 2 + 1 we already know q is odd, so just shift right */
        if (q == NULL || !BN_rshift1(q, q) || (BN_cmp(dh->params.q, q) != 0))
            nid = NID_undef;
        BN_free(q);
    }
    return nid;
}
