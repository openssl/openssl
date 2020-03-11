/*
 * Copyright 2017-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/* DH parameters from RFC7919 and RFC3526 */

/*
 * DH low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include "dh_local.h"
#include <openssl/bn.h>
#include <openssl/objects.h>
#include "crypto/bn_dh.h"
#include "crypto/dh.h"
#include "crypto/security_bits.h"


#define FFDHE(sz) { NID_ffdhe##sz, sz, &_bignum_ffdhe##sz##_p }
#define MODP(sz)  { NID_modp_##sz, sz, &_bignum_modp_##sz##_p }

typedef struct safe_prime_group_st {
    int nid;
    int32_t nbits;
    const BIGNUM *p;
} SP_GROUP;

static const SP_GROUP sp_groups[] = {
    FFDHE(2048),
    FFDHE(3072),
    FFDHE(4096),
    FFDHE(6144),
    FFDHE(8192),
#ifndef FIPS_MODE
    MODP(1536),
#endif
    MODP(2048),
    MODP(3072),
    MODP(4096),
    MODP(6144),
    MODP(8192),
};

#ifndef FIPS_MODE
static DH *dh_new_by_nid_with_ctx(OPENSSL_CTX *libctx, int nid);

static DH *dh_param_init(OPENSSL_CTX *libctx, int nid, const BIGNUM *p,
                         int32_t nbits)
{
    BIGNUM *q = NULL;
    DH *dh = dh_new_with_ctx(libctx);

    if (dh == NULL)
        return NULL;

    q = BN_dup(p);
    /* Set q = (p - 1) / 2 (p is known to be odd so just shift right ) */
    if (q == NULL || !BN_rshift1(q, q)) {
        BN_free(q);
        DH_free(dh);
        return NULL;
    }
    dh->params.nid = nid;
    dh->params.p = (BIGNUM *)p;
    dh->params.q = (BIGNUM *)q;
    dh->params.g = (BIGNUM *)&_bignum_const_2;
    /* Private key length = 2 * max_target_security_strength */
    dh->length = nbits;
    dh->dirty_cnt++;
    return dh;
}

static DH *dh_new_by_nid_with_ctx(OPENSSL_CTX *libctx, int nid)
{
    int i;

    for (i = 0; i < (int)OSSL_NELEM(sp_groups); ++i) {
        if (sp_groups[i].nid == nid) {
            int max_target_security_strength =
                ifc_ffc_compute_security_bits(sp_groups[i].nbits);

            /*
             * The last parameter specified here is
             * 2 * max_target_security_strength.
             * See SP800-56Ar3 Table(s) 25 & 26.
             */
            return dh_param_init(libctx, nid, sp_groups[i].p,
                                 2 * max_target_security_strength);
        }
    }
    DHerr(0, DH_R_INVALID_PARAMETER_NID);
    return NULL;
}

DH *DH_new_by_nid(int nid)
{
    return dh_new_by_nid_with_ctx(NULL, nid);
}
#endif

int DH_get_nid(DH *dh)
{
    BIGNUM *q = NULL;
    int i, nid;

    if (dh == NULL)
        return NID_undef;

    nid = dh->params.nid;
    /* Just return if it is already cached */
    if (nid != NID_undef)
        return nid;

    if (BN_get_word(dh->params.g) != 2)
        return NID_undef;

    for (i = 0; i < (int)OSSL_NELEM(sp_groups); ++i) {
        /* If a matching p is found then we will break out of the loop */
        if (!BN_cmp(dh->params.p, sp_groups[i].p)) {
            /* Set q = (p - 1) / 2 (p is known to be odd so just shift right ) */
            q = BN_dup(dh->params.p);

            if (q == NULL || !BN_rshift1(q, q))
                break; /* returns nid = NID_undef on failure */

            /* Verify q is correct if it exists */
            if (dh->params.q != NULL) {
                if (BN_cmp(dh->params.q, q) != 0)
                    break;  /* returns nid = NID_undef if q does not match */
            } else {
                /* assign the calculated q */
                dh->params.q = q;
                q = NULL; /* set to NULL so it is not freed */
            }
            dh->params.nid = sp_groups[i].nid; /* cache the nid */
            dh->length = 2 * ifc_ffc_compute_security_bits(sp_groups[i].nbits);
            dh->dirty_cnt++;
            break;
        }
    }
    BN_free(q);
    return nid;
}
