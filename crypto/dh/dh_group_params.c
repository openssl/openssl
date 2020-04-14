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
#include "internal/ffc.h"
#include "dh_local.h"
#include <openssl/bn.h>
#include <openssl/objects.h>
#include "crypto/bn_dh.h"
#include "crypto/dh.h"
#include "crypto/security_bits.h"
#include "e_os.h" /* strcasecmp */

#define FFDHE(sz) {                                                            \
    SN_ffdhe##sz, NID_ffdhe##sz,                                               \
    sz,                                                                        \
    &_bignum_ffdhe##sz##_p, NULL, &_bignum_const_2                             \
}

#define MODP(sz)  {                                                            \
    SN_modp_##sz, NID_modp_##sz,                                               \
    sz,                                                                        \
    &_bignum_modp_##sz##_p, NULL,  &_bignum_const_2                            \
}

#define RFC5114(name, uid, sz, tag)  {                                         \
    name, uid,                                                                 \
    sz,                                                                        \
    &_bignum_dh##tag##_p, &_bignum_dh##tag##_q, &_bignum_dh##tag##_g           \
}

typedef struct dh_named_group_st {
    const char *name;
    int uid;
    int32_t nbits;
    const BIGNUM *p;
    const BIGNUM *q;
    const BIGNUM *g;
} DH_NAMED_GROUP;


static const DH_NAMED_GROUP dh_named_groups[] = {
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
    /*
     * Additional dh named groups from RFC 5114 that have a different g.
     * The uid can be any unique identifier.
     */
#ifndef FIPS_MODE
    RFC5114("dh_1024_160", 1, 1024, 1024_160),
    RFC5114("dh_2048_224", 2, 2048, 2048_224),
    RFC5114("dh_2048_256", 3, 2048, 2048_256),
#endif
};

int ffc_named_group_to_uid(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dh_named_groups); ++i) {
        if (strcasecmp(dh_named_groups[i].name, name) == 0)
            return dh_named_groups[i].uid;
    }
    return NID_undef;
}

const char *ffc_named_group_from_uid(int uid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dh_named_groups); ++i) {
        if (dh_named_groups[i].uid == uid)
            return dh_named_groups[i].name;
    }
    return NULL;
}

static DH *dh_param_init(OPENSSL_CTX *libctx, int uid, const BIGNUM *p,
                         const BIGNUM *q, const BIGNUM *g,
                         int32_t nbits)
{
    BIGNUM *qtmp = NULL;
    DH *dh = dh_new_with_libctx(libctx);

    if (dh == NULL)
        return NULL;

    if (q == NULL) {
        qtmp = BN_dup(p);
        /* Set q = (p - 1) / 2 (p is known to be odd so just shift right ) */
        if (qtmp == NULL || !BN_rshift1(qtmp, qtmp)) {
            BN_free(qtmp);
            DH_free(dh);
            return NULL;
        }
    }
    dh->params.nid = uid;
    dh->params.p = (BIGNUM *)p;
    dh->params.q = (q != NULL ? (BIGNUM *)q : qtmp);
    dh->params.g = (BIGNUM *)g;
    /* Private key length = 2 * max_target_security_strength */
    dh->length = nbits;
    dh->dirty_cnt++;
    return dh;
}

static DH *dh_new_by_group_name(OPENSSL_CTX *libctx, const char *name)
{
    int i;

    if (name == NULL)
        return NULL;

    for (i = 0; i < (int)OSSL_NELEM(dh_named_groups); ++i) {
        if (strcasecmp(dh_named_groups[i].name, name) == 0) {
            int max_target_security_strength =
                ifc_ffc_compute_security_bits(dh_named_groups[i].nbits);

            /*
             * The last parameter specified here is
             * 2 * max_target_security_strength.
             * See SP800-56Ar3 Table(s) 25 & 26.
             */
            return dh_param_init(libctx, dh_named_groups[i].uid,
                                 dh_named_groups[i].p,
                                 dh_named_groups[i].q,
                                 dh_named_groups[i].g,
                                 2 * max_target_security_strength);
        }
    }
    DHerr(0, DH_R_INVALID_PARAMETER_NID);
    return NULL;
}

DH *dh_new_by_nid_with_libctx(OPENSSL_CTX *libctx, int nid)
{
    const char *name = ffc_named_group_from_uid(nid);

    return dh_new_by_group_name(libctx, name);
}

DH *DH_new_by_nid(int nid)
{
    return dh_new_by_nid_with_libctx(NULL, nid);
}

int ffc_set_group_pqg(FFC_PARAMS *ffc, const char *group_name)
{
    int i;
    BIGNUM *q = NULL;

    if (ffc == NULL)
        return 0;

    for (i = 0; i < (int)OSSL_NELEM(dh_named_groups); ++i) {
        if (strcasecmp(dh_named_groups[i].name, group_name) == 0) {
            if (dh_named_groups[i].q != NULL) {
                /* For groups with a q */
                ffc_params_set0_pqg(ffc,
                                    (BIGNUM *)dh_named_groups[i].p,
                                    (BIGNUM *)dh_named_groups[i].q,
                                    (BIGNUM *)dh_named_groups[i].g);
            } else {
                /* For SAFE PRIME GROUPS */
                /* Set q = (p - 1) / 2 (p is known to be odd so just shift right) */
                q = BN_dup(dh_named_groups[i].p);
                if (q == NULL || !BN_rshift1(q, q))
                    break; /* exit with failure */

                ffc_params_set0_pqg(ffc,
                                    (BIGNUM *)dh_named_groups[i].p, q,
                                    (BIGNUM *)dh_named_groups[i].g);
            }
            /* flush the cached nid, The DH layer is responsible for caching */
            ffc->nid = NID_undef;
            return 1;
        }
    }
    /* gets here on error or if the name was not found */
    BN_free(q);
    return 0;
}

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

    for (i = 0; i < (int)OSSL_NELEM(dh_named_groups); ++i) {
        /* Keep searching until a matching p is found */
        if (BN_cmp(dh->params.p, dh_named_groups[i].p) != 0)
            continue;

        /* Return an error if g is not matching */
        if (BN_cmp(dh->params.g, dh_named_groups[i].g) != 0)
            break;
        if (dh_named_groups[i].q != NULL) {
            /* RFC5114 NAMED GROUPS have q defined */

            /* Verify q is correct if it exists */
            if (dh->params.q != NULL) {
                if (BN_cmp(dh->params.q, dh_named_groups[i].q) != 0)
                    break;  /* returns nid = NID_undef if q does not match */
            } else {
                dh->params.q = (BIGNUM *)dh_named_groups[i].q;
            }
        } else {
            /* For SAFE PRIME GROUPS */

            /* Set q = (p - 1) / 2 (p is known to be odd so just shift right) */
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
        }
        nid = dh->params.nid = dh_named_groups[i].uid; /* cache the nid */
        dh->length =
            2 * ifc_ffc_compute_security_bits(dh_named_groups[i].nbits);
        dh->dirty_cnt++;
        /* A matching p was found so break out of the loop */
        break;
    }
    BN_free(q);
    return nid;
}
