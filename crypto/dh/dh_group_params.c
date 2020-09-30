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
#include "e_os.h" /* strcasecmp */

#define FFDHE(sz) {                                                            \
    SN_ffdhe##sz, NID_ffdhe##sz,                                               \
    sz,                                                                        \
    &_bignum_ffdhe##sz##_p, &_bignum_ffdhe##sz##_q, &_bignum_const_2           \
}

#define MODP(sz)  {                                                            \
    SN_modp_##sz, NID_modp_##sz,                                               \
    sz,                                                                        \
    &_bignum_modp_##sz##_p, &_bignum_modp_##sz##_q,  &_bignum_const_2          \
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
#ifndef FIPS_MODULE
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
#ifndef FIPS_MODULE
    RFC5114("dh_1024_160", 1, 1024, 1024_160),
    RFC5114("dh_2048_224", 2, 2048, 2048_224),
    RFC5114("dh_2048_256", 3, 2048, 2048_256),
#endif
};

int ossl_ffc_named_group_to_uid(const char *name)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dh_named_groups); ++i) {
        if (strcasecmp(dh_named_groups[i].name, name) == 0)
            return dh_named_groups[i].uid;
    }
    return NID_undef;
}

const char *ossl_ffc_named_group_from_uid(int uid)
{
    size_t i;

    for (i = 0; i < OSSL_NELEM(dh_named_groups); ++i) {
        if (dh_named_groups[i].uid == uid)
            return dh_named_groups[i].name;
    }
    return NULL;
}

static DH *dh_param_init(OPENSSL_CTX *libctx, int uid, const BIGNUM *p,
                         const BIGNUM *q, const BIGNUM *g)
{
    DH *dh = dh_new_ex(libctx);

    if (dh == NULL)
        return NULL;

    dh->params.nid = uid;
    dh->params.p = (BIGNUM *)p;
    dh->params.q = (BIGNUM *)q;
    dh->params.g = (BIGNUM *)g;
    dh->length = BN_num_bits(q);
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
            return dh_param_init(libctx, dh_named_groups[i].uid,
                                 dh_named_groups[i].p,
                                 dh_named_groups[i].q,
                                 dh_named_groups[i].g);
        }
    }
    DHerr(0, DH_R_INVALID_PARAMETER_NID);
    return NULL;
}

DH *dh_new_by_nid_ex(OPENSSL_CTX *libctx, int nid)
{
    const char *name = ossl_ffc_named_group_from_uid(nid);

    return dh_new_by_group_name(libctx, name);
}

DH *DH_new_by_nid(int nid)
{
    return dh_new_by_nid_ex(NULL, nid);
}

int ossl_ffc_set_group_pqg(FFC_PARAMS *ffc, const char *group_name)
{
    int i;
    BIGNUM *q = NULL;

    if (ffc == NULL)
        return 0;

    for (i = 0; i < (int)OSSL_NELEM(dh_named_groups); ++i) {
        if (strcasecmp(dh_named_groups[i].name, group_name) == 0) {
            ossl_ffc_params_set0_pqg(ffc,
                                     (BIGNUM *)dh_named_groups[i].p,
                                     (BIGNUM *)dh_named_groups[i].q,
                                     (BIGNUM *)dh_named_groups[i].g);
            /* flush the cached nid, The DH layer is responsible for caching */
            ffc->nid = NID_undef;
            return 1;
        }
    }
    /* gets here on error or if the name was not found */
    BN_free(q);
    return 0;
}

void dh_cache_named_group(DH *dh)
{
    int i;

    if (dh == NULL)
        return;

    dh->params.nid = NID_undef; /* flush cached value */

    /* Exit if p or g is not set */
    if (dh->params.p == NULL
        || dh->params.g == NULL)
        return;

    for (i = 0; i < (int)OSSL_NELEM(dh_named_groups); ++i) {
        /* Keep searching until a matching p and g is found */
        if (BN_cmp(dh->params.p, dh_named_groups[i].p) == 0
            && BN_cmp(dh->params.g, dh_named_groups[i].g) == 0) {
                /* Verify q is correct if it exists */
                if (dh->params.q != NULL) {
                    if (BN_cmp(dh->params.q, dh_named_groups[i].q) != 0)
                        continue;  /* ignore if q does not match */
                } else {
                    dh->params.q = (BIGNUM *)dh_named_groups[i].q;
                }
                dh->params.nid = dh_named_groups[i].uid; /* cache the nid */
                dh->length = BN_num_bits(dh->params.q);
                dh->dirty_cnt++;
                break;
        }
    }
}

int DH_get_nid(const DH *dh)
{
    if (dh == NULL)
        return NID_undef;

    return dh->params.nid;
}
