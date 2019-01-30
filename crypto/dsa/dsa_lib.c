/*
 * Copyright 1995-2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"
#include <openssl/bn.h>
#include "dsa_locl.h"
#include <openssl/asn1.h>
#include <openssl/engine.h>
#include <openssl/dh.h>

DSA *DSA_new(void)
{
    return DSA_new_method(NULL);
}

int DSA_set_method(DSA *dsa, const DSA_METHOD *meth)
{
    /*
     * NB: The caller is specifically setting a method, so it's not up to us
     * to deal with which ENGINE it comes from.
     */
    const DSA_METHOD *mtmp;
    mtmp = dsa->meth;
    if (mtmp->finish)
        mtmp->finish(dsa);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(dsa->engine);
    dsa->engine = NULL;
#endif
    dsa->meth = meth;
    if (meth->init)
        meth->init(dsa);
    return 1;
}

const DSA_METHOD *DSA_get_method(DSA *d)
{
    return d->meth;
}

DSA *DSA_new_method(ENGINE *engine)
{
    DSA *ret = OPENSSL_zalloc(sizeof(*ret));

    if (ret == NULL) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    ret->references = 1;
    ret->lock = CRYPTO_THREAD_lock_new();
    if (ret->lock == NULL) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(ret);
        return NULL;
    }

    ret->meth = DSA_get_default_method();
#ifndef OPENSSL_NO_ENGINE
    ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW; /* early default init */
    if (engine) {
        if (!ENGINE_init(engine)) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
        ret->engine = engine;
    } else
        ret->engine = ENGINE_get_default_DSA();
    if (ret->engine) {
        ret->meth = ENGINE_get_DSA(ret->engine);
        if (ret->meth == NULL) {
            DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_ENGINE_LIB);
            goto err;
        }
    }
#endif

    ret->flags = ret->meth->flags & ~DSA_FLAG_NON_FIPS_ALLOW;

    if (!CRYPTO_new_ex_data(CRYPTO_EX_INDEX_DSA, ret, &ret->ex_data))
        goto err;

    if ((ret->meth->init != NULL) && !ret->meth->init(ret)) {
        DSAerr(DSA_F_DSA_NEW_METHOD, ERR_R_INIT_FAIL);
        goto err;
    }

    return ret;

 err:
    DSA_free(ret);
    return NULL;
}

void DSA_free(DSA *r)
{
    int i;

    if (r == NULL)
        return;

    CRYPTO_DOWN_REF(&r->references, &i, r->lock);
    REF_PRINT_COUNT("DSA", r);
    if (i > 0)
        return;
    REF_ASSERT_ISNT(i < 0);

    if (r->meth != NULL && r->meth->finish != NULL)
        r->meth->finish(r);
#ifndef OPENSSL_NO_ENGINE
    ENGINE_finish(r->engine);
#endif

    CRYPTO_free_ex_data(CRYPTO_EX_INDEX_DSA, r, &r->ex_data);

    CRYPTO_THREAD_lock_free(r->lock);

    FFC_PARAMS_cleanup(&r->params);
    BN_clear_free(r->pub_key);
    BN_clear_free(r->priv_key);
    OPENSSL_free(r);
}

int DSA_up_ref(DSA *r)
{
    int i;

    if (CRYPTO_UP_REF(&r->references, &i, r->lock) <= 0)
        return 0;

    REF_PRINT_COUNT("DSA", r);
    REF_ASSERT_ISNT(i < 2);
    return ((i > 1) ? 1 : 0);
}

int DSA_size(const DSA *r)
{
    int ret, i;
    ASN1_INTEGER bs;
    unsigned char buf[4];       /* 4 bytes looks really small. However,
                                 * i2d_ASN1_INTEGER() will not look beyond
                                 * the first byte, as long as the second
                                 * parameter is NULL. */

    i = BN_num_bits(DSA_get0_q(r));
    bs.length = (i + 7) / 8;
    bs.data = buf;
    bs.type = V_ASN1_INTEGER;
    /* If the top bit is set the asn1 encoding is 1 larger. */
    buf[0] = 0xff;

    i = i2d_ASN1_INTEGER(&bs, NULL);
    i += i;                     /* r and s */
    ret = ASN1_object_size(1, i, V_ASN1_SEQUENCE);
    return ret;
}

int DSA_set_ex_data(DSA *d, int idx, void *arg)
{
    return CRYPTO_set_ex_data(&d->ex_data, idx, arg);
}

void *DSA_get_ex_data(DSA *d, int idx)
{
    return CRYPTO_get_ex_data(&d->ex_data, idx);
}

int DSA_security_bits(const DSA *d)
{
    const BIGNUM *p = DSA_get0_p(d);
    const BIGNUM *q = DSA_get0_q(d);

    if (p != NULL  && q != NULL)
        return BN_security_bits(BN_num_bits(p), BN_num_bits(q));
    return -1;
}

#ifndef OPENSSL_NO_DH
extern FFC_PARAMS *dh_get0_params(DH *dh);

/* This is really a FFC copy */
DH *DSA_dup_DH(const DSA *r)
{
    /*
     * DSA has p, q, g, optional pub_key, optional priv_key.
     * DH has p, optional length, g, optional pub_key,
     * optional priv_key, optional q.
     */

    DH *ret = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if (r == NULL)
        goto err;
    ret = DH_new();
    if (ret == NULL)
        goto err;

    if (!FFC_PARAMS_copy(dh_get0_params(ret), &r->params))
        goto err;

    if (r->pub_key != NULL) {
        pub_key = BN_dup(r->pub_key);
        if (pub_key == NULL)
            goto err;
        if (r->priv_key != NULL) {
            priv_key = BN_dup(r->priv_key);
            if (priv_key == NULL)
                goto err;
        }
        if (!DH_set0_key(ret, pub_key, priv_key))
            goto err;
    } else if (r->priv_key != NULL) {
        /* Shouldn't happen */
        goto err;
    }

    return ret;

 err:
    BN_free(pub_key);
    BN_free(priv_key);
    DH_free(ret);
    return NULL;
}
#endif


void DSA_get0_pqg(const DSA *d,
                  const BIGNUM **p, const BIGNUM **q, const BIGNUM **g)
{
    FFC_PARAMS_get0_pqg(&d->params, p, q, g);
}

int DSA_set0_pqg(DSA *d, BIGNUM *p, BIGNUM *q, BIGNUM *g)
{
    if (DSA_get0_q(d) == NULL && q == NULL)
        return 0;
    FFC_PARAMS_set0_pqg(&d->params, p, q, g);
    return 1;
}

void DSA_get0_key(const DSA *d,
                  const BIGNUM **pub_key, const BIGNUM **priv_key)
{
    if (pub_key != NULL)
        *pub_key = d->pub_key;
    if (priv_key != NULL)
        *priv_key = d->priv_key;
}

int DSA_set0_key(DSA *d, BIGNUM *pub_key, BIGNUM *priv_key)
{
    /* If the field pub_key in d is NULL, the corresponding input
     * parameters MUST be non-NULL.  The priv_key field may
     * be left NULL.
     */
    if (d->pub_key == NULL && pub_key == NULL)
        return 0;

    if (pub_key != NULL) {
        BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        BN_free(d->priv_key);
        d->priv_key = priv_key;
    }

    return 1;
}

void DSA_get0_validate_params(const DSA *dsa, unsigned char **seed,
                              size_t *seedlen, int *counter, int *gindex,
                              unsigned long *hret)
{
    if (gindex != NULL)
        *gindex = FFC_PARAMS_get0_gindex(&dsa->params);
    if (hret != NULL)
        *hret = FFC_PARAMS_get0_h(&dsa->params);
    FFC_PARAMS_get_validate_params(&dsa->params, seed, seedlen, counter);
}

int DSA_set0_validate_params(DSA *dsa, const unsigned char *seed,
                             size_t seedlen, int counter, int gindex)
{
    FFC_PARAMS_set0_gindex(&dsa->params, gindex);
    return FFC_PARAMS_set_validate_params(&dsa->params, seed, seedlen, counter);
}

const BIGNUM *DSA_get0_p(const DSA *d)
{
    return FFC_PARAMS_get0_p(&d->params);
}

const BIGNUM *DSA_get0_q(const DSA *d)
{
    return FFC_PARAMS_get0_q(&d->params);
}

const BIGNUM *DSA_get0_g(const DSA *d)
{
    return FFC_PARAMS_get0_g(&d->params);
}

const BIGNUM *DSA_get0_pub_key(const DSA *d)
{
    return d->pub_key;
}

const BIGNUM *DSA_get0_priv_key(const DSA *d)
{
    return d->priv_key;
}

void DSA_clear_flags(DSA *d, int flags)
{
    d->flags &= ~flags;
}

int DSA_test_flags(const DSA *d, int flags)
{
    return d->flags & flags;
}

void DSA_set_flags(DSA *d, int flags)
{
    d->flags |= flags;
}

ENGINE *DSA_get0_engine(DSA *d)
{
    return d->engine;
}

int DSA_bits(const DSA *dsa)
{
    return BN_num_bits(DSA_get0_p(dsa));
}
