/*
 * Copyright 2017-2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright 2017 BaishanCloud. All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/bn.h>
#include <openssl/err.h>
#include "crypto/bn.h"
#include "crypto/fn.h"
#include "crypto/fn_intern.h"
#include "rsa_local.h"

void ossl_rsa_multip_info_free_ex(RSA_PRIME_INFO *pinfo)
{
    /* free pp and pinfo only */
    BN_clear_free(pinfo->pp);
    OPENSSL_free(pinfo);
}

void ossl_rsa_multip_info_free(RSA_PRIME_INFO *pinfo)
{
    /* free an RSA_PRIME_INFO structure */
    BN_clear_free(pinfo->r);
    BN_clear_free(pinfo->d);
    BN_clear_free(pinfo->t);
    ossl_rsa_multip_info_free_ex(pinfo);
}

RSA_PRIME_INFO *ossl_rsa_multip_info_new(void)
{
    RSA_PRIME_INFO *pinfo;

    /* create an RSA_PRIME_INFO structure */
    if ((pinfo = OPENSSL_zalloc(sizeof(RSA_PRIME_INFO))) == NULL)
        return NULL;
    if ((pinfo->r = BN_secure_new()) == NULL)
        goto err;
    if ((pinfo->d = BN_secure_new()) == NULL)
        goto err;
    if ((pinfo->t = BN_secure_new()) == NULL)
        goto err;
    if ((pinfo->pp = BN_secure_new()) == NULL)
        goto err;

    return pinfo;

err:
    BN_free(pinfo->r);
    BN_free(pinfo->d);
    BN_free(pinfo->t);
    BN_free(pinfo->pp);
    OPENSSL_free(pinfo);
    return NULL;
}

/* Refill products of primes */
int ossl_rsa_multip_calc_product(RSA *rsa)
{
    RSA_PRIME_INFO *pinfo;
    BIGNUM *p1 = NULL, *p2 = NULL;
    OSSL_FN_CTX *fn_ctx = NULL;
    OSSL_FN *fn_pp = NULL;
    const OSSL_FN *fn_p1, *fn_p2;
    size_t fn_size, ppl;
    int i, rv = 0, ex_primes, pp_bits;

    if ((ex_primes = sk_RSA_PRIME_INFO_num(rsa->prime_infos)) <= 0) {
        /* invalid */
        goto err;
    }

    /* calculate pinfo->pp = p * q for first 'extra' prime */
    p1 = rsa->p;
    p2 = rsa->q;

    for (i = 0; i < ex_primes; i++) {
        pinfo = sk_RSA_PRIME_INFO_value(rsa->prime_infos, i);
        if (pinfo->pp == NULL) {
            pinfo->pp = BN_secure_new();
            if (pinfo->pp == NULL)
                goto err;
        }

        fn_p1 = bn_get_ossl_fn(p1);
        fn_p2 = bn_get_ossl_fn(p2);
        if (fn_p1 == NULL || fn_p2 == NULL)
            goto err;
        ppl = ossl_fn_get_dsize((OSSL_FN *)fn_p1)
            + ossl_fn_get_dsize((OSSL_FN *)fn_p2);

        if ((fn_pp = bn_acquire_ossl_fn(pinfo->pp, (int)ppl)) == NULL)
            goto err;
        fn_size = OSSL_FN_mul_ctx_size(fn_pp, fn_p1, fn_p2);
        if (fn_size == 0)
            goto err;
        fn_ctx = OSSL_FN_CTX_secure_new_size(NULL, fn_size);
        if (fn_ctx == NULL)
            goto err;
        if (!OSSL_FN_mul(fn_pp, fn_p1, fn_p2, fn_ctx)) {
            bn_release(pinfo->pp, (int)ppl);
            OSSL_FN_CTX_free(fn_ctx);
            fn_ctx = NULL;
            goto err;
        }
        pp_bits = (int)OSSL_FN_num_bits(fn_pp);
        bn_release(pinfo->pp,
            pp_bits > 0 ? (pp_bits + BN_BITS2 - 1) / BN_BITS2 : 1);
        fn_pp = NULL;
        OSSL_FN_CTX_free(fn_ctx);
        fn_ctx = NULL;

        /* save previous one */
        p1 = pinfo->pp;
        p2 = pinfo->r;
    }

    rv = 1;
err:
    OSSL_FN_CTX_free(fn_ctx);
    return rv;
}

int ossl_rsa_multip_cap(int bits)
{
    int cap = RSA_MAX_PRIME_NUM;

    if (bits < 1024)
        cap = 2;
    else if (bits < 4096)
        cap = 3;
    else if (bits < 8192)
        cap = 4;

    if (cap > RSA_MAX_PRIME_NUM)
        cap = RSA_MAX_PRIME_NUM;

    return cap;
}
