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
#include "crypto/fsn.h"
#include "crypto/fsn_intern.h"
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
    OSSL_FSN_CTX *fsn_ctx = NULL;
    OSSL_FSN *fsn_pp = NULL;
    const OSSL_FSN *fsn_p1, *fsn_p2;
    size_t fsn_size, ppl;
    int i, rv = 0, ex_primes;

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
        if (BN_num_bits(p1) > OPENSSL_RSA_MAX_MODULUS_BITS
            || BN_num_bits(p2) > OPENSSL_RSA_MAX_MODULUS_BITS) {
            ERR_raise(ERR_LIB_RSA, RSA_R_INVALID_MULTI_PRIME_KEY);
            goto err;
        }

        fsn_p1 = bn_get_ossl_fsn(p1);
        fsn_p2 = bn_get_ossl_fsn(p2);
        if (fsn_p1 == NULL || fsn_p2 == NULL)
            goto err;
        ppl = ossl_fsn_get_dsize((OSSL_FSN *)fsn_p1)
            + ossl_fsn_get_dsize((OSSL_FSN *)fsn_p2);

        if ((fsn_pp = bn_acquire_ossl_fsn(pinfo->pp, (int)ppl)) == NULL)
            goto err;
        fsn_size = OSSL_FSN_mul_ctx_size_from_nums(fsn_pp, fsn_p1, fsn_p2);
        if (fsn_size == 0)
            goto err;
        /* TODO(FIXNUM): a secure arena is a possible future consideration */
        fsn_ctx = OSSL_FSN_CTX_new_size(NULL, fsn_size);
        if (fsn_ctx == NULL)
            goto err;
        if (!OSSL_FSN_mul(fsn_pp, fsn_p1, fsn_p2, fsn_ctx)) {
            bn_release(pinfo->pp, (int)ppl);
            OSSL_FSN_CTX_free(fsn_ctx);
            fsn_ctx = NULL;
            goto err;
        }
        /* pp = p1 * p2 fits in the sum of the operand widths */
        bn_release(pinfo->pp, (int)ppl);
        fsn_pp = NULL;
        OSSL_FSN_CTX_free(fsn_ctx);
        fsn_ctx = NULL;

        /* save previous one */
        p1 = pinfo->pp;
        p2 = pinfo->r;
    }

    rv = 1;
err:
    OSSL_FSN_CTX_free(fsn_ctx);
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
