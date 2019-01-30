/*
 * Copyright 1995-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * NB: These functions have been upgraded - the previous prototypes are in
 * dh_depr.c as wrappers to these ones.  - Geoff
 */

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include "dh_locl.h"

#ifndef FIPS_MODE
static int dh_builtin_genparams(DH *ret, int prime_len, int generator,
                                BN_GENCB *cb);
#endif /* FIPS_MODE */

int DH_generate_ffc_parameters(DH *dh, int bits, int qbits, int gindex,
                               BN_GENCB *cb)
{
    int res;
    if (qbits <= 0) {
        const EVP_MD *evpmd = bits >= 2048 ? EVP_sha256() : EVP_sha1();
        qbits = EVP_MD_size(evpmd) * 8;
    }
    FFC_PARAMS_set0_gindex(&dh->params, gindex);
    return FFC_PARAMS_FIPS186_4_generate(&dh->params, FFC_PARAM_TYPE_DH,
                                         bits, qbits, NULL, &res, cb);
}


int DH_generate_parameters_ex(DH *ret, int prime_len, int generator,
                              BN_GENCB *cb)
{
#ifdef FIPS_MODE
    /*
     * Just chose a approved safe prime group.
     * The alternative to this is to generate FIPS186-4 domain parameters i.e.
     * return DH_generate_ffc_parameters(ret, prime_len, -1, -1, cb);
     * As the FIPS186-4 generated params are for backwards compatability,
     * the safe prime group should be used as the default.
     */
    DH *dh = NULL;
    int ok = 0, nid;

    if (generator != 2)
        return 0;

    switch (prime_len) {
    case 2048:
        nid = NID_ffdhe2048;
        break;
    case 3072:
        nid = NID_ffdhe3072;
        break;
    case 4096:
        nid = NID_ffdhe4096;
        break;
    case 6144:
        nid = NID_ffdhe6144;
        break;
    case 8192:
        nid = NID_ffdhe8192;
        break;
    /* unsupported prime_len */
    default:
        return 0;
    }
    dh = DH_new_by_nid(nid);
    if (dh != NULL && FFC_PARAMS_copy(&ret->params, &dh->params))
        ok = 1;
    DH_free(dh);
    return ok;
#else
    if (ret->meth->generate_params)
        return ret->meth->generate_params(ret, prime_len, generator, cb);
    return dh_builtin_genparams(ret, prime_len, generator, cb);
#endif /* FIPS_MODE */
}

#ifndef FIPS_MODE
/*-
 * We generate DH parameters as follows
 * find a prime q which is prime_len/2 bits long.
 * p=(2*q)+1 or (p-1)/2 = q
 * For this case, g is a generator if
 * g^((p-1)/q) mod p != 1 for values of q which are the factors of p-1.
 * Since the factors of p-1 are q and 2, we just need to check
 * g^2 mod p != 1 and g^q mod p != 1.
 *
 * Having said all that,
 * there is another special case method for the generators 2, 3 and 5.
 * for 2, p mod 24 == 11
 * for 3, p mod 12 == 5  <<<<< does not work for safe primes.
 * for 5, p mod 10 == 3 or 7
 *
 * Thanks to Phil Karn for the pointers about the
 * special generators and for answering some of my questions.
 *
 * I've implemented the second simple method :-).
 * Since DH should be using a safe prime (both p and q are prime),
 * this generator function can take a very very long time to run.
 */
/*
 * Actually there is no reason to insist that 'generator' be a generator.
 * It's just as OK (and in some sense better) to use a generator of the
 * order-q subgroup.
 */
static int dh_builtin_genparams(DH *ret, int prime_len, int generator,
                                BN_GENCB *cb)
{
    BIGNUM *t1, *t2;
    int g, ok = -1;
    BN_CTX *ctx = NULL;

    ctx = BN_CTX_new();
    if (ctx == NULL)
        goto err;
    BN_CTX_start(ctx);
    t1 = BN_CTX_get(ctx);
    t2 = BN_CTX_get(ctx);
    if (t2 == NULL)
        goto err;

    /* Make sure 'ret' has the necessary elements */
    if (!ret->params.p && ((ret->params.p = BN_new()) == NULL))
        goto err;
    if (!ret->params.g && ((ret->params.g = BN_new()) == NULL))
        goto err;

    if (generator <= 1) {
        DHerr(DH_F_DH_BUILTIN_GENPARAMS, DH_R_BAD_GENERATOR);
        goto err;
    }
    if (generator == DH_GENERATOR_2) {
        if (!BN_set_word(t1, 24))
            goto err;
        if (!BN_set_word(t2, 11))
            goto err;
        g = 2;
    } else if (generator == DH_GENERATOR_5) {
        if (!BN_set_word(t1, 10))
            goto err;
        if (!BN_set_word(t2, 3))
            goto err;
        /*
         * BN_set_word(t3,7); just have to miss out on these ones :-(
         */
        g = 5;
    } else {
        /*
         * in the general case, don't worry if 'generator' is a generator or
         * not: since we are using safe primes, it will generate either an
         * order-q or an order-2q group, which both is OK
         */
        if (!BN_set_word(t1, 2))
            goto err;
        if (!BN_set_word(t2, 1))
            goto err;
        g = generator;
    }

    if (!BN_generate_prime_ex(ret->params.p, prime_len, 1, t1, t2, cb))
        goto err;
    if (!BN_GENCB_call(cb, 3, 0))
        goto err;
    if (!BN_set_word(ret->params.g, g))
        goto err;
    ok = 1;
 err:
    if (ok == -1) {
        DHerr(DH_F_DH_BUILTIN_GENPARAMS, ERR_R_BN_LIB);
        ok = 0;
    }

    if (ctx != NULL) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    return ok;
}
#endif /* FIPS_MODE */
