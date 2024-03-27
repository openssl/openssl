/*
 * Copyright 1995-2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <stdio.h>
#include <time.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/self_test.h>
#include "prov/providercommon.h"
#include "crypto/dsa.h"
#include "dsa_local.h"

/* DSA Keygen is not allowed in FIPS 140-3 */
#ifndef FIPS_MODULE
# define MIN_STRENGTH 80

static int dsa_keygen(DSA *dsa)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if ((ctx = BN_CTX_new_ex(dsa->libctx)) == NULL)
        goto err;

    if (dsa->priv_key == NULL) {
        if ((priv_key = BN_secure_new()) == NULL)
            goto err;
    } else {
        priv_key = dsa->priv_key;
    }

    /* Do a partial check for invalid p, q, g */
    if (!ossl_ffc_params_simple_validate(dsa->libctx, &dsa->params,
                                         FFC_PARAM_TYPE_DSA, NULL))
        goto err;

    /*
     * For FFC FIPS 186-4 keygen
     * security strength s = 112,
     * Max Private key size N = len(q)
     */
    if (!ossl_ffc_generate_private_key(ctx, &dsa->params,
                                       BN_num_bits(dsa->params.q),
                                       MIN_STRENGTH, priv_key))
        goto err;

    if (dsa->pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL)
            goto err;
    } else {
        pub_key = dsa->pub_key;
    }

    if (!ossl_dsa_generate_public_key(ctx, dsa, priv_key, pub_key))
        goto err;

    dsa->priv_key = priv_key;
    dsa->pub_key = pub_key;

    ok = 1;
    dsa->dirty_cnt++;

 err:
    if (pub_key != dsa->pub_key)
        BN_free(pub_key);
    if (priv_key != dsa->priv_key)
        BN_free(priv_key);
    BN_CTX_free(ctx);

    return ok;
}

int DSA_generate_key(DSA *dsa)
{
    if (dsa->meth->dsa_keygen != NULL)
        return dsa->meth->dsa_keygen(dsa);
    return dsa_keygen(dsa);
}
#endif /* FIPS_MODULE */

int ossl_dsa_generate_public_key(BN_CTX *ctx, const DSA *dsa,
                                 const BIGNUM *priv_key, BIGNUM *pub_key)
{
    int ret = 0;
    BIGNUM *prk = BN_new();

    if (prk == NULL)
        return 0;
    BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);

    /* pub_key = g ^ priv_key mod p */
    if (!BN_mod_exp(pub_key, dsa->params.g, prk, dsa->params.p, ctx))
        goto err;
    ret = 1;
err:
    BN_clear_free(prk);
    return ret;
}

