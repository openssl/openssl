/*
 * Copyright 1995-2016 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/dsa.h"
#include "dsa_local.h"

static int dsa_builtin_keygen(OPENSSL_CTX *libctx, DSA *dsa);

int DSA_generate_key(DSA *dsa)
{
    if (dsa->meth->dsa_keygen != NULL)
        return dsa->meth->dsa_keygen(dsa);
    return dsa_builtin_keygen(NULL, dsa);
}

int dsa_generate_key_ctx(OPENSSL_CTX *libctx, DSA *dsa)
{
#ifndef FIPS_MODE
    if (dsa->meth->dsa_keygen != NULL)
        return dsa->meth->dsa_keygen(dsa);
#endif
    return dsa_builtin_keygen(libctx, dsa);
}

static int dsa_builtin_keygen(OPENSSL_CTX *libctx, DSA *dsa)
{
    int ok = 0;
    BN_CTX *ctx = NULL;
    BIGNUM *pub_key = NULL, *priv_key = NULL;

    if ((ctx = BN_CTX_new_ex(libctx)) == NULL)
        goto err;

    if (dsa->priv_key == NULL) {
        if ((priv_key = BN_secure_new()) == NULL)
            goto err;
    } else {
        priv_key = dsa->priv_key;
    }

    if (!ffc_generate_private_key(ctx, &dsa->params, BN_num_bits(dsa->params.q),
                                  112, priv_key))
        goto err;

    if (dsa->pub_key == NULL) {
        if ((pub_key = BN_new()) == NULL)
            goto err;
    } else {
        pub_key = dsa->pub_key;
    }

    {
        BIGNUM *prk = BN_new();

        if (prk == NULL)
            goto err;
        BN_with_flags(prk, priv_key, BN_FLG_CONSTTIME);

        /* pub_key = g ^ priv_key mod p */
        if (!BN_mod_exp(pub_key, dsa->params.g, prk, dsa->params.p, ctx)) {
            BN_free(prk);
            goto err;
        }
        /* We MUST free prk before any further use of priv_key */
        BN_free(prk);
    }

    dsa->priv_key = priv_key;
    dsa->pub_key = pub_key;
    dsa->dirty_cnt++;
    ok = 1;

 err:
    if (pub_key != dsa->pub_key)
        BN_free(pub_key);
    if (priv_key != dsa->priv_key)
        BN_free(priv_key);
    BN_CTX_free(ctx);
    return ok;
}
