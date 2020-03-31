/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h> /* memcpy */
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include "crypto/rsa.h"
#include "rsa_local.h"

int rsa_acvp_test_copy_params(const OSSL_PARAM src[], OSSL_PARAM **dst)
{
    const OSSL_PARAM *s;
    OSSL_PARAM *d;
    size_t sz;

    static const OSSL_PARAM settable[] = {
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XP, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XP1, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XP2, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XQ, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XQ1, NULL, 0),
        OSSL_PARAM_BN(OSSL_PKEY_PARAM_TEST_XQ2, NULL, 0),
        OSSL_PARAM_END
    };

    /* Assume the first element is a required filed if this feature is used */
    s = OSSL_PARAM_locate_const(src, settable[0].key);
    if (s == NULL)
        return 1;

    sz = sizeof(settable);

    d = OPENSSL_zalloc(sz);
    if (d == NULL)
        return 0;
    *dst = d;
    memcpy(d, settable, sz);

    for ( ; d->key != NULL; ++d) {
        /* For each key in the dest shallow copy the equivalent src */
        s = OSSL_PARAM_locate_const(src, d->key);
        if (s != NULL)
            *d = *s;
    }
    return 1;
}

int rsa_acvp_test_set_params(RSA *r, const OSSL_PARAM params[])
{
    RSA_ACVP_TEST *t;
    const OSSL_PARAM *p;

    if (r->acvp_test != NULL) {
        rsa_acvp_test_free(r->acvp_test);
        r->acvp_test = NULL;
    }

    t = OPENSSL_zalloc(sizeof(*t));
    if (t == NULL)
        return 0;

    /* Set the input parameters */
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XP1)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xp1))
        goto err;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XP2)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xp2))
        goto err;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XP)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xp))
        goto err;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XQ1)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xq1))
        goto err;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XQ2)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xq2))
        goto err;
    if ((p = OSSL_PARAM_locate_const(params, OSSL_PKEY_PARAM_TEST_XQ)) != NULL
         && !OSSL_PARAM_get_BN(p, &t->Xq))
        goto err;

    /* Setup the output parameters */
    t->p1 = BN_new();
    t->p2 = BN_new();
    t->q1 = BN_new();
    t->q2 = BN_new();
    r->acvp_test = t;
    return 1;
err:
    rsa_acvp_test_free(t);
    return 0;
}

int rsa_acvp_test_get_params(RSA *r, OSSL_PARAM params[])
{
    RSA_ACVP_TEST *t;
    OSSL_PARAM *p;

    if (r == NULL)
        return 0;

    t = r->acvp_test;
    if (t != NULL) {
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_TEST_P1)) != NULL
             && !OSSL_PARAM_set_BN(p, t->p1))
                    return 0;
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_TEST_P2)) != NULL
             && !OSSL_PARAM_set_BN(p, t->p2))
                    return 0;
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_TEST_Q1)) != NULL
             && !OSSL_PARAM_set_BN(p, t->q1))
                    return 0;
        if ((p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_TEST_Q2)) != NULL
             && !OSSL_PARAM_set_BN(p, t->q2))
                    return 0;
    }
    return 1;
}

void rsa_acvp_test_free(RSA_ACVP_TEST *t)
{
    if (t != NULL) {
        BN_free(t->Xp1);
        BN_free(t->Xp2);
        BN_free(t->Xp);
        BN_free(t->Xq1);
        BN_free(t->Xq2);
        BN_free(t->Xq);
        BN_free(t->p1);
        BN_free(t->p2);
        BN_free(t->q1);
        BN_free(t->q2);
        OPENSSL_free(t);
    }
}

