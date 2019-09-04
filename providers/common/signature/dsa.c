/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include "internal/provider_algs.h"

static OSSL_OP_signature_newctx_fn dsa_newctx;
static OSSL_OP_signature_sign_init_fn dsa_signature_init;
static OSSL_OP_signature_verify_init_fn dsa_signature_init;
static OSSL_OP_signature_sign_fn dsa_sign;
static OSSL_OP_signature_freectx_fn dsa_freectx;
static OSSL_OP_signature_dupctx_fn dsa_dupctx;
static OSSL_OP_signature_get_ctx_params_fn dsa_get_ctx_params;
static OSSL_OP_signature_gettable_ctx_params_fn dsa_gettable_ctx_params;
static OSSL_OP_signature_set_ctx_params_fn dsa_set_ctx_params;
static OSSL_OP_signature_settable_ctx_params_fn dsa_settable_ctx_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DSA structures, so
 * we use that here too.
 */

typedef struct {
    DSA *dsa;
    size_t mdsize;
    /* Should be big enough */
    char mdname[80];
} PROV_DSA_CTX;

static void *dsa_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(PROV_DSA_CTX));
}

static int dsa_signature_init(void *vpdsactx, void *vdsa)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx == NULL || vdsa == NULL || !DSA_up_ref(vdsa))
        return 0;
    DSA_free(pdsactx->dsa);
    pdsactx->dsa = vdsa;
    return 1;
}

static int dsa_sign(void *vpdsactx, unsigned char *sig, size_t *siglen,
                    size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    int ret;
    unsigned int sltmp;
    size_t dsasize = DSA_size(pdsactx->dsa);

    if (sig == NULL) {
        *siglen = dsasize;
        return 1;
    }

    if (sigsize < (size_t)dsasize)
        return 0;

    if (pdsactx->mdsize != 0 && tbslen != pdsactx->mdsize)
        return 0;

    ret = DSA_sign(0, tbs, tbslen, sig, &sltmp, pdsactx->dsa);

    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int dsa_verify(void *vpdsactx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx->mdsize != 0 && tbslen != pdsactx->mdsize)
        return 0;

    return DSA_verify(0, tbs, tbslen, sig, siglen, pdsactx->dsa);
}


static void dsa_freectx(void *vpdsactx)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    DSA_free(pdsactx->dsa);

    OPENSSL_free(pdsactx);
}

static void *dsa_dupctx(void *vpdsactx)
{
    PROV_DSA_CTX *srcctx = (PROV_DSA_CTX *)vpdsactx;
    PROV_DSA_CTX *dstctx;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    if (dstctx->dsa != NULL && !DSA_up_ref(dstctx->dsa)) {
        OPENSSL_free(dstctx);
        return NULL;
    }

    return dstctx;
}

static int dsa_get_ctx_params(void *vpdsactx, OSSL_PARAM *params)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    OSSL_PARAM *p;

    if (pdsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, pdsactx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdsactx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsa_gettable_ctx_params(void)
{
    return known_gettable_ctx_params;
}

static int dsa_set_ctx_params(void *vpdsactx, const OSSL_PARAM params[])
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    const OSSL_PARAM *p;
    char *mdname;

    if (pdsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &pdsactx->mdsize))
        return 0;

    /*
     * We never actually use the mdname, but we do support getting it later.
     * This can be useful for applications that want to know the MD that they
     * previously set.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    mdname = pdsactx->mdname;
    if (p != NULL
            && !OSSL_PARAM_get_utf8_string(p, &mdname, sizeof(pdsactx->mdname)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsa_settable_ctx_params(void)
{
    return known_settable_ctx_params;
}

const OSSL_DISPATCH dsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dsa_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dsa_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dsa_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_settable_ctx_params },
    { 0, NULL }
};
