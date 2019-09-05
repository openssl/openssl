/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include "internal/provider_util.h"

void ossl_prov_cipher_reset(PROV_CIPHER *pc)
{
    EVP_CIPHER_free(pc->alloc_cipher);
    pc->alloc_cipher = NULL;
    pc->cipher = NULL;
    pc->engine = NULL;
}

int ossl_prov_cipher_copy(PROV_CIPHER *dst, const PROV_CIPHER *src)
{
    if (src->alloc_cipher != NULL && !EVP_CIPHER_up_ref(src->alloc_cipher))
        return 0;
    dst->engine = src->engine;
    dst->cipher = src->cipher;
    dst->alloc_cipher = src->alloc_cipher;
    return 1;
}

static int load_common(const OSSL_PARAM params[], const char **propquery,
                       ENGINE **engine)
{
    const OSSL_PARAM *p;

    *propquery = NULL;
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        *propquery = p->data;
    }

    *engine = NULL;
    /* TODO legacy stuff, to be removed */
#ifndef FIPS_MODE /* Inside the FIPS module, we don't support legacy ciphers */
    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_ENGINE);
    if (p != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        ENGINE_finish(*engine);
        *engine = ENGINE_by_id(p->data);
        if (*engine == NULL)
            return 0;
    }
#endif
    return 1;
}

int ossl_prov_cipher_load_from_params(PROV_CIPHER *pc,
                                      const OSSL_PARAM params[],
                                      OPENSSL_CTX *ctx)
{
    const OSSL_PARAM *p;
    const char *propquery;

    if (!load_common(params, &propquery, &pc->engine))
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER);
    if (p == NULL)
        return 1;
    if (p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;

    EVP_CIPHER_free(pc->alloc_cipher);
    pc->cipher = pc->alloc_cipher = EVP_CIPHER_fetch(ctx, p->data, propquery);
    /* TODO legacy stuff, to be removed */
#ifndef FIPS_MODE /* Inside the FIPS module, we don't support legacy ciphers */
    if (pc->cipher == NULL)
        pc->cipher = EVP_get_cipherbyname(p->data);
#endif
    return pc->cipher != NULL;
}

const EVP_CIPHER *ossl_prov_cipher_cipher(const PROV_CIPHER *pc)
{
    return pc->cipher;
}

ENGINE *ossl_prov_cipher_engine(const PROV_CIPHER *pc)
{
    return pc->engine;
}

void ossl_prov_digest_reset(PROV_DIGEST *pd)
{
    EVP_MD_free(pd->alloc_md);
    pd->alloc_md = NULL;
    pd->md = NULL;
    pd->engine = NULL;
}

int ossl_prov_digest_copy(PROV_DIGEST *dst, const PROV_DIGEST *src)
{
    if (src->alloc_md != NULL && !EVP_MD_up_ref(src->alloc_md))
        return 0;
    dst->engine = src->engine;
    dst->md = src->md;
    dst->alloc_md = src->alloc_md;
    return 1;
}

int ossl_prov_digest_load_from_params(PROV_DIGEST *pd,
                                      const OSSL_PARAM params[],
                                      OPENSSL_CTX *ctx)
{
    const OSSL_PARAM *p;
    const char *propquery;

    if (!load_common(params, &propquery, &pd->engine))
        return 0;


    p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
    if (p == NULL)
        return 1;
    if (p->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;

    EVP_MD_free(pd->alloc_md);
    pd->md = pd->alloc_md = EVP_MD_fetch(ctx, p->data, propquery);
    /* TODO legacy stuff, to be removed */
#ifndef FIPS_MODE /* Inside the FIPS module, we don't support legacy digests */
    if (pd->md == NULL)
        pd->md = EVP_get_digestbyname(p->data);
#endif
    return pd->md != NULL;
}

const EVP_MD *ossl_prov_digest_md(const PROV_DIGEST *pd)
{
    return pd->md;
}

ENGINE *ossl_prov_digest_engine(const PROV_DIGEST *pd)
{
    return pd->engine;
}

