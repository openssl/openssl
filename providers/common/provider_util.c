/*
 * Copyright 2019-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#ifndef FIPS_MODULE
# include "crypto/evp.h"
#endif
#include "prov/providercommon.h"
#include "prov/provider_util.h"

void ossl_prov_cipher_reset(PROV_CIPHER *pc)
{
    EVP_CIPHER_free(pc->alloc_cipher);
    pc->alloc_cipher = NULL;
    pc->cipher = NULL;
}

int ossl_prov_cipher_copy(PROV_CIPHER *dst, const PROV_CIPHER *src)
{
    if (src->alloc_cipher != NULL && !EVP_CIPHER_up_ref(src->alloc_cipher))
        return 0;
    dst->cipher = src->cipher;
    dst->alloc_cipher = src->alloc_cipher;
    return 1;
}

static int set_propq(const OSSL_PARAM *propq, const char **propquery)
{
    *propquery = NULL;
    if (propq != NULL) {
        if (propq->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        *propquery = propq->data;
    }
    return 1;
}

int ossl_prov_cipher_load(PROV_CIPHER *pc, const OSSL_PARAM *cipher,
                          const OSSL_PARAM *propq, OSSL_LIB_CTX *ctx)
{
    const char *propquery;

    if (!set_propq(propq, &propquery))
        return 0;

    if (cipher == NULL)
        return 1;
    if (cipher->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;

    EVP_CIPHER_free(pc->alloc_cipher);
    ERR_set_mark();
    pc->cipher = pc->alloc_cipher = EVP_CIPHER_fetch(ctx, cipher->data,
                                                     propquery);
#ifndef FIPS_MODULE /* Inside the FIPS module, we don't support legacy ciphers */
    if (pc->cipher == NULL) {
        const EVP_CIPHER *evp_cipher;

        evp_cipher = EVP_get_cipherbyname(cipher->data);
        /* Do not use global EVP_CIPHERs */
        if (evp_cipher != NULL && evp_cipher->origin != EVP_ORIG_GLOBAL)
            pc->cipher = evp_cipher;
    }
#endif
    if (pc->cipher != NULL)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return pc->cipher != NULL;
}
                            
int ossl_prov_cipher_load_from_params(PROV_CIPHER *pc,
                                      const OSSL_PARAM params[],
                                      OSSL_LIB_CTX *ctx)
{
     return ossl_prov_cipher_load(pc,
                                  OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER),
                                  OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
                                  ctx);
}

const EVP_CIPHER *ossl_prov_cipher_cipher(const PROV_CIPHER *pc)
{
    return pc->cipher;
}

void ossl_prov_digest_reset(PROV_DIGEST *pd)
{
    EVP_MD_free(pd->alloc_md);
    pd->alloc_md = NULL;
    pd->md = NULL;
}

int ossl_prov_digest_copy(PROV_DIGEST *dst, const PROV_DIGEST *src)
{
    if (src->alloc_md != NULL && !EVP_MD_up_ref(src->alloc_md))
        return 0;
    dst->md = src->md;
    dst->alloc_md = src->alloc_md;
    return 1;
}

const EVP_MD *ossl_prov_digest_fetch(PROV_DIGEST *pd, OSSL_LIB_CTX *libctx,
                                     const char *mdname, const char *propquery)
{
    EVP_MD_free(pd->alloc_md);
    pd->md = pd->alloc_md = EVP_MD_fetch(libctx, mdname, propquery);

    return pd->md;
}

int ossl_prov_digest_load(PROV_DIGEST *pd, const OSSL_PARAM *digest,
                          const OSSL_PARAM *propq, OSSL_LIB_CTX *ctx)
{
    const char *propquery;

    if (!set_propq(propq, &propquery))
        return 0;

    if (digest == NULL)
        return 1;
    if (digest->data_type != OSSL_PARAM_UTF8_STRING)
        return 0;

    ERR_set_mark();
    ossl_prov_digest_fetch(pd, ctx, digest->data, propquery);
#ifndef FIPS_MODULE /* Inside the FIPS module, we don't support legacy digests */
    if (pd->md == NULL) {
        const EVP_MD *md;

        md = EVP_get_digestbyname(digest->data);
        /* Do not use global EVP_MDs */
        if (md != NULL && md->origin != EVP_ORIG_GLOBAL)
            pd->md = md;
    }
#endif
    if (pd->md != NULL)
        ERR_pop_to_mark();
    else
        ERR_clear_last_mark();
    return pd->md != NULL;
}

int ossl_prov_digest_load_from_params(PROV_DIGEST *pd,
                                      const OSSL_PARAM params[],
                                      OSSL_LIB_CTX *ctx)
{
    return ossl_prov_digest_load(pd,
                                 OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST),
                                 OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
                                 ctx);
}

void ossl_prov_digest_set_md(PROV_DIGEST *pd, EVP_MD *md)
{
    ossl_prov_digest_reset(pd);
    pd->md = pd->alloc_md = md;
}

const EVP_MD *ossl_prov_digest_md(const PROV_DIGEST *pd)
{
    return pd->md;
}

int ossl_prov_set_macctx(EVP_MAC_CTX *macctx,
                         const char *ciphername,
                         const char *mdname,
                         const char *properties)
{
    OSSL_PARAM mac_params[5], *mp = mac_params;

    if (mdname != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST,
                                                 (char *)mdname, 0);
    if (ciphername != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                                 (char *)ciphername, 0);
    if (properties != NULL)
        *mp++ = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_PROPERTIES,
                                                 (char *)properties, 0);

    *mp = OSSL_PARAM_construct_end();

    return EVP_MAC_CTX_set_params(macctx, mac_params);

}

int ossl_prov_macctx_load(EVP_MAC_CTX **macctx,
                          const OSSL_PARAM *pmac, const OSSL_PARAM *pcipher,
                          const OSSL_PARAM *pdigest, const OSSL_PARAM *propq,
                          const char *macname, const char *ciphername,
                          const char *mdname, OSSL_LIB_CTX *libctx)
{
    const char *properties = NULL;

    if (macname == NULL && pmac != NULL)
        if (!OSSL_PARAM_get_utf8_string_ptr(pmac, &macname))
            return 0;
    if (propq != NULL && !OSSL_PARAM_get_utf8_string_ptr(propq, &properties))
        return 0;

    /* If we got a new mac name, we make a new EVP_MAC_CTX */
    if (macname != NULL) {
        EVP_MAC *mac = EVP_MAC_fetch(libctx, macname, properties);

        EVP_MAC_CTX_free(*macctx);
        *macctx = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
        /* The context holds on to the MAC */
        EVP_MAC_free(mac);
        if (*macctx == NULL)
            return 0;
    }

    /*
     * If there is no MAC yet (and therefore, no MAC context), we ignore
     * all other parameters.
     */
    if (*macctx == NULL)
        return 1;

    if (ciphername == NULL && pcipher != NULL)
        if (!OSSL_PARAM_get_utf8_string_ptr(pcipher, &ciphername))
            return 0;
    if (mdname == NULL && pdigest != NULL)
        if (!OSSL_PARAM_get_utf8_string_ptr(pdigest, &mdname))
            return 0;

    if (ossl_prov_set_macctx(*macctx, ciphername, mdname, properties))
        return 1;

    EVP_MAC_CTX_free(*macctx);
    *macctx = NULL;
    return 0;
}

int ossl_prov_macctx_load_from_params(EVP_MAC_CTX **macctx,
                                      const OSSL_PARAM params[],
                                      const char *macname,
                                      const char *ciphername,
                                      const char *mdname,
                                      OSSL_LIB_CTX *libctx)
{
    return ossl_prov_macctx_load
            (macctx, OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_MAC),
             OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_CIPHER),
             OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST),
             OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_PROPERTIES),
             macname, ciphername, mdname, libctx);
}

void ossl_prov_cache_exported_algorithms(const OSSL_ALGORITHM_CAPABLE *in,
                                         OSSL_ALGORITHM *out)
{
    int i, j;

    if (out[0].algorithm_names == NULL) {
        for (i = j = 0; in[i].alg.algorithm_names != NULL; ++i) {
            if (in[i].capable == NULL || in[i].capable())
                out[j++] = in[i].alg;
        }
        out[j++] = in[i].alg;
    }
}

/* Duplicate a lump of memory safely */
int ossl_prov_memdup(const void *src, size_t src_len,
                     unsigned char **dest, size_t *dest_len)
{
    if (src != NULL) {
        if ((*dest = OPENSSL_memdup(src, src_len)) == NULL)
            return 0;
        *dest_len = src_len;
    } else {
        *dest = NULL;
        *dest_len = 0;
    }
    return 1;
}
