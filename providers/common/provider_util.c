/*
 * Copyright 2019-2026 The OpenSSL Project Authors. All Rights Reserved.
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
#include "crypto/evp.h"
#endif
#include "internal/params.h"
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

static int set_propq(const OSSL_PARAM *propq, char **propquery)
{
    *propquery = NULL;
    return propq == NULL
        || (propq->data == NULL
                ? propq->data_type == OSSL_PARAM_UTF8_STRING
                : OSSL_PARAM_get_utf8_string(propq, propquery, 0));
}

int ossl_prov_cipher_load(PROV_CIPHER *pc, const OSSL_PARAM *cipher,
    const OSSL_PARAM *propq, OSSL_LIB_CTX *ctx)
{
    char *propquery = NULL, *name = NULL;
    int ret = 0;

    if (!set_propq(propq, &propquery))
        goto end;

    if (cipher == NULL) {
        ret = 1;
        goto end;
    }
    if (!OSSL_PARAM_get_utf8_string(cipher, &name, 0))
        goto end;

    EVP_CIPHER_free(pc->alloc_cipher);
    pc->cipher = pc->alloc_cipher = EVP_CIPHER_fetch(ctx, name, propquery);
    ret = pc->cipher != NULL;
end:
    OPENSSL_free(name);
    OPENSSL_free(propquery);
    return ret;
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
    char *propquery = NULL, *name = NULL;
    int ret = 0;

    if (!set_propq(propq, &propquery))
        goto end;

    if (digest == NULL) {
        ret = 1;
        goto end;
    }
    if (!OSSL_PARAM_get_utf8_string(digest, &name, 0))
        goto end;

    ossl_prov_digest_fetch(pd, ctx, name, propquery);
    ret = pd->md != NULL;
end:
    OPENSSL_free(name);
    OPENSSL_free(propquery);
    return ret;
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
    const char *properties,
    const OSSL_PARAM param[])
{
    OSSL_PARAM mac_params[5], *mp = mac_params, *mergep;
    int free_merge = 0;
    int ret;

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

    /*
     * OSSL_PARAM_merge returns NULL and sets an error if either
     * list passed to it is NULL, and we aren't guaranteed that the
     * passed in value of param is not NULL here.
     * Given that we just want the union of the two lists, even if one
     * is empty, we have to check for that case, and if param is NULL,
     * just use the mac_params list.  In turn we only free the merge
     * result if we actually did the merge
     */
    if (param == NULL) {
        mergep = mac_params;
    } else {
        free_merge = 1;
        mergep = OSSL_PARAM_merge(mac_params, param);
        if (mergep == NULL)
            return 0;
    }

    ret = EVP_MAC_CTX_set_params(macctx, mergep);

    if (free_merge == 1)
        OSSL_PARAM_free(mergep);
    return ret;
}

static int get_mac_param(const OSSL_PARAM *param, char **value)
{
    const char *data;

    return OSSL_PARAM_get_utf8_string_ptr(param, &data)
        && (data == NULL
            || ossl_param_get_utf8_string(param, value, 0));
}

int ossl_prov_macctx_load(EVP_MAC_CTX **macctx,
    const OSSL_PARAM *pmac, const OSSL_PARAM *pcipher,
    const OSSL_PARAM *pdigest, const OSSL_PARAM *propq,
    const char *macname, const char *ciphername,
    const char *mdname, OSSL_LIB_CTX *libctx)
{
    char *properties = NULL, *macbuf = NULL, *cipherbuf = NULL, *mdbuf = NULL;
    int ret = 0;

    if (macname == NULL && pmac != NULL) {
        if (!get_mac_param(pmac, &macbuf))
            goto end;
        macname = macbuf;
    }
    if (propq != NULL && !get_mac_param(propq, &properties))
        goto end;

    /* If we got a new mac name, we make a new EVP_MAC_CTX */
    if (macname != NULL) {
        EVP_MAC *mac = EVP_MAC_fetch(libctx, macname, properties);

        EVP_MAC_CTX_free(*macctx);
        *macctx = mac == NULL ? NULL : EVP_MAC_CTX_new(mac);
        /* The context holds on to the MAC */
        EVP_MAC_free(mac);
        if (*macctx == NULL)
            goto end;
    }

    /*
     * If there is no MAC yet (and therefore, no MAC context), we ignore
     * all other parameters.
     */
    if (*macctx == NULL) {
        ret = 1;
        goto end;
    }

    if (ciphername == NULL && pcipher != NULL) {
        if (!get_mac_param(pcipher, &cipherbuf))
            goto end;
        ciphername = cipherbuf;
    }
    if (mdname == NULL && pdigest != NULL) {
        if (!get_mac_param(pdigest, &mdbuf))
            goto end;
        mdname = mdbuf;
    }

    if (ossl_prov_set_macctx(*macctx, ciphername, mdname, properties, NULL)) {
        ret = 1;
        goto end;
    }

    EVP_MAC_CTX_free(*macctx);
    *macctx = NULL;
end:
    OPENSSL_free(properties);
    OPENSSL_free(macbuf);
    OPENSSL_free(cipherbuf);
    OPENSSL_free(mdbuf);
    return ret;
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
