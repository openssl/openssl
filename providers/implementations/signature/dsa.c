/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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

#include <string.h>

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "crypto/dsa.h"

static OSSL_OP_signature_newctx_fn dsa_newctx;
static OSSL_OP_signature_sign_init_fn dsa_signature_init;
static OSSL_OP_signature_verify_init_fn dsa_signature_init;
static OSSL_OP_signature_sign_fn dsa_sign;
static OSSL_OP_signature_verify_fn dsa_verify;
static OSSL_OP_signature_digest_sign_init_fn dsa_digest_signverify_init;
static OSSL_OP_signature_digest_sign_update_fn dsa_digest_signverify_update;
static OSSL_OP_signature_digest_sign_final_fn dsa_digest_sign_final;
static OSSL_OP_signature_digest_verify_init_fn dsa_digest_signverify_init;
static OSSL_OP_signature_digest_verify_update_fn dsa_digest_signverify_update;
static OSSL_OP_signature_digest_verify_final_fn dsa_digest_verify_final;
static OSSL_OP_signature_freectx_fn dsa_freectx;
static OSSL_OP_signature_dupctx_fn dsa_dupctx;
static OSSL_OP_signature_get_ctx_params_fn dsa_get_ctx_params;
static OSSL_OP_signature_gettable_ctx_params_fn dsa_gettable_ctx_params;
static OSSL_OP_signature_set_ctx_params_fn dsa_set_ctx_params;
static OSSL_OP_signature_settable_ctx_params_fn dsa_settable_ctx_params;
static OSSL_OP_signature_get_ctx_md_params_fn dsa_get_ctx_md_params;
static OSSL_OP_signature_gettable_ctx_md_params_fn dsa_gettable_ctx_md_params;
static OSSL_OP_signature_set_ctx_md_params_fn dsa_set_ctx_md_params;
static OSSL_OP_signature_settable_ctx_md_params_fn dsa_settable_ctx_md_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DSA structures, so
 * we use that here too.
 */

typedef struct {
    OPENSSL_CTX *libctx;
    DSA *dsa;

    /*
     * Flag to determine if the hash function can be changed (1) or not (0)
     * Because it's dangerous to change during a DigestSign or DigestVerify
     * operation, this flag is cleared by their Init function, and set again
     * by their Final function.
     */
    unsigned int flag_allow_md : 1;

    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature agorithm */
    unsigned char aid[OSSL_MAX_ALGORITHM_ID_SIZE];
    size_t  aid_len;

    /* main digest */
    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    size_t mdsize;
} PROV_DSA_CTX;

static size_t dsa_get_md_size(const PROV_DSA_CTX *pdsactx)
{
    if (pdsactx->md != NULL)
        return EVP_MD_size(pdsactx->md);
    return 0;
}

static int dsa_get_md_nid(const EVP_MD *md)
{
    /*
     * Because the DSA library deals with NIDs, we need to translate.
     * We do so using EVP_MD_is_a(), and therefore need a name to NID
     * map.
     */
    static const OSSL_ITEM name_to_nid[] = {
        { NID_sha1,   OSSL_DIGEST_NAME_SHA1   },
        { NID_sha224, OSSL_DIGEST_NAME_SHA2_224 },
        { NID_sha256, OSSL_DIGEST_NAME_SHA2_256 },
        { NID_sha384, OSSL_DIGEST_NAME_SHA2_384 },
        { NID_sha512, OSSL_DIGEST_NAME_SHA2_512 },
        { NID_sha3_224, OSSL_DIGEST_NAME_SHA3_224 },
        { NID_sha3_256, OSSL_DIGEST_NAME_SHA3_256 },
        { NID_sha3_384, OSSL_DIGEST_NAME_SHA3_384 },
        { NID_sha3_512, OSSL_DIGEST_NAME_SHA3_512 },
    };
    size_t i;
    int mdnid = NID_undef;

    if (md == NULL)
        goto end;

    for (i = 0; i < OSSL_NELEM(name_to_nid); i++) {
        if (EVP_MD_is_a(md, name_to_nid[i].ptr)) {
            mdnid = (int)name_to_nid[i].id;
            break;
        }
    }

    if (mdnid == NID_undef)
        ERR_raise(ERR_LIB_PROV, PROV_R_INVALID_DIGEST);

 end:
    return mdnid;
}

static void *dsa_newctx(void *provctx)
{
    PROV_DSA_CTX *pdsactx = OPENSSL_zalloc(sizeof(PROV_DSA_CTX));

    if (pdsactx == NULL)
        return NULL;

    pdsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    pdsactx->flag_allow_md = 1;
    return pdsactx;
}

static int dsa_setup_md(PROV_DSA_CTX *ctx,
                        const char *mdname, const char *mdprops)
{
    if (mdname != NULL) {
        EVP_MD *md = EVP_MD_fetch(ctx->libctx, mdname, mdprops);
        int md_nid = dsa_get_md_nid(md);
        size_t algorithmidentifier_len = 0;
        const unsigned char *algorithmidentifier;

        EVP_MD_free(ctx->md);
        ctx->md = NULL;
        ctx->mdname[0] = '\0';

        algorithmidentifier =
            dsa_algorithmidentifier_encoding(md_nid, &algorithmidentifier_len);

        if (algorithmidentifier == NULL) {
            EVP_MD_free(md);
            return 0;
        }

        ctx->md = md;
        OPENSSL_strlcpy(ctx->mdname, mdname, sizeof(ctx->mdname));
        memcpy(ctx->aid, algorithmidentifier, algorithmidentifier_len);
        ctx->aid_len = algorithmidentifier_len;
    }
    return 1;
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
    size_t mdsize = dsa_get_md_size(pdsactx);

    if (sig == NULL) {
        *siglen = dsasize;
        return 1;
    }

    if (sigsize < (size_t)dsasize)
        return 0;

    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    ret = dsa_sign_int(pdsactx->libctx, 0, tbs, tbslen, sig, &sltmp,
                       pdsactx->dsa);
    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int dsa_verify(void *vpdsactx, const unsigned char *sig, size_t siglen,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    size_t mdsize = dsa_get_md_size(pdsactx);

    if (mdsize != 0 && tbslen != mdsize)
        return 0;

    return DSA_verify(0, tbs, tbslen, sig, siglen, pdsactx->dsa);
}

static int dsa_digest_signverify_init(void *vpdsactx, const char *mdname,
                                      const char *props, void *vdsa)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    pdsactx->flag_allow_md = 0;
    if (!dsa_signature_init(vpdsactx, vdsa))
        return 0;

    if (!dsa_setup_md(pdsactx, mdname, props))
        return 0;

    pdsactx->mdctx = EVP_MD_CTX_new();
    if (pdsactx->mdctx == NULL)
        goto error;

    if (!EVP_DigestInit_ex(pdsactx->mdctx, pdsactx->md, NULL))
        goto error;

    return 1;

 error:
    EVP_MD_CTX_free(pdsactx->mdctx);
    EVP_MD_free(pdsactx->md);
    pdsactx->mdctx = NULL;
    pdsactx->md = NULL;
    return 0;
}

int dsa_digest_signverify_update(void *vpdsactx, const unsigned char *data,
                                 size_t datalen)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(pdsactx->mdctx, data, datalen);
}

int dsa_digest_sign_final(void *vpdsactx, unsigned char *sig, size_t *siglen,
                          size_t sigsize)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to dsa_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         */
        if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
            return 0;
    }

    pdsactx->flag_allow_md = 1;

    return dsa_sign(vpdsactx, sig, siglen, sigsize, digest, (size_t)dlen);
}


int dsa_digest_verify_final(void *vpdsactx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (pdsactx == NULL || pdsactx->mdctx == NULL)
        return 0;

    /*
     * TODO(3.0): There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     */
    if (!EVP_DigestFinal_ex(pdsactx->mdctx, digest, &dlen))
        return 0;

    pdsactx->flag_allow_md = 1;

    return dsa_verify(vpdsactx, sig, siglen, digest, (size_t)dlen);
}

static void dsa_freectx(void *vpdsactx)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    DSA_free(pdsactx->dsa);
    EVP_MD_CTX_free(pdsactx->mdctx);
    EVP_MD_free(pdsactx->md);

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
    dstctx->dsa = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->dsa != NULL && !DSA_up_ref(srcctx->dsa))
        goto err;
    dstctx->dsa = srcctx->dsa;

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->mdctx != NULL) {
        dstctx->mdctx = EVP_MD_CTX_new();
        if (dstctx->mdctx == NULL
                || !EVP_MD_CTX_copy_ex(dstctx->mdctx, srcctx->mdctx))
            goto err;
    }

    return dstctx;
 err:
    dsa_freectx(dstctx);
    return NULL;
}

static int dsa_get_ctx_params(void *vpdsactx, OSSL_PARAM *params)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;
    OSSL_PARAM *p;

    if (pdsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL
        && !OSSL_PARAM_set_octet_string(p, pdsactx->aid, pdsactx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, pdsactx->mdname))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
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

    if (pdsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    /* Not allowed during certain operations */
    if (p != NULL && !pdsactx->flag_allow_md)
        return 0;
    if (p != NULL) {
        char mdname[OSSL_MAX_NAME_SIZE] = "", *pmdname = mdname;
        char mdprops[OSSL_MAX_PROPQUERY_SIZE] = "", *pmdprops = mdprops;
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params,
                                    OSSL_SIGNATURE_PARAM_PROPERTIES);

        if (!OSSL_PARAM_get_utf8_string(p, &pmdname, sizeof(mdname)))
            return 0;
        if (propsp != NULL
            && !OSSL_PARAM_get_utf8_string(propsp, &pmdprops, sizeof(mdprops)))
            return 0;
        if (!dsa_setup_md(pdsactx, mdname, mdprops))
            return 0;
    }

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *dsa_settable_ctx_params(void)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     */
    return known_settable_ctx_params;
}

static int dsa_get_ctx_md_params(void *vpdsactx, OSSL_PARAM *params)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(pdsactx->mdctx, params);
}

static const OSSL_PARAM *dsa_gettable_ctx_md_params(void *vpdsactx)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(pdsactx->md);
}

static int dsa_set_ctx_md_params(void *vpdsactx, const OSSL_PARAM params[])
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(pdsactx->mdctx, params);
}

static const OSSL_PARAM *dsa_settable_ctx_md_params(void *vpdsactx)
{
    PROV_DSA_CTX *pdsactx = (PROV_DSA_CTX *)vpdsactx;

    if (pdsactx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(pdsactx->md);
}

const OSSL_DISPATCH dsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))dsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))dsa_signature_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))dsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))dsa_signature_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))dsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))dsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))dsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))dsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))dsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))dsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))dsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))dsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))dsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))dsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))dsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))dsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))dsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))dsa_settable_ctx_md_params },
    { 0, NULL }
};
