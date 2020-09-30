/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * ECDSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h> /* memcpy */
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "internal/cryptlib.h"
#include "prov/providercommon.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include "crypto/ec.h"
#include "prov/der_ec.h"

static OSSL_FUNC_signature_newctx_fn ecdsa_newctx;
static OSSL_FUNC_signature_sign_init_fn ecdsa_sign_init;
static OSSL_FUNC_signature_verify_init_fn ecdsa_verify_init;
static OSSL_FUNC_signature_sign_fn ecdsa_sign;
static OSSL_FUNC_signature_verify_fn ecdsa_verify;
static OSSL_FUNC_signature_digest_sign_init_fn ecdsa_digest_sign_init;
static OSSL_FUNC_signature_digest_sign_update_fn ecdsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_sign_final_fn ecdsa_digest_sign_final;
static OSSL_FUNC_signature_digest_verify_init_fn ecdsa_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn ecdsa_digest_signverify_update;
static OSSL_FUNC_signature_digest_verify_final_fn ecdsa_digest_verify_final;
static OSSL_FUNC_signature_freectx_fn ecdsa_freectx;
static OSSL_FUNC_signature_dupctx_fn ecdsa_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn ecdsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn ecdsa_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn ecdsa_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn ecdsa_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn ecdsa_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn ecdsa_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn ecdsa_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn ecdsa_settable_ctx_md_params;

/*
 * What's passed as an actual key is defined by the KEYMGMT interface.
 * We happen to know that our KEYMGMT simply passes DSA structures, so
 * we use that here too.
 */

typedef struct {
    OPENSSL_CTX *libctx;
    char *propq;
    EC_KEY *ec;
    char mdname[OSSL_MAX_NAME_SIZE];

    /* The Algorithm Identifier of the combined signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;
    size_t mdsize;
    int operation;

    EVP_MD *md;
    EVP_MD_CTX *mdctx;
    /*
     * Internally used to cache the results of calling the EC group
     * sign_setup() methods which are then passed to the sign operation.
     * This is used by CAVS failure tests to terminate a loop if the signature
     * is not valid.
     * This could of also been done with a simple flag.
     */
    BIGNUM *kinv;
    BIGNUM *r;
#if !defined(OPENSSL_NO_ACVP_TESTS)
    /*
     * This indicates that KAT (CAVS) test is running. Externally an app will
     * override the random callback such that the generated private key and k
     * are known.
     * Normal operation will loop to choose a new k if the signature is not
     * valid - but for this mode of operation it forces a failure instead.
     */
    unsigned int kattest;
#endif
} PROV_ECDSA_CTX;

static void *ecdsa_newctx(void *provctx, const char *propq)
{
    PROV_ECDSA_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_ECDSA_CTX));
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);
    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL) {
        OPENSSL_free(ctx);
        ctx = NULL;
        ERR_raise(ERR_LIB_PROV, ERR_R_MALLOC_FAILURE);
    }
    return ctx;
}

static int ecdsa_signverify_init(void *vctx, void *ec, int operation)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (!ossl_prov_is_running()
            || ctx == NULL
            || ec == NULL
            || !EC_KEY_up_ref(ec))
        return 0;
    EC_KEY_free(ctx->ec);
    ctx->ec = ec;
    ctx->operation = operation;
    return ec_check_key(ec, operation == EVP_PKEY_OP_SIGN);
}

static int ecdsa_sign_init(void *vctx, void *ec)
{
    return ecdsa_signverify_init(vctx, ec, EVP_PKEY_OP_SIGN);
}

static int ecdsa_verify_init(void *vctx, void *ec)
{
    return ecdsa_signverify_init(vctx, ec, EVP_PKEY_OP_VERIFY);
}

static int ecdsa_sign(void *vctx, unsigned char *sig, size_t *siglen,
                      size_t sigsize, const unsigned char *tbs, size_t tbslen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    int ret;
    unsigned int sltmp;
    size_t ecsize = ECDSA_size(ctx->ec);

    if (!ossl_prov_is_running())
        return 0;

    if (sig == NULL) {
        *siglen = ecsize;
        return 1;
    }

#if !defined(OPENSSL_NO_ACVP_TESTS)
    if (ctx->kattest && !ECDSA_sign_setup(ctx->ec, NULL, &ctx->kinv, &ctx->r))
        return 0;
#endif

    if (sigsize < (size_t)ecsize)
        return 0;

    if (ctx->mdsize != 0 && tbslen != ctx->mdsize)
        return 0;

    ret = ECDSA_sign_ex(0, tbs, tbslen, sig, &sltmp, ctx->kinv, ctx->r, ctx->ec);
    if (ret <= 0)
        return 0;

    *siglen = sltmp;
    return 1;
}

static int ecdsa_verify(void *vctx, const unsigned char *sig, size_t siglen,
                        const unsigned char *tbs, size_t tbslen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (!ossl_prov_is_running() || (ctx->mdsize != 0 && tbslen != ctx->mdsize))
        return 0;

    return ECDSA_verify(0, tbs, tbslen, sig, siglen, ctx->ec);
}

static void free_md(PROV_ECDSA_CTX *ctx)
{
    OPENSSL_free(ctx->propq);
    EVP_MD_CTX_free(ctx->mdctx);
    EVP_MD_free(ctx->md);
    ctx->propq = NULL;
    ctx->mdctx = NULL;
    ctx->md = NULL;
    ctx->mdsize = 0;
}

static int ecdsa_digest_signverify_init(void *vctx, const char *mdname,
                                        void *ec, int operation)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    int md_nid = NID_undef;
    WPACKET pkt;
    int sha1_allowed = (ctx->operation != EVP_PKEY_OP_SIGN);

    if (!ossl_prov_is_running())
        return 0;

    free_md(ctx);

    if (!ecdsa_signverify_init(vctx, ec, operation))
        return 0;

    ctx->md = EVP_MD_fetch(ctx->libctx, mdname, ctx->propq);
    md_nid = digest_get_approved_nid_with_sha1(ctx->md, sha1_allowed);
    if (md_nid == NID_undef)
        goto error;

    ctx->mdsize = EVP_MD_size(ctx->md);
    ctx->mdctx = EVP_MD_CTX_new();
    if (ctx->mdctx == NULL)
        goto error;

    /*
     * TODO(3.0) Should we care about DER writing errors?
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    ctx->aid_len = 0;
    if (WPACKET_init_der(&pkt, ctx->aid_buf, sizeof(ctx->aid_buf))
        && ossl_DER_w_algorithmIdentifier_ECDSA_with_MD(&pkt, -1, ctx->ec,
                                                        md_nid)
        && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &ctx->aid_len);
        ctx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    if (!EVP_DigestInit_ex(ctx->mdctx, ctx->md, NULL))
        goto error;
    return 1;
error:
    free_md(ctx);
    return 0;
}

static int ecdsa_digest_sign_init(void *vctx, const char *mdname, void *ec)
{
    return ecdsa_digest_signverify_init(vctx, mdname, ec, EVP_PKEY_OP_SIGN);
}

static int ecdsa_digest_verify_init(void *vctx, const char *mdname, void *ec)
{
    return ecdsa_digest_signverify_init(vctx, mdname, ec, EVP_PKEY_OP_VERIFY);
}

int ecdsa_digest_signverify_update(void *vctx, const unsigned char *data,
                                   size_t datalen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx == NULL || ctx->mdctx == NULL)
        return 0;

    return EVP_DigestUpdate(ctx->mdctx, data, datalen);
}

int ecdsa_digest_sign_final(void *vctx, unsigned char *sig, size_t *siglen,
                            size_t sigsize)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!ossl_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /*
     * If sig is NULL then we're just finding out the sig size. Other fields
     * are ignored. Defer to ecdsa_sign.
     */
    if (sig != NULL) {
        /*
         * TODO(3.0): There is the possibility that some externally provided
         * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
         * but that problem is much larger than just in DSA.
         */
        if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
            return 0;
    }

    return ecdsa_sign(vctx, sig, siglen, sigsize, digest, (size_t)dlen);
}

int ecdsa_digest_verify_final(void *vctx, const unsigned char *sig,
                              size_t siglen)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int dlen = 0;

    if (!ossl_prov_is_running() || ctx == NULL || ctx->mdctx == NULL)
        return 0;

    /*
     * TODO(3.0): There is the possibility that some externally provided
     * digests exceed EVP_MAX_MD_SIZE. We should probably handle that somehow -
     * but that problem is much larger than just in DSA.
     */
    if (!EVP_DigestFinal_ex(ctx->mdctx, digest, &dlen))
        return 0;

    return ecdsa_verify(ctx, sig, siglen, digest, (size_t)dlen);
}

static void ecdsa_freectx(void *vctx)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    free_md(ctx);
    EC_KEY_free(ctx->ec);
    BN_clear_free(ctx->kinv);
    BN_clear_free(ctx->r);
    OPENSSL_free(ctx);
}

static void *ecdsa_dupctx(void *vctx)
{
    PROV_ECDSA_CTX *srcctx = (PROV_ECDSA_CTX *)vctx;
    PROV_ECDSA_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->ec = NULL;
    dstctx->md = NULL;
    dstctx->mdctx = NULL;

    if (srcctx->ec != NULL && !EC_KEY_up_ref(srcctx->ec))
        goto err;
    /* Test KATS should not need to be supported */
    if (srcctx->kinv != NULL || srcctx->r != NULL)
        goto err;
    dstctx->ec = srcctx->ec;

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
    ecdsa_freectx(dstctx);
    return NULL;
}

static int ecdsa_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    OSSL_PARAM *p;

    if (ctx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, ctx->aid, ctx->aid_len))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, ctx->mdsize))
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_DIGEST);
    if (p != NULL && !OSSL_PARAM_set_utf8_string(p, ctx->md == NULL
                                                    ? ctx->mdname
                                                    : EVP_MD_name(ctx->md)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecdsa_gettable_ctx_params(ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int ecdsa_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;
    const OSSL_PARAM *p;
    char *mdname;

    if (ctx == NULL || params == NULL)
        return 0;

    if (ctx->md != NULL) {
        /*
         * You cannot set the digest name/size when doing a DigestSign or
         * DigestVerify.
         */
        return 1;
    }
#if !defined(OPENSSL_NO_ACVP_TESTS)
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_KAT);
    if (p != NULL && !OSSL_PARAM_get_uint(p, &ctx->kattest))
        return 0;
#endif

    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST_SIZE);
    if (p != NULL && !OSSL_PARAM_get_size_t(p, &ctx->mdsize))
        return 0;

    /*
     * We never actually use the mdname, but we do support getting it later.
     * This can be useful for applications that want to know the MD that they
     * previously set.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_DIGEST);
    mdname = ctx->mdname;
    if (p != NULL
            && !OSSL_PARAM_get_utf8_string(p, &mdname, sizeof(ctx->mdname)))
        return 0;

    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_SIGNATURE_PARAM_DIGEST_SIZE, NULL),
    OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_DIGEST, NULL, 0),
    OSSL_PARAM_uint(OSSL_SIGNATURE_PARAM_KAT, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *ecdsa_settable_ctx_params(ossl_unused void *provctx)
{
    /*
     * TODO(3.0): Should this function return a different set of settable ctx
     * params if the ctx is being used for a DigestSign/DigestVerify? In that
     * case it is not allowed to set the digest size/digest name because the
     * digest is explicitly set as part of the init.
     */
    return known_settable_ctx_params;
}

static int ecdsa_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_get_params(ctx->mdctx, params);
}

static const OSSL_PARAM *ecdsa_gettable_ctx_md_params(void *vctx)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_gettable_ctx_params(ctx->md);
}

static int ecdsa_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx->mdctx == NULL)
        return 0;

    return EVP_MD_CTX_set_params(ctx->mdctx, params);
}

static const OSSL_PARAM *ecdsa_settable_ctx_md_params(void *vctx)
{
    PROV_ECDSA_CTX *ctx = (PROV_ECDSA_CTX *)vctx;

    if (ctx->md == NULL)
        return 0;

    return EVP_MD_settable_ctx_params(ctx->md);
}

const OSSL_DISPATCH ecossl_dsa_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))ecdsa_newctx },
    { OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))ecdsa_sign_init },
    { OSSL_FUNC_SIGNATURE_SIGN, (void (*)(void))ecdsa_sign },
    { OSSL_FUNC_SIGNATURE_VERIFY_INIT, (void (*)(void))ecdsa_verify_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))ecdsa_verify },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))ecdsa_digest_sign_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE,
      (void (*)(void))ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL,
      (void (*)(void))ecdsa_digest_sign_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))ecdsa_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))ecdsa_digest_signverify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))ecdsa_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))ecdsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))ecdsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))ecdsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))ecdsa_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))ecdsa_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))ecdsa_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))ecdsa_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))ecdsa_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))ecdsa_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))ecdsa_settable_ctx_md_params },
    { 0, NULL }
};
