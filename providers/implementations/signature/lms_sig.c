/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h> /* memcpy */
#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/dsa.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "internal/cryptlib.h"
#include "internal/deterministic_nonce.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "prov/securitycheck.h"
#include "crypto/lms.h"
#include "prov/der_ec.h"

static OSSL_FUNC_signature_newctx_fn lms_newctx;
static OSSL_FUNC_signature_digest_verify_init_fn lms_digest_verify_init;
static OSSL_FUNC_signature_digest_verify_update_fn lms_digest_verify_update;
static OSSL_FUNC_signature_digest_verify_final_fn lms_digest_verify_final;
static OSSL_FUNC_signature_digest_verify_fn lms_digest_verify;
static OSSL_FUNC_signature_freectx_fn lms_freectx;
static OSSL_FUNC_signature_dupctx_fn lms_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn lms_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn lms_gettable_ctx_params;
static OSSL_FUNC_signature_set_ctx_params_fn lms_set_ctx_params;
static OSSL_FUNC_signature_settable_ctx_params_fn lms_settable_ctx_params;
static OSSL_FUNC_signature_get_ctx_md_params_fn lms_get_ctx_md_params;
static OSSL_FUNC_signature_gettable_ctx_md_params_fn lms_gettable_ctx_md_params;
static OSSL_FUNC_signature_set_ctx_md_params_fn lms_set_ctx_md_params;
static OSSL_FUNC_signature_settable_ctx_md_params_fn lms_settable_ctx_md_params;

typedef struct {
    OSSL_LIB_CTX *libctx;
    char *propq;
    LMS_KEY *key;
    const LMS_SIG *lms_sig;
    LM_OTS_CTX *pubctx;
    const LMS_KEY *sigkey;

    unsigned char *msg;
    size_t msglen;
    unsigned char *sig;
    size_t siglen;
    EVP_MD *md;
    int hss;
} PROV_LMS_CTX;


static void *lms_dupctx(void *vctx)
{
    PROV_LMS_CTX *srcctx = (PROV_LMS_CTX *)vctx;
    PROV_LMS_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->key = NULL;
    dstctx->md = NULL;
    dstctx->pubctx = NULL;
    dstctx->propq = NULL;
    dstctx->sig = NULL;

    if (srcctx->msg != NULL) {
        dstctx->msg = OPENSSL_memdup(srcctx->msg, srcctx->msglen);
        if (dstctx->msg == NULL)
            goto err;
    }
    if (srcctx->sig != NULL) {
        dstctx->sig = OPENSSL_memdup(srcctx->sig, srcctx->siglen);
        if (dstctx->sig == NULL)
            goto err;
    }
    if (srcctx->propq != NULL) {
        dstctx->propq = OPENSSL_strdup(srcctx->propq);
        if (dstctx->propq == NULL)
            goto err;
    }
    if (srcctx->pubctx != NULL) {
        dstctx->pubctx = ossl_lm_ots_ctx_dup(srcctx->pubctx);
        if (dstctx->pubctx == NULL)
            goto err;
    }

    if (srcctx->md != NULL && !EVP_MD_up_ref(srcctx->md))
        goto err;
    dstctx->md = srcctx->md;

    if (srcctx->key != NULL && !ossl_lms_key_up_ref(srcctx->key))
        goto err;
    dstctx->key = srcctx->key;

    return dstctx;
 err:
    lms_freectx(dstctx);
    return NULL;
}

static void *lms_newctx(void *provctx, const char *propq)
{
    PROV_LMS_CTX *ctx;
    LM_OTS_CTX *pubctx = NULL;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_LMS_CTX));
    if (ctx == NULL)
        return NULL;
    pubctx = ossl_lm_ots_ctx_new();
    if (pubctx == NULL)
        goto err;

    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    ctx->pubctx = pubctx;
    return ctx;
err:
    ossl_lm_ots_ctx_free(pubctx);
    OPENSSL_free(ctx);
    return NULL;
}

static void *hss_newctx(void *provctx, const char *propq)
{
    PROV_LMS_CTX *ctx = lms_newctx(provctx, propq);

    if (ctx != NULL)
        ctx->hss = 1;
    return ctx;
}

static void lms_freectx(void *vctx)
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (ctx == NULL)
        return;
    ossl_lms_key_free(ctx->key);
    OPENSSL_free(ctx->propq);
    ossl_lm_ots_ctx_free(ctx->pubctx);
    OPENSSL_free(ctx->sig);
    OPENSSL_free(ctx->msg);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx);
}

static int setdigest(PROV_LMS_CTX *ctx, const char *digestname)
{
    if (ctx->md != NULL) {
        if (EVP_MD_is_a(ctx->md, digestname))
            return 1;
        EVP_MD_free(ctx->md);
    }
    ctx->md = EVP_MD_fetch(ctx->libctx, digestname, ctx->propq);
    return ctx->md != NULL;
}

static int lms_verify_init(void *vctx, void *key, const OSSL_PARAM params[])
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;

    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (key != NULL) {
        if (!ossl_lms_key_up_ref(key))
            return 0;
        ossl_lms_key_free(ctx->key);
        ctx->key = key;
        setdigest(ctx, ctx->key->lms_params->digestname);
    }
    return lms_set_ctx_params(ctx, params);
}

static int lms_sig_verify_init(PROV_LMS_CTX *ctx,
                               const LMS_SIG *lms_sig,
                               const LMS_KEY *key)
{
    ctx->lms_sig = lms_sig;
    ctx->sigkey = key;
    return ossl_lm_ots_ctx_pubkey_init(ctx->pubctx, ctx->md, &lms_sig->sig,
                                        key->ots_params, key->I, lms_sig->q);
}

static int lms_sig_verify_update(PROV_LMS_CTX *ctx,
                                 const unsigned char *msg, size_t msglen)
{
    return ossl_lm_ots_ctx_pubkey_update(ctx->pubctx, msg, msglen);
}

static unsigned char D_LEAF[] = { 0x82, 0x82 };
static unsigned char D_INTR[] = { 0x83, 0x83 };

static int lms_sig_verify_final(PROV_LMS_CTX *vctx)
{
    EVP_MD_CTX *ctx = vctx->pubctx->mdctx;
    EVP_MD_CTX *ctxI = vctx->pubctx->mdctxIq;
    const LMS_KEY *key = vctx->sigkey;
    const LMS_SIG *lms_sig = vctx->lms_sig;
    unsigned char Kc[LMS_MAX_DIGEST_SIZE];
    unsigned char Tc[LMS_MAX_DIGEST_SIZE];
    unsigned char buf[4];
    const LMS_PARAMS *lmsParams;
    uint32_t node_num, m;
    const unsigned char *path;

    if (!ossl_lm_ots_ctx_pubkey_final(vctx->pubctx, Kc))
        return 0;

    /* Compute the candidate LMS root value Tc */
    lmsParams = key->lms_params;
    m = lmsParams->n;
    node_num = (1 << lmsParams->h) + lms_sig->q;

    U32STR(buf, node_num);
    if (!EVP_DigestInit_ex2(ctx, NULL, NULL)
        || !EVP_DigestUpdate(ctx, key->I, LMS_ISIZE)
        || !EVP_MD_CTX_copy_ex(ctxI, ctx)
        || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
        || !EVP_DigestUpdate(ctx, D_LEAF, sizeof(D_LEAF))
        || !EVP_DigestUpdate(ctx, Kc, m)
        || !EVP_DigestFinal_ex(ctx, Tc, NULL))
        goto err;

    path = lms_sig->paths;
    while (node_num > 1) {
        int odd = node_num & 1;

        node_num = node_num >> 1;
        U32STR(buf, node_num);

        if (!EVP_MD_CTX_copy_ex(ctx, ctxI)
            || !EVP_DigestUpdate(ctx, buf, sizeof(buf))
            || !EVP_DigestUpdate(ctx, D_INTR, sizeof(D_INTR)))
            goto err;

        if (odd) {
            if (!EVP_DigestUpdate(ctx, path, m)
                || !EVP_DigestUpdate(ctx, Tc, m))
                goto err;
        } else {
            if (!EVP_DigestUpdate(ctx, Tc, m)
                || !EVP_DigestUpdate(ctx, path, m))
                goto err;
        }
        if (!EVP_DigestFinal_ex(ctx, Tc, NULL))
            goto err;
        path += m;
    }
    return memcmp(key->K, Tc, m) == 0;
err:
    return 0;
}

static int lms_sig_verify(PROV_LMS_CTX *ctx,
                          const LMS_SIG *lms_sig,
                          const LMS_KEY *key,
                          const unsigned char *msg, size_t msglen)
{
    int valid = 0;

    if (!lms_sig_verify_init(ctx, lms_sig, key))
        return 0;
    if (!lms_sig_verify_update(ctx, msg, msglen))
        goto end;
    if (!lms_sig_verify_final(ctx))
        goto end;
    valid = 1;
end:
    return valid;
}

static int lms_verify_int(PROV_LMS_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *msg, size_t msglen)
{
    int ret;
    LMS_SIG *s = ossl_lms_sig_from_data(sig, siglen, ctx->key);

    if (s == NULL)
        return 0;
    ret = (lms_sig_verify(ctx, s, ctx->key, msg, msglen) == 1);
    ossl_lms_sig_free(s);
    return ret;
}

static int hss_verify_int(PROV_LMS_CTX *ctx,
                          const unsigned char *sig, size_t siglen,
                          const unsigned char *msg, size_t msglen)
{
    int ret = 0, i;
    STACK_OF(LMS_KEY) *publist = NULL;
    STACK_OF(LMS_SIG) *siglist = NULL;

    publist = sk_LMS_KEY_new_null();
    siglist = sk_LMS_SIG_new_null();
    if (publist == NULL || siglist == NULL)
        goto err;

    /* Add the public key to the stack */
    if (!ossl_lms_key_up_ref(ctx->key))
        goto err;
    if (sk_LMS_KEY_push(publist, ctx->key) <= 0) {
        ossl_lms_key_free(ctx->key);
        goto err;
    }

    /* Decode the HSS signature data which contains signatures and public keys */
    if (!ossl_hss_decode(ctx->key, sig, siglen, publist, siglist))
        goto err;

    /* Verify each tree */
    for (i = 0; i < sk_LMS_SIG_num(siglist) - 1; ++i) {
        LMS_KEY *next = sk_LMS_KEY_value(publist, i + 1);

        if (next == NULL)
            goto err;
        if (lms_sig_verify(ctx, sk_LMS_SIG_value(siglist, i),
                           sk_LMS_KEY_value(publist, i),
                           next->pub, next->publen) != 1)
            goto err;
    }
    if (lms_sig_verify(ctx, sk_LMS_SIG_value(siglist, i),
                       sk_LMS_KEY_value(publist, i),
                       msg, msglen) != 1)
        goto err;
    ret = 1;
err:
    sk_LMS_KEY_pop_free(publist, ossl_lms_key_free);
    sk_LMS_SIG_pop_free(siglist, ossl_lms_sig_free);
    return ret;
}

static int lms_digest_verify(void *vctx, const unsigned char *sig, size_t siglen,
                             const unsigned char *msg, size_t msglen)
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;
    if (ctx->hss != 0)
        return hss_verify_int(ctx, sig, siglen, msg, msglen);
    else
        return lms_verify_int(ctx, sig, siglen, msg, msglen);
    return 0;
}

static int lms_digest_verify_init(void *vctx, const char *mdname, void *key,
                                  const OSSL_PARAM params[])
{
    return lms_verify_init(vctx, key, params);
}

int lms_digest_verify_update(void *vctx, const unsigned char *data,
                             size_t datalen)
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;
    void *ptr;

    /*
     * Since the signature is required before we can process the message
     * we need to buffer the message, if we use the normal pattern of passing
     * the signature during the final.
     */
    ptr = OPENSSL_realloc(ctx->msg, ctx->msglen + datalen);
    if (ptr == NULL)
        return 0;

    ctx->msg = ptr;
    memcpy(&ctx->msg[ctx->msglen], data, datalen);
    ctx->msglen += datalen;

    return 1;
}

int lms_digest_verify_final(void *vctx, const unsigned char *sig,
                            size_t siglen)
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (ctx == NULL)
        return 0;
    return lms_digest_verify(vctx, sig, siglen, ctx->msg, ctx->msglen);
}

static int lms_get_ctx_params(void *vctx, OSSL_PARAM *params)
{
    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *lms_gettable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int lms_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_LMS_CTX *ctx = (PROV_LMS_CTX *)vctx;

    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    return 1;
}

static const OSSL_PARAM settable_ctx_params[] = {
    OSSL_PARAM_END
};

static const OSSL_PARAM *lms_settable_ctx_params(void *vctx,
                                                 ossl_unused void *provctx)
{
    return settable_ctx_params;
}

static int lms_get_ctx_md_params(void *vctx, OSSL_PARAM *params)
{
    return 1;
}

static const OSSL_PARAM *lms_gettable_ctx_md_params(void *vctx)
{
    return NULL;
}

static int lms_set_ctx_md_params(void *vctx, const OSSL_PARAM params[])
{
    return 1;
}

static const OSSL_PARAM *lms_settable_ctx_md_params(void *vctx)
{
    return NULL;
}

const OSSL_DISPATCH ossl_lms_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))lms_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))lms_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))lms_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))lms_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))lms_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))lms_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))lms_digest_verify },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))lms_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))lms_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))lms_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))lms_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))lms_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lms_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))lms_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lms_settable_ctx_md_params },
    OSSL_DISPATCH_END
};

const OSSL_DISPATCH ossl_hss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))hss_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))lms_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))lms_dupctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))lms_digest_verify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_UPDATE,
      (void (*)(void))lms_digest_verify_update },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_FINAL,
      (void (*)(void))lms_digest_verify_final },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY, (void (*)(void))lms_digest_verify },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))lms_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))lms_gettable_ctx_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))lms_set_ctx_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,
      (void (*)(void))lms_settable_ctx_params },
    { OSSL_FUNC_SIGNATURE_GET_CTX_MD_PARAMS,
      (void (*)(void))lms_get_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lms_gettable_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SET_CTX_MD_PARAMS,
      (void (*)(void))lms_set_ctx_md_params },
    { OSSL_FUNC_SIGNATURE_SETTABLE_CTX_MD_PARAMS,
      (void (*)(void))lms_settable_ctx_md_params },
    OSSL_DISPATCH_END
};
