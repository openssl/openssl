/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/proverr.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include "prov/providercommon.h"
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "crypto/hss_sig.h"

static OSSL_FUNC_signature_newctx_fn hss_newctx;
static OSSL_FUNC_signature_freectx_fn hss_freectx;
static OSSL_FUNC_signature_verify_message_init_fn hss_verify_msg_init;
static OSSL_FUNC_signature_verify_fn hss_verify;

typedef struct {
    HSS_KEY *key;
    EVP_MD *md;
    OSSL_LIB_CTX *libctx;
    char *propq;
} PROV_HSS_CTX;

static void *hss_newctx(void *provctx, const char *propq)
{
    PROV_HSS_CTX *ctx;

    if (!ossl_prov_is_running())
        return NULL;

    ctx = OPENSSL_zalloc(sizeof(PROV_HSS_CTX));
    if (ctx == NULL)
        return NULL;

    if (propq != NULL && (ctx->propq = OPENSSL_strdup(propq)) == NULL)
        goto err;
    ctx->libctx = PROV_LIBCTX_OF(provctx);
    return ctx;
err:
    OPENSSL_free(ctx);
    return NULL;
}

static void hss_freectx(void *vctx)
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;

    if (ctx == NULL)
        return;
    ossl_hss_key_free(ctx->key);
    OPENSSL_free(ctx->propq);
    EVP_MD_free(ctx->md);
    OPENSSL_free(ctx);
}

static int setdigest(PROV_HSS_CTX *ctx, const char *digestname)
{
    /*
     * Assume that only one digest can be used by HSS.
     * Set the digest to the one contained in the public key.
     * If the optional digestname passed in by the user is different
     * then return an error.
     */
    HSS_KEY *hsskey = ctx->key;
    const char *pub_digestname = ossl_hss_key_get_digestname(hsskey);

    if (ctx->md != NULL) {
        if (EVP_MD_is_a(ctx->md, pub_digestname))
            goto end;
        EVP_MD_free(ctx->md);
    }
    ctx->md = EVP_MD_fetch(ctx->libctx, pub_digestname, ctx->propq);
    if (ctx->md == NULL)
        return 0;
end:
    return digestname == NULL || EVP_MD_is_a(ctx->md, digestname);
}

static int hss_verify_msg_init(void *vctx, void *vkey, const OSSL_PARAM params[])
{
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    HSS_KEY *key = (HSS_KEY *)vkey;

    if (!ossl_prov_is_running() || ctx == NULL)
        return 0;

    if (key == NULL && ctx->key == NULL) {
        ERR_raise(ERR_LIB_PROV, PROV_R_NO_KEY_SET);
        return 0;
    }

    if (!ossl_hss_key_up_ref(key))
        return 0;
    ossl_hss_key_free(ctx->key);
    ctx->key = key;
    if (!setdigest(ctx, NULL))
        return 0;
    return 1;
}

static int hss_verify(void *vctx, const unsigned char *sigbuf, size_t sigbuf_len,
                      const unsigned char *msg, size_t msglen)
{
    int ret = 0;
    PROV_HSS_CTX *ctx = (PROV_HSS_CTX *)vctx;
    HSS_KEY *pub = ctx->key;
    HSS_SIG *sig = NULL;

    /* A root public key is required to perform a verify operation */
    if (!ossl_prov_is_running() || pub == NULL)
        return 0;

    sig = ossl_hss_sig_new();
    if (sig == NULL)
        return 0;

    /* Decode the HSS signature data into a HSS_SIG object */
    if (!ossl_hss_sig_decode(sig, pub, pub->L, sigbuf, sigbuf_len))
        goto end;
    ret = ossl_hss_sig_verify(sig, pub, ctx->md, msg, msglen);
 end:
    ossl_hss_sig_free(sig);
    return ret;
}

const OSSL_DISPATCH ossl_hss_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))hss_newctx },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))hss_freectx },
    { OSSL_FUNC_SIGNATURE_VERIFY_MESSAGE_INIT,
      (void (*)(void))hss_verify_msg_init },
    { OSSL_FUNC_SIGNATURE_VERIFY, (void (*)(void))hss_verify },
    OSSL_DISPATCH_END
};
