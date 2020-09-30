/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "prov/providercommon.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "prov/der_ecx.h"
#include "crypto/ecx.h"

static OSSL_FUNC_signature_newctx_fn eddsa_newctx;
static OSSL_FUNC_signature_digest_sign_init_fn eddsa_digest_signverify_init;
static OSSL_FUNC_signature_digest_sign_fn ed25519_digest_sign;
static OSSL_FUNC_signature_digest_sign_fn ed448_digest_sign;
static OSSL_FUNC_signature_digest_verify_fn ed25519_digest_verify;
static OSSL_FUNC_signature_digest_verify_fn ed448_digest_verify;
static OSSL_FUNC_signature_freectx_fn eddsa_freectx;
static OSSL_FUNC_signature_dupctx_fn eddsa_dupctx;
static OSSL_FUNC_signature_get_ctx_params_fn eddsa_get_ctx_params;
static OSSL_FUNC_signature_gettable_ctx_params_fn eddsa_gettable_ctx_params;

typedef struct {
    OPENSSL_CTX *libctx;
    ECX_KEY *key;

    /* The Algorithm Identifier of the signature algorithm */
    unsigned char aid_buf[OSSL_MAX_ALGORITHM_ID_SIZE];
    unsigned char *aid;
    size_t  aid_len;
} PROV_EDDSA_CTX;

static void *eddsa_newctx(void *provctx, const char *propq_unused)
{
    PROV_EDDSA_CTX *peddsactx;

    if (!ossl_prov_is_running())
        return NULL;

    peddsactx = OPENSSL_zalloc(sizeof(PROV_EDDSA_CTX));
    if (peddsactx == NULL) {
        PROVerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    peddsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    return peddsactx;
}

static int eddsa_digest_signverify_init(void *vpeddsactx, const char *mdname,
                                        void *vedkey)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    ECX_KEY *edkey = (ECX_KEY *)vedkey;
    WPACKET pkt;
    int ret;

    if (!ossl_prov_is_running())
        return 0;

    if (mdname != NULL && mdname[0] != '\0') {
        PROVerr(0, PROV_R_INVALID_DIGEST);
        return 0;
    }

    if (!ecx_key_up_ref(edkey)) {
        PROVerr(0, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    /*
     * TODO(3.0) Should we care about DER writing errors?
     * All it really means is that for some reason, there's no
     * AlgorithmIdentifier to be had, but the operation itself is
     * still valid, just as long as it's not used to construct
     * anything that needs an AlgorithmIdentifier.
     */
    peddsactx->aid_len = 0;
    ret = WPACKET_init_der(&pkt, peddsactx->aid_buf, sizeof(peddsactx->aid_buf));
    switch (edkey->type) {
    case ECX_KEY_TYPE_ED25519:
        ret = ret && ossl_DER_w_algorithmIdentifier_ED25519(&pkt, -1, edkey);
        break;
    case ECX_KEY_TYPE_ED448:
        ret = ret && ossl_DER_w_algorithmIdentifier_ED448(&pkt, -1, edkey);
        break;
    default:
        /* Should never happen */
        PROVerr(0, ERR_R_INTERNAL_ERROR);
        return 0;
    }
    if (ret && WPACKET_finish(&pkt)) {
        WPACKET_get_total_written(&pkt, &peddsactx->aid_len);
        peddsactx->aid = WPACKET_get_curr(&pkt);
    }
    WPACKET_cleanup(&pkt);

    peddsactx->key = edkey;

    return 1;
}

int ed25519_digest_sign(void *vpeddsactx, unsigned char *sigret,
                        size_t *siglen, size_t sigsize,
                        const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running())
        return 0;

    if (sigret == NULL) {
        *siglen = ED25519_SIGSIZE;
        return 1;
    }
    if (sigsize < ED25519_SIGSIZE) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED25519_sign(sigret, tbs, tbslen, edkey->pubkey, edkey->privkey,
                     peddsactx->libctx, NULL) == 0) {
        PROVerr(0, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    *siglen = ED25519_SIGSIZE;
    return 1;
}

int ed448_digest_sign(void *vpeddsactx, unsigned char *sigret,
                      size_t *siglen, size_t sigsize,
                      const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running())
        return 0;

    if (sigret == NULL) {
        *siglen = ED448_SIGSIZE;
        return 1;
    }
    if (sigsize < ED448_SIGSIZE) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED448_sign(peddsactx->libctx, sigret, tbs, tbslen, edkey->pubkey,
                   edkey->privkey, NULL, 0, edkey->propq) == 0) {
        PROVerr(0, PROV_R_FAILED_TO_SIGN);
        return 0;
    }
    *siglen = ED448_SIGSIZE;
    return 1;
}

int ed25519_digest_verify(void *vpeddsactx, const unsigned char *sig,
                          size_t siglen, const unsigned char *tbs,
                          size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running() || siglen != ED25519_SIGSIZE)
        return 0;

    return ED25519_verify(tbs, tbslen, sig, edkey->pubkey, peddsactx->libctx,
                          edkey->propq);
}

int ed448_digest_verify(void *vpeddsactx, const unsigned char *sig,
                        size_t siglen, const unsigned char *tbs,
                        size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (!ossl_prov_is_running() || siglen != ED448_SIGSIZE)
        return 0;

    return ED448_verify(peddsactx->libctx, tbs, tbslen, sig, edkey->pubkey,
                        NULL, 0, edkey->propq);
}

static void eddsa_freectx(void *vpeddsactx)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;

    ecx_key_free(peddsactx->key);

    OPENSSL_free(peddsactx);
}

static void *eddsa_dupctx(void *vpeddsactx)
{
    PROV_EDDSA_CTX *srcctx = (PROV_EDDSA_CTX *)vpeddsactx;
    PROV_EDDSA_CTX *dstctx;

    if (!ossl_prov_is_running())
        return NULL;

    dstctx = OPENSSL_zalloc(sizeof(*srcctx));
    if (dstctx == NULL)
        return NULL;

    *dstctx = *srcctx;
    dstctx->key = NULL;

    if (srcctx->key != NULL && !ecx_key_up_ref(srcctx->key)) {
        PROVerr(0, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    dstctx->key = srcctx->key;

    return dstctx;
 err:
    eddsa_freectx(dstctx);
    return NULL;
}

static int eddsa_get_ctx_params(void *vpeddsactx, OSSL_PARAM *params)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    OSSL_PARAM *p;

    if (peddsactx == NULL || params == NULL)
        return 0;

    p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
    if (p != NULL && !OSSL_PARAM_set_octet_string(p, peddsactx->aid,
                                                  peddsactx->aid_len))
        return 0;

    return 1;
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *eddsa_gettable_ctx_params(ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

const OSSL_DISPATCH ossl_ed25519_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))ed25519_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))ed25519_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_gettable_ctx_params },
    { 0, NULL }
};

const OSSL_DISPATCH ossl_ed448_signature_functions[] = {
    { OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))eddsa_newctx },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_SIGN,
      (void (*)(void))ed448_digest_sign },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY_INIT,
      (void (*)(void))eddsa_digest_signverify_init },
    { OSSL_FUNC_SIGNATURE_DIGEST_VERIFY,
      (void (*)(void))ed448_digest_verify },
    { OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))eddsa_freectx },
    { OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))eddsa_dupctx },
    { OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS, (void (*)(void))eddsa_get_ctx_params },
    { OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,
      (void (*)(void))eddsa_gettable_ctx_params },
    { 0, NULL }
};
