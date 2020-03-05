/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "internal/nelem.h"
#include "internal/sizes.h"
#include "prov/providercommonerr.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "crypto/ecx.h"

static OSSL_OP_signature_newctx_fn eddsa_newctx;
static OSSL_OP_signature_digest_sign_init_fn eddsa_digest_signverify_init;
static OSSL_OP_signature_digest_sign_fn ed25519_digest_sign;
static OSSL_OP_signature_digest_sign_fn ed448_digest_sign;
static OSSL_OP_signature_digest_verify_fn ed25519_digest_verify;
static OSSL_OP_signature_digest_verify_fn ed448_digest_verify;
static OSSL_OP_signature_freectx_fn eddsa_freectx;
static OSSL_OP_signature_dupctx_fn eddsa_dupctx;

typedef struct {
    OPENSSL_CTX *libctx;
    ECX_KEY *key;
} PROV_EDDSA_CTX;

static void *eddsa_newctx(void *provctx)
{
    PROV_EDDSA_CTX *peddsactx = OPENSSL_zalloc(sizeof(PROV_EDDSA_CTX));

    if (peddsactx == NULL) {
        PROVerr(0, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    peddsactx->libctx = PROV_LIBRARY_CONTEXT_OF(provctx);

    return peddsactx;
}

static int eddsa_digest_signverify_init(void *vpeddsactx, const char *mdname,
                                        const char *props, void *vedkey)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    ECX_KEY *edkey = (ECX_KEY *)vedkey;

    if (mdname != NULL) {
        PROVerr(0, PROV_R_INVALID_DIGEST);
        return 0;
    }

    if (!ecx_key_up_ref(edkey)) {
        PROVerr(0, ERR_R_INTERNAL_ERROR);
        return 0;
    }

    peddsactx->key = edkey;

    return 1;
}

int ed25519_digest_sign(void *vpeddsactx, unsigned char *sigret,
                        size_t *siglen, size_t sigsize,
                        const unsigned char *tbs, size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (sigret == NULL) {
        *siglen = ED25519_SIGSIZE;
        return 1;
    }
    if (sigsize < ED25519_SIGSIZE) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED25519_sign(sigret, tbs, tbslen, edkey->pubkey, edkey->privkey) == 0) {
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

    if (sigret == NULL) {
        *siglen = ED448_SIGSIZE;
        return 1;
    }
    if (sigsize < ED448_SIGSIZE) {
        PROVerr(0, PROV_R_OUTPUT_BUFFER_TOO_SMALL);
        return 0;
    }

    if (ED448_sign(peddsactx->libctx, sigret, tbs, tbslen, edkey->pubkey,
                   edkey->privkey, NULL, 0) == 0) {
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

    if (siglen != ED25519_SIGSIZE)
        return 0;

    return ED25519_verify(tbs, tbslen, sig, edkey->pubkey);
}

int ed448_digest_verify(void *vpeddsactx, const unsigned char *sig,
                        size_t siglen, const unsigned char *tbs,
                        size_t tbslen)
{
    PROV_EDDSA_CTX *peddsactx = (PROV_EDDSA_CTX *)vpeddsactx;
    const ECX_KEY *edkey = peddsactx->key;

    if (siglen != ED448_SIGSIZE)
        return 0;

    return ED448_verify(peddsactx->libctx, tbs, tbslen, sig, edkey->pubkey,
                        NULL, 0);
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

const OSSL_DISPATCH ed25519_signature_functions[] = {
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
    { 0, NULL }
};

const OSSL_DISPATCH ed448_signature_functions[] = {
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
    { 0, NULL }
};
