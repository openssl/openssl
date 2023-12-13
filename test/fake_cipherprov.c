/*
 * Copyright 2023 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * https://www.openssl.org/source/license.html
 * or in the file LICENSE in the source distribution.
 */

#include <string.h>
#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/rand.h>
#include <openssl/provider.h>
#include "prov/ciphercommon.h"
#include "testutil.h"
#include "fake_cipherprov.h"

typedef struct prov_fake_cipher_ctx_st {
    int enc;
    size_t tlsmacsize;
    const unsigned char *tlsmac;
} PROV_FAKE_CIPHER_CTX;

static OSSL_FUNC_cipher_newctx_fn fake_cipher_newctx;
static OSSL_FUNC_cipher_freectx_fn fake_cipher_freectx;
static OSSL_FUNC_cipher_encrypt_init_fn fake_cipher_einit;
static OSSL_FUNC_cipher_decrypt_init_fn fake_cipher_dinit;
static OSSL_FUNC_cipher_cipher_fn fake_cipher_cipher;
static OSSL_FUNC_cipher_final_fn fake_cipher_final;
static OSSL_FUNC_cipher_get_params_fn fake_cipher_get_params;
static OSSL_FUNC_cipher_get_params_fn fake_cipher_bad_get_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn fake_cipher_gettable_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn fake_cipher_settable_ctx_params;
static OSSL_FUNC_cipher_set_ctx_params_fn fake_cipher_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn fake_cipher_get_ctx_params;

static void *fake_cipher_newctx(void *provctx)
{
    return OPENSSL_zalloc(sizeof(PROV_FAKE_CIPHER_CTX));
}

static void fake_cipher_freectx(void *vctx)
{
    OPENSSL_free(vctx);
}

static int fake_cipher_einit(void *vctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[])
{
    PROV_FAKE_CIPHER_CTX *ctx = (PROV_FAKE_CIPHER_CTX *)vctx;

    ctx->enc = 1;
    return 1;
}


static int fake_cipher_dinit(void *vctx, const unsigned char *key, size_t keylen,
                             const unsigned char *iv, size_t ivlen,
                             const OSSL_PARAM params[])
{
    return 1;
}

static int fake_cipher_cipher(void *vctx,
                              unsigned char *out, size_t *outl, size_t outsize,
                              const unsigned char *in, size_t inl)
{
    PROV_FAKE_CIPHER_CTX *ctx = (PROV_FAKE_CIPHER_CTX *)vctx;

    if (!ctx->enc && ctx->tlsmacsize > 0) {
        if (inl < ctx->tlsmacsize)
            return 0;
        ctx->tlsmac = in + inl - ctx->tlsmacsize;
        inl -= ctx->tlsmacsize;
    }
    if (outsize < inl)
        return 0;
    if (in != out && out != NULL)
        memcpy(out, in, inl);
    if (outl != NULL)
        *outl = inl;
    return 1;
}

static int fake_cipher_final(void *vctx, unsigned char *out, size_t *outl,
                             size_t outsize)
{
    *outl = 0;
    return 1;
}

static int fake_cipher_bad_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if (!ossl_cipher_generic_get_params(params, 0, 0, 16*8, 0, 16*8))
        return 0;
    /* Setup a invalid blocksize */
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_BLOCK_SIZE);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, -1))
        return 0;
    return 1;
}

static int fake_cipher_get_params(OSSL_PARAM params[])
{
    return ossl_cipher_generic_get_params(params, 0, 0, 16*8, 8, 16*8);
}

static const OSSL_PARAM known_gettable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_KEYLEN, NULL),
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_IVLEN, NULL),
    { OSSL_CIPHER_PARAM_TLS_MAC, OSSL_PARAM_OCTET_PTR, NULL, 0,
      OSSL_PARAM_UNMODIFIED },
    OSSL_PARAM_END
};

static const OSSL_PARAM *fake_cipher_gettable_ctx_params(ossl_unused void *cctx,
                                                         ossl_unused void *provctx)
{
    return known_gettable_ctx_params;
}

static int fake_cipher_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    PROV_FAKE_CIPHER_CTX *ctx = (PROV_FAKE_CIPHER_CTX *)vctx;
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_IVLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_KEYLEN);
    if (p != NULL && !OSSL_PARAM_set_size_t(p, 16))
        return 0;
    p = OSSL_PARAM_locate(params, OSSL_CIPHER_PARAM_TLS_MAC);
    if (p != NULL
            && !OSSL_PARAM_set_octet_ptr(p, ctx->tlsmac, ctx->tlsmacsize))
        return 0;
    return 1;
}

static const OSSL_PARAM known_settable_ctx_params[] = {
    OSSL_PARAM_size_t(OSSL_CIPHER_PARAM_TLS_MAC_SIZE, NULL),
    OSSL_PARAM_END
};

static const OSSL_PARAM *fake_cipher_settable_ctx_params(ossl_unused void *cctx,
                                                         ossl_unused void *provctx)
{
    return known_settable_ctx_params;
}

static int fake_cipher_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_FAKE_CIPHER_CTX *ctx = (PROV_FAKE_CIPHER_CTX *)vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_CIPHER_PARAM_TLS_MAC_SIZE);
    if (p != NULL
            && !OSSL_PARAM_get_size_t(p, &ctx->tlsmacsize))
        return 0;

    return 1;
}

/* This cipher is used to test an invalid blocksize being used by API's */
static const OSSL_DISPATCH fake_bad_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void)) fake_cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) fake_cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))fake_cipher_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))fake_cipher_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))fake_cipher_cipher },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))fake_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))fake_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) fake_cipher_bad_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
      (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))fake_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))fake_cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))fake_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))fake_cipher_settable_ctx_params },
    OSSL_DISPATCH_END
};

static const OSSL_DISPATCH fake_good_cipher_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX,
      (void (*)(void)) fake_cipher_newctx },
    { OSSL_FUNC_CIPHER_FREECTX, (void (*)(void)) fake_cipher_freectx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (void (*)(void))fake_cipher_einit },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (void (*)(void))fake_cipher_dinit },
    { OSSL_FUNC_CIPHER_UPDATE, (void (*)(void))fake_cipher_cipher },
    { OSSL_FUNC_CIPHER_FINAL, (void (*)(void))fake_cipher_final },
    { OSSL_FUNC_CIPHER_CIPHER, (void (*)(void))fake_cipher_cipher },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (void (*)(void)) fake_cipher_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS,
      (void (*)(void))ossl_cipher_generic_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS,
      (void (*)(void))fake_cipher_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (void (*)(void))fake_cipher_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS,
      (void (*)(void))fake_cipher_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (void (*)(void))fake_cipher_settable_ctx_params },
    OSSL_DISPATCH_END
};


static const OSSL_ALGORITHM fake_cipher_algs[] = {
    { "Good", "provider=fake-cipher", fake_good_cipher_functions, "Fake Cipher" },
    { "Bad", "provider=fake-cipher", fake_bad_cipher_functions, "Fake Cipher" },
    { NULL, NULL, NULL, NULL }
};

static const OSSL_ALGORITHM *fake_cipher_query(void *provctx,
                                               int operation_id,
                                               int *no_cache)
{
    *no_cache = 0;
    if (operation_id == OSSL_OP_CIPHER)
        return fake_cipher_algs;
    return NULL;
}

/* Functions we provide to the core */
static const OSSL_DISPATCH fake_cipher_method[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))OSSL_LIB_CTX_free },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))fake_cipher_query },
    OSSL_DISPATCH_END
};

static int fake_cipher_provider_init(const OSSL_CORE_HANDLE *handle,
                                     const OSSL_DISPATCH *in,
                                     const OSSL_DISPATCH **out, void **provctx)
{
    if (!TEST_ptr(*provctx = OSSL_LIB_CTX_new()))
        return 0;
    *out = fake_cipher_method;
    return 1;
}

OSSL_PROVIDER *fake_cipher_start(OSSL_LIB_CTX *libctx)
{
    OSSL_PROVIDER *p;

    if (!TEST_true(OSSL_PROVIDER_add_builtin(libctx, "fake-cipher",
                                             fake_cipher_provider_init))
            || !TEST_ptr(p = OSSL_PROVIDER_try_load(libctx, "fake-cipher", 1)))
        return NULL;

    return p;
}

void fake_cipher_finish(OSSL_PROVIDER *p)
{
    OSSL_PROVIDER_unload(p);
}
