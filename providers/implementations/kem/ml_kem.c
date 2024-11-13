/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/proverr.h>
#include "prov/provider_ctx.h"
#include "prov/implementations.h"
#include "prov/securitycheck.h"
#include "prov/providercommon.h"
#include "prov/mlkem.h"

#define BUFSIZE 1000
#if defined(NDEBUG) || defined(OPENSSL_NO_STDIO)
/* TODO(ML-KEM) to remove or replace with TRACE */
static void debug_print(char *fmt, ...)
{
}
#else
static void debug_print(char *fmt, ...)
{
    char out[BUFSIZE];
    va_list argptr;

    va_start(argptr, fmt);
    vsnprintf(out, BUFSIZE, fmt, argptr);
    va_end(argptr);
    if (getenv("TEMPLATEKM"))
        fprintf(stderr, "TEMPLATE_KM: %s", out);
}
#endif

typedef struct {
    OSSL_LIB_CTX *libctx;
    MLKEM768_KEY *key;
    int op;
    uint8_t *entropy;
} PROV_MLKEM_CTX;

static OSSL_FUNC_kem_newctx_fn mlkem_newctx;
static OSSL_FUNC_kem_encapsulate_init_fn mlkem_encapsulate_init;
static OSSL_FUNC_kem_encapsulate_fn mlkem_encapsulate;
static OSSL_FUNC_kem_decapsulate_init_fn mlkem_decapsulate_init;
static OSSL_FUNC_kem_decapsulate_fn mlkem_decapsulate;
static OSSL_FUNC_kem_freectx_fn mlkem_freectx;
static OSSL_FUNC_kem_set_ctx_params_fn mlkem_set_ctx_params;

static void *mlkem_newctx(void *provctx)
{
    PROV_MLKEM_CTX *ctx = OPENSSL_zalloc(sizeof(*ctx));

    debug_print("MLKEMKEM newctx called\n");
    if (ctx == NULL)
        return NULL;

    ctx->libctx = PROV_LIBCTX_OF(provctx);

    debug_print("MLKEMKEM newctx returns %p\n", ctx);
    return ctx;
}

static void mlkem_freectx(void *vctx)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;

    OPENSSL_free(ctx->entropy);
    debug_print("MLKEMKEM freectx %p\n", ctx);
    OPENSSL_free(ctx);
}

static int mlkem_init(void *vctx, int operation, void *vkey, void *vauth,
                      const OSSL_PARAM params[])
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;
    MLKEM768_KEY *mlkemkey = vkey;

    debug_print("MLKEMKEM init %p / %p\n", ctx, mlkemkey);
    if (!ossl_prov_is_running())
        return 0;

    if (mlkemkey->keytype != MLKEM_KEY_TYPE_768)
        return 0;

    ctx->key = mlkemkey;
    ctx->op = operation;
    ctx->entropy = NULL;

    if (!mlkem_set_ctx_params(vctx, params))
        return 0;

    debug_print("MLKEMKEM init OK\n");
    return 1;
}

static int mlkem_encapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    return mlkem_init(vctx, EVP_PKEY_OP_ENCAPSULATE, vkey, NULL, params);
}

static int mlkem_decapsulate_init(void *vctx, void *vkey,
                                  const OSSL_PARAM params[])
{
    return mlkem_init(vctx, EVP_PKEY_OP_DECAPSULATE, vkey, NULL, params);
}

static int mlkem_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;
    const OSSL_PARAM *p;

    debug_print("MLKEMKEM set ctx params %p\n", ctx);
    if (ctx == NULL)
        return 0;
    if (params == NULL)
        return 1;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_KEM_PARAM_MLKEM_ENC_ENTROPY)) != NULL
        && (p->data_size != MLKEM_ENCAP_ENTROPY
            || (ctx->entropy = OPENSSL_memdup(p->data, MLKEM_ENCAP_ENTROPY)) == NULL))
        return 0;

    debug_print("MLKEMKEM set ctx params OK\n");
    return 1;
}

static const OSSL_PARAM known_settable_mlkem_ctx_params[] = {
    OSSL_PARAM_octet_string(OSSL_KEM_PARAM_MLKEM_ENC_ENTROPY, NULL, 0),
    OSSL_PARAM_END
};

static const OSSL_PARAM *mlkem_settable_ctx_params(ossl_unused void *vctx,
                                                   ossl_unused void *provctx)
{
    return known_settable_mlkem_ctx_params;
}

static int mlkem_encapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             unsigned char *secret, size_t *secretlen)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;
    int ret;

    debug_print("MLKEMKEM encaps %p to %p\n", ctx, out);
    if (outlen != NULL)
        *outlen = OSSL_MLKEM768_CIPHERTEXT_BYTES;
    if (secretlen != NULL)
        *secretlen = OSSL_MLKEM768_SHARED_SECRET_BYTES;

    if (out == NULL) {
        debug_print("MLKEMKEM encaps outlens set to %ld and %ld\n", *outlen, *secretlen);
        return 1;
    }

    if (ctx->key == NULL
        || ctx->key->keytype != MLKEM_KEY_TYPE_768
        || ctx->key->encoded_pubkey == NULL
        || secret == NULL)
        return 0;

    if (ctx->entropy != NULL) {
        ret = ossl_mlkem768_encap_external_entropy(out, secret,
                                                   &ctx->key->pubkey,
                                                   ctx->entropy,
                                                   ctx->key->mlkem_ctx);
    } else {
        ret = ossl_mlkem768_encap(out, (uint8_t *)secret, &ctx->key->pubkey,
                                  ctx->key->mlkem_ctx);
    }

    debug_print("MLKEMKEM encaps returns %d\n", ret);
    return ret;
}

static int mlkem_decapsulate(void *vctx, unsigned char *out, size_t *outlen,
                             const unsigned char *in, size_t inlen)
{
    PROV_MLKEM_CTX *ctx = (PROV_MLKEM_CTX *)vctx;
    int ret;

    debug_print("MLKEMKEM decaps %p to %p\n", ctx, out);
    debug_print("MLKEMKEM decaps inlen at %ld\n", inlen);
    if (outlen != NULL)
        *outlen = OSSL_MLKEM768_SHARED_SECRET_BYTES;

    if (out == NULL) {
        debug_print("MLKEMKEM decaps outlen set to %ld \n", *outlen);
        return 1;
    }

    if (ctx->key == NULL
        || ctx->key->keytype != MLKEM_KEY_TYPE_768
        || ctx->key->encoded_privkey == NULL
        || in == NULL)
        return 0;

    if (inlen != OSSL_MLKEM768_CIPHERTEXT_BYTES)
        return 0;

    ret = ossl_mlkem768_decap((uint8_t *)out, (uint8_t *)in, inlen, &ctx->key->privkey,
                              ctx->key->mlkem_ctx);

    debug_print("MLKEMKEM decaps returns %d\n", ret);
    return ret;
}

const OSSL_DISPATCH ossl_mlkem768_asym_kem_functions[] = {
    { OSSL_FUNC_KEM_NEWCTX, (void (*)(void))mlkem_newctx },
    { OSSL_FUNC_KEM_ENCAPSULATE_INIT,
      (void (*)(void))mlkem_encapsulate_init },
    { OSSL_FUNC_KEM_ENCAPSULATE, (void (*)(void))mlkem_encapsulate },
    { OSSL_FUNC_KEM_DECAPSULATE_INIT,
      (void (*)(void))mlkem_decapsulate_init },
    { OSSL_FUNC_KEM_DECAPSULATE, (void (*)(void))mlkem_decapsulate },
    { OSSL_FUNC_KEM_FREECTX, (void (*)(void))mlkem_freectx },
    { OSSL_FUNC_KEM_SET_CTX_PARAMS,
      (void (*)(void))mlkem_set_ctx_params },
    { OSSL_FUNC_KEM_SETTABLE_CTX_PARAMS,
      (void (*)(void))mlkem_settable_ctx_params },
    OSSL_DISPATCH_END
};
