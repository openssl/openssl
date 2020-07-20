/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * RSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <string.h>

#include <openssl/core_dispatch.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include "prov/bio.h"
#include "prov/bio.h"
#include "prov/providercommonerr.h"
#include "serializer_local.h"

static OSSL_FUNC_deserializer_newctx_fn pem2der_newctx;
static OSSL_FUNC_deserializer_freectx_fn pem2der_freectx;
static OSSL_FUNC_deserializer_gettable_params_fn pem2der_gettable_params;
static OSSL_FUNC_deserializer_get_params_fn pem2der_get_params;
static OSSL_FUNC_deserializer_deserialize_fn pem2der_deserialize;

/*
 * Context used for PEM to DER deserialization.
 */
struct pem2der_ctx_st {
    PROV_CTX *provctx;

    /* Set to 1 if intending to encrypt/decrypt, otherwise 0 */
    int cipher_intent;

    EVP_CIPHER *cipher;

    /* Passphrase that was passed by the caller */
    void *cipher_pass;
    size_t cipher_pass_length;

    /* This callback is only used if |cipher_pass| is NULL */
    OSSL_PASSPHRASE_CALLBACK *cb;
    void *cbarg;
};

static void *pem2der_newctx(void *provctx)
{
    struct pem2der_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL)
        ctx->provctx = provctx;
    return ctx;
}

static void pem2der_freectx(void *vctx)
{
    struct pem2der_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->cipher);
    OPENSSL_clear_free(ctx->cipher_pass, ctx->cipher_pass_length);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *pem2der_gettable_params(void)
{
    static const OSSL_PARAM gettables[] = {
        { OSSL_DESERIALIZER_PARAM_INPUT_TYPE, OSSL_PARAM_UTF8_PTR, NULL, 0, 0 },
        OSSL_PARAM_END,
    };

    return gettables;
}

static int pem2der_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    p = OSSL_PARAM_locate(params, OSSL_DESERIALIZER_PARAM_INPUT_TYPE);
    if (p != NULL && !OSSL_PARAM_set_utf8_ptr(p, "PEM"))
        return 0;

    return 1;
}

static const OSSL_PARAM *pem2der_settable_ctx_params(void)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_octet_string(OSSL_DESERIALIZER_PARAM_PASS, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int pem2der_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct pem2der_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_PASS))
        != NULL) {
        OPENSSL_clear_free(ctx->cipher_pass, ctx->cipher_pass_length);
        ctx->cipher_pass = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &ctx->cipher_pass, 0,
                                         &ctx->cipher_pass_length))
            return 0;
    }
    return 1;
}

/* pem_password_cb compatible function */
static int pem2der_pass_helper(char *buf, int num, int w, void *data)
{
    struct pem2der_ctx_st *ctx = data;
    size_t plen;

    if (ctx->cipher_pass != NULL) {
        if (ctx->cipher_pass_length < (size_t)num - 1) {
            strncpy(buf, ctx->cipher_pass, ctx->cipher_pass_length);
            buf[ctx->cipher_pass_length] = '\0';
        } else {
            OPENSSL_strlcpy(buf, ctx->cipher_pass, num);
        }
    } else if (ctx->cb == NULL
               || !ctx->cb(buf, num, &plen, NULL, ctx->cbarg)) {
        return -1;
    }
    return (int)ctx->cipher_pass_length;
}

static int pem2der_deserialize(void *vctx, OSSL_CORE_BIO *cin,
                               OSSL_CALLBACK *data_cb, void *data_cbarg,
                               OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
    struct pem2der_ctx_st *ctx = vctx;
    char *pem_name = NULL, *pem_header = NULL;
    unsigned char *der = NULL;
    long der_len = 0;
    int ok = 0;

    if (ossl_prov_read_pem(ctx->provctx, cin, &pem_name, &pem_header,
                           &der, &der_len) <= 0)
        return 0;

    /*
     * 10 is the number of characters in "Proc-Type:", which
     * PEM_get_EVP_CIPHER_INFO() requires to be present.
     * If the PEM header has less characters than that, it's
     * not worth spending cycles on it.
     */
    if (strlen(pem_header) > 10) {
        EVP_CIPHER_INFO cipher;

        if (!PEM_get_EVP_CIPHER_INFO(pem_header, &cipher)
            || !PEM_do_header(&cipher, der, &der_len, pem2der_pass_helper, ctx))
            goto end;
    }

    {
        OSSL_PARAM params[3];

        params[0] =
            OSSL_PARAM_construct_utf8_string(OSSL_DESERIALIZER_PARAM_DATA_TYPE,
                                             pem_name, 0);
        params[1] =
            OSSL_PARAM_construct_octet_string(OSSL_DESERIALIZER_PARAM_DATA,
                                              der, der_len);
        params[2] = OSSL_PARAM_construct_end();

        ok = data_cb(params, data_cbarg);
    }

 end:
    OPENSSL_free(pem_name);
    OPENSSL_free(pem_header);
    OPENSSL_free(der);
    return ok;
}

const OSSL_DISPATCH pem_to_der_deserializer_functions[] = {
    { OSSL_FUNC_DESERIALIZER_NEWCTX, (void (*)(void))pem2der_newctx },
    { OSSL_FUNC_DESERIALIZER_FREECTX, (void (*)(void))pem2der_freectx },
    { OSSL_FUNC_DESERIALIZER_GETTABLE_PARAMS,
      (void (*)(void))pem2der_gettable_params },
    { OSSL_FUNC_DESERIALIZER_GET_PARAMS,
      (void (*)(void))pem2der_get_params },
    { OSSL_FUNC_DESERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))pem2der_settable_ctx_params },
    { OSSL_FUNC_DESERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))pem2der_set_ctx_params },
    { OSSL_FUNC_DESERIALIZER_DESERIALIZE, (void (*)(void))pem2der_deserialize },
    { 0, NULL }
};
