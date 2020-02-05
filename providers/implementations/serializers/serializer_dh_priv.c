/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dh.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn dh_priv_newctx;
static OSSL_OP_serializer_freectx_fn dh_priv_freectx;
static OSSL_OP_serializer_set_ctx_params_fn dh_priv_set_ctx_params;
static OSSL_OP_serializer_settable_ctx_params_fn dh_priv_settable_ctx_params;
static OSSL_OP_serializer_serialize_data_fn dh_priv_der_data;
static OSSL_OP_serializer_serialize_object_fn dh_priv_der;
static OSSL_OP_serializer_serialize_data_fn dh_pem_priv_data;
static OSSL_OP_serializer_serialize_object_fn dh_pem_priv;

static OSSL_OP_serializer_newctx_fn dh_print_newctx;
static OSSL_OP_serializer_freectx_fn dh_print_freectx;
static OSSL_OP_serializer_serialize_data_fn dh_priv_print_data;
static OSSL_OP_serializer_serialize_object_fn dh_priv_print;

 /*
 * Context used for private key serialization.
 */
struct dh_priv_ctx_st {
    void *provctx;

    struct pkcs8_encrypt_ctx_st sc;
};

/* Private key : context */
static void *dh_priv_newctx(void *provctx)
{
    struct dh_priv_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;

        /* -1 is the "whatever" indicator, i.e. the PKCS8 library default PBE */
        ctx->sc.pbe_nid = -1;
    }
    return ctx;
}

static void dh_priv_freectx(void *vctx)
{
    struct dh_priv_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->sc.cipher);
    OPENSSL_free(ctx->sc.cipher_pass);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *dh_priv_settable_ctx_params(void)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_SERIALIZER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SERIALIZER_PARAM_PASS, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int dh_priv_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct dh_priv_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_CIPHER))
        != NULL) {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_PROPERTIES);
        const char *props = NULL;

        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        if (propsp != NULL && propsp->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        props = (propsp != NULL ? propsp->data : NULL);

        EVP_CIPHER_free(ctx->sc.cipher);
        ctx->sc.cipher_intent = p->data != NULL;
        if (p->data != NULL
            && ((ctx->sc.cipher = EVP_CIPHER_fetch(NULL, p->data, props))
                == NULL))
            return 0;
    }
    if ((p = OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_PASS))
        != NULL) {
        OPENSSL_free(ctx->sc.cipher_pass);
        ctx->sc.cipher_pass = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &ctx->sc.cipher_pass, 0,
                                         &ctx->sc.cipher_pass_length))
            return 0;
    }
    return 1;
}

/* Private key : DER */
static int dh_priv_der_data(void *vctx, const OSSL_PARAM params[], BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dh_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        if ((dh = dh_new(ctx->provctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_priv_der(ctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_priv_der(void *vctx, void *dh, BIO *out,
                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dh_priv_ctx_st *ctx = vctx;
    int ret;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_der_from_obj(out, dh, EVP_PKEY_DH,
                                            ossl_prov_prepare_dh_params,
                                            ossl_prov_dh_priv_to_der,
                                            &ctx->sc);

    return ret;
}

/* Private key : PEM */
static int dh_pem_priv_data(void *vctx, const OSSL_PARAM params[], BIO *out,
                            OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dh_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        if ((dh = dh_new(ctx->provctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_pem_priv(ctx->provctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_pem_priv(void *vctx, void *dh, BIO *out,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dh_priv_ctx_st *ctx = vctx;
    int ret;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_pem_from_obj(out, dh, EVP_PKEY_DH,
                                            ossl_prov_prepare_dh_params,
                                            ossl_prov_dh_priv_to_der,
                                            &ctx->sc);

    return ret;
}

/*
 * There's no specific print context, so we use the provider context
 */
static void *dh_print_newctx(void *provctx)
{
    return provctx;
}

static void dh_print_freectx(void *ctx)
{
}

static int dh_priv_print_data(void *vctx, const OSSL_PARAM params[], BIO *out,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dh_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *dh_new = ossl_prov_get_keymgmt_dh_new();
    OSSL_OP_keymgmt_free_fn *dh_free = ossl_prov_get_keymgmt_dh_free();
    OSSL_OP_keymgmt_import_fn *dh_import = ossl_prov_get_keymgmt_dh_import();
    int ok = 0;

    if (dh_import != NULL) {
        DH *dh;

        if ((dh = dh_new(ctx->provctx)) != NULL
            && dh_import(dh, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dh_priv_print(ctx, dh, out, cb, cbarg))
            ok = 1;
        dh_free(dh);
    }
    return ok;
}

static int dh_priv_print(void *ctx, void *dh, BIO *out,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_print_dh(out, dh, dh_print_priv);
}

const OSSL_DISPATCH dh_priv_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_priv_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_priv_freectx },
    { OSSL_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))dh_priv_set_ctx_params },
    { OSSL_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))dh_priv_settable_ctx_params },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_priv_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_priv_der },
    { 0, NULL }
};

const OSSL_DISPATCH dh_priv_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_priv_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_priv_freectx },
    { OSSL_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))dh_priv_set_ctx_params },
    { OSSL_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))dh_priv_settable_ctx_params },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_pem_priv_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pem_priv },
    { 0, NULL }
};

const OSSL_DISPATCH dh_priv_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_print_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_print_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_priv_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dh_priv_print_data },
    { 0, NULL }
};
