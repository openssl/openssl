/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/core_names.h>
#include <opentls/err.h>
#include <opentls/pem.h>
#include <opentls/dsa.h>
#include <opentls/types.h>
#include <opentls/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static Otls_OP_serializer_newctx_fn dsa_priv_newctx;
static Otls_OP_serializer_freectx_fn dsa_priv_freectx;
static Otls_OP_serializer_set_ctx_params_fn dsa_priv_set_ctx_params;
static Otls_OP_serializer_settable_ctx_params_fn dsa_priv_settable_ctx_params;
static Otls_OP_serializer_serialize_data_fn dsa_priv_der_data;
static Otls_OP_serializer_serialize_object_fn dsa_priv_der;
static Otls_OP_serializer_serialize_data_fn dsa_pem_priv_data;
static Otls_OP_serializer_serialize_object_fn dsa_pem_priv;

static Otls_OP_serializer_newctx_fn dsa_print_newctx;
static Otls_OP_serializer_freectx_fn dsa_print_freectx;
static Otls_OP_serializer_serialize_data_fn dsa_priv_print_data;
static Otls_OP_serializer_serialize_object_fn dsa_priv_print;

 /*
 * Context used for private key serialization.
 */
struct dsa_priv_ctx_st {
    void *provctx;

    struct pkcs8_encrypt_ctx_st sc;
};

/* Private key : context */
static void *dsa_priv_newctx(void *provctx)
{
    struct dsa_priv_ctx_st *ctx = OPENtls_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;

        /* -1 is the "whatever" indicator, i.e. the PKCS8 library default PBE */
        ctx->sc.pbe_nid = -1;
    }
    return ctx;
}

static void dsa_priv_freectx(void *vctx)
{
    struct dsa_priv_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->sc.cipher);
    OPENtls_free(ctx->sc.cipher_pass);
    OPENtls_free(ctx);
}

static const Otls_PARAM *dsa_priv_settable_ctx_params(void)
{
    static const Otls_PARAM settables[] = {
        Otls_PARAM_utf8_string(Otls_SERIALIZER_PARAM_CIPHER, NULL, 0),
        Otls_PARAM_octet_string(Otls_SERIALIZER_PARAM_PASS, NULL, 0),
        Otls_PARAM_END,
    };

    return settables;
}

static int dsa_priv_set_ctx_params(void *vctx, const Otls_PARAM params[])
{
    struct dsa_priv_ctx_st *ctx = vctx;
    const Otls_PARAM *p;

    if ((p = Otls_PARAM_locate_const(params, Otls_SERIALIZER_PARAM_CIPHER))
        != NULL) {
        const Otls_PARAM *propsp =
            Otls_PARAM_locate_const(params, Otls_SERIALIZER_PARAM_PROPERTIES);
        const char *props = NULL;

        if (p->data_type != Otls_PARAM_UTF8_STRING)
            return 0;
        if (propsp != NULL && propsp->data_type != Otls_PARAM_UTF8_STRING)
            return 0;
        props = (propsp != NULL ? propsp->data : NULL);

        EVP_CIPHER_free(ctx->sc.cipher);
        ctx->sc.cipher_intent = p->data != NULL;
        if (p->data != NULL
            && ((ctx->sc.cipher = EVP_CIPHER_fetch(NULL, p->data, props))
                == NULL))
            return 0;
    }
    if ((p = Otls_PARAM_locate_const(params, Otls_SERIALIZER_PARAM_PASS))
        != NULL) {
        OPENtls_free(ctx->sc.cipher_pass);
        ctx->sc.cipher_pass = NULL;
        if (!Otls_PARAM_get_octet_string(p, &ctx->sc.cipher_pass, 0,
                                         &ctx->sc.cipher_pass_length))
            return 0;
    }
    return 1;
}

/* Private key : DER */
static int dsa_priv_der_data(void *vctx, const Otls_PARAM params[], BIO *out,
                             Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dsa_priv_ctx_st *ctx = vctx;
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(ctx->provctx, params);

        ok = dsa_priv_der(ctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_priv_der(void *vctx, void *dsa, BIO *out,
                        Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dsa_priv_ctx_st *ctx = vctx;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    return otls_prov_write_priv_der_from_obj(out, dsa, EVP_PKEY_DSA,
                                             otls_prov_prepare_dsa_params,
                                             otls_prov_dsa_priv_to_der,
                                             &ctx->sc);
}

/* Private key : PEM */
static int dsa_pem_priv_data(void *vctx, const Otls_PARAM params[], BIO *out,
                             Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dsa_priv_ctx_st *ctx = vctx;
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(ctx, params);

        ok = dsa_pem_priv(ctx->provctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_pem_priv(void *vctx, void *dsa, BIO *out,
                        Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct dsa_priv_ctx_st *ctx = vctx;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    return otls_prov_write_priv_pem_from_obj(out, dsa, EVP_PKEY_DSA,
                                             otls_prov_prepare_dsa_params,
                                             otls_prov_dsa_priv_to_der,
                                             &ctx->sc);
}

/*
 * There's no specific print context, so we use the provider context
 */
static void *dsa_print_newctx(void *provctx)
{
    return provctx;
}

static void dsa_print_freectx(void *ctx)
{
}

static int dsa_priv_print_data(void *provctx, const Otls_PARAM params[],
                               BIO *out,
                               Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(provctx, params); /* ctx == provctx */

        ok = dsa_priv_print(provctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_priv_print(void *ctx, void *dsa, BIO *out,
                          Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return otls_prov_print_dsa(out, dsa, dsa_print_priv);
}

const Otls_DISPATCH dsa_priv_der_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_priv_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_priv_freectx },
    { Otls_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))dsa_priv_set_ctx_params },
    { Otls_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_priv_settable_ctx_params },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_priv_der_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_priv_der },
    { 0, NULL }
};

const Otls_DISPATCH dsa_priv_pem_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_priv_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_priv_freectx },
    { Otls_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))dsa_priv_set_ctx_params },
    { Otls_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))dsa_priv_settable_ctx_params },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_pem_priv_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_pem_priv },
    { 0, NULL }
};

const Otls_DISPATCH dsa_priv_text_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_print_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_print_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_priv_print },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dsa_priv_print_data },
    { 0, NULL }
};
