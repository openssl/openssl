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
#include <openssl/rsa.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include <openssl/safestack.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn rsa_priv_newctx;
static OSSL_OP_serializer_freectx_fn rsa_priv_freectx;
static OSSL_OP_serializer_set_ctx_params_fn rsa_priv_set_ctx_params;
static OSSL_OP_serializer_settable_ctx_params_fn rsa_priv_settable_ctx_params;
static OSSL_OP_serializer_serialize_data_fn rsa_priv_der_data;
static OSSL_OP_serializer_serialize_object_fn rsa_priv_der;
static OSSL_OP_serializer_serialize_data_fn rsa_pem_priv_data;
static OSSL_OP_serializer_serialize_object_fn rsa_pem_priv;

static OSSL_OP_serializer_newctx_fn rsa_print_newctx;
static OSSL_OP_serializer_freectx_fn rsa_print_freectx;
static OSSL_OP_serializer_serialize_data_fn rsa_priv_print_data;
static OSSL_OP_serializer_serialize_object_fn rsa_priv_print;

 /*
 * Context used for private key serialization.
 */
struct rsa_priv_ctx_st {
    void *provctx;

    struct pkcs8_encrypt_ctx_st sc;
};

/* Helper functions to prepare RSA-PSS params for serialization */

static int prepare_rsa_params(const void *rsa, int nid,
                              ASN1_STRING **pstr, int *pstrtype)
{
    const RSA_PSS_PARAMS *pss = RSA_get0_pss_params(rsa);
    *pstr = NULL;

    /* If RSA it's just NULL type */
    if (nid != EVP_PKEY_RSA_PSS) {
        *pstrtype = V_ASN1_NULL;
        return 1;
    }
    /* If no PSS parameters we omit parameters entirely */
    if (pss == NULL) {
        *pstrtype = V_ASN1_UNDEF;
        return 1;
    }
    /* Encode PSS parameters */
    if (ASN1_item_pack((void *)pss, ASN1_ITEM_rptr(RSA_PSS_PARAMS), pstr)
        == NULL)
        return 0;

    *pstrtype = V_ASN1_SEQUENCE;
    return 1;
}

/* Private key : context */
static void *rsa_priv_newctx(void *provctx)
{
    struct rsa_priv_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;
        /* -1 is the "whatever" indicator, i.e. the PKCS8 library default PBE */
        ctx->sc.pbe_nid = -1;
    }
    return ctx;
}

static void rsa_priv_freectx(void *vctx)
{
    struct rsa_priv_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->sc.cipher);
    OPENSSL_free(ctx->sc.cipher_pass);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *rsa_priv_settable_ctx_params(void)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_SERIALIZER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SERIALIZER_PARAM_PASS, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int rsa_priv_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct rsa_priv_ctx_st *ctx = vctx;
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
static int rsa_priv_der_data(void *vctx, const OSSL_PARAM params[], BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct rsa_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_OP_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_OP_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        if ((rsa = rsa_new(ctx->provctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_priv_der(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_priv_der(void *vctx, void *rsa, BIO *out,
                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct rsa_priv_ctx_st *ctx = vctx;
    int ret;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_der_from_obj(out, rsa, EVP_PKEY_RSA,
                                            prepare_rsa_params,
                                            (i2d_of_void *)i2d_RSAPrivateKey,
                                            &ctx->sc);

    return ret;
}

/* Private key : PEM */
static int rsa_pem_priv_data(void *vctx, const OSSL_PARAM params[], BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct rsa_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_OP_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_OP_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        if ((rsa = rsa_new(ctx->provctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_pem_priv(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_pem_priv(void *vctx, void *rsa, BIO *out,
                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct rsa_priv_ctx_st *ctx = vctx;
    int ret;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_pem_from_obj(out, rsa, EVP_PKEY_RSA,
                                            prepare_rsa_params,
                                            (i2d_of_void *)i2d_RSAPrivateKey,
                                            &ctx->sc);

    return ret;
}

/*
 * There's no specific print context, so we use the provider context
 */
static void *rsa_print_newctx(void *provctx)
{
    return provctx;
}

static void rsa_print_freectx(void *ctx)
{
}

static int rsa_priv_print_data(void *vctx, const OSSL_PARAM params[],
                               BIO *out,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct rsa_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *rsa_new = ossl_prov_get_keymgmt_rsa_new();
    OSSL_OP_keymgmt_free_fn *rsa_free = ossl_prov_get_keymgmt_rsa_free();
    OSSL_OP_keymgmt_import_fn *rsa_import = ossl_prov_get_keymgmt_rsa_import();
    int ok = 0;

    if (rsa_import != NULL) {
        RSA *rsa;

        if ((rsa = rsa_new(ctx->provctx)) != NULL
            && rsa_import(rsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && rsa_priv_print(ctx, rsa, out, cb, cbarg))
            ok = 1;
        rsa_free(rsa);
    }
    return ok;
}

static int rsa_priv_print(void *ctx, void *rsa, BIO *out,
                          OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_print_rsa(out, rsa, 1);
}

const OSSL_DISPATCH rsa_priv_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_priv_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_priv_freectx },
    { OSSL_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))rsa_priv_set_ctx_params },
    { OSSL_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_priv_settable_ctx_params },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))rsa_priv_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_priv_der },
    { 0, NULL }
};

const OSSL_DISPATCH rsa_priv_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_priv_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_priv_freectx },
    { OSSL_FUNC_SERIALIZER_SET_CTX_PARAMS,
      (void (*)(void))rsa_priv_set_ctx_params },
    { OSSL_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS,
      (void (*)(void))rsa_priv_settable_ctx_params },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))rsa_pem_priv_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_pem_priv },
    { 0, NULL }
};

const OSSL_DISPATCH rsa_priv_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))rsa_print_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))rsa_print_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))rsa_priv_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))rsa_priv_print_data },
    { 0, NULL }
};
