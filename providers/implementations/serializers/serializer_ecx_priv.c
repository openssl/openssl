/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/types.h>
#include <openssl/params.h>
#include "crypto/ecx.h"
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/provider_ctx.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn x25519_priv_newctx;
static OSSL_OP_serializer_newctx_fn x448_priv_newctx;
static OSSL_OP_serializer_newctx_fn ed25519_priv_newctx;
static OSSL_OP_serializer_newctx_fn ed448_priv_newctx;
static OSSL_OP_serializer_freectx_fn ecx_priv_freectx;
static OSSL_OP_serializer_set_ctx_params_fn ecx_priv_set_ctx_params;
static OSSL_OP_serializer_settable_ctx_params_fn ecx_priv_settable_ctx_params;
static OSSL_OP_serializer_serialize_data_fn ecx_priv_der_data;
static OSSL_OP_serializer_serialize_object_fn ecx_priv_der;
static OSSL_OP_serializer_serialize_data_fn ecx_priv_pem_data;
static OSSL_OP_serializer_serialize_object_fn ecx_priv_pem;

static OSSL_OP_serializer_serialize_data_fn ecx_priv_print_data;
static OSSL_OP_serializer_serialize_object_fn ecx_priv_print;

 /*
 * Context used for private key serialization.
 */
struct ecx_priv_ctx_st {
    void *provctx;

    struct pkcs8_encrypt_ctx_st sc;
    ECX_KEY_TYPE type;
};

/* Private key : context */
static void *ecx_priv_newctx(void *provctx, ECX_KEY_TYPE type)
{
    struct ecx_priv_ctx_st *ctx = OPENSSL_zalloc(sizeof(*ctx));

    if (ctx != NULL) {
        ctx->provctx = provctx;

        /* -1 is the "whatever" indicator, i.e. the PKCS8 library default PBE */
        ctx->sc.pbe_nid = -1;
        ctx->type = type;
    }
    return ctx;
}

static void *x25519_priv_newctx(void *provctx)
{
    return ecx_priv_newctx(provctx, ECX_KEY_TYPE_X25519);
}

static void *x448_priv_newctx(void *provctx)
{
    return ecx_priv_newctx(provctx, ECX_KEY_TYPE_X448);
}

static void *ed25519_priv_newctx(void *provctx)
{
    return ecx_priv_newctx(provctx, ECX_KEY_TYPE_ED25519);
}

static void *ed448_priv_newctx(void *provctx)
{
    return ecx_priv_newctx(provctx, ECX_KEY_TYPE_ED448);
}

static void ecx_priv_freectx(void *vctx)
{
    struct ecx_priv_ctx_st *ctx = vctx;

    EVP_CIPHER_free(ctx->sc.cipher);
    OPENSSL_free(ctx->sc.cipher_pass);
    OPENSSL_free(ctx);
}

static const OSSL_PARAM *ecx_priv_settable_ctx_params(void)
{
    static const OSSL_PARAM settables[] = {
        OSSL_PARAM_utf8_string(OSSL_SERIALIZER_PARAM_CIPHER, NULL, 0),
        OSSL_PARAM_octet_string(OSSL_SERIALIZER_PARAM_PASS, NULL, 0),
        OSSL_PARAM_END,
    };

    return settables;
}

static int ecx_priv_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct ecx_priv_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_CIPHER);
    if (p != NULL) {
        const OSSL_PARAM *propsp =
            OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_PROPERTIES);
        const char *props;

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
    p = OSSL_PARAM_locate_const(params, OSSL_SERIALIZER_PARAM_PASS);
    if (p != NULL) {
        OPENSSL_free(ctx->sc.cipher_pass);
        ctx->sc.cipher_pass = NULL;
        if (!OSSL_PARAM_get_octet_string(p, &ctx->sc.cipher_pass, 0,
                                         &ctx->sc.cipher_pass_length))
            return 0;
    }
    return 1;
}

/* Private key : DER */
static int ecx_priv_der_data(void *vctx, const OSSL_PARAM params[],
                             OSSL_CORE_BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *ecx_new;
    OSSL_OP_keymgmt_free_fn *ecx_free;
    OSSL_OP_keymgmt_import_fn *ecx_import;
    int ok = 0;

    ecx_get_new_free_import(ctx->type, &ecx_new, &ecx_free, &ecx_import);

    if (ecx_import != NULL) {
        ECX_KEY *ecxkey;

        if ((ecxkey = ecx_new(ctx->provctx)) != NULL
            && ecx_import(ecxkey, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && ecx_priv_der(ctx, ecxkey, out, cb, cbarg))
            ok = 1;
        ecx_free(ecxkey);
    }
    return ok;
}

static int ecx_priv_der(void *vctx, void *vecxkey, OSSL_CORE_BIO *cout,
                        OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    ECX_KEY *ecxkey = vecxkey;
    int ret;
    int nid = KEYTYPE2NID(ctx->type);
    BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

    if (out == NULL)
        return 0;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_der_from_obj(out, ecxkey,
                                            nid,
                                            NULL,
                                            ossl_prov_ecx_priv_to_der,
                                            &ctx->sc);
    BIO_free(out);

    return ret;
}

/* Private key : PEM */
static int ecx_priv_pem_data(void *vctx, const OSSL_PARAM params[],
                             OSSL_CORE_BIO *out,
                             OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *ecx_new;
    OSSL_OP_keymgmt_free_fn *ecx_free;
    OSSL_OP_keymgmt_import_fn *ecx_import;
    int ok = 0;

    ecx_get_new_free_import(ctx->type, &ecx_new, &ecx_free, &ecx_import);

    if (ecx_import != NULL) {
        ECX_KEY *ecxkey;

        if ((ecxkey = ecx_new(ctx->provctx)) != NULL
            && ecx_import(ecxkey, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && ecx_priv_pem(ctx->provctx, ecxkey, out, cb, cbarg))
            ok = 1;
        ecx_free(ecxkey);
    }
    return ok;
}

static int ecx_priv_pem(void *vctx, void *ecxkey, OSSL_CORE_BIO *cout,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    int ret;
    int nid = KEYTYPE2NID(ctx->type);
    BIO *out = bio_new_from_core_bio(ctx->provctx, cout);

    if (out == NULL)
        return 0;

    ctx->sc.cb = cb;
    ctx->sc.cbarg = cbarg;

    ret = ossl_prov_write_priv_pem_from_obj(out, ecxkey,
                                            nid,
                                            NULL,
                                            ossl_prov_ecx_priv_to_der,
                                            &ctx->sc);
    BIO_free(out);

    return ret;
}

static int ecx_priv_print_data(void *vctx, const OSSL_PARAM params[],
                               OSSL_CORE_BIO *out,
                               OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    OSSL_OP_keymgmt_new_fn *ecx_new;
    OSSL_OP_keymgmt_free_fn *ecx_free;
    OSSL_OP_keymgmt_import_fn *ecx_import;
    int ok = 0;

    ecx_get_new_free_import(ctx->type, &ecx_new, &ecx_free, &ecx_import);

    if (ecx_import != NULL) {
        ECX_KEY *ecxkey;

        if ((ecxkey = ecx_new(ctx->provctx)) != NULL
            && ecx_import(ecxkey, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && ecx_priv_print(ctx, ecxkey, out, cb, cbarg))
            ok = 1;
        ecx_free(ecxkey);
    }
    return ok;
}

static int ecx_priv_print(void *vctx, void *ecxkey, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    struct ecx_priv_ctx_st *ctx = vctx;
    BIO *out = bio_new_from_core_bio(ctx->provctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_print_ecx(out, ecxkey, ecx_print_priv);
    BIO_free(out);

    return ret;
}

#define MAKE_SERIALIZER_FUNCTIONS(alg, type) \
    const OSSL_DISPATCH alg##_priv_##type##_serializer_functions[] = { \
        { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))alg##_priv_newctx }, \
        { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))ecx_priv_freectx }, \
        { OSSL_FUNC_SERIALIZER_SET_CTX_PARAMS, \
          (void (*)(void))ecx_priv_set_ctx_params }, \
        { OSSL_FUNC_SERIALIZER_SETTABLE_CTX_PARAMS, \
          (void (*)(void))ecx_priv_settable_ctx_params }, \
        { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, \
          (void (*)(void))ecx_priv_##type##_data }, \
        { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, \
          (void (*)(void))ecx_priv_##type }, \
        { 0, NULL } \
    };

#define MAKE_SERIALIZER_FUNCTIONS_GROUP(alg) \
    MAKE_SERIALIZER_FUNCTIONS(alg, der) \
    MAKE_SERIALIZER_FUNCTIONS(alg, pem) \
    const OSSL_DISPATCH alg##_priv_print_serializer_functions[] = { \
        { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))alg##_priv_newctx }, \
        { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))ecx_priv_freectx }, \
        { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, \
          (void (*)(void))ecx_priv_print }, \
        { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, \
          (void (*)(void))ecx_priv_print_data }, \
        { 0, NULL } \
    };

MAKE_SERIALIZER_FUNCTIONS_GROUP(x25519)
MAKE_SERIALIZER_FUNCTIONS_GROUP(x448)
MAKE_SERIALIZER_FUNCTIONS_GROUP(ed25519)
MAKE_SERIALIZER_FUNCTIONS_GROUP(ed448)
