/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

/*
 * DSA low level APIs are deprecated for public use, but still ok for
 * internal use.
 */
#include "internal/deprecated.h"

#include <openssl/core_numbers.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "prov/provider_ctx.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn dsa_param_newctx;
static OSSL_OP_serializer_freectx_fn dsa_param_freectx;
static OSSL_OP_serializer_serialize_data_fn dsa_param_der_data;
static OSSL_OP_serializer_serialize_object_fn dsa_param_der;
static OSSL_OP_serializer_serialize_data_fn dsa_param_pem_data;
static OSSL_OP_serializer_serialize_object_fn dsa_param_pem;

static OSSL_OP_serializer_serialize_data_fn dsa_param_print_data;
static OSSL_OP_serializer_serialize_object_fn dsa_param_print;

/* Parameters : context */

/*
 * There's no specific implementation context, so we use the provider context
 */
static void *dsa_param_newctx(void *provctx)
{
    return provctx;
}

static void dsa_param_freectx(void *ctx)
{
}

/* Public key : DER */
static int dsa_param_der_data(void *ctx, const OSSL_PARAM params[],
                              OSSL_CORE_BIO *out,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dsa_new = ossl_prov_get_keymgmt_dsa_new();
    OSSL_OP_keymgmt_free_fn *dsa_free = ossl_prov_get_keymgmt_dsa_free();
    OSSL_OP_keymgmt_import_fn *dsa_import = ossl_prov_get_keymgmt_dsa_import();
    int ok = 0;

    if (dsa_import != NULL) {
        DSA *dsa;

        /* ctx == provctx */
        if ((dsa = dsa_new(ctx)) != NULL
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && dsa_param_der(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_param_der(void *ctx, void *dsa, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = i2d_DSAparams_bio(out, dsa);
    BIO_free(out);

    return ret;
}

/* Public key : PEM */
static int dsa_param_pem_data(void *ctx, const OSSL_PARAM params[],
                              OSSL_CORE_BIO *out,
                              OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dsa_new = ossl_prov_get_keymgmt_dsa_new();
    OSSL_OP_keymgmt_free_fn *dsa_free = ossl_prov_get_keymgmt_dsa_free();
    OSSL_OP_keymgmt_import_fn *dsa_import = ossl_prov_get_keymgmt_dsa_import();
    int ok = 0;

    if (dsa_import != NULL) {
        DSA *dsa;

        /* ctx == provctx */
        if ((dsa = dsa_new(ctx)) != NULL
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && dsa_param_pem(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_param_pem(void *ctx, void *dsa, OSSL_CORE_BIO *cout,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = PEM_write_bio_DSAparams(out, dsa);
    BIO_free(out);

    return ret;
}

static int dsa_param_print_data(void *ctx, const OSSL_PARAM params[],
                                OSSL_CORE_BIO *out,
                                OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    OSSL_OP_keymgmt_new_fn *dsa_new = ossl_prov_get_keymgmt_dsa_new();
    OSSL_OP_keymgmt_free_fn *dsa_free = ossl_prov_get_keymgmt_dsa_free();
    OSSL_OP_keymgmt_import_fn *dsa_import = ossl_prov_get_keymgmt_dsa_import();
    int ok = 0;

    if (dsa_import != NULL) {
        DSA *dsa;

        /* ctx == provctx */
        if ((dsa = dsa_new(ctx)) != NULL
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_ALL_PARAMETERS, params)
            && dsa_param_print(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_param_print(void *ctx, void *dsa, OSSL_CORE_BIO *cout,
                           OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    BIO *out = bio_new_from_core_bio(ctx, cout);
    int ret;

    if (out == NULL)
        return 0;

    ret = ossl_prov_print_dsa(out, dsa, dsa_print_params);
    BIO_free(out);

    return ret;
}

const OSSL_DISPATCH dsa_param_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_param_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_der },
    { 0, NULL }
};

const OSSL_DISPATCH dsa_param_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_param_pem_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_pem },
    { 0, NULL }
};

const OSSL_DISPATCH dsa_param_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dsa_param_print_data },
    { 0, NULL }
};
