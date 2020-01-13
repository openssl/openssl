/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/pem.h>
#include <opentls/dsa.h>
#include <opentls/types.h>
#include <opentls/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "prov/providercommonerr.h"
#include "serializer_local.h"

static Otls_OP_serializer_newctx_fn dsa_param_newctx;
static Otls_OP_serializer_freectx_fn dsa_param_freectx;
static Otls_OP_serializer_serialize_data_fn dsa_param_der_data;
static Otls_OP_serializer_serialize_object_fn dsa_param_der;
static Otls_OP_serializer_serialize_data_fn dsa_param_pem_data;
static Otls_OP_serializer_serialize_object_fn dsa_param_pem;

static Otls_OP_serializer_serialize_data_fn dsa_param_print_data;
static Otls_OP_serializer_serialize_object_fn dsa_param_print;

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
static int dsa_param_der_data(void *ctx, const Otls_PARAM params[], BIO *out,
                             Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(ctx, params); /* ctx == provctx */

        ok = dsa_param_der(ctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_param_der(void *ctx, void *dsa, BIO *out,
                        Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return i2d_DSAparams_bio(out, dsa);
}

/* Public key : PEM */
static int dsa_param_pem_data(void *ctx, const Otls_PARAM params[], BIO *out,
                            Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(ctx, params); /* ctx == provctx */

        ok = dsa_param_pem(ctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_param_pem(void *ctx, void *dsa, BIO *out,
                       Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return PEM_write_bio_DSAparams(out, dsa);
}

static int dsa_param_print_data(void *ctx, const Otls_PARAM params[], BIO *out,
                              Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dsa_importkey =
        otls_prov_get_dsa_importkey();
    int ok = 0;

    if (dsa_importkey != NULL) {
        DSA *dsa = dsa_importkey(ctx, params); /* ctx == provctx */

        ok = dsa_param_print(ctx, dsa, out, cb, cbarg);
        DSA_free(dsa);
    }
    return ok;
}

static int dsa_param_print(void *ctx, void *dsa, BIO *out,
                         Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return otls_prov_print_dsa(out, dsa, dsa_print_params);
}

const Otls_DISPATCH dsa_param_der_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_param_der_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_der },
    { 0, NULL }
};

const Otls_DISPATCH dsa_param_pem_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_param_pem_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_pem },
    { 0, NULL }
};

const Otls_DISPATCH dsa_param_text_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_param_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_param_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_param_print },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dsa_param_print_data },
    { 0, NULL }
};
