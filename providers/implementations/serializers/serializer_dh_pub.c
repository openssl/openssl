/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/err.h>
#include <opentls/pem.h>
#include <opentls/dh.h>
#include <opentls/types.h>
#include <opentls/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static Otls_OP_serializer_newctx_fn dh_pub_newctx;
static Otls_OP_serializer_freectx_fn dh_pub_freectx;
static Otls_OP_serializer_serialize_data_fn dh_pub_der_data;
static Otls_OP_serializer_serialize_object_fn dh_pub_der;
static Otls_OP_serializer_serialize_data_fn dh_pub_pem_data;
static Otls_OP_serializer_serialize_object_fn dh_pub_pem;

static Otls_OP_serializer_serialize_data_fn dh_pub_print_data;
static Otls_OP_serializer_serialize_object_fn dh_pub_print;

/* Public key : context */

/*
 * There's no specific implementation context, so we use the provider context
 */
static void *dh_pub_newctx(void *provctx)
{
    return provctx;
}

static void dh_pub_freectx(void *ctx)
{
}

/* Public key : DER */
static int dh_pub_der_data(void *ctx, const Otls_PARAM params[], BIO *out,
                            Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dh_importkey =
        otls_prov_get_dh_importkey();
    int ok = 0;

    if (dh_importkey != NULL) {
        DH *dh = dh_importkey(ctx, params); /* ctx == provctx */

        ok = dh_pub_der(ctx, dh, out, cb, cbarg);
        DH_free(dh);
    }
    return ok;
}

static int dh_pub_der(void *ctx, void *dh, BIO *out,
                       Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return otls_prov_write_pub_der_from_obj(out, dh, EVP_PKEY_DH,
                                            otls_prov_prepare_dh_params,
                                            otls_prov_dh_pub_to_der);
}

/* Public key : PEM */
static int dh_pub_pem_data(void *ctx, const Otls_PARAM params[], BIO *out,
                            Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dh_importkey =
        otls_prov_get_dh_importkey();
    int ok = 0;

    if (dh_importkey != NULL) {
        DH *dh = dh_importkey(ctx, params); /* ctx == provctx */

        ok = dh_pub_pem(ctx, dh, out, cb, cbarg);
        DH_free(dh);
    }
    return ok;
}

static int dh_pub_pem(void *ctx, void *dh, BIO *out,
                       Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return otls_prov_write_pub_pem_from_obj(out, dh, EVP_PKEY_DH,
                                            otls_prov_prepare_dh_params,
                                            otls_prov_dh_pub_to_der);

}

static int dh_pub_print_data(void *ctx, const Otls_PARAM params[], BIO *out,
                              Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    Otls_OP_keymgmt_importkey_fn *dh_importkey =
        otls_prov_get_dh_importkey();
    int ok = 0;

    if (dh_importkey != NULL) {
        DH *dh = dh_importkey(ctx, params); /* ctx == provctx */

        ok = dh_pub_print(ctx, dh, out, cb, cbarg);
        DH_free(dh);
    }
    return ok;
}

static int dh_pub_print(void *ctx, void *dh, BIO *out,
                         Otls_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return otls_prov_print_dh(out, dh, 0);
}

const Otls_DISPATCH dh_pub_der_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_pub_der_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_der },
    { 0, NULL }
};

const Otls_DISPATCH dh_pub_pem_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dh_pub_pem_data },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_pem },
    { 0, NULL }
};

const Otls_DISPATCH dh_pub_text_serializer_functions[] = {
    { Otls_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dh_pub_newctx },
    { Otls_FUNC_SERIALIZER_FREECTX, (void (*)(void))dh_pub_freectx },
    { Otls_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dh_pub_print },
    { Otls_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dh_pub_print_data },
    { 0, NULL }
};
