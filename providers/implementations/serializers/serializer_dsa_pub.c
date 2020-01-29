/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/dsa.h>
#include <openssl/types.h>
#include <openssl/params.h>
#include "prov/bio.h"
#include "prov/implementations.h"
#include "serializer_local.h"

static OSSL_OP_serializer_newctx_fn dsa_pub_newctx;
static OSSL_OP_serializer_freectx_fn dsa_pub_freectx;
static OSSL_OP_serializer_serialize_data_fn dsa_pub_der_data;
static OSSL_OP_serializer_serialize_object_fn dsa_pub_der;
static OSSL_OP_serializer_serialize_data_fn dsa_pub_pem_data;
static OSSL_OP_serializer_serialize_object_fn dsa_pub_pem;

static OSSL_OP_serializer_serialize_data_fn dsa_pub_print_data;
static OSSL_OP_serializer_serialize_object_fn dsa_pub_print;

/* Public key : context */

/*
 * There's no specific implementation context, so we use the provider context
 */
static void *dsa_pub_newctx(void *provctx)
{
    return provctx;
}

static void dsa_pub_freectx(void *ctx)
{
}

/* Public key : DER */
static int dsa_pub_der_data(void *ctx, const OSSL_PARAM params[], BIO *out,
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
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dsa_pub_der(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_pub_der(void *ctx, void *dsa, BIO *out,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    /*
     * TODO(v3.0) implement setting save_parameters, see dsa_pub_encode()
     * in crypto/dsa/dsa_ameth.c
     */
    int save_parameters = 1;

    return
        save_parameters
        ? ossl_prov_write_pub_der_from_obj(out, dsa, EVP_PKEY_DSA,
                                           ossl_prov_prepare_all_dsa_params,
                                           ossl_prov_dsa_pub_to_der)
        : ossl_prov_write_pub_der_from_obj(out, dsa, EVP_PKEY_DSA,
                                           ossl_prov_prepare_dsa_params,
                                           ossl_prov_dsa_pub_to_der);

}

/* Public key : PEM */
static int dsa_pub_pem_data(void *ctx, const OSSL_PARAM params[], BIO *out,
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
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dsa_pub_pem(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_pub_pem(void *ctx, void *dsa, BIO *out,
                       OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_write_pub_pem_from_obj(out, dsa, EVP_PKEY_DSA,
                                            ossl_prov_prepare_dsa_params,
                                            ossl_prov_dsa_pub_to_der);
}

static int dsa_pub_print_data(void *ctx, const OSSL_PARAM params[], BIO *out,
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
            && dsa_import(dsa, OSSL_KEYMGMT_SELECT_KEYPAIR, params)
            && dsa_pub_print(ctx, dsa, out, cb, cbarg))
            ok = 1;
        dsa_free(dsa);
    }
    return ok;
}

static int dsa_pub_print(void *ctx, void *dsa, BIO *out,
                         OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
    return ossl_prov_print_dsa(out, dsa, 0);
}

const OSSL_DISPATCH dsa_pub_der_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_pub_der_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_pub_der },
    { 0, NULL }
};

const OSSL_DISPATCH dsa_pub_pem_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA, (void (*)(void))dsa_pub_pem_data },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_pub_pem },
    { 0, NULL }
};

const OSSL_DISPATCH dsa_pub_text_serializer_functions[] = {
    { OSSL_FUNC_SERIALIZER_NEWCTX, (void (*)(void))dsa_pub_newctx },
    { OSSL_FUNC_SERIALIZER_FREECTX, (void (*)(void))dsa_pub_freectx },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_OBJECT, (void (*)(void))dsa_pub_print },
    { OSSL_FUNC_SERIALIZER_SERIALIZE_DATA,
      (void (*)(void))dsa_pub_print_data },
    { 0, NULL }
};
