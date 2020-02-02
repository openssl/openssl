/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_numbers.h>
#include <openssl/types.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"

struct ossl_serializer_st {
    OSSL_PROVIDER *prov;
    int id;
    const char *propdef;

    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    OSSL_OP_serializer_newctx_fn *newctx;
    OSSL_OP_serializer_freectx_fn *freectx;
    OSSL_OP_serializer_set_ctx_params_fn *set_ctx_params;
    OSSL_OP_serializer_settable_ctx_params_fn *settable_ctx_params;
    OSSL_OP_serializer_serialize_data_fn *serialize_data;
    OSSL_OP_serializer_serialize_object_fn *serialize_object;
};

struct ossl_serializer_ctx_st {
    OSSL_SERIALIZER *ser;
    void *serctx;

    int selection;

    /*
     * |object| is the libcrypto object to handle.
     * |do_output| must have intimate knowledge of this object.
     */
    const void *object;
    int (*do_output)(OSSL_SERIALIZER_CTX *ctx, BIO *out);

    /* For any function that needs a passphrase reader */
    const UI_METHOD *ui_method;
    void *ui_data;
    /*
     * if caller used OSSL_SERIALIZER_CTX_set_passphrase_cb(), we need
     * intermediary storage.
     */
    UI_METHOD *allocated_ui_method;
};
