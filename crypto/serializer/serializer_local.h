/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core_numbers.h>
#include <opentls/types.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"

struct otls_serializer_st {
    Otls_PROVIDER *prov;
    int id;
    const char *propdef;

    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;

    Otls_OP_serializer_newctx_fn *newctx;
    Otls_OP_serializer_freectx_fn *freectx;
    Otls_OP_serializer_set_ctx_params_fn *set_ctx_params;
    Otls_OP_serializer_settable_ctx_params_fn *settable_ctx_params;
    Otls_OP_serializer_serialize_data_fn *serialize_data;
    Otls_OP_serializer_serialize_object_fn *serialize_object;
};

struct otls_serializer_ctx_st {
    Otls_SERIALIZER *ser;
    void *serctx;

    /*
     * |object| is the libcrypto object to handle.
     * |do_output| must have intimate knowledge of this object.
     */
    const void *object;
    int (*do_output)(Otls_SERIALIZER_CTX *ctx, BIO *out);

    /* For any function that needs a passphrase reader */
    const UI_METHOD *ui_method;
    void *ui_data;
    /*
     * if caller used Otls_SERIALIZER_CTX_set_passphrase_cb(), we need
     * intermediary storage.
     */
    UI_METHOD *allocated_ui_method;
};
