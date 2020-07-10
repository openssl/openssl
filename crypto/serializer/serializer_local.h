/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_dispatch.h>
#include <openssl/types.h>
#include <openssl/safestack.h>
#include <openssl/serializer.h>
#include <openssl/deserializer.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"

struct ossl_serdes_base_st {
    OSSL_PROVIDER *prov;
    int id;
    const char *propdef;

    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
};

struct ossl_serializer_st {
    struct ossl_serdes_base_st base;
    OSSL_FUNC_serializer_newctx_fn *newctx;
    OSSL_FUNC_serializer_freectx_fn *freectx;
    OSSL_FUNC_serializer_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_serializer_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_serializer_serialize_data_fn *serialize_data;
    OSSL_FUNC_serializer_serialize_object_fn *serialize_object;
};

struct ossl_deserializer_st {
    struct ossl_serdes_base_st base;
    OSSL_FUNC_deserializer_newctx_fn *newctx;
    OSSL_FUNC_deserializer_freectx_fn *freectx;
    OSSL_FUNC_deserializer_get_params_fn *get_params;
    OSSL_FUNC_deserializer_gettable_params_fn *gettable_params;
    OSSL_FUNC_deserializer_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_deserializer_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_deserializer_deserialize_fn *deserialize;
    OSSL_FUNC_deserializer_export_object_fn *export_object;
};

struct ossl_serializer_ctx_st {
    OSSL_SERIALIZER *ser;
    void *serctx;

    int selection;

    /*-
     * Output / serializing data, used by OSSL_SERIALIZER_to_{bio,fp}
     *
     * |object|         is the libcrypto object to handle.
     * |do_output|      performs the actual serialization.
     *
     * |do_output| must have intimate knowledge of |object|.
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

struct ossl_deserializer_instance_st {
    OSSL_DESERIALIZER *deser;    /* Never NULL */
    void *deserctx;              /* Never NULL */
    const char *input_type;      /* Never NULL */
};

DEFINE_STACK_OF(OSSL_DESERIALIZER_INSTANCE)

struct ossl_deserializer_ctx_st {
    /*
     * The caller may know the input type of the data they pass.  If not,
     * this will remain NULL and the deserializing functionality will start
     * with trying to deserialize with any desserializer in |deser_insts|,
     * regardless of their respective input type.
     */
    const char *start_input_type;

    /*
     * Deserializers that are components of any current deserialization path.
     */
    STACK_OF(OSSL_DESERIALIZER_INSTANCE) *deser_insts;

    /*
     * The finalizer of a deserialization, and its caller argument.
     */
    OSSL_DESERIALIZER_FINALIZER *finalizer;
    OSSL_DESERIALIZER_CLEANER *cleaner;
    void *finalize_arg;

    /* For any function that needs a passphrase reader */
    const UI_METHOD *ui_method;
    void *ui_data;
    /*
     * if caller used OSSL_SERIALIZER_CTX_set_passphrase_cb(), we need
     * intermediary storage.
     */
    UI_METHOD *allocated_ui_method;
    /*
     * Because the same input may pass through more than one deserializer,
     * we cache any passphrase passed to us.  The desrializing processor
     * must clear this at the end of a run.
     */
    unsigned char *cached_passphrase;
    size_t cached_passphrase_len;
};

/* Passphrase callbacks, found in serdes_pass.c */

/*
 * Serializers typically want to get an outgoing passphrase, while
 * deserializers typically want to get en incoming passphrase.
 */
OSSL_PASSPHRASE_CALLBACK ossl_serializer_passphrase_out_cb;
OSSL_PASSPHRASE_CALLBACK ossl_deserializer_passphrase_in_cb;
