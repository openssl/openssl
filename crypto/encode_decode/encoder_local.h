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
#include <openssl/encoder.h>
#include <openssl/decoder.h>
#include "internal/cryptlib.h"
#include "internal/refcount.h"

struct ossl_serdes_base_st {
    OSSL_PROVIDER *prov;
    int id;
    const char *propdef;

    CRYPTO_REF_COUNT refcnt;
    CRYPTO_RWLOCK *lock;
};

struct ossl_encoder_st {
    struct ossl_serdes_base_st base;
    OSSL_FUNC_encoder_newctx_fn *newctx;
    OSSL_FUNC_encoder_freectx_fn *freectx;
    OSSL_FUNC_encoder_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_encoder_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_encoder_encode_data_fn *encode_data;
    OSSL_FUNC_encoder_encode_object_fn *encode_object;
};

struct ossl_decoder_st {
    struct ossl_serdes_base_st base;
    OSSL_FUNC_decoder_newctx_fn *newctx;
    OSSL_FUNC_decoder_freectx_fn *freectx;
    OSSL_FUNC_decoder_get_params_fn *get_params;
    OSSL_FUNC_decoder_gettable_params_fn *gettable_params;
    OSSL_FUNC_decoder_set_ctx_params_fn *set_ctx_params;
    OSSL_FUNC_decoder_settable_ctx_params_fn *settable_ctx_params;
    OSSL_FUNC_decoder_decode_fn *decode;
    OSSL_FUNC_decoder_export_object_fn *export_object;
};

struct ossl_encoder_ctx_st {
    OSSL_ENCODER *encoder;
    void *serctx;

    int selection;

    /*-
     * Output / encoding data, used by OSSL_ENCODER_to_{bio,fp}
     *
     * |object|         is the libcrypto object to handle.
     * |do_output|      performs the actual encoding.
     *
     * |do_output| must have intimate knowledge of |object|.
     */
    const void *object;
    int (*do_output)(OSSL_ENCODER_CTX *ctx, BIO *out);

    /* For any function that needs a passphrase reader */
    const UI_METHOD *ui_method;
    void *ui_data;
    /*
     * if caller used OSSL_ENCODER_CTX_set_passphrase_cb(), we need
     * intermediary storage.
     */
    UI_METHOD *allocated_ui_method;
};

struct ossl_decoder_instance_st {
    OSSL_DECODER *decoder;    /* Never NULL */
    void *deserctx;              /* Never NULL */
    const char *input_type;      /* Never NULL */
};

DEFINE_STACK_OF(OSSL_DECODER_INSTANCE)

struct ossl_decoder_ctx_st {
    /*
     * The caller may know the input type of the data they pass.  If not,
     * this will remain NULL and the decoding functionality will start
     * with trying to decode with any desencoder in |decoder_insts|,
     * regardless of their respective input type.
     */
    const char *start_input_type;

    /*
     * Decoders that are components of any current decoding path.
     */
    STACK_OF(OSSL_DECODER_INSTANCE) *decoder_insts;

    /*
     * The constructors of a decoding, and its caller argument.
     */
    OSSL_DECODER_CONSTRUCT *construct;
    OSSL_DECODER_CLEANUP *cleanup;
    void *construct_data;

    /* For any function that needs a passphrase reader */
    OSSL_PASSPHRASE_CALLBACK *passphrase_cb;
    const UI_METHOD *ui_method;
    void *ui_data;
    /*
     * if caller used OSSL_ENCODER_CTX_set_pem_password_cb(), we need
     * intermediary storage.
     */
    UI_METHOD *allocated_ui_method;
    /*
     * Because the same input may pass through more than one decoder,
     * we cache any passphrase passed to us.  The desrializing processor
     * must clear this at the end of a run.
     */
    unsigned char *cached_passphrase;
    size_t cached_passphrase_len;

    /*
     * Flag section.  Keep these together
     */

    /*
     * The passphrase was passed to us by the user.  In that case, it
     * should only be freed when freeing this context.
     */
    unsigned int flag_user_passphrase:1;
};

/* Passphrase callbacks, found in serdes_pass.c */

/*
 * Encoders typically want to get an outgoing passphrase, while
 * decoders typically want to get en incoming passphrase.
 */
OSSL_PASSPHRASE_CALLBACK ossl_encoder_passphrase_out_cb;
OSSL_PASSPHRASE_CALLBACK ossl_decoder_passphrase_in_cb;
