/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include <openssl/deserializer.h>
#include <openssl/safestack.h>
#include "crypto/evp.h"
#include "serializer_local.h"

int OSSL_DESERIALIZER_CTX_set_passphrase(OSSL_DESERIALIZER_CTX *ctx,
                                         const unsigned char *kstr,
                                         size_t klen)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    OPENSSL_clear_free(ctx->cached_passphrase, ctx->cached_passphrase_len);
    ctx->cached_passphrase = NULL;
    ctx->cached_passphrase_len = 0;
    if (kstr != NULL) {
        if (klen == 0) {
            ctx->cached_passphrase = OPENSSL_zalloc(1);
            ctx->cached_passphrase_len = 0;
        } else {
            ctx->cached_passphrase = OPENSSL_memdup(kstr, klen);
            ctx->cached_passphrase_len = klen;
        }
        if (ctx->cached_passphrase == NULL) {
            ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    ctx->flag_user_passphrase = 1;
    return 1;
}

static void deserializer_ctx_reset_passphrase_ui(OSSL_DESERIALIZER_CTX *ctx)
{
    UI_destroy_method(ctx->allocated_ui_method);
    ctx->allocated_ui_method = NULL;
    ctx->ui_method = NULL;
    ctx->ui_data = NULL;
}

int OSSL_DESERIALIZER_CTX_set_passphrase_ui(OSSL_DESERIALIZER_CTX *ctx,
                                            const UI_METHOD *ui_method,
                                            void *ui_data)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    deserializer_ctx_reset_passphrase_ui(ctx);
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    return 1;
}

int OSSL_DESERIALIZER_CTX_set_pem_password_cb(OSSL_DESERIALIZER_CTX *ctx,
                                              pem_password_cb *cb, void *cbarg)
{
    UI_METHOD *ui_method = NULL;

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    /*
     * If |cb| is NULL, it means the caller wants to reset previous
     * password callback info.  Otherwise, we only set the new data
     * if a new UI_METHOD could be created for this sort of callback.
     */
    if (cb == NULL
        || (ui_method = UI_UTIL_wrap_read_pem_callback(cb, 0)) != NULL) {
        deserializer_ctx_reset_passphrase_ui(ctx);
        ctx->ui_method = ctx->allocated_ui_method = ui_method;
        ctx->ui_data = cbarg;
        ctx->passphrase_cb = ossl_deserializer_passphrase_in_cb;
        return 1;
    }

    return 0;
}

/*
 * Support for OSSL_DESERIALIZER_CTX_new_by_EVP_PKEY:
 * The construct data, and collecting keymgmt information for it
 */

DEFINE_STACK_OF(EVP_KEYMGMT)

struct deser_EVP_PKEY_data_st {
    char *object_type;           /* recorded object data type, may be NULL */
    void **object;               /* Where the result should end up */
    STACK_OF(EVP_KEYMGMT) *keymgmts; /* The EVP_KEYMGMTs we handle */
};

static int deser_construct_EVP_PKEY(OSSL_DESERIALIZER_INSTANCE *deser_inst,
                                    const OSSL_PARAM *params,
                                    void *construct_data)
{
    struct deser_EVP_PKEY_data_st *data = construct_data;
    OSSL_DESERIALIZER *deser =
        OSSL_DESERIALIZER_INSTANCE_deserializer(deser_inst);
    void *deserctx = OSSL_DESERIALIZER_INSTANCE_deserializer_ctx(deser_inst);
    size_t i, end_i;
    /*
     * |object_ref| points to a provider reference to an object, its exact
     * contents entirely opaque to us, but may be passed to any provider
     * function that expects this (such as OSSL_FUNC_keymgmt_load().
     *
     * This pointer is considered volatile, i.e. whatever it points at
     * is assumed to be freed as soon as this function returns.
     */
    void *object_ref = NULL;
    size_t object_ref_sz = 0;
    const OSSL_PARAM *p;

    p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_DATA_TYPE);
    if (p != NULL) {
        char *object_type = NULL;

        if (!OSSL_PARAM_get_utf8_string(p, &object_type, 0))
            return 0;
        OPENSSL_free(data->object_type);
        data->object_type = object_type;
    }

    /*
     * For stuff that should end up in an EVP_PKEY, we only accept an object
     * reference for the moment.  This enforces that the key data itself
     * remains with the provider.
     */
    p = OSSL_PARAM_locate_const(params, OSSL_DESERIALIZER_PARAM_REFERENCE);
    if (p == NULL || p->data_type != OSSL_PARAM_OCTET_STRING)
        return 0;
    object_ref = p->data;
    object_ref_sz = p->data_size;

    /* We may have reached one of the goals, let's find out! */
    end_i = sk_EVP_KEYMGMT_num(data->keymgmts);
    for (i = 0; end_i; i++) {
        EVP_KEYMGMT *keymgmt = sk_EVP_KEYMGMT_value(data->keymgmts, i);

        /*
         * There are two ways to find a matching KEYMGMT:
         *
         * 1.  If the object data type (recorded in |data->object_type|)
         *     is defined, by checking it using EVP_KEYMGMT_is_a().
         * 2.  If the object data type is NOT defined, by comparing the
         *     EVP_KEYMGMT and OSSL_DESERIALIZER method numbers.  Since
         *     EVP_KEYMGMT and OSSL_DESERIALIZE operate with the same
         *     namemap, we know that the method numbers must match.
         *
         * This allows individual deserializers to specify variants of keys,
         * such as a DER to RSA deserializer finding a RSA-PSS key, without
         * having to deserialize the exact same DER blob into the exact same
         * internal structure twice.  This is, of course, entirely at the
         * discretion of the deserializer implementations.
         */
        if (data->object_type != NULL
            ? EVP_KEYMGMT_is_a(keymgmt, data->object_type)
            : EVP_KEYMGMT_number(keymgmt) == OSSL_DESERIALIZER_number(deser)) {
            EVP_PKEY *pkey = NULL;
            void *keydata = NULL;
            const OSSL_PROVIDER *keymgmt_prov =
                EVP_KEYMGMT_provider(keymgmt);
            const OSSL_PROVIDER *deser_prov =
                OSSL_DESERIALIZER_provider(deser);

            /*
             * If the EVP_KEYMGMT and the OSSL_DDESERIALIZER are from the
             * same provider, we assume that the KEYMGMT has a key loading
             * function that can handle the provider reference we hold.
             *
             * Otherwise, we export from the deserializer and import the
             * result in the keymgmt.
             */
            if (keymgmt_prov == deser_prov) {
                keydata = evp_keymgmt_load(keymgmt, object_ref, object_ref_sz);
            } else {
                struct evp_keymgmt_util_try_import_data_st import_data;

                import_data.keymgmt = keymgmt;
                import_data.keydata = NULL;
                import_data.selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;

                /*
                 * No need to check for errors here, the value of
                 * |import_data.keydata| is as much an indicator.
                 */
                (void)deser->export_object(deserctx, object_ref, object_ref_sz,
                                           &evp_keymgmt_util_try_import,
                                           &import_data);
                keydata = import_data.keydata;
                import_data.keydata = NULL;
            }

            if (keydata != NULL
                && (pkey =
                    evp_keymgmt_util_make_pkey(keymgmt, keydata)) == NULL)
                evp_keymgmt_freedata(keymgmt, keydata);

            *data->object = pkey;

            break;
        }
    }
    /*
     * We successfully looked through, |*ctx->object| determines if we
     * actually found something.
     */
    return (*data->object != NULL);
}

static void deser_clean_EVP_PKEY_construct_arg(void *construct_data)
{
    struct deser_EVP_PKEY_data_st *data = construct_data;

    if (data != NULL) {
        sk_EVP_KEYMGMT_pop_free(data->keymgmts, EVP_KEYMGMT_free);
        OPENSSL_free(data->object_type);
        OPENSSL_free(data);
    }
}

DEFINE_STACK_OF_CSTRING()

struct collected_data_st {
    struct deser_EVP_PKEY_data_st *process_data;
    STACK_OF(OPENSSL_CSTRING) *names;

    unsigned int error_occured:1;
};

static void collect_keymgmt(EVP_KEYMGMT *keymgmt, void *arg)
{
    struct collected_data_st *data = arg;

    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */

    if (!EVP_KEYMGMT_up_ref(keymgmt) /* ref++ */)
        return;
    if (sk_EVP_KEYMGMT_push(data->process_data->keymgmts, keymgmt) <= 0) {
        EVP_KEYMGMT_free(keymgmt); /* ref-- */
        return;
    }

    data->error_occured = 0;         /* All is good now */
}

static void collect_name(const char *name, void *arg)
{
    struct collected_data_st *data = arg;

    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */

    if (sk_OPENSSL_CSTRING_push(data->names, name) <= 0)
        return;

    data->error_occured = 0;         /* All is good now */
}

OSSL_DESERIALIZER_CTX *
OSSL_DESERIALIZER_CTX_new_by_EVP_PKEY(EVP_PKEY **pkey,
                                      const char *input_type,
                                      OPENSSL_CTX *libctx,
                                      const char *propquery)
{
    OSSL_DESERIALIZER_CTX *ctx = NULL;
    struct collected_data_st *data = NULL;
    size_t i, end_i;

    if ((ctx = OSSL_DESERIALIZER_CTX_new()) == NULL
        || (data = OPENSSL_zalloc(sizeof(*data))) == NULL
        || (data->process_data =
            OPENSSL_zalloc(sizeof(*data->process_data))) == NULL
        || (data->process_data->keymgmts
            = sk_EVP_KEYMGMT_new_null()) == NULL
        || (data->names = sk_OPENSSL_CSTRING_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    data->process_data->object = (void **)pkey;
    OSSL_DESERIALIZER_CTX_set_input_type(ctx, input_type);

    /* First, find all keymgmts to form goals */
    EVP_KEYMGMT_do_all_provided(libctx, collect_keymgmt, data);

    if (data->error_occured)
        goto err;

    /*
     * Then, use the names of those keymgmts to find the first set of
     * derializers.
     */
    ERR_set_mark();
    end_i = sk_EVP_KEYMGMT_num(data->process_data->keymgmts);
    for (i = 0; i < end_i; i++) {
        EVP_KEYMGMT *keymgmt =
            sk_EVP_KEYMGMT_value(data->process_data->keymgmts, i);
        size_t j;
        OSSL_DESERIALIZER *deser = NULL;

        EVP_KEYMGMT_names_do_all(keymgmt, collect_name, data);

        for (j = sk_OPENSSL_CSTRING_num(data->names);
             j-- > 0 && deser == NULL;) {
            const char *name = sk_OPENSSL_CSTRING_pop(data->names);

            ERR_set_mark();
            deser = OSSL_DESERIALIZER_fetch(libctx, name, propquery);
            ERR_pop_to_mark();
        }

        /*
         * The names in |data->names| aren't allocated for the stack,
         * so we can simply clear it and let it be re-used.
         */
        sk_OPENSSL_CSTRING_zero(data->names);

        /*
         * If we found a matching serializer, try to add it to the context.
         */
        if (deser != NULL) {
            (void)OSSL_DESERIALIZER_CTX_add_deserializer(ctx, deser);
            OSSL_DESERIALIZER_free(deser);
        }
    }
    /* If we found no deserializers to match the keymgmts, we err */
    if (OSSL_DESERIALIZER_CTX_num_deserializers(ctx) == 0) {
        ERR_clear_last_mark();
        goto err;
    }
    ERR_pop_to_mark();

    /* Finally, collect extra deserializers based on what we already have */
    (void)OSSL_DESERIALIZER_CTX_add_extra(ctx, libctx, propquery);

    if (!OSSL_DESERIALIZER_CTX_set_construct(ctx, deser_construct_EVP_PKEY)
        || !OSSL_DESERIALIZER_CTX_set_construct_data(ctx, data->process_data)
        || !OSSL_DESERIALIZER_CTX_set_cleanup
                (ctx, deser_clean_EVP_PKEY_construct_arg))
        goto err;

    data->process_data = NULL;
 err:
    deser_clean_EVP_PKEY_construct_arg(data->process_data);
    sk_OPENSSL_CSTRING_free(data->names);
    OPENSSL_free(data);
    return ctx;
}
