/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core_names.h>
#include <openssl/core_object.h>
#include <openssl/evp.h>
#include <openssl/ui.h>
#include <openssl/decoder.h>
#include <openssl/safestack.h>
#include "crypto/evp.h"
#include "crypto/decoder.h"
#include "encoder_local.h"

int OSSL_DECODER_CTX_set_passphrase(OSSL_DECODER_CTX *ctx,
                                    const unsigned char *kstr,
                                    size_t klen)
{
    return ossl_pw_set_passphrase(&ctx->pwdata, kstr, klen);
}

int OSSL_DECODER_CTX_set_passphrase_ui(OSSL_DECODER_CTX *ctx,
                                       const UI_METHOD *ui_method,
                                       void *ui_data)
{
    return ossl_pw_set_ui_method(&ctx->pwdata, ui_method, ui_data);
}

int OSSL_DECODER_CTX_set_pem_password_cb(OSSL_DECODER_CTX *ctx,
                                         pem_password_cb *cb, void *cbarg)
{
    return ossl_pw_set_pem_password_cb(&ctx->pwdata, cb, cbarg);
}

int OSSL_DECODER_CTX_set_passphrase_cb(OSSL_DECODER_CTX *ctx,
                                       OSSL_PASSPHRASE_CALLBACK *cb,
                                       void *cbarg)
{
    return ossl_pw_set_ossl_passphrase_cb(&ctx->pwdata, cb, cbarg);
}

/*
 * Support for OSSL_DECODER_CTX_new_by_EVP_PKEY:
 * The construct data, and collecting keymgmt information for it
 */

DEFINE_STACK_OF(EVP_KEYMGMT)

struct decoder_EVP_PKEY_data_st {
    char *object_type;           /* recorded object data type, may be NULL */
    void **object;               /* Where the result should end up */
    STACK_OF(EVP_KEYMGMT) *keymgmts; /* The EVP_KEYMGMTs we handle */
};

static int decoder_construct_EVP_PKEY(OSSL_DECODER_INSTANCE *decoder_inst,
                                      const OSSL_PARAM *params,
                                      void *construct_data)
{
    struct decoder_EVP_PKEY_data_st *data = construct_data;
    OSSL_DECODER *decoder = OSSL_DECODER_INSTANCE_get_decoder(decoder_inst);
    void *decoderctx = OSSL_DECODER_INSTANCE_get_decoder_ctx(decoder_inst);
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

    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_DATA_TYPE);
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
    p = OSSL_PARAM_locate_const(params, OSSL_OBJECT_PARAM_REFERENCE);
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
         *     EVP_KEYMGMT and OSSL_DECODER method numbers.  Since
         *     EVP_KEYMGMT and OSSL_DECODE operate with the same
         *     namemap, we know that the method numbers must match.
         *
         * This allows individual decoders to specify variants of keys,
         * such as a DER to RSA decoder finding a RSA-PSS key, without
         * having to decode the exact same DER blob into the exact same
         * internal structure twice.  This is, of course, entirely at the
         * discretion of the decoder implementations.
         */
        if (data->object_type != NULL
            ? EVP_KEYMGMT_is_a(keymgmt, data->object_type)
            : EVP_KEYMGMT_number(keymgmt) == OSSL_DECODER_number(decoder)) {
            EVP_PKEY *pkey = NULL;
            void *keydata = NULL;
            const OSSL_PROVIDER *keymgmt_prov =
                EVP_KEYMGMT_provider(keymgmt);
            const OSSL_PROVIDER *decoder_prov =
                OSSL_DECODER_provider(decoder);

            /*
             * If the EVP_KEYMGMT and the OSSL_DECODER are from the
             * same provider, we assume that the KEYMGMT has a key loading
             * function that can handle the provider reference we hold.
             *
             * Otherwise, we export from the decoder and import the
             * result in the keymgmt.
             */
            if (keymgmt_prov == decoder_prov) {
                keydata = evp_keymgmt_load(keymgmt, object_ref, object_ref_sz);
            } else {
                struct evp_keymgmt_util_try_import_data_st import_data;

                import_data.keymgmt = keymgmt;
                import_data.keydata = NULL;
                import_data.selection = OSSL_KEYMGMT_SELECT_ALL;

                /*
                 * No need to check for errors here, the value of
                 * |import_data.keydata| is as much an indicator.
                 */
                (void)decoder->export_object(decoderctx,
                                             object_ref, object_ref_sz,
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

static void decoder_clean_EVP_PKEY_construct_arg(void *construct_data)
{
    struct decoder_EVP_PKEY_data_st *data = construct_data;

    if (data != NULL) {
        sk_EVP_KEYMGMT_pop_free(data->keymgmts, EVP_KEYMGMT_free);
        OPENSSL_free(data->object_type);
        OPENSSL_free(data);
    }
}

struct collected_data_st {
    struct decoder_EVP_PKEY_data_st *process_data;
    const char *keytype;
    STACK_OF(OPENSSL_CSTRING) *names;
    OSSL_DECODER_CTX *ctx;

    unsigned int error_occured:1;
};

static void collect_keymgmt(EVP_KEYMGMT *keymgmt, void *arg)
{
    struct collected_data_st *data = arg;

    if (data->keytype != NULL && !EVP_KEYMGMT_is_a(keymgmt, data->keytype))
        return;
    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */

    if (!EVP_KEYMGMT_up_ref(keymgmt) /* ref++ */)
        return;
    if (sk_EVP_KEYMGMT_push(data->process_data->keymgmts, keymgmt) <= 0) {
        EVP_KEYMGMT_free(keymgmt);   /* ref-- */
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

static void collect_decoder(OSSL_DECODER *decoder, void *arg)
{
    struct collected_data_st *data = arg;
    size_t i, end_i;

    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */
    if (data->names == NULL)
        return;

    end_i = sk_OPENSSL_CSTRING_num(data->names);
    for (i = 0; i < end_i; i++) {
        const char *name = sk_OPENSSL_CSTRING_value(data->names, i);

        if (!OSSL_DECODER_is_a(decoder, name))
            continue;
        (void)OSSL_DECODER_CTX_add_decoder(data->ctx, decoder);
    }

    data->error_occured = 0;         /* All is good now */
}

int ossl_decoder_ctx_setup_for_EVP_PKEY(OSSL_DECODER_CTX *ctx,
                                        EVP_PKEY **pkey, const char *keytype,
                                        OPENSSL_CTX *libctx,
                                        const char *propquery)
{
    struct collected_data_st *data = NULL;
    size_t i, end_i;
    int ok = 0;

    if ((data = OPENSSL_zalloc(sizeof(*data))) == NULL
        || (data->process_data =
            OPENSSL_zalloc(sizeof(*data->process_data))) == NULL
        || (data->process_data->keymgmts = sk_EVP_KEYMGMT_new_null()) == NULL
        || (data->names = sk_OPENSSL_CSTRING_new_null()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    data->process_data->object = (void **)pkey;
    data->ctx = ctx;
    data->keytype = keytype;

    /* First, find all keymgmts to form goals */
    EVP_KEYMGMT_do_all_provided(libctx, collect_keymgmt, data);

    if (data->error_occured)
        goto err;

    /* Then, we collect all the keymgmt names */
    end_i = sk_EVP_KEYMGMT_num(data->process_data->keymgmts);
    for (i = 0; i < end_i; i++) {
        EVP_KEYMGMT *keymgmt =
            sk_EVP_KEYMGMT_value(data->process_data->keymgmts, i);

        EVP_KEYMGMT_names_do_all(keymgmt, collect_name, data);

        if (data->error_occured)
            goto err;
    }

    /*
     * Finally, find all decoders that have any keymgmt of the collected
     * keymgmt names
     */
    OSSL_DECODER_do_all_provided(libctx, collect_decoder, data);

    if (data->error_occured)
        goto err;

    if (OSSL_DECODER_CTX_get_num_decoders(ctx) != 0) {
        if (!OSSL_DECODER_CTX_set_construct(ctx, decoder_construct_EVP_PKEY)
            || !OSSL_DECODER_CTX_set_construct_data(ctx, data->process_data)
            || !OSSL_DECODER_CTX_set_cleanup(ctx,
                                             decoder_clean_EVP_PKEY_construct_arg))
            goto err;

        data->process_data = NULL; /* Avoid it being freed */
    }

    ok = 1;
 err:
    if (data != NULL) {
        decoder_clean_EVP_PKEY_construct_arg(data->process_data);
        sk_OPENSSL_CSTRING_free(data->names);
        OPENSSL_free(data);
    }
    return ok;
}

OSSL_DECODER_CTX *
OSSL_DECODER_CTX_new_by_EVP_PKEY(EVP_PKEY **pkey,
                                 const char *input_type, const char *keytype,
                                 OPENSSL_CTX *libctx, const char *propquery)
{
    OSSL_DECODER_CTX *ctx = NULL;

    if ((ctx = OSSL_DECODER_CTX_new()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_DECODER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (OSSL_DECODER_CTX_set_input_type(ctx, input_type)
        && ossl_decoder_ctx_setup_for_EVP_PKEY(ctx, pkey, keytype,
                                               libctx, propquery)
        && OSSL_DECODER_CTX_add_extra(ctx, libctx, propquery))
        return ctx;

    OSSL_DECODER_CTX_free(ctx);
    return NULL;
}
