/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "e_os.h"                /* strcasecmp on Windows */
#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/params.h>
#include <openssl/encoder.h>
#include <openssl/core_names.h>
#include <openssl/safestack.h>
#include "internal/provider.h"
#include "internal/property.h"
#include "crypto/evp.h"
#include "encoder_local.h"

DEFINE_STACK_OF(OSSL_ENCODER)

int OSSL_ENCODER_CTX_set_cipher(OSSL_ENCODER_CTX *ctx,
                                const char *cipher_name,
                                const char *propquery)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_CIPHER,
                                         (void *)cipher_name, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_ENCODER_PARAM_PROPERTIES,
                                         (void *)propquery, 0);

    return OSSL_ENCODER_CTX_set_params(ctx, params);
}

int OSSL_ENCODER_CTX_set_passphrase(OSSL_ENCODER_CTX *ctx,
                                    const unsigned char *kstr,
                                    size_t klen)
{
    return ossl_pw_set_passphrase(&ctx->pwdata, kstr, klen);
}

int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
                                       const UI_METHOD *ui_method,
                                       void *ui_data)
{
    return ossl_pw_set_ui_method(&ctx->pwdata, ui_method, ui_data);
}

int OSSL_ENCODER_CTX_set_pem_password_cb(OSSL_ENCODER_CTX *ctx,
                                         pem_password_cb *cb, void *cbarg)
{
    return ossl_pw_set_pem_password_cb(&ctx->pwdata, cb, cbarg);
}

int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
                                       OSSL_PASSPHRASE_CALLBACK *cb,
                                       void *cbarg)
{
    return ossl_pw_set_ossl_passphrase_cb(&ctx->pwdata, cb, cbarg);
}

/*
 * Support for OSSL_ENCODER_CTX_new_by_TYPE:
 * finding a suitable encoder
 */

struct collected_encoder_st {
    const char *output_type;
    STACK_OF(OSSL_ENCODER) *encoders;
    int error_occured;
};

static void collect_encoder(OSSL_ENCODER *encoder, void *arg)
{
    struct collected_encoder_st *data = arg;
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    const char *output_type = NULL;

    if (data->error_occured)
        return;

    /*
     * Ask for the output type.  If the encoder doesn't answer to that,
     * we refuse it.
     */
    params[0] =
        OSSL_PARAM_construct_utf8_ptr(OSSL_ENCODER_PARAM_OUTPUT_TYPE,
                                      (char **)&output_type, 0);
    if (!encoder->get_params(params)
        || !OSSL_PARAM_modified(&params[0])
        || output_type == NULL
        || strcasecmp(output_type, data->output_type) != 0)
        return;

    data->error_occured = 1;         /* Assume the worst */

    if (!OSSL_ENCODER_up_ref(encoder) /* ref++ */)
        return;
    if (sk_OSSL_ENCODER_push(data->encoders, encoder) <= 0) {
        OSSL_ENCODER_free(encoder);  /* ref-- */
        return;
    }

    data->error_occured = 0;         /* All is good now */
}

struct collected_names_st {
    STACK_OF(OPENSSL_CSTRING) *names;
    unsigned int error_occured:1;
};

static void collect_name(const char *name, void *arg)
{
    struct collected_names_st *data = arg;

    if (data->error_occured)
        return;

    data->error_occured = 1;         /* Assume the worst */

    if (sk_OPENSSL_CSTRING_push(data->names, name) <= 0)
        return;

    data->error_occured = 0;         /* All is good now */
}

/*
 * Support for OSSL_ENCODER_to_bio:
 * writing callback for the OSSL_PARAM (the implementation doesn't have
 * intimate knowledge of the provider side object)
 */

struct construct_data_st {
    const EVP_PKEY *pk;
    int selection;

    OSSL_ENCODER_INSTANCE *encoder_inst;
    const void *obj;
    void *constructed_obj;
};

static int encoder_import_cb(const OSSL_PARAM params[], void *arg)
{
    struct construct_data_st *construct_data = arg;
    OSSL_ENCODER_INSTANCE *encoder_inst = construct_data->encoder_inst;
    OSSL_ENCODER *encoder = OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
    void *encoderctx = OSSL_ENCODER_INSTANCE_get_encoder_ctx(encoder_inst);

    construct_data->constructed_obj =
        encoder->import_object(encoderctx, construct_data->selection, params);

    return (construct_data->constructed_obj != NULL);
}

static const void *
encoder_construct_EVP_PKEY(OSSL_ENCODER_INSTANCE *encoder_inst, void *arg)
{
    struct construct_data_st *data = arg;

    if (data->obj == NULL) {
        OSSL_ENCODER *encoder =
            OSSL_ENCODER_INSTANCE_get_encoder(encoder_inst);
        const EVP_PKEY *pk = data->pk;
        const OSSL_PROVIDER *k_prov = EVP_KEYMGMT_provider(pk->keymgmt);
        const OSSL_PROVIDER *e_prov = OSSL_ENCODER_provider(encoder);

        if (k_prov != e_prov) {
            data->encoder_inst = encoder_inst;

            if (!evp_keymgmt_export(pk->keymgmt, pk->keydata, data->selection,
                                    &encoder_import_cb, data))
                return NULL;
            data->obj = data->constructed_obj;
        } else {
            data->obj = pk->keydata;
        }
    }

    return data->obj;
}

static void encoder_destruct_EVP_PKEY(void *arg)
{
    struct construct_data_st *data = arg;

    if (data->encoder_inst != NULL) {
        OSSL_ENCODER *encoder =
            OSSL_ENCODER_INSTANCE_get_encoder(data->encoder_inst);

        encoder->free_object(data->constructed_obj);
    }
    data->constructed_obj = NULL;
}

/*
 * OSSL_ENCODER_CTX_new_by_EVP_PKEY() returns a ctx with no encoder if
 * it couldn't find a suitable encoder.  This allows a caller to detect if
 * a suitable encoder was found, with OSSL_ENCODER_CTX_get_num_encoder(),
 * and to use fallback methods if the result is NULL.
 */
static int ossl_encoder_ctx_setup_for_EVP_PKEY(OSSL_ENCODER_CTX *ctx,
                                               const EVP_PKEY *pkey,
                                               int selection,
                                               OPENSSL_CTX *libctx,
                                               const char *propquery)
{
    struct construct_data_st *data = NULL;
    int ok = 0;

    if (!ossl_assert(ctx != NULL) || !ossl_assert(pkey != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (pkey->keymgmt != NULL) {
        OSSL_ENCODER *found = NULL;
        const OSSL_PROVIDER *desired_prov = EVP_KEYMGMT_provider(pkey->keymgmt);
        struct collected_encoder_st encoder_data;
        struct collected_names_st keymgmt_data;
        int i;

        if ((data = OPENSSL_zalloc(sizeof(*data))) == NULL) {
            ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
            goto err;
        }

        /*
         * Select the encoder in two steps.  First, collect all encoders
         * that have the correct output type, as well as all keymgmt names.
         */
        encoder_data.output_type = ctx->output_type;
        encoder_data.encoders = sk_OSSL_ENCODER_new_null();
        encoder_data.error_occured = 0;
        keymgmt_data.names = sk_OPENSSL_CSTRING_new_null();
        keymgmt_data.error_occured = 0;
        if (encoder_data.encoders == NULL || keymgmt_data.names == NULL) {
            sk_OSSL_ENCODER_free(encoder_data.encoders);
            sk_OPENSSL_CSTRING_free(keymgmt_data.names);
            return 0;
        }
        OSSL_ENCODER_do_all_provided(libctx, collect_encoder, &encoder_data);
        EVP_KEYMGMT_names_do_all(pkey->keymgmt, collect_name, &keymgmt_data);

        /*-
         * Now we look for the most desirable encoder for our |pkey|.
         *
         * Encoders offer two functions:
         *
         * - one ('encode') that encodes a given provider-native object that
         *   it knows intimately, so it must be from the same provider.
         * - one ('import_object') that imports the parameters of an object
         *   of the same type from a different provider, which is used to
         *   create a temporary object that 'encode' can handle.
         *
         * It is, of course, more desirable to be able to use 'encode'
         * directly without having to go through an export/import maneuver,
         * but the latter allows us to have generic encoders.
         *
         * Of course, if |libctx| is different from |pkey|'s library context,
         * we're going to have to do an export/import maneuvre no matter what.
         */
        for (i = 0; i < sk_OSSL_ENCODER_num(encoder_data.encoders); i++) {
            OSSL_ENCODER *encoder =
                sk_OSSL_ENCODER_value(encoder_data.encoders, i);
            int j;

            /* Check that any of the |keymgmt| names match */
            for (j = 0; j < sk_OPENSSL_CSTRING_num(keymgmt_data.names); j++) {
                const char *name =
                    sk_OPENSSL_CSTRING_value(keymgmt_data.names, j);

                if (OSSL_ENCODER_is_a(encoder, name))
                    break;
            }

            if (j == sk_OPENSSL_CSTRING_num(keymgmt_data.names))
                continue;

            /* We found one!  Process it */
            if (OSSL_ENCODER_provider(encoder) == desired_prov) {
                /*
                 * We found one in the same provider as the keymgmt.  Choose
                 * it and stop looking.
                 */
                found = encoder;
                break;
            }
            if (found == NULL && encoder->import_object != NULL) {
                /*
                 * We found one that's good enough.  Choose it for now, but
                 * keep looking.
                 */
                found = encoder;
            }
        }

        if (found != NULL) {
            (void)OSSL_ENCODER_CTX_add_encoder(ctx, found);
        } else {
            if (encoder_data.error_occured)
                ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
            else
                ERR_raise(ERR_LIB_OSSL_ENCODER,
                          OSSL_ENCODER_R_ENCODER_NOT_FOUND);
        }

        sk_OPENSSL_CSTRING_free(keymgmt_data.names);
        sk_OSSL_ENCODER_pop_free(encoder_data.encoders, OSSL_ENCODER_free);
    }

    if (OSSL_ENCODER_CTX_get_num_encoders(ctx) != 0) {
        if (!OSSL_ENCODER_CTX_set_construct(ctx, encoder_construct_EVP_PKEY)
            || !OSSL_ENCODER_CTX_set_construct_data(ctx, data)
            || !OSSL_ENCODER_CTX_set_cleanup(ctx, encoder_destruct_EVP_PKEY))
            goto err;

        data->pk = pkey;
        data->selection = selection;

        data = NULL;             /* Avoid it being freed */
    }

    ok = 1;
 err:
    if (data != NULL) {
        OSSL_ENCODER_CTX_set_construct_data(ctx, NULL);
        OPENSSL_free(data);
    }
    return ok;
}

OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                   const char *output_type,
                                                   int selection,
                                                   OPENSSL_CTX *libctx,
                                                   const char *propquery)
{
    OSSL_ENCODER_CTX *ctx = NULL;

    if ((ctx = OSSL_ENCODER_CTX_new()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    if (OSSL_ENCODER_CTX_set_output_type(ctx, output_type)
        && OSSL_ENCODER_CTX_set_selection(ctx, selection)
        && ossl_encoder_ctx_setup_for_EVP_PKEY(ctx, pkey, selection,
                                               libctx, propquery)
        && OSSL_ENCODER_CTX_add_extra(ctx, libctx, propquery))
        return ctx;

    OSSL_ENCODER_CTX_free(ctx);
    return NULL;
}
