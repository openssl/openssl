/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

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

DEFINE_STACK_OF_CSTRING()

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
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_ENCODER_PARAM_PASS,
                                                  (void *)kstr, klen);

    return OSSL_ENCODER_CTX_set_params(ctx, params);
}

int OSSL_ENCODER_CTX_set_passphrase_ui(OSSL_ENCODER_CTX *ctx,
                                       const UI_METHOD *ui_method,
                                       void *ui_data)
{
    return ossl_pw_set_ui_method(&ctx->pwdata, ui_method, ui_data);
}

int OSSL_ENCODER_CTX_set_passphrase_cb(OSSL_ENCODER_CTX *ctx,
                                       pem_password_cb *cb, void *cbarg)
{
    return ossl_pw_set_pem_password_cb(&ctx->pwdata, cb, cbarg);
}

/*
 * Support for OSSL_ENCODER_CTX_new_by_TYPE:
 * finding a suitable encoder
 */

struct selected_encoder_st {
    STACK_OF(OPENSSL_CSTRING) *names;
    int error;
};

static void cache_encoders(const char *name, void *data)
{
    struct selected_encoder_st *d = data;

    if (sk_OPENSSL_CSTRING_push(d->names, name) <= 0)
        d->error = 1;
}

/*
 * Support for OSSL_ENCODER_to_bio:
 * writing callback for the OSSL_PARAM (the implementation doesn't have
 * intimate knowledge of the provider side object)
 */

struct encoder_write_data_st {
    OSSL_ENCODER_CTX *ctx;
    BIO *out;
};

static int encoder_write_cb(const OSSL_PARAM params[], void *arg)
{
    struct encoder_write_data_st *write_data = arg;
    OSSL_ENCODER_CTX *ctx = write_data->ctx;
    BIO *out = write_data->out;

    return ctx->encoder->encode_data(ctx->serctx, params, (OSSL_CORE_BIO *)out,
                                     ossl_pw_passphrase_callback_enc,
                                     &ctx->pwdata);
}

/*
 * Support for OSSL_ENCODER_to_bio:
 * Perform the actual output.
 */

static int encoder_EVP_PKEY_to_bio(OSSL_ENCODER_CTX *ctx, BIO *out)
{
    const EVP_PKEY *pkey = ctx->object;
    void *keydata = pkey->keydata;
    EVP_KEYMGMT *keymgmt = pkey->keymgmt;

    /*
     * OSSL_ENCODER_CTX_new() creates a context, even when the
     * encoder it's given is NULL.  Callers can detect the lack
     * of encoder with OSSL_ENCODER_CTX_get_encoder() and
     * should take precautions, possibly call a fallback instead of
     * OSSL_ENCODER_to_bio() / OSSL_ENCODER_to_fp().  If it's
     * come this far, we return an error.
     */
    if (ctx->encoder == NULL)
        return 0;

    if (ctx->encoder->encode_object == NULL
        || (OSSL_ENCODER_provider(ctx->encoder)
            != EVP_KEYMGMT_provider(keymgmt))) {
        struct encoder_write_data_st write_data;

        write_data.ctx = ctx;
        write_data.out = out;

        return evp_keymgmt_export(keymgmt, keydata, ctx->selection,
                                  &encoder_write_cb, &write_data);
    }

    return ctx->encoder->encode_object(ctx->serctx, keydata,
                                       (OSSL_CORE_BIO *)out,
                                       ossl_pw_passphrase_callback_enc,
                                       &ctx->pwdata);
}

/*
 * OSSL_ENCODER_CTX_new_by_EVP_PKEY() returns a ctx with no encoder if
 * it couldn't find a suitable encoder.  This allows a caller to detect if
 * a suitable encoder was found, with OSSL_ENCODER_CTX_get_encoder(),
 * and to use fallback methods if the result is NULL.
 */
OSSL_ENCODER_CTX *OSSL_ENCODER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                   const char *propquery)
{
    OSSL_ENCODER_CTX *ctx = NULL;
    OSSL_ENCODER *encoder = NULL;
    EVP_KEYMGMT *keymgmt = pkey->keymgmt;
    int selection = OSSL_KEYMGMT_SELECT_ALL;

    if (!ossl_assert(pkey != NULL && propquery != NULL)) {
        ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (keymgmt != NULL) {
        const OSSL_PROVIDER *desired_prov = EVP_KEYMGMT_provider(keymgmt);
        OPENSSL_CTX *libctx = ossl_provider_library_context(desired_prov);
        struct selected_encoder_st sel_data;
        OSSL_ENCODER *first = NULL;
        const char *name;
        int i;

        /*
         * Select the encoder in two steps.  First, get the names of all of
         * the encoders.  Then determine which is the best one to use.
         * This has to be broken because it isn't possible to fetch the
         * serialisers inside EVP_KEYMGMT_names_do_all() due to locking
         * order inversions with the store lock.
         */
        sel_data.error = 0;
        sel_data.names = sk_OPENSSL_CSTRING_new_null();
        if (sel_data.names == NULL)
            return NULL;
        EVP_KEYMGMT_names_do_all(keymgmt, cache_encoders, &sel_data);
        /*
         * Ignore memory allocation errors that are indicated in sel_data.error
         * in case a suitable provider does get found regardless.
         */

        /*
         * Encoders offer two functions, one that handles object data in
         * the form of a OSSL_PARAM array, and one that directly handles a
         * provider side object.  The latter requires that the encoder
         * is offered by the same provider that holds that object, but is
         * more desirable because it usually provides faster encoding.
         *
         * When looking up possible encoders, we save the first that can
         * handle an OSSL_PARAM array in |first| and use that if nothing
         * better turns up.
         */
        for (i = 0; i < sk_OPENSSL_CSTRING_num(sel_data.names); i++) {
            name = sk_OPENSSL_CSTRING_value(sel_data.names, i);
            encoder = OSSL_ENCODER_fetch(libctx, name, propquery);
            if (encoder != NULL) {
                if (OSSL_ENCODER_provider(encoder) == desired_prov
                        && encoder->encode_object != NULL) {
                    OSSL_ENCODER_free(first);
                    break;
                }
                if (first == NULL && encoder->encode_data != NULL)
                    first = encoder;
                else
                    OSSL_ENCODER_free(encoder);
                encoder = NULL;
            }
        }
        sk_OPENSSL_CSTRING_free(sel_data.names);
        if (encoder == NULL)
            encoder = first;

        if (encoder != NULL) {
            OSSL_PROPERTY_LIST *check = NULL, *current_props = NULL;

            check = ossl_parse_query(libctx, "type=parameters");
            current_props =
                ossl_parse_property(libctx, OSSL_ENCODER_properties(encoder));
            if (ossl_property_match_count(check, current_props) > 0)
                selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
            ossl_property_free(current_props);
            ossl_property_free(check);
        } else {
            if (sel_data.error)
                ERR_raise(ERR_LIB_OSSL_ENCODER, ERR_R_MALLOC_FAILURE);
            else
                ERR_raise(ERR_LIB_OSSL_ENCODER,
                          OSSL_ENCODER_R_ENCODER_NOT_FOUND);
        }
    }

    ctx = OSSL_ENCODER_CTX_new(encoder); /* refcnt(encoder)++ */
    OSSL_ENCODER_free(encoder);          /* refcnt(encoder)-- */

    if (ctx != NULL) {
        /* Setup for OSSL_ENCODE_to_bio() */
        ctx->selection = selection;
        ctx->object = pkey;
        ctx->do_output = encoder_EVP_PKEY_to_bio;
    }

    return ctx;
}

