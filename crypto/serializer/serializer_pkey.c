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
#include <openssl/serializer.h>
#include <openssl/core_names.h>
#include <openssl/safestack.h>
#include "internal/provider.h"
#include "internal/property.h"
#include "crypto/evp.h"
#include "serializer_local.h"

DEFINE_STACK_OF_CSTRING()

int OSSL_SERIALIZER_CTX_set_cipher(OSSL_SERIALIZER_CTX *ctx,
                                   const char *cipher_name,
                                   const char *propquery)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] =
        OSSL_PARAM_construct_utf8_string(OSSL_SERIALIZER_PARAM_CIPHER,
                                         (void *)cipher_name, 0);
    params[1] =
        OSSL_PARAM_construct_utf8_string(OSSL_SERIALIZER_PARAM_PROPERTIES,
                                         (void *)propquery, 0);

    return OSSL_SERIALIZER_CTX_set_params(ctx, params);
}

int OSSL_SERIALIZER_CTX_set_passphrase(OSSL_SERIALIZER_CTX *ctx,
                                       const unsigned char *kstr,
                                       size_t klen)
{
    OSSL_PARAM params[] = { OSSL_PARAM_END, OSSL_PARAM_END };

    params[0] = OSSL_PARAM_construct_octet_string(OSSL_SERIALIZER_PARAM_PASS,
                                                  (void *)kstr, klen);

    return OSSL_SERIALIZER_CTX_set_params(ctx, params);
}

static void serializer_ctx_reset_passphrase_ui(OSSL_SERIALIZER_CTX *ctx)
{
    UI_destroy_method(ctx->allocated_ui_method);
    ctx->allocated_ui_method = NULL;
    ctx->ui_method = NULL;
    ctx->ui_data = NULL;
}

int OSSL_SERIALIZER_CTX_set_passphrase_ui(OSSL_SERIALIZER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    serializer_ctx_reset_passphrase_ui(ctx);
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    return 1;
}

int OSSL_SERIALIZER_CTX_set_passphrase_cb(OSSL_SERIALIZER_CTX *ctx,
                                          pem_password_cb *cb, void *cbarg)
{
    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    serializer_ctx_reset_passphrase_ui(ctx);
    if (cb == NULL)
        return 1;
    ctx->ui_method =
        ctx->allocated_ui_method = UI_UTIL_wrap_read_pem_callback(cb, 1);
    ctx->ui_data = cbarg;

    return ctx->ui_method != NULL;
}

/*
 * Support for OSSL_SERIALIZER_CTX_new_by_TYPE:
 * finding a suitable serializer
 */

struct selected_serializer_st {
    STACK_OF(OPENSSL_CSTRING) *names;
    int error;
};

static void cache_serializers(const char *name, void *data)
{
    struct selected_serializer_st *d = data;

    if (sk_OPENSSL_CSTRING_push(d->names, name) <= 0)
        d->error = 1;
}

/*
 * Support for OSSL_SERIALIZER_to_bio:
 * writing callback for the OSSL_PARAM (the implementation doesn't have
 * intimate knowledge of the provider side object)
 */

struct serializer_write_data_st {
    OSSL_SERIALIZER_CTX *ctx;
    BIO *out;
};

static int serializer_write_cb(const OSSL_PARAM params[], void *arg)
{
    struct serializer_write_data_st *write_data = arg;
    OSSL_SERIALIZER_CTX *ctx = write_data->ctx;
    BIO *out = write_data->out;

    return ctx->ser->serialize_data(ctx->serctx, params, (OSSL_CORE_BIO *)out,
                                    ossl_serializer_passphrase_out_cb, ctx);
}

/*
 * Support for OSSL_SERIALIZER_to_bio:
 * Perform the actual output.
 */

static int serializer_EVP_PKEY_to_bio(OSSL_SERIALIZER_CTX *ctx, BIO *out)
{
    const EVP_PKEY *pkey = ctx->object;
    void *keydata = pkey->keydata;
    EVP_KEYMGMT *keymgmt = pkey->keymgmt;

    /*
     * OSSL_SERIALIZER_CTX_new() creates a context, even when the
     * serializer it's given is NULL.  Callers can detect the lack
     * of serializer with OSSL_SERIALIZER_CTX_get_serializer() and
     * should take precautions, possibly call a fallback instead of
     * OSSL_SERIALIZER_to_bio() / OSSL_SERIALIZER_to_fp().  If it's
     * come this far, we return an error.
     */
    if (ctx->ser == NULL)
        return 0;

    if (ctx->ser->serialize_object == NULL) {
        struct serializer_write_data_st write_data;

        write_data.ctx = ctx;
        write_data.out = out;

        return evp_keymgmt_export(keymgmt, keydata, ctx->selection,
                                  &serializer_write_cb, &write_data);
    }

    return ctx->ser->serialize_object(ctx->serctx, keydata,
                                      (OSSL_CORE_BIO *)out,
                                      ossl_serializer_passphrase_out_cb, ctx);
}

/*
 * OSSL_SERIALIZER_CTX_new_by_EVP_PKEY() returns a ctx with no serializer if
 * it couldn't find a suitable serializer.  This allows a caller to detect if
 * a suitable serializer was found, with OSSL_SERIALIZER_CTX_get_serializer(),
 * and to use fallback methods if the result is NULL.
 */
OSSL_SERIALIZER_CTX *OSSL_SERIALIZER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                         const char *propquery)
{
    OSSL_SERIALIZER_CTX *ctx = NULL;
    OSSL_SERIALIZER *ser = NULL;
    EVP_KEYMGMT *keymgmt = pkey->keymgmt;
    int selection = OSSL_KEYMGMT_SELECT_ALL;

    if (!ossl_assert(pkey != NULL && propquery != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (keymgmt != NULL) {
        const OSSL_PROVIDER *desired_prov = EVP_KEYMGMT_provider(keymgmt);
        OPENSSL_CTX *libctx = ossl_provider_library_context(desired_prov);
        struct selected_serializer_st sel_data;
        OSSL_SERIALIZER *first = NULL;
        const char *name;
        int i;

        /*
         * Select the serializer in two steps.  First, get the names of all of
         * the serializers.  Then determine which is the best one to use.
         * This has to be broken because it isn't possible to fetch the
         * serialisers inside EVP_KEYMGMT_names_do_all() due to locking
         * order inversions with the store lock.
         */
        sel_data.error = 0;
        sel_data.names = sk_OPENSSL_CSTRING_new_null();
        if (sel_data.names == NULL)
            return NULL;
        EVP_KEYMGMT_names_do_all(keymgmt, cache_serializers, &sel_data);
        /*
         * Ignore memory allocation errors that are indicated in sel_data.error
         * in case a suitable provider does get found regardless.
         */

        /*
         * Serializers offer two functions, one that handles object data in
         * the form of a OSSL_PARAM array, and one that directly handles a
         * provider side object.  The latter requires that the serializer
         * is offered by the same provider that holds that object, but is
         * more desirable because it usually provides faster serialization.
         *
         * When looking up possible serializers, we save the first that can
         * handle an OSSL_PARAM array in |first| and use that if nothing
         * better turns up.
         */
        for (i = 0; i < sk_OPENSSL_CSTRING_num(sel_data.names); i++) {
            name = sk_OPENSSL_CSTRING_value(sel_data.names, i);
            ser = OSSL_SERIALIZER_fetch(libctx, name, propquery);
            if (ser != NULL) {
                if (OSSL_SERIALIZER_provider(ser) == desired_prov
                        && ser->serialize_object != NULL) {
                    OSSL_SERIALIZER_free(first);
                    break;
                }
                if (first == NULL && ser->serialize_data != NULL)
                    first = ser;
                else
                    OSSL_SERIALIZER_free(ser);
                ser = NULL;
            }
        }
        sk_OPENSSL_CSTRING_free(sel_data.names);
        if (ser == NULL)
            ser = first;

        if (ser != NULL) {
            OSSL_PROPERTY_LIST *check = NULL, *current_props = NULL;

            check = ossl_parse_query(libctx, "type=parameters");
            current_props =
                ossl_parse_property(libctx, OSSL_SERIALIZER_properties(ser));
            if (ossl_property_match_count(check, current_props) > 0)
                selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;
            ossl_property_free(current_props);
            ossl_property_free(check);
        } else {
            if (sel_data.error)
                ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_MALLOC_FAILURE);
            else
                ERR_raise(ERR_LIB_OSSL_SERIALIZER,
                          OSSL_SERIALIZER_R_SERIALIZER_NOT_FOUND);
        }
    }

    ctx = OSSL_SERIALIZER_CTX_new(ser); /* refcnt(ser)++ */
    OSSL_SERIALIZER_free(ser);          /* refcnt(ser)-- */

    if (ctx != NULL) {
        /* Setup for OSSL_SERIALIZE_to_bio() */
        ctx->selection = selection;
        ctx->object = pkey;
        ctx->do_output = serializer_EVP_PKEY_to_bio;
    }

    return ctx;
}

