/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
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
#include "internal/provider.h"
#include "internal/property.h"
#include "crypto/evp.h"
#include "serializer_local.h"

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

int OSSL_SERIALIZER_CTX_set_passphrase_cb(OSSL_SERIALIZER_CTX *ctx, int enc,
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
        ctx->allocated_ui_method = UI_UTIL_wrap_read_pem_callback(cb, enc);
    ctx->ui_data = cbarg;

    return ctx->ui_method != NULL;
}

/*
 * Support for OSSL_SERIALIZER_CTX_new_by_TYPE:
 * finding a suitable serializer
 */

struct selected_serializer_st {
    OPENSSL_CTX *libctx;
    const OSSL_PROVIDER *desired_provider;
    const char *propquery;

    /*
     * Serializers offer two functions, one that handles object data in
     * the form of a OSSL_PARAM array, and one that directly handles a
     * provider side object.  The latter requires that the serializer
     * is offered by the same provider that holds that object, but is
     * more desirable because it usually provides faster serialization.
     *
     * When looking up possible serializers, we save the first that can
     * handle an OSSL_PARAM array in |first|, and the first that can
     * handle a provider side object in |desired|.
     */
    OSSL_SERIALIZER *first;
    OSSL_SERIALIZER *desired;
};

static void select_serializer(const char *name, void *data)
{
    struct selected_serializer_st *d = data;
    OSSL_SERIALIZER *s = NULL;

    /* No need to look further if we already have the more desirable option */
    if (d->desired != NULL)
        return;

    if ((s = OSSL_SERIALIZER_fetch(d->libctx, name, d->propquery)) != NULL) {
        if (d->first == NULL && s->serialize_data != NULL) {
            d->first = s;
        } else if (OSSL_SERIALIZER_provider(s) == d->desired_provider
                   && s->serialize_object != NULL) {
            OSSL_SERIALIZER_free(d->first);
            d->first = NULL;
            d->desired = s;
        } else {
            OSSL_SERIALIZER_free(s);
        }
    }
}

/*
 * Support for OSSL_SERIALIZER_CTX_new_by_TYPE and OSSL_SERIALIZER_to_bio:
 * Passphrase callbacks
 */

/*
 * First, we define the generic passphrase function that supports both
 * outgoing (with passphrase verify) and incoming (without passphrase verify)
 * passphrase reading.
 */
static int serializer_passphrase(char *pass, size_t pass_size,
                                 size_t *pass_len, int verify,
                                 const OSSL_PARAM params[], void *arg)
{
    OSSL_SERIALIZER_CTX *ctx = arg;
    const OSSL_PARAM *p;
    const char *prompt_info = NULL;
    char *prompt = NULL, *vpass = NULL;
    int prompt_idx = -1, verify_idx = -1;
    UI *ui = NULL;
    int ret = 0;

    if (!ossl_assert(ctx != NULL && pass != NULL
                    && pass_size != 0 && pass_len != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_PASSPHRASE_PARAM_INFO)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        prompt_info = p->data;
    }

    if ((ui = UI_new()) == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    UI_set_method(ui, ctx->ui_method);
    UI_add_user_data(ui, ctx->ui_data);

    /* Get an application constructed prompt */
    prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
   if (prompt == NULL) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    prompt_idx = UI_add_input_string(ui, prompt,
                                     UI_INPUT_FLAG_DEFAULT_PWD,
                                     pass, 0, pass_size - 1) - 1;
    if (prompt_idx < 0) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_UI_LIB);
        goto end;
    }

    if (verify) {
        /* Get a buffer for verification prompt */
        vpass = OPENSSL_zalloc(pass_size);
        if (vpass == NULL) {
            ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        verify_idx = UI_add_verify_string(ui, prompt,
                                          UI_INPUT_FLAG_DEFAULT_PWD,
                                          vpass, 0, pass_size - 1,
                                          pass) - 1;
        if (verify_idx < 0) {
            ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_UI_LIB);
            goto end;
        }
    }

    switch (UI_process(ui)) {
    case -2:
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_INTERRUPTED_OR_CANCELLED);
        break;
    case -1:
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_UI_LIB);
        break;
    default:
        *pass_len = (size_t)UI_get_result_length(ui, prompt_idx);
        ret = 1;
        break;
    }

 end:
    OPENSSL_free(vpass);
    OPENSSL_free(prompt);
    UI_free(ui);
    return ret;
}

/* Ensure correct function definition for outgoing passphrase reader */
static OSSL_PASSPHRASE_CALLBACK serializer_passphrase_out_cb;
static int serializer_passphrase_out_cb(char *pass, size_t pass_size,
                                        size_t *pass_len,
                                        const OSSL_PARAM params[], void *arg)
{
    return serializer_passphrase(pass, pass_size, pass_len, 1, params, arg);
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

    return ctx->ser->serialize_data(ctx->serctx, params, out,
                                    serializer_passphrase_out_cb, ctx);
}

/*
 * Support for OSSL_SERIALIZER_to_bio:
 * Perform the actual output.
 */

static int serializer_EVP_PKEY_to_bio(OSSL_SERIALIZER_CTX *ctx, BIO *out)
{
    const EVP_PKEY *pkey = ctx->object;
    void *keydata = pkey->pkeys[0].keydata;
    EVP_KEYMGMT *keymgmt = pkey->pkeys[0].keymgmt;

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

    return ctx->ser->serialize_object(ctx->serctx, keydata, out,
                                      serializer_passphrase_out_cb, ctx);
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
    EVP_KEYMGMT *keymgmt = pkey->pkeys[0].keymgmt;
    int selection = OSSL_KEYMGMT_SELECT_ALL;

    if (!ossl_assert(pkey != NULL && propquery != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (keymgmt != NULL) {
        const OSSL_PROVIDER *desired_prov = EVP_KEYMGMT_provider(keymgmt);
        OPENSSL_CTX *libctx = ossl_provider_library_context(desired_prov);
        struct selected_serializer_st sel_data;
        OSSL_PROPERTY_LIST *check =
            ossl_parse_query(libctx, "type=parameters");
        OSSL_PROPERTY_LIST *current_props = NULL;

        memset(&sel_data, 0, sizeof(sel_data));
        sel_data.libctx = libctx;
        sel_data.desired_provider = desired_prov;
        sel_data.propquery = propquery;
        EVP_KEYMGMT_names_do_all(keymgmt, select_serializer, &sel_data);

        if (sel_data.desired != NULL) {
            ser = sel_data.desired;
            sel_data.desired = NULL;
        } else if (sel_data.first != NULL) {
            ser = sel_data.first;
            sel_data.first = NULL;
        }
        OSSL_SERIALIZER_free(sel_data.first);
        OSSL_SERIALIZER_free(sel_data.desired);

        current_props =
            ossl_parse_property(libctx, OSSL_SERIALIZER_properties(ser));
        if (ossl_property_match_count(check, current_props) > 0)
            selection = OSSL_KEYMGMT_SELECT_ALL_PARAMETERS;

        ossl_property_free(current_props);
        ossl_property_free(check);
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

