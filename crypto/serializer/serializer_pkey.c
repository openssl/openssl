/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/err.h>
#include <opentls/ui.h>
#include <opentls/params.h>
#include <opentls/serializer.h>
#include <opentls/core_names.h>
#include "internal/provider.h"
#include "internal/property.h"
#include "crypto/evp.h"
#include "serializer_local.h"

int Otls_SERIALIZER_CTX_set_cipher(Otls_SERIALIZER_CTX *ctx,
                                   const char *cipher_name,
                                   const char *propquery)
{
    Otls_PARAM params[] = { Otls_PARAM_END, Otls_PARAM_END, Otls_PARAM_END };

    params[0] =
        Otls_PARAM_construct_utf8_string(Otls_SERIALIZER_PARAM_CIPHER,
                                         (void *)cipher_name, 0);
    params[1] =
        Otls_PARAM_construct_utf8_string(Otls_SERIALIZER_PARAM_PROPERTIES,
                                         (void *)propquery, 0);

    return Otls_SERIALIZER_CTX_set_params(ctx, params);
}

int Otls_SERIALIZER_CTX_set_passphrase(Otls_SERIALIZER_CTX *ctx,
                                       const unsigned char *kstr,
                                       size_t klen)
{
    Otls_PARAM params[] = { Otls_PARAM_END, Otls_PARAM_END };

    params[0] = Otls_PARAM_construct_octet_string(Otls_SERIALIZER_PARAM_PASS,
                                                  (void *)kstr, klen);

    return Otls_SERIALIZER_CTX_set_params(ctx, params);
}

static void serializer_ctx_reset_passphrase_ui(Otls_SERIALIZER_CTX *ctx)
{
    UI_destroy_method(ctx->allocated_ui_method);
    ctx->allocated_ui_method = NULL;
    ctx->ui_method = NULL;
    ctx->ui_data = NULL;
}

int Otls_SERIALIZER_CTX_set_passphrase_ui(Otls_SERIALIZER_CTX *ctx,
                                          const UI_METHOD *ui_method,
                                          void *ui_data)
{
    if (!otls_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    serializer_ctx_reset_passphrase_ui(ctx);
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    return 1;
}

int Otls_SERIALIZER_CTX_set_passphrase_cb(Otls_SERIALIZER_CTX *ctx, int enc,
                                          pem_password_cb *cb, void *cbarg)
{
    if (!otls_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
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
 * Support for Otls_SERIALIZER_CTX_new_by_TYPE:
 * finding a suitable serializer
 */

struct selected_serializer_st {
    OPENtls_CTX *libctx;
    const Otls_PROVIDER *desired_provider;
    const char *propquery;

    /*
     * When selecting serializers, we need to check the intended use.
     * This is governed by the |domainparams| flag in the EVP_PKEY,
     * we must just make sure to filter on 'type=domainparams' accordingly.
     */
    int want_domainparams;

    /*
     * Serializers offer two functions, one that handles object data in
     * the form of a Otls_PARAM array, and one that directly handles a
     * provider side object.  The latter requires that the serializer
     * is offered by the same provider that holds that object, but is
     * more desirable because it usually provides faster serialization.
     *
     * When looking up possible serializers, we save the first that can
     * handle an Otls_PARAM array in |first|, and the first that can
     * handle a provider side object in |desired|.
     */
    Otls_SERIALIZER *first;
    Otls_SERIALIZER *desired;
};

static void select_serializer(const char *name, void *data)
{
    struct selected_serializer_st *d = data;
    Otls_SERIALIZER *s = NULL;
    Otls_PROPERTY_LIST *check =
        d->want_domainparams
        ? otls_parse_query(d->libctx, "type=domainparams")
        : NULL;

    /* No need to look further if we already have the more desirable option */
    if (d->desired != NULL)
        return;

    if ((s = Otls_SERIALIZER_fetch(d->libctx, name, d->propquery)) != NULL) {
        /*
         * Extra check if domain parameters are explicitly specified:
         * only accept serializers that have the "type=domainparams"
         * property.
         *
         * For data that isn't marked as domain parameters, a domain
         * parameters serializer is still acceptable, because a key
         * may hold domain parameters too.
         */
        if (d->want_domainparams) {
            Otls_PROPERTY_LIST *current_props =
                otls_parse_property(d->libctx, Otls_SERIALIZER_properties(s));
            int check_cnt = otls_property_match_count(check, current_props);

            if (check_cnt == 0) {
                Otls_SERIALIZER_free(s);
                return;
            }
        }

        if (d->first == NULL && s->serialize_data != NULL) {
            d->first = s;
        } else if (Otls_SERIALIZER_provider(s) == d->desired_provider
                   && s->serialize_object != NULL) {
            Otls_SERIALIZER_free(d->first);
            d->first = NULL;
            d->desired = s;
        } else {
            Otls_SERIALIZER_free(s);
        }
    }
}

/*
 * Support for Otls_SERIALIZER_CTX_new_by_TYPE and Otls_SERIALIZER_to_bio:
 * Passphrase callbacks
 */

/*
 * First, we define the generic passphrase function that supports both
 * outgoing (with passphrase verify) and incoming (without passphrase verify)
 * passphrase reading.
 */
static int serializer_passphrase(char *pass, size_t pass_size,
                                 size_t *pass_len, int verify,
                                 const Otls_PARAM params[], void *arg)
{
    Otls_SERIALIZER_CTX *ctx = arg;
    const Otls_PARAM *p;
    const char *prompt_info = NULL;
    char *prompt = NULL, *vpass = NULL;
    int prompt_idx = -1, verify_idx = -1;
    UI *ui = NULL;
    int ret = 0;

    if (!otls_assert(ctx != NULL && pass != NULL
                    && pass_size != 0 && pass_len != NULL)) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((p = Otls_PARAM_locate_const(params,
                                     Otls_PASSPHRASE_PARAM_INFO)) != NULL) {
        if (p->data_type != Otls_PARAM_UTF8_STRING)
            return 0;
        prompt_info = p->data;
    }

    if ((ui = UI_new()) == NULL) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    UI_set_method(ui, ctx->ui_method);
    UI_add_user_data(ui, ctx->ui_data);

    /* Get an application constructed prompt */
    prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
   if (prompt == NULL) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    prompt_idx = UI_add_input_string(ui, prompt,
                                     UI_INPUT_FLAG_DEFAULT_PWD,
                                     pass, 0, pass_size - 1) - 1;
    if (prompt_idx < 0) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_UI_LIB);
        goto end;
    }

    if (verify) {
        /* Get a buffer for verification prompt */
        vpass = OPENtls_zalloc(pass_size);
        if (vpass == NULL) {
            ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        verify_idx = UI_add_verify_string(ui, prompt,
                                          UI_INPUT_FLAG_DEFAULT_PWD,
                                          vpass, 0, pass_size - 1,
                                          pass) - 1;
        if (verify_idx < 0) {
            ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_UI_LIB);
            goto end;
        }
    }

    switch (UI_process(ui)) {
    case -2:
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_INTERRUPTED_OR_CANCELLED);
        break;
    case -1:
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_UI_LIB);
        break;
    default:
        *pass_len = (size_t)UI_get_result_length(ui, prompt_idx);
        ret = 1;
        break;
    }

 end:
    OPENtls_free(vpass);
    OPENtls_free(prompt);
    UI_free(ui);
    return ret;
}

/* Ensure correct function definition for outgoing passphrase reader */
static Otls_PASSPHRASE_CALLBACK serializer_passphrase_out_cb;
static int serializer_passphrase_out_cb(char *pass, size_t pass_size,
                                        size_t *pass_len,
                                        const Otls_PARAM params[], void *arg)
{
    return serializer_passphrase(pass, pass_size, pass_len, 1, params, arg);
}

/*
 * Support for Otls_SERIALIZER_to_bio:
 * writing callback for the Otls_PARAM (the implementation doesn't have
 * intimate knowledge of the provider side object)
 */

struct serializer_write_data_st {
    Otls_SERIALIZER_CTX *ctx;
    BIO *out;
};

static int serializer_write_cb(const Otls_PARAM params[], void *arg)
{
    struct serializer_write_data_st *write_data = arg;
    Otls_SERIALIZER_CTX *ctx = write_data->ctx;
    BIO *out = write_data->out;

    return ctx->ser->serialize_data(ctx->serctx, params, out,
                                    serializer_passphrase_out_cb, ctx);
}

/*
 * Support for Otls_SERIALIZER_to_bio:
 * Perform the actual output.
 */

static int serializer_EVP_PKEY_to_bio(Otls_SERIALIZER_CTX *ctx, BIO *out)
{
    const EVP_PKEY *pkey = ctx->object;
    void *provdata = pkey->pkeys[0].provdata;
    int domainparams = pkey->pkeys[0].domainparams;
    EVP_KEYMGMT *keymgmt = pkey->pkeys[0].keymgmt;

    /*
     * Otls_SERIALIZER_CTX_new() creates a context, even when the
     * serializer it's given is NULL.  Callers can detect the lack
     * of serializer with Otls_SERIALIZER_CTX_get_serializer() and
     * should take precautions, possibly call a fallback instead of
     * Otls_SERIALIZER_to_bio() / Otls_SERIALIZER_to_fp().  If it's
     * come this far, we return an error.
     */
    if (ctx->ser == NULL)
        return 0;

    if (ctx->ser->serialize_object == NULL) {
        struct serializer_write_data_st write_data;

        write_data.ctx = ctx;
        write_data.out = out;

        if (domainparams)
            return evp_keymgmt_exportdomparams(keymgmt, provdata,
                                               serializer_write_cb,
                                               &write_data);
        return evp_keymgmt_exportkey(keymgmt, provdata,
                                     serializer_write_cb, &write_data);
    }

    return ctx->ser->serialize_object(ctx->serctx, provdata, out,
                                      serializer_passphrase_out_cb, ctx);
}

/*
 * Otls_SERIALIZER_CTX_new_by_EVP_PKEY() returns a ctx with no serializer if
 * it couldn't find a suitable serializer.  This allows a caller to detect if
 * a suitable serializer was found, with Otls_SERIALIZER_CTX_get_serializer(),
 * and to use fallback methods if the result is NULL.
 */
Otls_SERIALIZER_CTX *Otls_SERIALIZER_CTX_new_by_EVP_PKEY(const EVP_PKEY *pkey,
                                                         const char *propquery)
{
    Otls_SERIALIZER_CTX *ctx = NULL;
    Otls_SERIALIZER *ser = NULL;
    EVP_KEYMGMT *keymgmt = pkey->pkeys[0].keymgmt;

    if (!otls_assert(pkey != NULL && propquery != NULL)) {
        ERR_raise(ERR_LIB_Otls_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (keymgmt != NULL) {
        const Otls_PROVIDER *desired_prov = EVP_KEYMGMT_provider(keymgmt);
        OPENtls_CTX *libctx = otls_provider_library_context(desired_prov);
        struct selected_serializer_st sel_data;

        memset(&sel_data, 0, sizeof(sel_data));
        sel_data.libctx = libctx;
        sel_data.desired_provider = desired_prov;
        sel_data.propquery = propquery;
        sel_data.want_domainparams = pkey->pkeys[0].domainparams;
        EVP_KEYMGMT_names_do_all(keymgmt, select_serializer, &sel_data);

        if (sel_data.desired != NULL) {
            ser = sel_data.desired;
            sel_data.desired = NULL;
        } else if (sel_data.first != NULL) {
            ser = sel_data.first;
            sel_data.first = NULL;
        }
        Otls_SERIALIZER_free(sel_data.first);
        Otls_SERIALIZER_free(sel_data.desired);
    }

    ctx = Otls_SERIALIZER_CTX_new(ser); /* refcnt(ser)++ */
    Otls_SERIALIZER_free(ser);          /* refcnt(ser)-- */

    if (ctx != NULL) {
        /* Setup for Otls_SERIALIZE_to_bio() */
        ctx->object = pkey;
        ctx->do_output = serializer_EVP_PKEY_to_bio;
    }

    return ctx;
}

