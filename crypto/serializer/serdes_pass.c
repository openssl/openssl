/*
 * Copyright 2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/err.h>
#include <openssl/ui.h>
#include <openssl/core_names.h>
#include "internal/cryptlib.h"
#include "serializer_local.h"

/* Passphrase callbacks for any who need it */

/*
 * First, define the generic passphrase function that supports both
 * outgoing (with passphrase verify) and incoming (without passphrase
 * verify) passphrase reading.
 */
static int do_passphrase(char *pass, size_t pass_size, size_t *pass_len,
                         const OSSL_PARAM params[], void *arg, int verify,
                         const UI_METHOD *ui_method, void *ui_data, int errlib)
{
    const OSSL_PARAM *p;
    const char *prompt_info = NULL;
    char *prompt = NULL, *vpass = NULL;
    int prompt_idx = -1, verify_idx = -1;
    UI *ui = NULL;
    int ret = 0;

    if (!ossl_assert(pass != NULL && pass_size != 0 && pass_len != NULL)) {
        ERR_raise(errlib, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params,
                                     OSSL_PASSPHRASE_PARAM_INFO)) != NULL) {
        if (p->data_type != OSSL_PARAM_UTF8_STRING)
            return 0;
        prompt_info = p->data;
    }

    if ((ui = UI_new()) == NULL) {
        ERR_raise(errlib, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if (ui_method != NULL) {
        UI_set_method(ui, ui_method);
        if (ui_data != NULL)
            UI_add_user_data(ui, ui_data);
    }

    /* Get an application constructed prompt */
    prompt = UI_construct_prompt(ui, "pass phrase", prompt_info);
   if (prompt == NULL) {
        ERR_raise(errlib, ERR_R_MALLOC_FAILURE);
        goto end;
    }

    prompt_idx = UI_add_input_string(ui, prompt,
                                     UI_INPUT_FLAG_DEFAULT_PWD,
                                     pass, 0, pass_size - 1) - 1;
    if (prompt_idx < 0) {
        ERR_raise(errlib, ERR_R_UI_LIB);
        goto end;
    }

    if (verify) {
        /* Get a buffer for verification prompt */
        vpass = OPENSSL_zalloc(pass_size);
        if (vpass == NULL) {
            ERR_raise(errlib, ERR_R_MALLOC_FAILURE);
            goto end;
        }
        verify_idx = UI_add_verify_string(ui, prompt,
                                          UI_INPUT_FLAG_DEFAULT_PWD,
                                          vpass, 0, pass_size - 1,
                                          pass) - 1;
        if (verify_idx < 0) {
            ERR_raise(errlib, ERR_R_UI_LIB);
            goto end;
        }
    }

    switch (UI_process(ui)) {
    case -2:
        ERR_raise(errlib, ERR_R_INTERRUPTED_OR_CANCELLED);
        break;
    case -1:
        ERR_raise(errlib, ERR_R_UI_LIB);
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

/*
 * Serializers typically want to get an outgoing passphrase, while
 * deserializers typically want to get en incoming passphrase.
 */
int ossl_serializer_passphrase_out_cb(char *pass, size_t pass_size,
                                      size_t *pass_len,
                                      const OSSL_PARAM params[], void *arg)
{
    OSSL_SERIALIZER_CTX *ctx = arg;

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_SERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    return do_passphrase(pass, pass_size, pass_len, params, arg, 1,
                         ctx->ui_method, ctx->ui_data,
                         ERR_LIB_OSSL_SERIALIZER);
}

int ossl_deserializer_passphrase_in_cb(char *pass, size_t pass_size,
                                       size_t *pass_len,
                                       const OSSL_PARAM params[], void *arg)
{
    OSSL_DESERIALIZER_CTX *ctx = arg;

    if (!ossl_assert(ctx != NULL)) {
        ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_PASSED_NULL_PARAMETER);
        return 0;
    }

    if (ctx->cached_passphrase != NULL) {
        size_t len = ctx->cached_passphrase_len;

        if (len > pass_size)
            len = pass_size;
        memcpy(pass, ctx->cached_passphrase, len);
        *pass_len = len;
        return 1;
    } else {
        if ((ctx->cached_passphrase = OPENSSL_zalloc(pass_size)) == NULL) {
            ERR_raise(ERR_LIB_OSSL_DESERIALIZER, ERR_R_MALLOC_FAILURE);
            return 0;
        }
    }
    if (do_passphrase(pass, pass_size, pass_len, params, arg, 0,
                      ctx->ui_method, ctx->ui_data,
                      ERR_LIB_OSSL_DESERIALIZER)) {
        memcpy(ctx->cached_passphrase, pass, *pass_len);
        ctx->cached_passphrase_len = *pass_len;
        return 1;
    }
    return 0;
}
