/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include "internal/thread_once.h"
#include "store_locl.h"

struct store_ctx_st {
    const STORE_LOADER *loader;
    STORE_LOADER_CTX *loader_ctx;
    const UI_METHOD *ui_method;
    void *ui_data;
    STORE_post_process_info_fn post_process;
    void *post_process_data;
};

STORE_CTX *STORE_open(const char *uri, const UI_METHOD *ui_method,
                      void *ui_data, STORE_post_process_info_fn post_process,
                      void *post_process_data)
{
    const STORE_LOADER *loader;
    STORE_LOADER_CTX *loader_ctx = NULL;
    STORE_CTX *ctx = NULL;
    char scheme_copy[256], *p;

    OPENSSL_strlcpy(scheme_copy, uri, sizeof(scheme_copy));
    if ((p = strchr(scheme_copy, ':')) != NULL) {
        *p = '\0';
        p = scheme_copy;
    } else {
        p = "file";
    }

    if ((loader = store_get0_loader_int(p)) == NULL
        || (loader_ctx = loader->open(loader, uri, ui_method, ui_data)) == NULL)
        goto done;
    if ((ctx = OPENSSL_zalloc(sizeof(*ctx))) == NULL) {
        STOREerr(STORE_F_STORE_OPEN, ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ctx->loader = loader;
    ctx->loader_ctx = loader_ctx;
    loader_ctx = NULL;
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    ctx->post_process = post_process;
    ctx->post_process_data = post_process_data;

 done:
    if (loader_ctx != NULL) {
        /*
         * We ignore a returned error because we will return NULL anyway in
         * this case, so if something goes wrong when closing, that'll simply
         * just add another entry on the error stack.
         */
        (void)loader->close(loader_ctx);
    }
    return ctx;
}

int STORE_ctrl(STORE_CTX *ctx, int cmd, ...)
{
    va_list args;
    int ret = 0;

    va_start(args, cmd);
    if (ctx->loader->ctrl != NULL)
        ret = ctx->loader->ctrl(ctx->loader_ctx, cmd, args);
    va_end(args);

    return ret;
}

STORE_INFO *STORE_load(STORE_CTX *ctx)
{
    STORE_INFO *v = NULL;

 again:
    v = ctx->loader->load(ctx->loader_ctx, ctx->ui_method, ctx->ui_data);

    if (ctx->post_process != NULL && v != NULL) {
        v = ctx->post_process(v, ctx->post_process_data);

        /*
         * By returning NULL, the callback decides that this object should
         * be ignored.
         */
        if (v == NULL)
            goto again;
    }

    return v;
}

int STORE_eof(STORE_CTX *ctx)
{
    return ctx->loader->eof(ctx->loader_ctx);
}

int STORE_close(STORE_CTX *ctx)
{
    int loader_ret = ctx->loader->close(ctx->loader_ctx);

    OPENSSL_free(ctx);
    return loader_ret;
}

/*
 * Functions to generate STORE_INFOs, one function for each type we
 * support having in them.  Along with each of them, one macro that
 * can be used to determine what types are supported.
 *
 * In all cases, ownership of the object is transfered to the STORE_INFO
 * and will therefore be freed when the STORE_INFO is freed.
 */
static STORE_INFO *store_info_new(int type, void *data)
{
    STORE_INFO *info = OPENSSL_zalloc(sizeof(*info));

    if (info == NULL)
        return NULL;

    info->type = type;
    info->_.data = data;
    return info;
}

STORE_INFO *STORE_INFO_new_NAME(char *name)
{
    STORE_INFO *info = store_info_new(STORE_INFO_NAME, NULL);

    if (info == NULL) {
        STOREerr(STORE_F_STORE_INFO_NEW_NAME, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    info->_.name.name = name;
    info->_.name.desc = NULL;

    return info;
}

int STORE_INFO_set0_NAME_description(STORE_INFO *info, char *desc)
{
    if (info->type != STORE_INFO_NAME) {
        STOREerr(STORE_F_STORE_INFO_SET0_NAME_DESCRIPTION,
                 ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    info->_.name.desc = desc;

    return 1;
}
STORE_INFO *STORE_INFO_new_PARAMS(EVP_PKEY *params)
{
    STORE_INFO *info = store_info_new(STORE_INFO_PARAMS, params);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_PARAMS, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_PKEY(EVP_PKEY *pkey)
{
    STORE_INFO *info = store_info_new(STORE_INFO_PKEY, pkey);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_PKEY, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_CERT(X509 *x509)
{
    STORE_INFO *info = store_info_new(STORE_INFO_CERT, x509);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_CERT, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_CRL(X509_CRL *crl)
{
    STORE_INFO *info = store_info_new(STORE_INFO_CRL, crl);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_CRL, ERR_R_MALLOC_FAILURE);
    return info;
}

STORE_INFO *STORE_INFO_new_ENDOFDATA(void)
{
    STORE_INFO *info = store_info_new(STORE_INFO_UNSPECIFIED, NULL);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_ENDOFDATA, ERR_R_MALLOC_FAILURE);
    return info;
}

/*
 * Functions to try to extract data from a STORE_INFO.
 */
int STORE_INFO_get_type(const STORE_INFO *store_info)
{
    return store_info->type;
}

const char *STORE_INFO_get0_NAME(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_NAME)
        return store_info->_.name.name;
    return NULL;
}

char *STORE_INFO_get1_NAME(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_NAME) {
        char *ret = OPENSSL_strdup(store_info->_.name.name);

        if (ret == NULL)
            STOREerr(STORE_F_STORE_INFO_GET1_NAME, ERR_R_MALLOC_FAILURE);
        return ret;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_NAME, STORE_R_NOT_A_NAME);
    return NULL;
}

const char *STORE_INFO_get0_NAME_description(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_NAME)
        return store_info->_.name.desc;
    return NULL;
}

char *STORE_INFO_get1_NAME_description(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_NAME) {
        char *ret = OPENSSL_strdup(store_info->_.name.desc
                                   ? store_info->_.name.desc : "");

        if (ret == NULL)
            STOREerr(STORE_F_STORE_INFO_GET1_NAME_DESCRIPTION,
                     ERR_R_MALLOC_FAILURE);
        return ret;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_NAME_DESCRIPTION, STORE_R_NOT_A_NAME);
    return NULL;
}

EVP_PKEY *STORE_INFO_get0_PARAMS(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PARAMS)
        return store_info->_.params;
    return NULL;
}

EVP_PKEY *STORE_INFO_get1_PARAMS(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PARAMS) {
        EVP_PKEY_up_ref(store_info->_.params);
        return store_info->_.params;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_PARAMS, STORE_R_NOT_PARAMETERS);
    return NULL;
}

EVP_PKEY *STORE_INFO_get0_PKEY(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PKEY)
        return store_info->_.pkey;
    return NULL;
}

EVP_PKEY *STORE_INFO_get1_PKEY(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PKEY) {
        EVP_PKEY_up_ref(store_info->_.pkey);
        return store_info->_.pkey;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_PKEY, STORE_R_NOT_A_KEY);
    return NULL;
}

X509 *STORE_INFO_get0_CERT(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CERT)
        return store_info->_.x509;
    return NULL;
}

X509 *STORE_INFO_get1_CERT(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CERT) {
        X509_up_ref(store_info->_.x509);
        return store_info->_.x509;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_CERT, STORE_R_NOT_A_CERTIFICATE);
    return NULL;
}

X509_CRL *STORE_INFO_get0_CRL(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CRL)
        return store_info->_.crl;
    return NULL;
}

X509_CRL *STORE_INFO_get1_CRL(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CRL) {
        X509_CRL_up_ref(store_info->_.crl);
        return store_info->_.crl;
    }
    STOREerr(STORE_F_STORE_INFO_GET1_CRL, STORE_R_NOT_A_CRL);
    return NULL;
}

/*
 * Free the STORE_INFO
 */
void STORE_INFO_free(STORE_INFO *store_info)
{
    if (store_info != NULL) {
        switch (store_info->type) {
        case STORE_INFO_DECODED:
            BUF_MEM_free(store_info->_.decoded.blob);
            OPENSSL_free(store_info->_.decoded.pem_name);
            break;
        case STORE_INFO_NAME:
            OPENSSL_free(store_info->_.name.name);
            OPENSSL_free(store_info->_.name.desc);
            break;
        case STORE_INFO_PARAMS:
            EVP_PKEY_free(store_info->_.params);
            break;
        case STORE_INFO_PKEY:
            EVP_PKEY_free(store_info->_.pkey);
            break;
        case STORE_INFO_CERT:
            X509_free(store_info->_.x509);
            break;
        case STORE_INFO_CRL:
            X509_CRL_free(store_info->_.crl);
            break;
        }
        OPENSSL_free(store_info);
    }
}

/* Internal functions */
STORE_INFO *store_info_new_DECODED(const char *new_pem_name, BUF_MEM *decoded)
{
    STORE_INFO *info = store_info_new(STORE_INFO_DECODED, NULL);

    if (info == NULL) {
        STOREerr(STORE_F_STORE_INFO_NEW_DECODED, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    info->_.decoded.blob = decoded;
    info->_.decoded.pem_name =
        new_pem_name == NULL ? NULL : OPENSSL_strdup(new_pem_name);

    if (new_pem_name != NULL && info->_.decoded.pem_name == NULL) {
        STOREerr(STORE_F_STORE_INFO_NEW_DECODED, ERR_R_MALLOC_FAILURE);
        STORE_INFO_free(info);
        info = NULL;
    }

    return info;
}

BUF_MEM *store_info_get0_DECODED_buffer(STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_DECODED)
        return store_info->_.decoded.blob;
    return NULL;
}

char *store_info_get0_DECODED_pem_name(STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_DECODED)
        return store_info->_.decoded.pem_name;
    return NULL;
}
