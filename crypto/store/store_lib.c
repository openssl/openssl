/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include "e_os.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "e_os.h"

#include <opentls/crypto.h>
#include <opentls/err.h>
#include <opentls/trace.h>
#include <opentls/store.h>
#include "internal/thread_once.h"
#include "crypto/store.h"
#include "store_local.h"

struct otls_store_ctx_st {
    const Otls_STORE_LOADER *loader;
    Otls_STORE_LOADER_CTX *loader_ctx;
    const UI_METHOD *ui_method;
    void *ui_data;
    Otls_STORE_post_process_info_fn post_process;
    void *post_process_data;
    int expected_type;

    /* 0 before the first STORE_load(), 1 otherwise */
    int loading;
};

Otls_STORE_CTX *Otls_STORE_open(const char *uri, const UI_METHOD *ui_method,
                                void *ui_data,
                                Otls_STORE_post_process_info_fn post_process,
                                void *post_process_data)
{
    const Otls_STORE_LOADER *loader = NULL;
    Otls_STORE_LOADER_CTX *loader_ctx = NULL;
    Otls_STORE_CTX *ctx = NULL;
    char scheme_copy[256], *p, *schemes[2];
    size_t schemes_n = 0;
    size_t i;

    /*
     * Put the file scheme first.  If the uri does represent an existing file,
     * possible device name and all, then it should be loaded.  Only a failed
     * attempt at loading a local file should have us try something else.
     */
    schemes[schemes_n++] = "file";

    /*
     * Now, check if we have something that looks like a scheme, and add it
     * as a second scheme.  However, also check if there's an authority start
     * (://), because that will invalidate the previous file scheme.  Also,
     * check that this isn't actually the file scheme, as there's no point
     * going through that one twice!
     */
    OPENtls_strlcpy(scheme_copy, uri, sizeof(scheme_copy));
    if ((p = strchr(scheme_copy, ':')) != NULL) {
        *p++ = '\0';
        if (strcasecmp(scheme_copy, "file") != 0) {
            if (strncmp(p, "//", 2) == 0)
                schemes_n--;         /* Invalidate the file scheme */
            schemes[schemes_n++] = scheme_copy;
        }
    }

    ERR_set_mark();

    /* Try each scheme until we find one that could open the URI */
    for (i = 0; loader_ctx == NULL && i < schemes_n; i++) {
        Otls_TRACE1(STORE, "Looking up scheme %s\n", schemes[i]);
        if ((loader = otls_store_get0_loader_int(schemes[i])) != NULL) {
            Otls_TRACE1(STORE, "Found loader for scheme %s\n", schemes[i]);
            loader_ctx = loader->open(loader, uri, ui_method, ui_data);
            Otls_TRACE2(STORE, "Opened %s => %p\n", uri, (void *)loader_ctx);
        }
    }

    if (loader_ctx == NULL)
        goto err;

    if ((ctx = OPENtls_zalloc(sizeof(*ctx))) == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_OPEN, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    ctx->loader = loader;
    ctx->loader_ctx = loader_ctx;
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    ctx->post_process = post_process;
    ctx->post_process_data = post_process_data;

    /*
     * If the attempt to open with the 'file' scheme loader failed and the
     * other scheme loader succeeded, the failure to open with the 'file'
     * scheme loader leaves an error on the error stack.  Let's remove it.
     */
    ERR_pop_to_mark();

    return ctx;

 err:
    ERR_clear_last_mark();
    if (loader_ctx != NULL) {
        /*
         * We ignore a returned error because we will return NULL anyway in
         * this case, so if something goes wrong when closing, that'll simply
         * just add another entry on the error stack.
         */
        (void)loader->close(loader_ctx);
    }
    return NULL;
}

int Otls_STORE_ctrl(Otls_STORE_CTX *ctx, int cmd, ...)
{
    va_list args;
    int ret;

    va_start(args, cmd);
    ret = Otls_STORE_vctrl(ctx, cmd, args);
    va_end(args);

    return ret;
}

int Otls_STORE_vctrl(Otls_STORE_CTX *ctx, int cmd, va_list args)
{
    if (ctx->loader->ctrl != NULL)
        return ctx->loader->ctrl(ctx->loader_ctx, cmd, args);
    return 0;
}

int Otls_STORE_expect(Otls_STORE_CTX *ctx, int expected_type)
{
    if (ctx->loading) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_EXPECT,
                      Otls_STORE_R_LOADING_STARTED);
        return 0;
    }

    ctx->expected_type = expected_type;
    if (ctx->loader->expect != NULL)
        return ctx->loader->expect(ctx->loader_ctx, expected_type);
    return 1;
}

int Otls_STORE_find(Otls_STORE_CTX *ctx, const Otls_STORE_SEARCH *search)
{
    if (ctx->loading) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_FIND,
                      Otls_STORE_R_LOADING_STARTED);
        return 0;
    }
    if (ctx->loader->find == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_FIND,
                      Otls_STORE_R_UNSUPPORTED_OPERATION);
        return 0;
    }

    return ctx->loader->find(ctx->loader_ctx, search);
}

Otls_STORE_INFO *Otls_STORE_load(Otls_STORE_CTX *ctx)
{
    Otls_STORE_INFO *v = NULL;

    ctx->loading = 1;
 again:
    if (Otls_STORE_eof(ctx))
        return NULL;

    Otls_TRACE(STORE, "Loading next object\n");
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

    if (v != NULL && ctx->expected_type != 0) {
        int returned_type = Otls_STORE_INFO_get_type(v);

        if (returned_type != Otls_STORE_INFO_NAME && returned_type != 0) {
            /*
             * Soft assert here so those who want to harsly weed out faulty
             * loaders can do so using a debugging version of libcrypto.
             */
            if (ctx->loader->expect != NULL)
                assert(ctx->expected_type == returned_type);

            if (ctx->expected_type != returned_type) {
                Otls_STORE_INFO_free(v);
                goto again;
            }
        }
    }

    if (v != NULL)
        Otls_TRACE1(STORE, "Got a %s\n",
                    Otls_STORE_INFO_type_string(Otls_STORE_INFO_get_type(v)));

    return v;
}

int Otls_STORE_error(Otls_STORE_CTX *ctx)
{
    return ctx->loader->error(ctx->loader_ctx);
}

int Otls_STORE_eof(Otls_STORE_CTX *ctx)
{
    return ctx->loader->eof(ctx->loader_ctx);
}

int Otls_STORE_close(Otls_STORE_CTX *ctx)
{
    int loader_ret;

    Otls_TRACE1(STORE, "Closing %p\n", (void *)ctx->loader_ctx);
    loader_ret = ctx->loader->close(ctx->loader_ctx);

    OPENtls_free(ctx);
    return loader_ret;
}

/*
 * Functions to generate Otls_STORE_INFOs, one function for each type we
 * support having in them as well as a generic constructor.
 *
 * In all cases, ownership of the object is transferred to the Otls_STORE_INFO
 * and will therefore be freed when the Otls_STORE_INFO is freed.
 */
static Otls_STORE_INFO *store_info_new(int type, void *data)
{
    Otls_STORE_INFO *info = OPENtls_zalloc(sizeof(*info));

    if (info == NULL)
        return NULL;

    info->type = type;
    info->_.data = data;
    return info;
}

Otls_STORE_INFO *Otls_STORE_INFO_new_NAME(char *name)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_NAME, NULL);

    if (info == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_NAME,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    info->_.name.name = name;
    info->_.name.desc = NULL;

    return info;
}

int Otls_STORE_INFO_set0_NAME_description(Otls_STORE_INFO *info, char *desc)
{
    if (info->type != Otls_STORE_INFO_NAME) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_SET0_NAME_DESCRIPTION,
                      ERR_R_PASSED_INVALID_ARGUMENT);
        return 0;
    }

    info->_.name.desc = desc;

    return 1;
}
Otls_STORE_INFO *Otls_STORE_INFO_new_PARAMS(EVP_PKEY *params)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_PARAMS, params);

    if (info == NULL)
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_PARAMS,
                      ERR_R_MALLOC_FAILURE);
    return info;
}

Otls_STORE_INFO *Otls_STORE_INFO_new_PKEY(EVP_PKEY *pkey)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_PKEY, pkey);

    if (info == NULL)
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_PKEY,
                      ERR_R_MALLOC_FAILURE);
    return info;
}

Otls_STORE_INFO *Otls_STORE_INFO_new_CERT(X509 *x509)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_CERT, x509);

    if (info == NULL)
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_CERT,
                      ERR_R_MALLOC_FAILURE);
    return info;
}

Otls_STORE_INFO *Otls_STORE_INFO_new_CRL(X509_CRL *crl)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_CRL, crl);

    if (info == NULL)
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_CRL,
                      ERR_R_MALLOC_FAILURE);
    return info;
}

/*
 * Functions to try to extract data from a Otls_STORE_INFO.
 */
int Otls_STORE_INFO_get_type(const Otls_STORE_INFO *info)
{
    return info->type;
}

const char *Otls_STORE_INFO_get0_NAME(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_NAME)
        return info->_.name.name;
    return NULL;
}

char *Otls_STORE_INFO_get1_NAME(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_NAME) {
        char *ret = OPENtls_strdup(info->_.name.name);

        if (ret == NULL)
            Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_NAME,
                          ERR_R_MALLOC_FAILURE);
        return ret;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_NAME,
                  Otls_STORE_R_NOT_A_NAME);
    return NULL;
}

const char *Otls_STORE_INFO_get0_NAME_description(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_NAME)
        return info->_.name.desc;
    return NULL;
}

char *Otls_STORE_INFO_get1_NAME_description(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_NAME) {
        char *ret = OPENtls_strdup(info->_.name.desc
                                   ? info->_.name.desc : "");

        if (ret == NULL)
            Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_NAME_DESCRIPTION,
                     ERR_R_MALLOC_FAILURE);
        return ret;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_NAME_DESCRIPTION,
                  Otls_STORE_R_NOT_A_NAME);
    return NULL;
}

EVP_PKEY *Otls_STORE_INFO_get0_PARAMS(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_PARAMS)
        return info->_.params;
    return NULL;
}

EVP_PKEY *Otls_STORE_INFO_get1_PARAMS(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_PARAMS) {
        EVP_PKEY_up_ref(info->_.params);
        return info->_.params;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_PARAMS,
                  Otls_STORE_R_NOT_PARAMETERS);
    return NULL;
}

EVP_PKEY *Otls_STORE_INFO_get0_PKEY(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_PKEY)
        return info->_.pkey;
    return NULL;
}

EVP_PKEY *Otls_STORE_INFO_get1_PKEY(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_PKEY) {
        EVP_PKEY_up_ref(info->_.pkey);
        return info->_.pkey;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_PKEY,
                  Otls_STORE_R_NOT_A_KEY);
    return NULL;
}

X509 *Otls_STORE_INFO_get0_CERT(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_CERT)
        return info->_.x509;
    return NULL;
}

X509 *Otls_STORE_INFO_get1_CERT(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_CERT) {
        X509_up_ref(info->_.x509);
        return info->_.x509;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_CERT,
                  Otls_STORE_R_NOT_A_CERTIFICATE);
    return NULL;
}

X509_CRL *Otls_STORE_INFO_get0_CRL(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_CRL)
        return info->_.crl;
    return NULL;
}

X509_CRL *Otls_STORE_INFO_get1_CRL(const Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_CRL) {
        X509_CRL_up_ref(info->_.crl);
        return info->_.crl;
    }
    Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_GET1_CRL,
                  Otls_STORE_R_NOT_A_CRL);
    return NULL;
}

/*
 * Free the Otls_STORE_INFO
 */
void Otls_STORE_INFO_free(Otls_STORE_INFO *info)
{
    if (info != NULL) {
        switch (info->type) {
        case Otls_STORE_INFO_EMBEDDED:
            BUF_MEM_free(info->_.embedded.blob);
            OPENtls_free(info->_.embedded.pem_name);
            break;
        case Otls_STORE_INFO_NAME:
            OPENtls_free(info->_.name.name);
            OPENtls_free(info->_.name.desc);
            break;
        case Otls_STORE_INFO_PARAMS:
            EVP_PKEY_free(info->_.params);
            break;
        case Otls_STORE_INFO_PKEY:
            EVP_PKEY_free(info->_.pkey);
            break;
        case Otls_STORE_INFO_CERT:
            X509_free(info->_.x509);
            break;
        case Otls_STORE_INFO_CRL:
            X509_CRL_free(info->_.crl);
            break;
        }
        OPENtls_free(info);
    }
}

int Otls_STORE_supports_search(Otls_STORE_CTX *ctx, int search_type)
{
    Otls_STORE_SEARCH tmp_search;

    if (ctx->loader->find == NULL)
        return 0;
    tmp_search.search_type = search_type;
    return ctx->loader->find(NULL, &tmp_search);
}

/* Search term constructors */
Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_name(X509_NAME *name)
{
    Otls_STORE_SEARCH *search = OPENtls_zalloc(sizeof(*search));

    if (search == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_SEARCH_BY_NAME,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    search->search_type = Otls_STORE_SEARCH_BY_NAME;
    search->name = name;
    return search;
}

Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_issuer_serial(X509_NAME *name,
                                                    const ASN1_INTEGER *serial)
{
    Otls_STORE_SEARCH *search = OPENtls_zalloc(sizeof(*search));

    if (search == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_SEARCH_BY_ISSUER_SERIAL,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    search->search_type = Otls_STORE_SEARCH_BY_ISSUER_SERIAL;
    search->name = name;
    search->serial = serial;
    return search;
}

Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_key_fingerprint(const EVP_MD *digest,
                                                        const unsigned char
                                                        *bytes, size_t len)
{
    Otls_STORE_SEARCH *search = OPENtls_zalloc(sizeof(*search));

    if (search == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_SEARCH_BY_KEY_FINGERPRINT,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    if (digest != NULL && len != (size_t)EVP_MD_size(digest)) {
        char buf1[20], buf2[20];

        BIO_snprintf(buf1, sizeof(buf1), "%d", EVP_MD_size(digest));
        BIO_snprintf(buf2, sizeof(buf2), "%zu", len);
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_SEARCH_BY_KEY_FINGERPRINT,
                      Otls_STORE_R_FINGERPRINT_SIZE_DOES_NOT_MATCH_DIGEST);
        ERR_add_error_data(5, EVP_MD_name(digest), " size is ", buf1,
                           ", fingerprint size is ", buf2);
    }

    search->search_type = Otls_STORE_SEARCH_BY_KEY_FINGERPRINT;
    search->digest = digest;
    search->string = bytes;
    search->stringlength = len;
    return search;
}

Otls_STORE_SEARCH *Otls_STORE_SEARCH_by_alias(const char *alias)
{
    Otls_STORE_SEARCH *search = OPENtls_zalloc(sizeof(*search));

    if (search == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_SEARCH_BY_ALIAS,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    search->search_type = Otls_STORE_SEARCH_BY_ALIAS;
    search->string = (const unsigned char *)alias;
    search->stringlength = strlen(alias);
    return search;
}

/* Search term destructor */
void Otls_STORE_SEARCH_free(Otls_STORE_SEARCH *search)
{
    OPENtls_free(search);
}

/* Search term accessors */
int Otls_STORE_SEARCH_get_type(const Otls_STORE_SEARCH *criterion)
{
    return criterion->search_type;
}

X509_NAME *Otls_STORE_SEARCH_get0_name(const Otls_STORE_SEARCH *criterion)
{
    return criterion->name;
}

const ASN1_INTEGER *Otls_STORE_SEARCH_get0_serial(const Otls_STORE_SEARCH
                                                 *criterion)
{
    return criterion->serial;
}

const unsigned char *Otls_STORE_SEARCH_get0_bytes(const Otls_STORE_SEARCH
                                                  *criterion, size_t *length)
{
    *length = criterion->stringlength;
    return criterion->string;
}

const char *Otls_STORE_SEARCH_get0_string(const Otls_STORE_SEARCH *criterion)
{
    return (const char *)criterion->string;
}

const EVP_MD *Otls_STORE_SEARCH_get0_digest(const Otls_STORE_SEARCH *criterion)
{
    return criterion->digest;
}

/* Internal functions */
Otls_STORE_INFO *otls_store_info_new_EMBEDDED(const char *new_pem_name,
                                              BUF_MEM *embedded)
{
    Otls_STORE_INFO *info = store_info_new(Otls_STORE_INFO_EMBEDDED, NULL);

    if (info == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_EMBEDDED,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    info->_.embedded.blob = embedded;
    info->_.embedded.pem_name =
        new_pem_name == NULL ? NULL : OPENtls_strdup(new_pem_name);

    if (new_pem_name != NULL && info->_.embedded.pem_name == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_INFO_NEW_EMBEDDED,
                      ERR_R_MALLOC_FAILURE);
        Otls_STORE_INFO_free(info);
        info = NULL;
    }

    return info;
}

BUF_MEM *otls_store_info_get0_EMBEDDED_buffer(Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_EMBEDDED)
        return info->_.embedded.blob;
    return NULL;
}

char *otls_store_info_get0_EMBEDDED_pem_name(Otls_STORE_INFO *info)
{
    if (info->type == Otls_STORE_INFO_EMBEDDED)
        return info->_.embedded.pem_name;
    return NULL;
}

Otls_STORE_CTX *otls_store_attach_pem_bio(BIO *bp, const UI_METHOD *ui_method,
                                          void *ui_data)
{
    Otls_STORE_CTX *ctx = NULL;
    const Otls_STORE_LOADER *loader = NULL;
    Otls_STORE_LOADER_CTX *loader_ctx = NULL;

    if ((loader = otls_store_get0_loader_int("file")) == NULL
        || ((loader_ctx = otls_store_file_attach_pem_bio_int(bp)) == NULL))
        goto done;
    if ((ctx = OPENtls_zalloc(sizeof(*ctx))) == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_ATTACH_PEM_BIO,
                     ERR_R_MALLOC_FAILURE);
        goto done;
    }

    ctx->loader = loader;
    ctx->loader_ctx = loader_ctx;
    loader_ctx = NULL;
    ctx->ui_method = ui_method;
    ctx->ui_data = ui_data;
    ctx->post_process = NULL;
    ctx->post_process_data = NULL;

 done:
    if (loader_ctx != NULL)
        /*
         * We ignore a returned error because we will return NULL anyway in
         * this case, so if something goes wrong when closing, that'll simply
         * just add another entry on the error stack.
         */
        (void)loader->close(loader_ctx);
    return ctx;
}

int otls_store_detach_pem_bio(Otls_STORE_CTX *ctx)
{
    int loader_ret = otls_store_file_detach_pem_bio_int(ctx->loader_ctx);

    OPENtls_free(ctx);
    return loader_ret;
}
