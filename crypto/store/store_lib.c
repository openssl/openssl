/*
 * Copyright 2001-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stdlib.h>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/store.h>
#include "internal/thread_once.h"
#include "internal/uri.h"
#include "store_local.h"

STACK_OF(STORE_INFO) *STORE_load(const char *uri,
                                 pem_password_cb *pw_callback,
                                 void *pw_callback_data)
{
    char *scheme = NULL, *authority = NULL, *path = NULL, *query = NULL;
    char *fragment = NULL;
    const char *used_scheme = "file";
    STORE_loader_fn loader = NULL;
    STACK_OF(STORE_INFO) *res = NULL;

    if (!OPENSSL_decode_uri(uri, &scheme, &authority, &path, &query,
                            &fragment))
        return NULL;
    if (scheme != NULL)
        used_scheme = scheme;

    loader = STORE_get_loader(used_scheme);
    if (loader == NULL) {
        goto done;
    }

    res = loader(authority, path, query, fragment,
                 pw_callback, pw_callback_data);

 done:
    OPENSSL_free(scheme);
    OPENSSL_free(authority);
    OPENSSL_free(path);
    OPENSSL_free(query);
    OPENSSL_free(fragment);
    return res;
}

/*
 * Function to register a loader for the given URI scheme.
 * The loader receives all the main components of an URI except for the
 * scheme.
 */
static CRYPTO_ONCE store_init = CRYPTO_ONCE_STATIC_INIT;
DEFINE_RUN_ONCE_STATIC(do_store_init)
{
    return OPENSSL_init_crypto(0, NULL) && OPENSSL_atexit(destroy_loaders_int);
}

int STORE_register_loader(const char *scheme, STORE_loader_fn loader)
{
    SCHEME_LOADER *scheme_loader = NULL;

    if (!RUN_ONCE(&store_init, do_store_init)) {
        STOREerr(STORE_F_STORE_REGISTER_LOADER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    if ((scheme_loader = OPENSSL_zalloc(sizeof(*scheme_loader))) == NULL
        || (scheme_loader->scheme = OPENSSL_strdup(scheme)) == NULL) {
        STOREerr(STORE_F_STORE_REGISTER_LOADER, ERR_R_MALLOC_FAILURE);
        OPENSSL_free(scheme_loader);
        return 0;
    }

    scheme_loader->loader = loader;
    if (register_loader_int(scheme_loader))
        return 1;

    OPENSSL_free(scheme_loader->scheme);
    OPENSSL_free(scheme_loader);
    return 0;
}

/*
 * Function to fetch the loader for a given URI scheme
 */
STORE_loader_fn STORE_get_loader(const char *scheme)
{
    const SCHEME_LOADER *scheme_loader = NULL;

    if (!RUN_ONCE(&store_init, do_store_init)) {
        STOREerr(STORE_F_STORE_GET_LOADER, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    scheme_loader = get_loader_int(scheme);
    if (scheme_loader == NULL) {
        STOREerr(STORE_F_STORE_GET_LOADER, STORE_R_UNSUPPORTED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
        return NULL;
    }

    return scheme_loader->loader;
}

/*
 * Function to unregister the loader for a given URI scheme
 */
int STORE_unregister_loader(const char *scheme)
{
    if (!RUN_ONCE(&store_init, do_store_init)) {
        STOREerr(STORE_F_STORE_UNREGISTER_LOADER, ERR_R_MALLOC_FAILURE);
        return 0;
    }

    return unregister_loader_int(scheme);
}

/*
 * Types of data that can be stored in a STORE_INFO.
 * STORE_INFO_NAME is typically found when getting a listing of
 * available "files" / "tokens" / what have you.
 */
# define STORE_INFO_NAME 0       /* char * */
# define STORE_INFO_PKEY 1       /* EVP_PKEY * */
# define STORE_INFO_CERT 2       /* X509 * */
# define STORE_INFO_CRL  3       /* X509_CRL * */

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
    STORE_INFO *info = store_info_new(STORE_INFO_NAME, name);

    if (info == NULL)
        STOREerr(STORE_F_STORE_INFO_NEW_NAME, ERR_R_MALLOC_FAILURE);
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
        return store_info->_.name;
    return NULL;
}

const EVP_PKEY *STORE_INFO_get0_PKEY(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_PKEY)
        return store_info->_.pkey;
    return NULL;
}

const X509 *STORE_INFO_get0_CERT(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CERT)
        return store_info->_.x509;
    return NULL;
}

const X509_CRL *STORE_INFO_get0_CRL(const STORE_INFO *store_info)
{
    if (store_info->type == STORE_INFO_CRL)
        return store_info->_.crl;
    return NULL;
}

/*
 * Free the STORE_INFO
 */
void STORE_INFO_free(STORE_INFO *store_info)
{
    if (store_info != NULL) {
        switch (store_info->type) {
        case STORE_INFO_NAME:
            OPENSSL_free(store_info->_.name);
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

