/*
 * Copyright 2016-2017 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <ctype.h>
#include <assert.h>

#include <openssl/err.h>
#include <openssl/lhash.h>
#include "store_locl.h"

static CRYPTO_RWLOCK *registry_lock;
static CRYPTO_ONCE registry_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_registry_init)
{
    registry_lock = CRYPTO_THREAD_lock_new();
    return registry_lock != NULL;
}

/*
 *  Functions for manipulating STORE_LOADERs
 */

STORE_LOADER *STORE_LOADER_new(ENGINE *e, const char *scheme)
{
    STORE_LOADER *res = OPENSSL_zalloc(sizeof(*res));

    if (res == NULL)
        STOREerr(STORE_F_STORE_LOADER_NEW, ERR_R_MALLOC_FAILURE);

    /*
     * We usually don't check NULL arguments.  For loaders, though, the
     * scheme is crucial and must never be NULL, or the user will get
     * mysterious errors when trying to register the created loader
     * later on.
     */
    if (scheme == NULL) {
        STOREerr(STORE_F_STORE_LOADER_NEW, ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    res->engine = e;
    res->scheme = scheme;
    return res;
}

const ENGINE *STORE_LOADER_get0_engine(const STORE_LOADER *loader)
{
    return loader->engine;
}

const char *STORE_LOADER_get0_scheme(const STORE_LOADER *loader)
{
    return loader->scheme;
}

int STORE_LOADER_set_open(STORE_LOADER *loader,
                          STORE_open_fn store_open_function)
{
    loader->open = store_open_function;
    return 1;
}

int STORE_LOADER_set_ctrl(STORE_LOADER *loader,
                          STORE_ctrl_fn store_ctrl_function)
{
    loader->ctrl = store_ctrl_function;
    return 1;
}

int STORE_LOADER_set_load(STORE_LOADER *loader,
                          STORE_load_fn store_load_function)
{
    loader->load = store_load_function;
    return 1;
}

int STORE_LOADER_set_eof(STORE_LOADER *loader,
                         STORE_eof_fn store_eof_function)
{
    loader->eof = store_eof_function;
    return 1;
}

int STORE_LOADER_set_close(STORE_LOADER *loader,
                          STORE_close_fn store_close_function)
{
    loader->close = store_close_function;
    return 1;
}

void STORE_LOADER_free(STORE_LOADER *loader)
{
    OPENSSL_free(loader);
}

/*
 *  Functions for registering STORE_LOADERs
 */

static unsigned long store_loader_hash(const STORE_LOADER *v)
{
    return OPENSSL_LH_strhash(v->scheme);
}

static int store_loader_cmp(const STORE_LOADER *a, const STORE_LOADER *b)
{
    if (a->scheme != NULL && b->scheme != NULL)
        return strcmp(a->scheme, b->scheme);
    else if (a->scheme == b->scheme)
        return 0;
    return a->scheme == NULL ? -1 : 1;
}

static LHASH_OF(STORE_LOADER) *loader_register = NULL;

int store_register_loader_int(STORE_LOADER *loader)
{
    const char *scheme = loader->scheme;
    int ok = 0;

    /*
     * Check that the given scheme conforms to correct scheme syntax as per
     * RFC 3986:
     *
     * scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
     */
    if (isalpha(*scheme))
        while (*scheme != '\0'
               && (isalpha(*scheme)
                   || isdigit(*scheme)
                   || strchr("+-.", *scheme) != NULL))
            scheme++;
    if (*scheme != '\0') {
        STOREerr(STORE_F_STORE_REGISTER_LOADER_INT, STORE_R_INVALID_SCHEME);
        ERR_add_error_data(4, "scheme=", loader->scheme);
        return 0;
    }

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        STOREerr(STORE_F_STORE_REGISTER_LOADER_INT, ERR_R_MALLOC_FAILURE);
        return 0;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    if (loader_register == NULL) {
        loader_register = lh_STORE_LOADER_new(store_loader_hash,
                                              store_loader_cmp);
    }

    if (loader_register != NULL
        && (lh_STORE_LOADER_insert(loader_register, loader) != NULL
            || lh_STORE_LOADER_error(loader_register) == 0))
        ok = 1;

    CRYPTO_THREAD_unlock(registry_lock);

    return ok;
}
int STORE_register_loader(STORE_LOADER *loader)
{
    if (!store_init_once())
        return 0;
    return store_register_loader_int(loader);
}

const STORE_LOADER *store_get0_loader_int(const char *scheme)
{
    STORE_LOADER template;
    STORE_LOADER *loader = NULL;

    template.scheme = scheme;
    template.open = NULL;
    template.load = NULL;
    template.eof = NULL;
    template.close = NULL;

    if (!store_init_once())
        return NULL;

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        STOREerr(STORE_F_STORE_GET0_LOADER_INT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    loader = lh_STORE_LOADER_retrieve(loader_register, &template);

    if (loader == NULL) {
        STOREerr(STORE_F_STORE_GET0_LOADER_INT, STORE_R_UNREGISTERED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
    }

    CRYPTO_THREAD_unlock(registry_lock);

    return loader;
}

STORE_LOADER *store_unregister_loader_int(const char *scheme)
{
    STORE_LOADER template;
    STORE_LOADER *loader = NULL;

    template.scheme = scheme;
    template.open = NULL;
    template.load = NULL;
    template.eof = NULL;
    template.close = NULL;

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        STOREerr(STORE_F_STORE_UNREGISTER_LOADER_INT, ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    loader = lh_STORE_LOADER_delete(loader_register, &template);

    if (loader == NULL) {
        STOREerr(STORE_F_STORE_UNREGISTER_LOADER_INT,
                 STORE_R_UNREGISTERED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
    }

    CRYPTO_THREAD_unlock(registry_lock);

    return loader;
}
STORE_LOADER *STORE_unregister_loader(const char *scheme)
{
    if (!store_init_once())
        return 0;
    return store_unregister_loader_int(scheme);
}

void destroy_loaders_int(void)
{
    assert(lh_STORE_LOADER_num_items(loader_register) == 0);
    lh_STORE_LOADER_free(loader_register);
    loader_register = NULL;
    CRYPTO_THREAD_lock_free(registry_lock);
    registry_lock = NULL;
}

/******************************************************************************
 *
 *  Functions to list STORE loaders
 *
 *****/
IMPLEMENT_LHASH_DOALL_ARG_CONST(STORE_LOADER, void);
int STORE_do_all_loaders(void (*do_function) (const STORE_LOADER *loader,
                                              void *do_arg),
                         void *do_arg)
{
    lh_STORE_LOADER_doall_void(loader_register, do_function, do_arg);
    return 1;
}
