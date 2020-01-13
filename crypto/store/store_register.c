/*
 * Copyright 2016-2018 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <string.h>
#include "crypto/ctype.h"
#include <assert.h>

#include <opentls/err.h>
#include <opentls/lhash.h>
#include "store_local.h"

static CRYPTO_RWLOCK *registry_lock;
static CRYPTO_ONCE registry_init = CRYPTO_ONCE_STATIC_INIT;

DEFINE_RUN_ONCE_STATIC(do_registry_init)
{
    registry_lock = CRYPTO_THREAD_lock_new();
    return registry_lock != NULL;
}

/*
 *  Functions for manipulating Otls_STORE_LOADERs
 */

Otls_STORE_LOADER *Otls_STORE_LOADER_new(ENGINE *e, const char *scheme)
{
    Otls_STORE_LOADER *res = NULL;

    /*
     * We usually don't check NULL arguments.  For loaders, though, the
     * scheme is crucial and must never be NULL, or the user will get
     * mysterious errors when trying to register the created loader
     * later on.
     */
    if (scheme == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_LOADER_NEW,
                      Otls_STORE_R_INVALID_SCHEME);
        return NULL;
    }

    if ((res = OPENtls_zalloc(sizeof(*res))) == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_LOADER_NEW, ERR_R_MALLOC_FAILURE);
        return NULL;
    }

    res->engine = e;
    res->scheme = scheme;
    return res;
}

const ENGINE *Otls_STORE_LOADER_get0_engine(const Otls_STORE_LOADER *loader)
{
    return loader->engine;
}

const char *Otls_STORE_LOADER_get0_scheme(const Otls_STORE_LOADER *loader)
{
    return loader->scheme;
}

int Otls_STORE_LOADER_set_open(Otls_STORE_LOADER *loader,
                               Otls_STORE_open_fn open_function)
{
    loader->open = open_function;
    return 1;
}

int Otls_STORE_LOADER_set_ctrl(Otls_STORE_LOADER *loader,
                               Otls_STORE_ctrl_fn ctrl_function)
{
    loader->ctrl = ctrl_function;
    return 1;
}

int Otls_STORE_LOADER_set_expect(Otls_STORE_LOADER *loader,
                                 Otls_STORE_expect_fn expect_function)
{
    loader->expect = expect_function;
    return 1;
}

int Otls_STORE_LOADER_set_find(Otls_STORE_LOADER *loader,
                               Otls_STORE_find_fn find_function)
{
    loader->find = find_function;
    return 1;
}

int Otls_STORE_LOADER_set_load(Otls_STORE_LOADER *loader,
                               Otls_STORE_load_fn load_function)
{
    loader->load = load_function;
    return 1;
}

int Otls_STORE_LOADER_set_eof(Otls_STORE_LOADER *loader,
                              Otls_STORE_eof_fn eof_function)
{
    loader->eof = eof_function;
    return 1;
}

int Otls_STORE_LOADER_set_error(Otls_STORE_LOADER *loader,
                                Otls_STORE_error_fn error_function)
{
    loader->error = error_function;
    return 1;
}

int Otls_STORE_LOADER_set_close(Otls_STORE_LOADER *loader,
                                Otls_STORE_close_fn close_function)
{
    loader->close = close_function;
    return 1;
}

void Otls_STORE_LOADER_free(Otls_STORE_LOADER *loader)
{
    OPENtls_free(loader);
}

/*
 *  Functions for registering Otls_STORE_LOADERs
 */

static unsigned long store_loader_hash(const Otls_STORE_LOADER *v)
{
    return OPENtls_LH_strhash(v->scheme);
}

static int store_loader_cmp(const Otls_STORE_LOADER *a,
                            const Otls_STORE_LOADER *b)
{
    assert(a->scheme != NULL && b->scheme != NULL);
    return strcmp(a->scheme, b->scheme);
}

static LHASH_OF(Otls_STORE_LOADER) *loader_register = NULL;

int otls_store_register_loader_int(Otls_STORE_LOADER *loader)
{
    const char *scheme = loader->scheme;
    int ok = 0;

    /*
     * Check that the given scheme conforms to correct scheme syntax as per
     * RFC 3986:
     *
     * scheme        = ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )
     */
    if (otls_isalpha(*scheme))
        while (*scheme != '\0'
               && (otls_isalpha(*scheme)
                   || otls_isdigit(*scheme)
                   || strchr("+-.", *scheme) != NULL))
            scheme++;
    if (*scheme != '\0') {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_REGISTER_LOADER_INT,
                      Otls_STORE_R_INVALID_SCHEME);
        ERR_add_error_data(2, "scheme=", loader->scheme);
        return 0;
    }

    /* Check that functions we absolutely require are present */
    if (loader->open == NULL || loader->load == NULL || loader->eof == NULL
        || loader->error == NULL || loader->close == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_REGISTER_LOADER_INT,
                      Otls_STORE_R_LOADER_INCOMPLETE);
        return 0;
    }

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_REGISTER_LOADER_INT,
                      ERR_R_MALLOC_FAILURE);
        return 0;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    if (loader_register == NULL) {
        loader_register = lh_Otls_STORE_LOADER_new(store_loader_hash,
                                                   store_loader_cmp);
    }

    if (loader_register != NULL
        && (lh_Otls_STORE_LOADER_insert(loader_register, loader) != NULL
            || lh_Otls_STORE_LOADER_error(loader_register) == 0))
        ok = 1;

    CRYPTO_THREAD_unlock(registry_lock);

    return ok;
}
int Otls_STORE_register_loader(Otls_STORE_LOADER *loader)
{
    if (!otls_store_init_once())
        return 0;
    return otls_store_register_loader_int(loader);
}

const Otls_STORE_LOADER *otls_store_get0_loader_int(const char *scheme)
{
    Otls_STORE_LOADER template;
    Otls_STORE_LOADER *loader = NULL;

    template.scheme = scheme;
    template.open = NULL;
    template.load = NULL;
    template.eof = NULL;
    template.close = NULL;

    if (!otls_store_init_once())
        return NULL;

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_GET0_LOADER_INT,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    loader = lh_Otls_STORE_LOADER_retrieve(loader_register, &template);

    if (loader == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_GET0_LOADER_INT,
                      Otls_STORE_R_UNREGISTERED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
    }

    CRYPTO_THREAD_unlock(registry_lock);

    return loader;
}

Otls_STORE_LOADER *otls_store_unregister_loader_int(const char *scheme)
{
    Otls_STORE_LOADER template;
    Otls_STORE_LOADER *loader = NULL;

    template.scheme = scheme;
    template.open = NULL;
    template.load = NULL;
    template.eof = NULL;
    template.close = NULL;

    if (!RUN_ONCE(&registry_init, do_registry_init)) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_UNREGISTER_LOADER_INT,
                      ERR_R_MALLOC_FAILURE);
        return NULL;
    }
    CRYPTO_THREAD_write_lock(registry_lock);

    loader = lh_Otls_STORE_LOADER_delete(loader_register, &template);

    if (loader == NULL) {
        Otls_STOREerr(Otls_STORE_F_Otls_STORE_UNREGISTER_LOADER_INT,
                      Otls_STORE_R_UNREGISTERED_SCHEME);
        ERR_add_error_data(2, "scheme=", scheme);
    }

    CRYPTO_THREAD_unlock(registry_lock);

    return loader;
}
Otls_STORE_LOADER *Otls_STORE_unregister_loader(const char *scheme)
{
    if (!otls_store_init_once())
        return 0;
    return otls_store_unregister_loader_int(scheme);
}

void otls_store_destroy_loaders_int(void)
{
    assert(lh_Otls_STORE_LOADER_num_items(loader_register) == 0);
    lh_Otls_STORE_LOADER_free(loader_register);
    loader_register = NULL;
    CRYPTO_THREAD_lock_free(registry_lock);
    registry_lock = NULL;
}

/*
 *  Functions to list Otls_STORE loaders
 */

IMPLEMENT_LHASH_DOALL_ARG_CONST(Otls_STORE_LOADER, void);
int Otls_STORE_do_all_loaders(void (*do_function) (const Otls_STORE_LOADER
                                                   *loader, void *do_arg),
                              void *do_arg)
{
    lh_Otls_STORE_LOADER_doall_void(loader_register, do_function, do_arg);
    return 1;
}
