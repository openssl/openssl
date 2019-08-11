/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <stddef.h>

#include <openssl/core.h>
#include "internal/cryptlib.h"
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"

struct construct_data_st {
    OPENSSL_CTX *libctx;
    OSSL_METHOD_STORE *store;
    int operation_id;
    int force_store;
    OSSL_METHOD_CONSTRUCT_METHOD *mcm;
    void *mcm_data;
};

static void ossl_method_construct_this(OSSL_PROVIDER *provider,
                                       const OSSL_ALGORITHM *algo,
                                       int no_store, void *cbdata)
{
    struct construct_data_st *data = cbdata;
    void *method = NULL;
    int global_store = data->force_store || !no_store;

    /*
     * Check to see if a method has already been constructed from this
     * implementation.  It's pointless to do this check if we're not
     * supposed to store the method in the global store.
     *
     * Note that while data->mcm->put() takes a property *definition*,
     * while data->mcm->get() takes a property *query*, but we're using
     * the property *definition* string as a property query here.
     * This is possible because property definitions have a syntax that
     * can also be used for a property query with equality tests.  We do
     * this to look up already existing methods matching the implementation
     * that we just for from the provider (via |algo|),
     */
    if (global_store
        && (method = data->mcm->get(data->libctx, NULL, data->operation_id,
                                    algo->algorithm_name,
                                    algo->property_definition,
                                    data->mcm_data)) != NULL)
        goto end;

    /*
     * No pre-existing method in the global store, then we create it.
     */
    if ((method = data->mcm->construct(algo->algorithm_name,
                                       algo->implementation, provider,
                                       data->mcm_data)) == NULL)
        return;

    /*
     * Note regarding putting the method in stores:
     *
     * we don't need to care if it actually got in or not here.
     * If it didn't get in, it will simply not be available when
     * ossl_method_construct() tries to get it from the store.
     *
     * It is *expected* that the put function increments the refcnt
     * of the passed method.
     */

    if (global_store) {
        /* If we haven't been told not to store, add to the global store */
        (void)data->mcm->put(data->libctx, NULL, method, data->operation_id,
                             algo->algorithm_name,
                             algo->property_definition, data->mcm_data);
    }

    (void)data->mcm->put(data->libctx, data->store, method, data->operation_id,
                         algo->algorithm_name, algo->property_definition,
                         data->mcm_data);

 end:
    /* refcnt-- because we're dropping the reference */
    data->mcm->destruct(method, data->mcm_data);
}

void *ossl_method_construct(OPENSSL_CTX *libctx, int operation_id,
                            const char *name, const char *propquery,
                            int force_store,
                            OSSL_METHOD_CONSTRUCT_METHOD *mcm, void *mcm_data)
{
    void *method = NULL;

    if ((method =
         mcm->get(libctx, NULL, operation_id, name, propquery, mcm_data))
        == NULL) {
        struct construct_data_st cbdata;

        /*
         * We have a temporary store to be able to easily search among new
         * items, or items that should find themselves in the global store.
         */
        if ((cbdata.store = mcm->alloc_tmp_store(libctx)) == NULL)
            goto fin;

        cbdata.libctx = libctx;
        cbdata.operation_id = operation_id;
        cbdata.force_store = force_store;
        cbdata.mcm = mcm;
        cbdata.mcm_data = mcm_data;
        ossl_algorithm_do_all(libctx, operation_id, NULL,
                              ossl_method_construct_this, &cbdata);

        method = mcm->get(libctx, cbdata.store, operation_id, name,
                          propquery, mcm_data);
        mcm->dealloc_tmp_store(cbdata.store);
    }

 fin:
    return method;
}
