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

    if ((method = data->mcm->construct(algo, provider, data->mcm_data))
        == NULL)
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

    if (data->force_store || !no_store) {
        /*
         * If we haven't been told not to store,
         * add to the global store
         */
        data->mcm->put(data->libctx, NULL, method, provider,
                       data->operation_id, algo->algorithm_names,
                       algo->property_definition, data->mcm_data);
    }

    data->mcm->put(data->libctx, data->store, method, provider,
                   data->operation_id, algo->algorithm_names,
                   algo->property_definition, data->mcm_data);

    /* refcnt-- because we're dropping the reference */
    data->mcm->destruct(method, data->mcm_data);
}

void *ossl_method_construct(OPENSSL_CTX *libctx, int operation_id,
                            int force_store,
                            OSSL_METHOD_CONSTRUCT_METHOD *mcm, void *mcm_data)
{
    void *method = NULL;

    if ((method = mcm->get(libctx, NULL, mcm_data)) == NULL) {
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

        method = mcm->get(libctx, cbdata.store, mcm_data);
        mcm->dealloc_tmp_store(cbdata.store);
    }

 fin:
    return method;
}
