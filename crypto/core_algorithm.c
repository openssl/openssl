/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"

struct algorithm_data_st {
    OSSL_LIB_CTX *libctx;
    int operation_id;            /* May be zero for finding them all */
    int (*pre)(OSSL_PROVIDER *, int operation_id, void *data, int *result);
    void (*fn)(OSSL_PROVIDER *, const OSSL_ALGORITHM *, int no_store,
               void *data);
    int (*post)(OSSL_PROVIDER *, int operation_id, int no_store, void *data,
                int *result);
    void *data;
};

static int algorithm_do_this(OSSL_PROVIDER *provider, void *cbdata)
{
    struct algorithm_data_st *data = cbdata;
    int no_store = 0;    /* Assume caching is ok */
    int first_operation = 1;
    int last_operation = OSSL_OP__HIGHEST;
    int cur_operation;
    int ok = 1;

    if (data->operation_id != 0)
        first_operation = last_operation = data->operation_id;

    for (cur_operation = first_operation;
         cur_operation <= last_operation;
         cur_operation++) {
        const OSSL_ALGORITHM *map = NULL;
        int ret;

        /* Do we fulfill pre-conditions? */
        if (data->pre == NULL) {
            /* If there is no pre-condition function, assume "yes" */
            ret = 1;
        } else {
            if (!data->pre(provider, cur_operation, data->data, &ret))
                /* Error, bail out! */
                return 0;
        }

        /* If pre-condition not fulfilled, go to the next operation */
        if (!ret)
            continue;

        map = ossl_provider_query_operation(provider, cur_operation,
                                            &no_store);
        if (map != NULL) {
            while (map->algorithm_names != NULL) {
                const OSSL_ALGORITHM *thismap = map++;

                data->fn(provider, thismap, no_store, data->data);
            }
        }

        /* Do we fulfill post-conditions? */
        if (data->post == NULL) {
            /* If there is no post-condition function, assume "yes" */
            ret = 1;
        } else {
            if (!data->post(provider, cur_operation, no_store, data->data,
                            &ret))
                /* Error, bail out! */
                return 0;
        }

        /* If post-condition not fulfilled, set general failure */
        if (!ret)
            ok = 0;
    }

    return ok;
}

void ossl_algorithm_do_all(OSSL_LIB_CTX *libctx, int operation_id,
                           OSSL_PROVIDER *provider,
                           int (*pre)(OSSL_PROVIDER *, int operation_id,
                                      void *data, int *result),
                           void (*fn)(OSSL_PROVIDER *provider,
                                      const OSSL_ALGORITHM *algo,
                                      int no_store, void *data),
                           int (*post)(OSSL_PROVIDER *, int operation_id,
                                       int no_store, void *data, int *result),
                           void *data)
{
    struct algorithm_data_st cbdata = { 0, };

    cbdata.libctx = libctx;
    cbdata.operation_id = operation_id;
    cbdata.pre = pre;
    cbdata.fn = fn;
    cbdata.post = post;
    cbdata.data = data;

    if (provider == NULL)
        ossl_provider_forall_loaded(libctx, algorithm_do_this, &cbdata);
    else
        algorithm_do_this(provider, &cbdata);
}
