/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/core.h>
#include <opentls/core_numbers.h>
#include "internal/core.h"
#include "internal/property.h"
#include "internal/provider.h"

struct algorithm_data_st {
    OPENtls_CTX *libctx;
    int operation_id;            /* May be zero for finding them all */
    void (*fn)(Otls_PROVIDER *, const Otls_ALGORITHM *, int no_store,
               void *data);
    void *data;
};

static int algorithm_do_this(Otls_PROVIDER *provider, void *cbdata)
{
    struct algorithm_data_st *data = cbdata;
    int no_store = 0;    /* Assume caching is ok */
    int first_operation = 1;
    int last_operation = Otls_OP__HIGHEST;
    int cur_operation;
    int ok = 0;

    if (data->operation_id != 0)
        first_operation = last_operation = data->operation_id;

    for (cur_operation = first_operation;
         cur_operation <= last_operation;
         cur_operation++) {
        const Otls_ALGORITHM *map =
            otls_provider_query_operation(provider, data->operation_id,
                                          &no_store);

        if (map == NULL)
            break;

        ok = 1;                  /* As long as we've found *something* */
        while (map->algorithm_names != NULL) {
            const Otls_ALGORITHM *thismap = map++;

            data->fn(provider, thismap, no_store, data->data);
        }
    }

    return ok;
}

void otls_algorithm_do_all(OPENtls_CTX *libctx, int operation_id,
                           Otls_PROVIDER *provider,
                           void (*fn)(Otls_PROVIDER *provider,
                                      const Otls_ALGORITHM *algo,
                                      int no_store, void *data),
                           void *data)
{
    struct algorithm_data_st cbdata;

    cbdata.libctx = libctx;
    cbdata.operation_id = operation_id;
    cbdata.fn = fn;
    cbdata.data = data;

    if (provider == NULL)
        otls_provider_forall_loaded(libctx, algorithm_do_this, &cbdata);
    else
        algorithm_do_this(provider, &cbdata);
}
