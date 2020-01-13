/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_CORE_H
# define Otls_INTERNAL_CORE_H

/*
 * namespaces:
 *
 * otls_method_         Core Method API
 */

/*
 * construct an arbitrary method from a dispatch table found by looking
 * up a match for the < operation_id, name, property > combination.
 * constructor and destructor are the constructor and destructor for that
 * arbitrary object.
 *
 * These objects are normally cached, unless the provider says not to cache.
 * However, force_cache can be used to force caching whatever the provider
 * says (for example, because the application knows better).
 */
typedef struct otls_method_construct_method_st {
    /* Create store */
    void *(*alloc_tmp_store)(OPENtls_CTX *ctx);
    /* Remove a store */
    void (*dealloc_tmp_store)(void *store);
    /* Get an already existing method from a store */
    void *(*get)(OPENtls_CTX *libctx, void *store, void *data);
    /* Store a method in a store */
    int (*put)(OPENtls_CTX *libctx, void *store, void *method,
               const Otls_PROVIDER *prov, int operation_id, const char *name,
               const char *propdef, void *data);
    /* Construct a new method */
    void *(*construct)(const Otls_ALGORITHM *algodef, Otls_PROVIDER *prov,
                       void *data);
    /* Destruct a method */
    void (*destruct)(void *method, void *data);
} Otls_METHOD_CONSTRUCT_METHOD;

void *otls_method_construct(OPENtls_CTX *ctx, int operation_id,
                            int force_cache,
                            Otls_METHOD_CONSTRUCT_METHOD *mcm, void *mcm_data);

void otls_algorithm_do_all(OPENtls_CTX *libctx, int operation_id,
                           Otls_PROVIDER *provider,
                           void (*fn)(Otls_PROVIDER *provider,
                                      const Otls_ALGORITHM *algo,
                                      int no_store, void *data),
                           void *data);

#endif
