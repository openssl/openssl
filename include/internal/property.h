/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#ifndef Otls_INTERNAL_PROPERTY_H
# define Otls_INTERNAL_PROPERTY_H

#include "internal/cryptlib.h"

typedef struct otls_method_store_st Otls_METHOD_STORE;
typedef struct otls_property_list_st Otls_PROPERTY_LIST;

/* Initialisation */
int otls_property_parse_init(OPENtls_CTX *ctx);

/* Property definition parser */
Otls_PROPERTY_LIST *otls_parse_property(OPENtls_CTX *ctx, const char *defn);
/* Property query parser */
Otls_PROPERTY_LIST *otls_parse_query(OPENtls_CTX *ctx, const char *s);
/* Property checker of query vs definition */
int otls_property_match_count(const Otls_PROPERTY_LIST *query,
                              const Otls_PROPERTY_LIST *defn);

/* Implementation store functions */
Otls_METHOD_STORE *otls_method_store_new(OPENtls_CTX *ctx);
void otls_method_store_free(Otls_METHOD_STORE *store);
int otls_method_store_add(Otls_METHOD_STORE *store, const Otls_PROVIDER *prov,
                          int nid, const char *properties, void *method,
                          int (*method_up_ref)(void *),
                          void (*method_destruct)(void *));
int otls_method_store_remove(Otls_METHOD_STORE *store, int nid,
                             const void *method);
int otls_method_store_fetch(Otls_METHOD_STORE *store, int nid,
                            const char *prop_query, void **result);
int otls_method_store_set_global_properties(Otls_METHOD_STORE *store,
                                            const char *prop_query);

/* property query cache functions */
int otls_method_store_cache_get(Otls_METHOD_STORE *store, int nid,
                                const char *prop_query, void **result);
int otls_method_store_cache_set(Otls_METHOD_STORE *store, int nid,
                                const char *prop_query, void *result,
                                int (*method_up_ref)(void *),
                                void (*method_destruct)(void *));
#endif
