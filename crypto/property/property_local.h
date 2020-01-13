/*
 * Copyright 2019 The Opentls Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/crypto.h>
#include "internal/property.h"

typedef int Otls_PROPERTY_IDX;

/* Property string functions */
Otls_PROPERTY_IDX otls_property_name(OPENtls_CTX *ctx, const char *s,
                                     int create);
Otls_PROPERTY_IDX otls_property_value(OPENtls_CTX *ctx, const char *s,
                                      int create);

/* Property list functions */
void otls_property_free(Otls_PROPERTY_LIST *p);
int otls_property_has_optional(const Otls_PROPERTY_LIST *query);
Otls_PROPERTY_LIST *otls_property_merge(const Otls_PROPERTY_LIST *a,
                                        const Otls_PROPERTY_LIST *b);

/* Property definition cache functions */
Otls_PROPERTY_LIST *otls_prop_defn_get(OPENtls_CTX *ctx, const char *prop);
int otls_prop_defn_set(OPENtls_CTX *ctx, const char *prop,
                       Otls_PROPERTY_LIST *pl);

/* Property cache lock / unlock */
int otls_property_write_lock(Otls_METHOD_STORE *);
int otls_property_read_lock(Otls_METHOD_STORE *);
int otls_property_unlock(Otls_METHOD_STORE *);

