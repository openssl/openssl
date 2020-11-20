/*
 * Copyright 2019-2020 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/property.h"

typedef int OSSL_PROPERTY_IDX;

/* Property string functions */
OSSL_PROPERTY_IDX ossl_property_name(OSSL_LIB_CTX *ctx, const char *s,
                                     int create);
OSSL_PROPERTY_IDX ossl_property_value(OSSL_LIB_CTX *ctx, const char *s,
                                      int create);

/* Property list functions */
void ossl_property_free(OSSL_PROPERTY_LIST *p);
int ossl_property_has_optional(const OSSL_PROPERTY_LIST *query);

/* Property definition cache functions */
OSSL_PROPERTY_LIST *ossl_prop_defn_get(OSSL_LIB_CTX *ctx, const char *prop);
int ossl_prop_defn_set(OSSL_LIB_CTX *ctx, const char *prop,
                       OSSL_PROPERTY_LIST *pl);

/* Property cache lock / unlock */
int ossl_property_write_lock(OSSL_METHOD_STORE *);
int ossl_property_read_lock(OSSL_METHOD_STORE *);
int ossl_property_unlock(OSSL_METHOD_STORE *);

