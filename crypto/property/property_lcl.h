/*
 * Copyright 2019 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2019, Oracle and/or its affiliates.  All rights reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/crypto.h>
#include "internal/property.h"

typedef struct ossl_property_list_st OSSL_PROPERTY_LIST;
typedef int OSSL_PROPERTY_IDX;

/* Initialisation and finalisation for subsystem */
int ossl_method_store_init(void);
void ossl_method_store_cleanup(void);

/* Property string functions */
OSSL_PROPERTY_IDX ossl_property_name(const char *s, int create);
OSSL_PROPERTY_IDX ossl_property_value(const char *s, int create);
int ossl_property_string_init(void);
void ossl_property_string_cleanup(void);

/* Property list functions */
int ossl_property_parse_init(void);
void ossl_property_free(OSSL_PROPERTY_LIST *p);
int ossl_property_match(const OSSL_PROPERTY_LIST *query,
                        const OSSL_PROPERTY_LIST *defn);
OSSL_PROPERTY_LIST *ossl_property_merge(const OSSL_PROPERTY_LIST *a,
                                        const OSSL_PROPERTY_LIST *b);

/* Property definition functions */
OSSL_PROPERTY_LIST *ossl_parse_property(const char *s);

/* Property query functions */
OSSL_PROPERTY_LIST *ossl_parse_query(const char *s);

/* Property definition cache functions */
int ossl_prop_defn_init(void);
void ossl_prop_defn_cleanup(void);
OSSL_PROPERTY_LIST *ossl_prop_defn_get(const char *prop);
int ossl_prop_defn_set(const char *prop, OSSL_PROPERTY_LIST *pl);

/* Property cache lock / unlock */
int ossl_property_write_lock(OSSL_METHOD_STORE *);
int ossl_property_read_lock(OSSL_METHOD_STORE *);
int ossl_property_unlock(OSSL_METHOD_STORE *);

