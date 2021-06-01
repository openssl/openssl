/*
 * Copyright 2021 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include "internal/propertyerr.h"
#include "internal/property.h"
#include "property_local.h"

const OSSL_PROPERTY_DEFINITION *
ossl_property_find_property(const OSSL_PROPERTY_LIST *list,
                            OSSL_LIB_CTX *libctx, const char *name)
{
    OSSL_PROPERTY_IDX name_idx;
    int i;

    if (list == NULL || name == NULL
        || (name_idx = ossl_property_name(libctx, name, 0)) == 0)
        return NULL;

    for (i = 0; i < list->n; i++)
        if (list->properties[i].name_idx == name_idx)
            return &list->properties[i];
    return NULL;
}

OSSL_PROPERTY_TYPE ossl_property_get_type(const OSSL_PROPERTY_DEFINITION *prop)
{
    return prop->type;
}

const char *ossl_property_get_string_value(OSSL_LIB_CTX *libctx,
                                           const OSSL_PROPERTY_DEFINITION *prop)
{
    const char *value = NULL;

    if (prop != NULL && prop->type == OSSL_PROPERTY_TYPE_STRING)
        value = ossl_property_value_str(libctx, prop->v.str_val);
    return value;
}

int64_t ossl_property_get_number_value(const OSSL_PROPERTY_DEFINITION *prop)
{
    int64_t value = 0;

    if (prop != NULL && prop->type == OSSL_PROPERTY_TYPE_NUMBER)
        value = prop->v.int_val;
    return value;
}
