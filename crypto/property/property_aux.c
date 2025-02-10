/*
 * Copyright 2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/err.h>
#include "internal/property.h"
#include "internal/propertyerr.h"

char *ossl_merge_queries(OSSL_LIB_CTX *libctx, const char *propq1,
                         const char *propq2)
{
    OSSL_PROPERTY_LIST *pl1, *pl2, *mergedpl;
    char *props;
    size_t props_len;

    if (propq1 == NULL) {
        if (propq2 == NULL)
            return NULL;
        return OPENSSL_strdup(propq2);
    } else if (propq2 == NULL) {
        return OPENSSL_strdup(propq1);
    }

    pl1 = ossl_parse_query(libctx, propq1, 1);
    if (pl1 == NULL) {
        ERR_raise(ERR_LIB_PROP, PROP_R_INVALID_PROPERTY_QUERY);
        return NULL;
    }
    pl2 = ossl_parse_query(libctx, propq2, 1);
    if (pl2 == NULL) {
        ossl_property_free(pl1);
        ERR_raise(ERR_LIB_PROP, PROP_R_INVALID_PROPERTY_QUERY);
        return NULL;
    }
    mergedpl = ossl_property_merge(pl2, pl1);
    ossl_property_free(pl1);
    ossl_property_free(pl2);
    if (mergedpl == NULL) {
        ERR_raise(ERR_LIB_PROP, ERR_R_INTERNAL_ERROR);
        return NULL;
    }
    props_len = ossl_property_list_to_string(libctx, mergedpl, NULL, 0);
    if (props_len == 0) {
        ERR_raise(ERR_LIB_PROP, ERR_R_INTERNAL_ERROR);
        goto err;
    } else {
        props = OPENSSL_malloc(props_len);
        if (props == NULL)
            goto err;
        if (ossl_property_list_to_string(libctx, mergedpl,
                                         props, props_len) == 0) {
            ERR_raise(ERR_LIB_RAND, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

 err:
    ossl_property_free(mergedpl);
    return props;
}
