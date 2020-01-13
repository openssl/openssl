/*
 * Copyright 2016-2017 The Opentls Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.opentls.org/source/license.html
 */

#include <opentls/store.h>

static char *type_strings[] = {
    "Name",                      /* Otls_STORE_INFO_NAME */
    "Parameters",                /* Otls_STORE_INFO_PARAMS */
    "Pkey",                      /* Otls_STORE_INFO_PKEY */
    "Certificate",               /* Otls_STORE_INFO_CERT */
    "CRL"                        /* Otls_STORE_INFO_CRL */
};

const char *Otls_STORE_INFO_type_string(int type)
{
    int types = sizeof(type_strings) / sizeof(type_strings[0]);

    if (type < 1 || type > types)
        return NULL;

    return type_strings[type - 1];
}
