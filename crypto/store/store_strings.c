/*
 * Copyright 2000-2016 The OpenSSL Project Authors. All Rights Reserved.
 *
 * Licensed under the OpenSSL license (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */

#include <openssl/store.h>

static char *type_strings[] = {
    "Name",                      /* STORE_INFO_NAME */
    "Pkey",                      /* STORE_INFO_PKEY */
    "Certificate",               /* STORE_INFO_CERT */
    "CRL"                        /* STORE_INFO_CRL */
};

const char *STORE_INFO_type_string(int type)
{
    int types = sizeof(type_strings) / sizeof(type_strings[0]);

    if (type < 1 || type > types)
        return NULL;

    return type_strings[type];
}
